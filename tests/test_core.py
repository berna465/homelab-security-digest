import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from homelab_security_digest import core as digest


UTC = dt.timezone.utc


class DigestTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 1, 15, 12, tzinfo=UTC)
        self.since = self.now - dt.timedelta(hours=24)

    def event(self, path, status=404, ip="198.51.100.10", offset=0, body=0, source="npm"):
        return {
            "id": f"event-{source}-{offset}", "event_hash": f"hash-{source}-{offset}",
            "source": source, "line": offset + 1,
            "timestamp": (self.now + dt.timedelta(seconds=offset)).isoformat(),
            "ip": ip, "client_ip": ip, "client_ip_trust": "configured",
            "status": status, "path": path, "method": "GET", "body_bytes": body,
        }

    def npm_line(self, timestamp, path="/ok", status=404, ip="198.51.100.10", body=0):
        rendered = timestamp.astimezone(UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'[{rendered}] - {status} {status} - GET https example.com "{path}" [Client {ip}] [Length {body}]'

    def opnsense_line(self, timestamp, source="198.51.100.20", destination="192.0.2.10", port=443):
        return (f"{timestamp.isoformat()} fw filterlog: 5,,,label,wan0,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,"
                f"{source},{destination},50000,{port},0,S,1,,65535,,mss")

    def test_npm_and_traefik_http_detectors_share_the_same_contract(self):
        events = [self.event(f"/probe-{index}", source="npm", offset=index) for index in range(20)]
        events += [self.event("/.env", status=200, body=4, source="traefik", ip="198.51.100.11", offset=40)]
        events += [self.event("/.git/HEAD", status=404, source="traefik", ip="198.51.100.11", offset=41)]
        findings = digest.detect(events, [])
        types = {finding["type"] for finding in findings}
        self.assertIn("web_scan", types)
        self.assertIn("blocked_probe", types)
        self.assertIn("sensitive_path_exposed", types)
        self.assertTrue(all(ref["source"] in {"npm", "traefik"} for finding in findings for ref in finding["evidence"]))

    def test_dynamic_ids_and_oidc_assets_do_not_create_false_scans(self):
        dynamic = [self.event(f"/api/pages/{index}/export/markdown", 403, offset=index) for index in range(20)]
        self.assertEqual(digest.detect(dynamic, []), [])
        oidc = [self.event(f"/.well-known/openid-configuration?nonce={index}", 404, offset=index) for index in range(20)]
        self.assertEqual(digest.detect(oidc, []), [])

    def test_sensitive_paths_remain_detectable_and_frontend_locales_do_not(self):
        exposed = [self.event("/.env", 200, body=10, offset=1)]
        self.assertEqual(digest.detect(exposed, [])[0]["type"], "sensitive_path_exposed")
        locales = [self.event("/locales/en/settings.json", 200, body=10, offset=1)]
        self.assertEqual(digest.detect(locales, []), [])

    def test_auth_failure_then_success_requires_order_and_window(self):
        failures = [{"ip": "198.51.100.9", "kind": "auth_failure", "timestamp": (self.now + dt.timedelta(seconds=i)).isoformat(), "id": f"f{i}", "event_hash": f"f{i}", "source": "authelia", "line": i} for i in range(5)]
        success = {"ip": "198.51.100.9", "kind": "auth_success", "timestamp": (self.now + dt.timedelta(seconds=10)).isoformat(), "id": "s", "event_hash": "s", "source": "authelia", "line": 10}
        finding = digest.detect([], failures + [success], auth_window_seconds=30)[0]
        self.assertEqual(finding["type"], "auth_failure_then_success")
        self.assertEqual(len(finding["failure_evidence"]), 5)
        self.assertEqual(len(finding["success_evidence"]), 1)
        success_first = dict(success, timestamp=(self.now - dt.timedelta(seconds=10)).isoformat())
        self.assertEqual(digest.detect([], [success_first] + failures, auth_window_seconds=30)[0]["type"], "auth_bruteforce")
        late = dict(success, timestamp=(self.now + dt.timedelta(hours=2)).isoformat())
        self.assertEqual(digest.detect([], failures + [late], auth_window_seconds=30)[0]["type"], "auth_bruteforce")

    def test_timezone_is_explicit_or_assumed_and_invalid_records_are_counted(self):
        winter, assumption = digest.parse_npm_timestamp("15/Jan/2026:13:00:00", "Europe/Rome")
        self.assertEqual(winter.isoformat(), "2026-01-15T12:00:00+00:00")
        self.assertEqual(assumption, "Europe/Rome")
        explicit, assumption = digest.parse_npm_timestamp("15/Jan/2026:13:00:00 +0100", "UTC")
        self.assertEqual(explicit.isoformat(), "2026-01-15T12:00:00+00:00")
        self.assertEqual(assumption, "explicit_offset")
        event, reason = digest.parse_authelia_line('{"time":"bad","remote_ip":"198.51.100.1"}', 1)
        self.assertIsNone(event)
        self.assertEqual(reason, "invalid_timestamp")

    def test_each_parser_emits_original_timezone_and_normalized_utc(self):
        npm, _ = digest.parse_npm_line("[15/Jan/2026:13:00:00] - 200 200 - GET https example.com \"/ok\" [Client 192.0.2.8] [Length 1]", 1, source_timezone="Europe/Rome")
        traefik, _ = digest.parse_traefik_line('{"StartUTC":"2026-01-15T13:00:00","ClientHost":"192.0.2.8","DownstreamStatus":200,"RequestPath":"/ok"}', 1, source_timezone="Europe/Rome")
        authelia, _ = digest.parse_authelia_line('{"time":"2026-01-15T13:00:00","remote_ip":"192.0.2.8","msg":"Successful authentication"}', 1, source_timezone="Europe/Rome")
        opnsense, _ = digest.parse_opnsense_line(self.opnsense_line(self.now), 1)
        for event in (npm, traefik, authelia, opnsense):
            self.assertIsNotNone(event["timestamp_original"])
            self.assertEqual(digest.parse_time(event["timestamp"]).tzinfo, UTC)
            self.assertTrue(event["timezone_assumption"])

    def test_client_ip_trust_never_claims_proxy_verification(self):
        _, source, trust = digest.classify_npm_client_ip("198.51.100.2", ("192.0.2.7",), ())
        self.assertEqual((source, trust), ("client_field", "unknown"))
        _, source, trust = digest.classify_npm_client_ip("192.0.2.8", (), ("192.0.2.0/24",))
        self.assertEqual((source, trust), ("configured_client_field", "configured"))
        with self.assertRaises(ValueError):
            digest.validate_address_list("not-an-address")
        with self.assertRaises(ValueError):
            digest.validate_address_list("not-a-network", networks=True)

    def test_opnsense_rotated_records_are_deduplicated_and_candidates_are_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            current = Path(directory) / "filterlog.log"
            rotated = Path(f"{current}.1")
            rows = [self.opnsense_line(self.now + dt.timedelta(seconds=i), port=1000 + i) for i in range(30)]
            rotated.write_text("\n".join(rows) + "\n", encoding="utf-8")
            current.write_text("\n".join(rows[:3]) + "\n", encoding="utf-8")
            funnel, diagnostic = digest.stream_opnsense(current, self.since, self.now + dt.timedelta(minutes=1), {"192.0.2.10"}, {"wan0"})
            self.assertEqual(funnel["files_read"], 2)
            self.assertEqual(funnel["parsed"], 30)
            self.assertEqual(funnel["excluded_reasons"]["duplicate_rotation_record"], 3)
            self.assertEqual(diagnostic["scan_candidates"][0]["candidate_types"], ["port_scan"])
            self.assertEqual(digest.deterministic_report([], diagnostic["scan_candidates"], status="ready").startswith("Candidate activity"), True)

    def test_source_status_and_degraded_report_never_claim_all_clear(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            npm = root / "npm.log"
            npm.write_text(self.npm_line(self.now) + "\n", encoding="utf-8")
            events, funnel = digest._source_result("npm", npm, digest.parse_npm_line, self.since, self.now, source="npm", source_timezone="UTC")
            self.assertEqual(funnel["status"], "active")
            self.assertEqual(digest.source_status(root / "missing.log", 0), "missing")
            self.assertEqual(digest.overall_status({"npm": "active", "traefik": "missing"}), "degraded")
            self.assertNotIn("No suspicious access detected", digest.deterministic_report([], status="degraded"))

    def test_all_source_states_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.log"
            empty = root / "empty.log"; empty.write_text("", encoding="utf-8")
            invalid = root / "invalid.log"; invalid.write_text("not a valid NPM record\n", encoding="utf-8")
            active = root / "active.log"; active.write_text(self.npm_line(self.now) + "\n", encoding="utf-8")
            self.assertEqual(digest.source_status(missing, 0), "missing")
            self.assertEqual(digest.source_status(empty, 0), "idle")
            _, invalid_funnel = digest._source_result("npm", invalid, digest.parse_npm_line, self.since, self.now, source="npm", source_timezone="UTC")
            self.assertEqual(invalid_funnel["status"], "invalid")
            _, active_funnel = digest._source_result("npm", active, digest.parse_npm_line, self.since, self.now, source="npm", source_timezone="UTC")
            self.assertEqual(active_funnel["status"], "active")
            with patch.object(digest.os, "access", return_value=False):
                self.assertEqual(digest.source_status(active, 0), "unavailable")

    def test_evidence_is_bounded_and_contains_no_paths_or_queries(self):
        events = [self.event("/.env?token=secret", 444, offset=i) for i in range(30)]
        refs = digest.evidence_refs(events, 12)
        self.assertEqual(len(refs), 12)
        self.assertNotIn("path", refs[0])
        self.assertNotIn("secret", json.dumps(refs))

    def test_notification_state_is_atomic_and_lock_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            digest.save_notified_fingerprints(state, {"one"})
            self.assertEqual(digest.load_notified_fingerprints(state), {"one"})
            fd = digest.notification_lock(state.with_suffix(".lock"))
            try:
                with self.assertRaises(FileExistsError):
                    digest.notification_lock(state.with_suffix(".lock"))
            finally:
                os.close(fd)
                state.with_suffix(".lock").unlink()

    def test_successful_notification_is_not_repeated_on_next_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); now = dt.datetime.now(UTC)
            npm = root / "npm.log"
            npm.write_text("\n".join(self.npm_line(now - dt.timedelta(seconds=20 - i), f"/probe-{i}", 404, "192.0.2.8") for i in range(20)) + "\n", encoding="utf-8")
            (root / "traefik.json").write_text("", encoding="utf-8")
            (root / "authelia.json").write_text("", encoding="utf-8")
            (root / "filterlog.log").write_text(self.opnsense_line(now) + "\n", encoding="utf-8")
            args = type("Args", (), {
                "hours": 24, "npm_log": str(npm), "authelia_log": str(root / "authelia.json"), "opnsense_log": str(root / "filterlog.log"), "traefik_log": str(root / "traefik.json"), "output_dir": str(root / "output"), "notification_state_file": str(root / "state.json"), "npm_source_timezone": "UTC", "traefik_source_timezone": "UTC", "authelia_source_timezone": "UTC", "opnsense_source_timezone": "UTC", "npm_trusted_proxy_peers": "", "npm_lan_networks": "192.0.2.0/24", "opnsense_wan_endpoints": "192.0.2.10", "opnsense_wan_interfaces": "wan0", "web_scan_min_4xx": 20, "web_scan_min_paths": 12, "web_scan_window_seconds": 300, "auth_window_seconds": 900, "opnsense_window_seconds": 300, "dry_run": False,
            })()
            with patch.dict(os.environ, {"SECURITY_DIGEST_TELEGRAM_ENABLED": "true", "SECURITY_DIGEST_TELEGRAM_BOT_TOKEN": "token", "SECURITY_DIGEST_TELEGRAM_CHAT_ID": "chat"}):
                with patch.object(digest, "send_telegram", return_value=True) as send:
                    digest.run(args); digest.run(args)
                    self.assertEqual(send.call_count, 1)
            self.assertTrue((root / "state.json").is_file())

    def test_telegram_requires_http_success_and_api_ok(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self): return b'{"ok": false}'
        with patch.dict(os.environ, {"SECURITY_DIGEST_TELEGRAM_ENABLED": "true", "SECURITY_DIGEST_TELEGRAM_BOT_TOKEN": "token", "SECURITY_DIGEST_TELEGRAM_CHAT_ID": "chat"}):
            with patch.object(digest.urllib.request, "urlopen", return_value=Response()):
                self.assertFalse(digest.send_telegram("offline test"))
            with patch.object(digest.urllib.request, "urlopen", side_effect=OSError("offline")):
                self.assertFalse(digest.send_telegram("offline test"))

    def test_cli_module_creates_both_outputs_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "output"
            (root / "npm.log").write_text(self.npm_line(dt.datetime.now(UTC)) + "\n", encoding="utf-8")
            (root / "traefik.json").write_text(json.dumps({"StartUTC": dt.datetime.now(UTC).isoformat(), "ClientHost": "198.51.100.3", "DownstreamStatus": 404, "RequestPath": "/ok", "RequestMethod": "GET"}) + "\n", encoding="utf-8")
            (root / "authelia.json").write_text(json.dumps({"time": dt.datetime.now(UTC).isoformat(), "remote_ip": "198.51.100.4", "msg": "Successful authentication"}) + "\n", encoding="utf-8")
            (root / "filterlog.log").write_text(self.opnsense_line(dt.datetime.now(UTC)) + "\n", encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src"), "PYTHONDONTWRITEBYTECODE": "1", "SECURITY_DIGEST_DRY_RUN": "true"}
            result = subprocess.run([sys.executable, "-m", "homelab_security_digest", "--npm-log", str(root / "npm.log"), "--traefik-log", str(root / "traefik.json"), "--authelia-log", str(root / "authelia.json"), "--opnsense-log", str(root / "filterlog.log"), "--output-dir", str(output)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            bundle = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(bundle["status"], "ready")
            self.assertTrue((output / "report.txt").is_file())


if __name__ == "__main__":
    unittest.main()
