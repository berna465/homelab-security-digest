"""Local, deterministic and privacy-preserving security digest.

The public implementation deliberately has no cloud dependency and never
changes the systems whose logs it reads.  Input records are normalized first;
findings, candidates and pipeline diagnostics are kept as separate outputs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import heapq
import ipaddress
import json
import os
import re
import resource
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = dt.timezone.utc
WEB_SCAN_SECURITY_STATUSES = frozenset({400, 401, 403, 404, 405, 429, 444})
BLOCKED_PROBE_STATUSES = frozenset({400, 401, 403, 404, 405, 444})
BLOCKED_PROBE_SIGNATURES = frozenset({"env", "git", "wordpress", "phpmyadmin", "actuator", "swagger", "traversal", "config_file", "backup_file"})
EXPOSED_PATH_SIGNATURES = frozenset({"env", "git", "config_file", "backup_file"})
WEB_SCAN_MIN_4XX = 20
WEB_SCAN_MIN_PATHS = 12
WEB_SCAN_WINDOW_SECONDS = 300
AUTH_FAILURE_THRESHOLD = 5
AUTH_WINDOW_SECONDS = 900

NPM_ACCESS_RE = re.compile(r'^\[(?P<time>[^]]+)\]\s+-\s+\S+\s+(?P<status>\d{3})\s+-\s+(?P<method>\S+)\s+\S+\s+(?P<host>\S+)\s+"(?P<path>[^"]*)"\s+\[Client (?P<ip>[^]]+)\]', re.I)
NPM_ERROR_RE = re.compile(r'^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?client:\s*(?P<ip>[^,]+).*?request:\s+"(?P<method>\S+)\s+(?P<path>\S+)', re.I)
NPM_BODY_RE = re.compile(r'\[Length (?P<body>\d+|-)\]')
IP_RE = re.compile(r'(?<![0-9a-fA-F:])(?:\d{1,3}\.){3}\d{1,3}(?![0-9a-fA-F:])')
AUTH_FAILURE = re.compile(r'invalid credentials|unsuccessful.*authentication|authentication.*failed|access denied|rejected', re.I)
AUTH_SUCCESS = re.compile(r'successful.*authentication|authentication.*succeeded|authenticated successfully', re.I)
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)
DYNAMIC_PARENTS = frozenset({'pages', 'assets', 'albums', 'photos', 'users', 'documents', 'files', 'items'})
SUSPICIOUS_PATHS = {
    'env': re.compile(r'(?:^|/)\.env(?:\.|/|$)', re.I),
    'git': re.compile(r'(?:^|/)\.git(?:/|$)', re.I),
    'wordpress': re.compile(r'/(?:wp-admin|wp-login\.php|wp-content)(?:/|$)', re.I),
    'phpmyadmin': re.compile(r'/(?:phpmyadmin|pma)(?:/|$)', re.I),
    'actuator': re.compile(r'/actuator(?:/|$)', re.I),
    'swagger': re.compile(r'/(?:swagger|api-docs)(?:/|$)', re.I),
    'traversal': re.compile(r'(?:\.\./|%2e%2e|%252e%252e)', re.I),
    'config_file': re.compile(r'(?:^|/)(?:config|configuration|settings|appsettings|rclone)[^/]*\.(?:ya?ml|json|ini|conf|bak|sql)(?:$|/)', re.I),
    'backup_file': re.compile(r'(?:^|)/[^/]+\.(?:bak|backup|old|orig|save|sql|dump)(?:$|/)', re.I),
    'api': re.compile(r'/api(?:/|$)', re.I),
}
BENIGN_ROUTE = re.compile(r'^/(?:_next|assets|static|locales|localization|i18n|oauth2|oidc|authorize|authorization|callback|login|logout)(?:/|$)|^/\.well-known/openid-configuration$|^/api/(?:auth|oidc|firstfactor|secondfactor|verify|state)(?:/|$)', re.I)
STATIC_ASSET = re.compile(r'\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|eot)(?:$|/)', re.I)


def _parse_time_detail(value: Any, source_timezone: str | None = None) -> tuple[dt.datetime | None, str]:
    if value is None:
        return None, 'missing'
    text = str(value).strip().replace('Z', '+00:00')
    try:
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is not None:
            return parsed.astimezone(UTC), 'explicit_offset'
        zone = ZoneInfo(source_timezone or 'UTC')
        return parsed.replace(tzinfo=zone).astimezone(UTC), source_timezone or 'UTC'
    except (ValueError, ZoneInfoNotFoundError, OSError):
        return None, 'unparseable'


def parse_time(value: Any, source_timezone: str | None = None) -> dt.datetime | None:
    """Normalize a timestamp to UTC while retaining the historical API."""
    return _parse_time_detail(value, source_timezone)[0]


def parse_npm_timestamp(value: str, source_timezone: str = 'UTC') -> tuple[dt.datetime | None, str]:
    for fmt in ('%d/%b/%Y:%H:%M:%S %z', '%Y-%m-%dT%H:%M:%S%z'):
        try:
            return dt.datetime.strptime(str(value).strip(), fmt).astimezone(UTC), 'explicit_offset'
        except ValueError:
            pass
    for fmt in ('%Y/%m/%d %H:%M:%S', '%d/%b/%Y:%H:%M:%S'):
        try:
            naive = dt.datetime.strptime(str(value).strip(), fmt)
            return naive.replace(tzinfo=ZoneInfo(source_timezone)).astimezone(UTC), source_timezone
        except (ValueError, ZoneInfoNotFoundError, OSError):
            pass
    return None, 'unparseable'


def valid_ip(value: Any) -> str | None:
    candidate = str(value or '').split(',', 1)[0].strip().strip('[]')
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        match = IP_RE.search(candidate)
        return match.group(0) if match else None


def classify_npm_client_ip(value: Any, trusted_proxy_peers: Iterable[str] = (), lan_networks: Iterable[str] = ()) -> tuple[str | None, str, str]:
    """Return client IP, provenance source and trust state.

    A standalone log line cannot verify the TCP peer or a forwarded chain.
    Configured LAN semantics therefore produce ``configured``; otherwise the
    trust state remains ``unknown`` rather than claiming verification.
    """
    ip = valid_ip(value)
    if not ip:
        return None, 'unknown', 'unknown'
    address = ipaddress.ip_address(ip)
    try:
        configured_networks = tuple(ipaddress.ip_network(item, strict=False) for item in lan_networks)
        configured_peers = {str(ipaddress.ip_address(item)) for item in trusted_proxy_peers}
    except ValueError:
        return ip, 'invalid_configuration', 'unknown'
    if ip in configured_peers:
        return ip, 'proxy_peer', 'unknown'
    if any(address in network for network in configured_networks):
        return ip, 'configured_client_field', 'configured'
    return ip, 'client_field', 'unknown'


def event_id(source: str, line: int, raw: str) -> str:
    return hashlib.sha256(f'{source}:{line}:{raw}'.encode()).hexdigest()[:16]


def event_hash(source: str, raw: str) -> str:
    return hashlib.sha256(f'{source}:{raw}'.encode()).hexdigest()[:16]


def read_lines(path: Path) -> Iterable[tuple[int, str]]:
    if not path.is_file():
        return
    with path.open(encoding='utf-8', errors='replace') as handle:
        for number, line in enumerate(handle, 1):
            if line.strip():
                yield number, line.rstrip('\n')


def rotated_input_paths(path: Path) -> list[Path]:
    return [candidate for candidate in (Path(f'{path}.1'), path) if candidate.is_file()]


def source_status(path: Path, parsed: int, invalid: int = 0) -> str:
    paths = rotated_input_paths(path)
    if not paths:
        return 'missing'
    if not all(os.access(candidate, os.R_OK) for candidate in paths):
        return 'unavailable'
    if parsed:
        return 'active'
    return 'invalid' if invalid else 'idle'


def overall_status(states: dict[str, str]) -> str:
    usable = {'active', 'idle'}
    if states and all(state in usable for state in states.values()):
        return 'ready'
    if any(state in usable for state in states.values()):
        return 'degraded'
    return 'unavailable'


def _base_event(source: str, number: int, raw: str, timestamp: dt.datetime | None, assumption: str, original: Any = None) -> dict[str, Any]:
    return {'id': event_id(source, number, raw), 'event_hash': event_hash(source, raw), 'source': source, 'line': number, 'timestamp': timestamp.isoformat() if timestamp else None, 'timestamp_original': str(original if original is not None else raw[:200])[:200], 'timezone_assumption': assumption}


def parse_npm_line(raw: str, number: int, source: str = 'npm', source_timezone: str = 'UTC', trusted_proxy_peers: Iterable[str] = (), lan_networks: Iterable[str] = ()) -> tuple[dict[str, Any] | None, str | None]:
    match = NPM_ACCESS_RE.search(raw) or NPM_ERROR_RE.search(raw)
    if not match:
        return None, 'unsupported_schema'
    values = match.groupdict()
    timestamp, assumption = parse_npm_timestamp(values['time'], source_timezone)
    if timestamp is None:
        return None, 'invalid_timestamp'
    client_ip, ip_source, trust = classify_npm_client_ip(values.get('ip'), trusted_proxy_peers, lan_networks)
    body = NPM_BODY_RE.search(raw)
    return {**_base_event(source, number, raw, timestamp, assumption, values['time']), 'ip': client_ip, 'client_ip': client_ip, 'client_ip_source': ip_source, 'client_ip_trust': trust, 'status': int(values.get('status') or 0), 'path': str(values.get('path') or '').split('?', 1)[0][:200], 'host': str(values.get('host') or '')[:200], 'method': str(values.get('method') or '')[:12], 'body_bytes': int(body.group('body')) if body and body.group('body').isdigit() else 0}, None


def parse_npm(path: Path, since: dt.datetime, source: str = 'npm', source_timezone: str = 'UTC', until: dt.datetime | None = None, trusted_proxy_peers: Iterable[str] = (), lan_networks: Iterable[str] = ()) -> list[dict[str, Any]]:
    upper = until or dt.datetime.now(UTC)
    result = []
    for number, raw in read_lines(path):
        event, _ = parse_npm_line(raw, number, source, source_timezone, trusted_proxy_peers, lan_networks)
        timestamp, _ = _parse_time_detail(event.get('timestamp')) if event else (None, '')
        if event and timestamp and since <= timestamp <= upper:
            result.append(event)
    return result


def parse_traefik_line(raw: str, number: int, source: str = 'traefik', source_timezone: str = 'UTC') -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None, 'unsupported_schema'
        timestamp, assumption = _parse_time_detail(data.get('StartUTC') or data.get('time'), source_timezone)
        if timestamp is None:
            return None, 'invalid_timestamp'
        status = int(data.get('DownstreamStatus') or 0)
        body = int(data.get('body_bytes') or data.get('DownstreamContentSize') or 0)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, 'invalid_record'
    ip = valid_ip(data.get('ClientHost') or data.get('ClientAddr'))
    return {**_base_event(source, number, raw, timestamp, assumption, data.get('StartUTC') or data.get('time')), 'ip': ip, 'client_ip': ip, 'client_ip_source': 'log_client_host' if ip else 'unknown', 'client_ip_trust': 'configured' if ip else 'unknown', 'status': status, 'path': str(data.get('RequestPath') or '').split('?', 1)[0][:200], 'method': str(data.get('RequestMethod') or '')[:12], 'body_bytes': body}, None


def parse_traefik(path: Path, since: dt.datetime, source: str = 'traefik', source_timezone: str = 'UTC', until: dt.datetime | None = None) -> list[dict[str, Any]]:
    upper = until or dt.datetime.now(UTC)
    result = []
    for number, raw in read_lines(path):
        event, _ = parse_traefik_line(raw, number, source, source_timezone)
        timestamp, _ = _parse_time_detail(event.get('timestamp')) if event else (None, '')
        if event and timestamp and since <= timestamp <= upper:
            result.append(event)
    return result


def parse_authelia_line(raw: str, number: int, source: str = 'authelia', source_timezone: str = 'UTC') -> tuple[dict[str, Any] | None, str | None]:
    start = raw.find('{')
    if start < 0:
        return None, 'non_event_line'
    try:
        data = json.loads(raw[start:])
        if not isinstance(data, dict):
            return None, 'unsupported_schema'
    except json.JSONDecodeError:
        return None, 'invalid_json'
    message = str(data.get('msg') or data.get('message') or '')
    timestamp, assumption = _parse_time_detail(data.get('time') or data.get('timestamp'), source_timezone)
    ip = valid_ip(data.get('remote_ip') or data.get('remote_ip_address') or data.get('client_ip') or message)
    if timestamp is None:
        return None, 'invalid_timestamp'
    if not message and not ip:
        return None, 'unsupported_schema'
    kind = 'auth_failure' if AUTH_FAILURE.search(message) else 'auth_success' if AUTH_SUCCESS.search(message) else 'other'
    return {**_base_event(source, number, raw, timestamp, assumption, data.get('time') or data.get('timestamp')), 'ip': ip, 'client_ip': ip, 'client_ip_source': 'authelia_field' if ip else 'unknown', 'client_ip_trust': 'configured' if ip else 'unknown', 'kind': kind}, None


def parse_authelia(path: Path, since: dt.datetime, source: str = 'authelia', source_timezone: str = 'UTC', until: dt.datetime | None = None) -> list[dict[str, Any]]:
    upper = until or dt.datetime.now(UTC)
    result = []
    for number, raw in read_lines(path):
        event, _ = parse_authelia_line(raw, number, source, source_timezone)
        timestamp, _ = _parse_time_detail(event.get('timestamp')) if event else (None, '')
        if event and timestamp and since <= timestamp <= upper:
            result.append(event)
    return result


def parse_filterlog_payload(raw: str) -> tuple[dict[str, Any] | None, str | None]:
    match = re.search(r'(?P<payload>\d+,[^,]*,[^,]*,[^,]*,[^,]+,[^,]+,(?:block|pass|reject),(?:in|out|in/out),[46],.*)$', raw.strip(), re.I)
    if not match:
        return None, 'unsupported_filterlog_envelope'
    fields = match.group('payload').split(',')
    version = fields[8]
    if version == '4':
        if len(fields) < 22:
            return None, 'truncated_ipv4_record'
        proto, source, dest, ports = 16, 18, 19, 20
    elif version == '6':
        if len(fields) < 18:
            return None, 'truncated_ipv6_record'
        proto, source, dest, ports = 12, 15, 16, 17
    else:
        return None, 'unsupported_ip_version'
    src_ip, dst_ip = valid_ip(fields[source]), valid_ip(fields[dest])
    if not src_ip or not dst_ip:
        return None, 'invalid_endpoint'
    protocol = fields[proto].lower()
    src_port = dst_port = None
    if protocol in ('tcp', 'udp'):
        if len(fields) <= ports + 1 or not fields[ports].isdigit() or not fields[ports + 1].isdigit():
            return None, 'invalid_transport_ports'
        src_port, dst_port = int(fields[ports]), int(fields[ports + 1])
    return {'ip_version': int(version), 'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port, 'interface': fields[4][:40], 'direction': fields[7].lower(), 'action': fields[6].lower(), 'protocol': protocol[:20]}, None


def parse_opnsense_line(raw: str, number: int, source: str = 'opnsense', source_timezone: str = 'UTC') -> tuple[dict[str, Any] | None, str | None]:
    normalized, reason = parse_filterlog_payload(raw)
    if not normalized:
        return None, reason
    timestamp, assumption = _parse_time_detail(raw.split(' ', 1)[0], source_timezone)
    if not timestamp:
        return None, 'missing_timestamp'
    return {**_base_event(source, number, raw, timestamp, assumption, raw.split(' ', 1)[0]), **normalized, 'ip': normalized['src_ip'], 'actor_role': 'source_endpoint', 'diagnostic_only': True}, None


def parse_opnsense(path: Path, since: dt.datetime, source: str = 'opnsense', source_timezone: str = 'UTC', until: dt.datetime | None = None) -> list[dict[str, Any]]:
    upper = until or dt.datetime.now(UTC)
    result = []
    for number, raw in read_lines(path):
        event, _ = parse_opnsense_line(raw, number, source, source_timezone)
        timestamp, _ = _parse_time_detail(event.get('timestamp')) if event else (None, '')
        if event and timestamp and since <= timestamp <= upper:
            result.append(event)
    return result


def _parse_file(path: Path, parser: Any, since: dt.datetime, until: dt.datetime, **kwargs: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events, reasons = [], Counter()
    paths = [path]
    for input_path in paths:
        for number, raw in read_lines(input_path):
            try:
                event, reason = parser(raw, number, **kwargs)
            except (TypeError, ValueError):
                event, reason = None, 'invalid_record'
            if event is None:
                reasons[reason or 'invalid_record'] += 1
                continue
            timestamp, _ = _parse_time_detail(event.get('timestamp'))
            if timestamp is None:
                reasons['invalid_timestamp'] += 1
            elif since <= timestamp <= until:
                events.append(event)
            elif timestamp > until:
                reasons['future_timestamp'] += 1
            else:
                reasons['outside_time_window'] += 1
    events.sort(key=lambda item: (_parse_time_detail(item.get('timestamp'))[0] or dt.datetime.max.replace(tzinfo=UTC), item.get('line', 0)))
    return events, {'total': sum(1 for _ in read_lines(path)), 'parsed': len(events), 'excluded_reasons': dict(reasons)}


def stream_opnsense(path: Path, since: dt.datetime, until: dt.datetime, configured_endpoints: set[str] | None = None, configured_interfaces: set[str] | None = None, window_seconds: int = 300, sample_limit: int = 12, top_limit: int = 20) -> tuple[dict[str, Any], dict[str, Any]]:
    """Process rotated/current OPNsense records with state bounded by the window."""
    configured_endpoints, configured_interfaces = configured_endpoints or set(), configured_interfaces or set()
    total = parsed = 0
    reasons = Counter(); actions = Counter(); sources = Counter(); window = deque(); seen = set(); candidates = {}
    def records(input_path: Path):
        nonlocal total
        for number, raw in read_lines(input_path):
            total += 1
            event, reason = parse_opnsense_line(raw, number)
            if not event:
                reasons[reason or 'invalid_record'] += 1
                continue
            timestamp, _ = _parse_time_detail(event['timestamp'])
            if not timestamp or timestamp < since or timestamp > until:
                reasons['outside_time_window' if timestamp and timestamp < since else 'future_timestamp'] += 1
                continue
            yield timestamp, event

    streams = [iter(records(input_path)) for input_path in rotated_input_paths(path)]
    pending = []
    sequence = 0
    for stream in streams:
        try:
            timestamp, event = next(stream)
            heapq.heappush(pending, (timestamp, sequence, event, stream)); sequence += 1
        except StopIteration:
            pass
    while pending:
        timestamp, _, event, stream = heapq.heappop(pending)
        try:
            next_timestamp, next_event = next(stream)
            heapq.heappush(pending, (next_timestamp, sequence, next_event, stream)); sequence += 1
        except StopIteration:
            pass
        if event['event_hash'] in seen:
            reasons['duplicate_rotation_record'] += 1
            continue
        seen.add(event['event_hash'])
        parsed += 1; actions[event['action']] += 1
        if event['direction'] not in ('in', 'in/out') or event['action'] not in ('block', 'reject'):
            continue
        if configured_endpoints and event['dst_ip'] not in configured_endpoints:
            continue
        if configured_interfaces and event['interface'] not in configured_interfaces:
            continue
        while window and timestamp - window[0][0] > dt.timedelta(seconds=window_seconds):
            expired = window.popleft()
            seen.discard(expired[1]['event_hash'])
        window.append((timestamp, event))
        group = [item[1] for item in window if item[1]['src_ip'] == event['src_ip']]
        ports = {item['dst_port'] for item in group if item.get('dst_port')}; destinations = {item['dst_ip'] for item in group}
        if len(group) >= 30 and (len(ports) >= 10 or len(destinations) >= 10):
            candidates[event['src_ip']] = {'ip': event['src_ip'], 'ip_scope': ip_scope(event['src_ip']), 'events': len(group), 'distinct_ports': len(ports), 'distinct_destinations': len(destinations), 'candidate_types': (["port_scan"] if len(ports) >= 10 else []) + (["network_scan"] if len(destinations) >= 10 else []), 'window_seconds': window_seconds, 'interval': {'start': group[0]['timestamp'], 'end': group[-1]['timestamp']}, 'evidence': [reference(item) for item in group[-sample_limit:]]}
        sources[event['src_ip']] += 1
    return {'total': total, 'parsed': parsed, 'excluded': total - parsed, 'excluded_reasons': dict(reasons), 'files_read': len(rotated_input_paths(path)), 'ordering': {'out_of_order_records': reasons.get('out_of_order_record', 0)}}, {'action': dict(actions), 'top_remote_sources': dict(sources.most_common(top_limit)), 'scan_candidates': sorted(candidates.values(), key=lambda item: (-item['events'], item['ip'])), 'streaming': {'window_seconds': window_seconds, 'evidence_sample_limit': sample_limit}}


def semantic_path(value: Any) -> str:
    raw = urllib.parse.unquote(str(value or '').split('?', 1)[0].split('#', 1)[0])
    parts = raw.split('/'); result = []
    for index, part in enumerate(parts):
        previous = parts[index - 1].lower() if index else ''
        if previous == 'export': result.append('{format}')
        elif UUID_RE.fullmatch(part) or (part.isdigit() and previous in DYNAMIC_PARENTS) or (len(part) >= 20 and re.fullmatch(r'[A-Za-z0-9_-]+', part)): result.append('{id}')
        else: result.append(part[:80])
    return '/'.join(result)[:200] or '/'


canonical_web_scan_path = semantic_path


def suspicious_signatures(path: str) -> list[str]:
    decoded = urllib.parse.unquote(path)
    return [name for name, pattern in SUSPICIOUS_PATHS.items() if pattern.search(decoded)]


def is_legitimate_frontend_route(path: Any) -> bool:
    value = urllib.parse.unquote(str(path or '').split('?', 1)[0])
    return bool(BENIGN_ROUTE.search(value) or STATIC_ASSET.search(value))


def has_successful_nonempty_body(event: dict[str, Any]) -> bool:
    try:
        return 200 <= int(event.get('status') or 0) <= 299 and int(event.get('body_bytes') or 0) > 0
    except (TypeError, ValueError):
        return False


def is_sensitive_path_exposure(event: dict[str, Any]) -> bool:
    return bool(not is_legitimate_frontend_route(event.get('path')) and has_successful_nonempty_body(event) and set(suspicious_signatures(str(event.get('path') or ''))) & EXPOSED_PATH_SIGNATURES)


def client_trust(event: dict[str, Any]) -> str:
    if event.get('client_ip_trust'):
        return str(event['client_ip_trust'])
    if event.get('client_ip_trusted') is True:
        return 'configured'
    return 'unknown'


def reference(event: dict[str, Any]) -> dict[str, Any]:
    return {key: event.get(key) for key in ('id', 'event_hash', 'source', 'line', 'timestamp')}


def evidence_refs(events: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    return [reference(event) for event in events[:max(0, limit)]]


def ip_scope(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    return 'internal' if address.is_private or address.is_loopback or address.is_link_local else 'external'


def _windows(events: list[dict[str, Any]], min_events: int, min_paths: int, seconds: int) -> list[list[dict[str, Any]]]:
    by_ip = defaultdict(list)
    for event in events:
        if event.get('ip') and event.get('status') in WEB_SCAN_SECURITY_STATUSES and _parse_time_detail(event.get('timestamp'))[0] and client_trust(event) in ('verified', 'configured'):
            by_ip[event['ip']].append(event)
    found = []
    for group in by_ip.values():
        group.sort(key=lambda item: _parse_time_detail(item['timestamp'])[0])
        for left, start in enumerate(group):
            start_time = _parse_time_detail(start['timestamp'])[0]
            window = [item for item in group[left:] if (_parse_time_detail(item['timestamp'])[0] - start_time).total_seconds() <= seconds]
            if len(window) >= min_events and len({semantic_path(item.get('path')) for item in window}) >= min_paths:
                found.append(window); break
    return found


def finding_fingerprint(finding_type: str, ip: str, events: list[dict[str, Any]]) -> str:
    signature = [{'timestamp': e.get('timestamp'), 'status': e.get('status'), 'method': e.get('method'), 'path': semantic_path(e.get('path'))} for e in events] if finding_type == 'web_scan' else [e.get('event_hash') or e.get('id') for e in events]
    return hashlib.sha256(json.dumps([finding_type, ip, signature], sort_keys=True).encode()).hexdigest()


def daily_finding_fingerprint(finding_type: str, ip: str, day: str) -> str:
    return hashlib.sha256(f'{finding_type}|{ip}|{day}'.encode()).hexdigest()


def _auth_sequence(events: list[dict[str, Any]], window_seconds: int) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    ordered = sorted((event for event in events if _parse_time_detail(event.get('timestamp'))[0]), key=lambda event: _parse_time_detail(event['timestamp'])[0])
    failures = [event for event in ordered if event.get('kind') == 'auth_failure']
    for success in (event for event in ordered if event.get('kind') == 'auth_success'):
        success_time = _parse_time_detail(success['timestamp'])[0]
        prior = [failure for failure in failures if 0 <= (success_time - _parse_time_detail(failure['timestamp'])[0]).total_seconds() <= window_seconds]
        if len(prior) >= AUTH_FAILURE_THRESHOLD:
            return prior[-8:], success
    return None


def detect(http_events: list[dict[str, Any]], authelia: list[dict[str, Any]], opnsense: list[dict[str, Any]] | None = None, web_scan_min_4xx: int = WEB_SCAN_MIN_4XX, web_scan_min_paths: int = WEB_SCAN_MIN_PATHS, web_scan_window_seconds: int = WEB_SCAN_WINDOW_SECONDS, auth_window_seconds: int = AUTH_WINDOW_SECONDS) -> list[dict[str, Any]]:
    findings = []
    for window in _windows(http_events, web_scan_min_4xx, web_scan_min_paths, web_scan_window_seconds):
        ip = window[0]['ip']; findings.append({'type': 'web_scan', 'severity': 'attention', 'ip': ip, 'ip_scope': ip_scope(ip), 'fingerprint': finding_fingerprint('web_scan', ip, window), 'paths': sorted({semantic_path(e.get('path')) for e in window}), 'event_count': len(window), 'evidence': evidence_refs(window), 'summary': f'Possible web scan: {len(window)} security responses across {len({semantic_path(e.get("path")) for e in window})} logical paths.'})
    blocked = defaultdict(list); exposed = defaultdict(list)
    for event in http_events:
        if not event.get('ip') or client_trust(event) not in ('verified', 'configured'):
            continue
        timestamp, _ = _parse_time_detail(event.get('timestamp')); day = timestamp.date().isoformat() if timestamp else 'unknown'
        categories = set(suspicious_signatures(str(event.get('path') or '')))
        if event.get('status') in BLOCKED_PROBE_STATUSES and categories & BLOCKED_PROBE_SIGNATURES: blocked[(event['ip'], day)].append(event)
        if is_sensitive_path_exposure(event): exposed[(event['ip'], day)].append(event)
    for (ip, day), events in sorted(blocked.items()):
        categories = Counter(category for event in events for category in suspicious_signatures(str(event.get('path') or '')) if category != 'api')
        findings.append({'type': 'blocked_probe', 'severity': 'info', 'ip': ip, 'ip_scope': ip_scope(ip), 'event_count': len(events), 'categories': dict(categories), 'fingerprint': daily_finding_fingerprint('blocked_probe', ip, day), 'evidence': evidence_refs(sorted(events, key=lambda item: item.get('timestamp') or '')), 'summary': f'{len(events)} sensitive probes blocked.'})
    for (ip, day), events in sorted(exposed.items()):
        categories = Counter(category for event in events for category in suspicious_signatures(str(event.get('path') or '')))
        findings.append({'type': 'sensitive_path_exposed', 'severity': 'high', 'ip': ip, 'ip_scope': ip_scope(ip), 'event_count': len(events), 'categories': dict(categories), 'fingerprint': daily_finding_fingerprint('sensitive_path_exposed', ip, day), 'evidence': evidence_refs(events), 'summary': f'{len(events)} sensitive paths returned non-empty success responses.'})
    by_ip = defaultdict(list)
    for event in authelia:
        if event.get('ip'):
            by_ip[event['ip']].append(event)
    for ip, events in by_ip.items():
        sequence = _auth_sequence(events, auth_window_seconds)
        failures = [event for event in events if event.get('kind') == 'auth_failure']
        if sequence:
            prior, success = sequence
            findings.append({'type': 'auth_failure_then_success', 'severity': 'attention', 'ip': ip, 'fingerprint': finding_fingerprint('auth_failure_then_success', ip, prior + [success]), 'failure_evidence': evidence_refs(prior), 'success_evidence': evidence_refs([success]), 'evidence': evidence_refs(prior + [success]), 'summary': f'{len(prior)} authentication failures were followed by a success from the same source.'})
        elif len(failures) >= AUTH_FAILURE_THRESHOLD:
            findings.append({'type': 'auth_bruteforce', 'severity': 'attention', 'ip': ip, 'fingerprint': finding_fingerprint('auth_bruteforce', ip, failures), 'evidence': evidence_refs(failures), 'summary': f'{len(failures)} authentication failures from one source.'})
    return findings


def _web_scan_funnel(events: list[dict[str, Any]], min_4xx: int, min_paths: int, seconds: int) -> dict[str, int]:
    windows = _windows(events, min_4xx, min_paths, seconds)
    return {'windows_evaluated': len(events), 'qualified_windows': len(windows)}


def load_notified_fingerprints(path: Path) -> set[str]:
    try:
        return {str(value) for value in json.loads(path.read_text(encoding='utf-8')).get('fingerprints', []) if value}
    except (OSError, json.JSONDecodeError, AttributeError):
        return set()


def save_notified_fingerprints(path: Path, fingerprints: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    with temporary.open('w', encoding='utf-8') as handle:
        json.dump({'fingerprints': sorted(fingerprints)}, handle, indent=2)
        handle.write('\n'); handle.flush(); os.fsync(handle.fileno())
    os.replace(temporary, path)


def notification_lock(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    return os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)


def partition_findings(findings: list[dict[str, Any]], notified: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return [f for f in findings if f.get('fingerprint') not in notified], [f for f in findings if f.get('fingerprint') in notified]


def dry_run_from_env(value: str | None = None) -> bool:
    return str(os.getenv('SECURITY_DIGEST_DRY_RUN') if value is None else value).strip().lower() != 'false'


def validate_address_list(value: str, networks: bool = False) -> None:
    for item in (part.strip() for part in value.split(',') if part.strip()):
        try:
            ipaddress.ip_network(item, strict=False) if networks else ipaddress.ip_address(item)
        except ValueError as exc:
            kind = 'network' if networks else 'address'
            raise ValueError(f'invalid {kind}: {item}') from exc


def deterministic_report(findings: list[dict[str, Any]], candidates: list[dict[str, Any]] | None = None, diagnostics: dict[str, Any] | None = None, status: str = 'ready') -> str:
    candidates = candidates or []; diagnostics = diagnostics or {}
    if status in ('degraded', 'unavailable'):
        return f'Pipeline status: {status}. No all-clear conclusion is available.'
    if findings:
        return 'Attention: ' + ' '.join(f['summary'] for f in findings[:3])
    if candidates:
        return f'Candidate activity requires review: {len(candidates)} OPNsense candidate(s). No operational finding was created.'
    return 'No suspicious access detected.'


def send_telegram(message: str) -> bool:
    if os.getenv('SECURITY_DIGEST_TELEGRAM_ENABLED', 'false').strip().lower() != 'true':
        return False
    token = os.getenv('SECURITY_DIGEST_TELEGRAM_BOT_TOKEN', '').strip(); chat_id = os.getenv('SECURITY_DIGEST_TELEGRAM_CHAT_ID', '').strip()
    if not token or not chat_id:
        return False
    body = urllib.parse.urlencode({'chat_id': chat_id, 'text': message}).encode()
    try:
        with urllib.request.urlopen(f'https://api.telegram.org/bot{token}/sendMessage', data=body, timeout=20) as response:
            if not 200 <= response.status < 300:
                return False
            payload = json.load(response)
        return payload.get('ok') is True
    except (OSError, urllib.error.URLError, json.JSONDecodeError, AttributeError, TypeError, ValueError):
        return False


def _source_result(name: str, path: Path, parser: Any, since: dt.datetime, until: dt.datetime, **kwargs: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not rotated_input_paths(path):
        return [], {'source': name, 'status': 'missing', 'total': 0, 'parsed': 0, 'excluded_reasons': {}}
    events, funnel = _parse_file(path, parser, since, until, **kwargs)
    invalid = sum(value for key, value in funnel['excluded_reasons'].items() if key not in ('outside_time_window', 'future_timestamp'))
    funnel.update({'source': name, 'status': source_status(path, len(events), invalid), 'invalid': invalid})
    return events, funnel


def run(args: argparse.Namespace) -> int:
    started = time.monotonic(); now = dt.datetime.now(UTC); since = now - dt.timedelta(hours=args.hours)
    peers = tuple(value.strip() for value in args.npm_trusted_proxy_peers.split(',') if value.strip()); networks = tuple(value.strip() for value in args.npm_lan_networks.split(',') if value.strip())
    npm, npm_diag = _source_result('npm', Path(args.npm_log), parse_npm_line, since, now, source='npm', source_timezone=args.npm_source_timezone, trusted_proxy_peers=peers, lan_networks=networks)
    traefik, traefik_diag = _source_result('traefik', Path(args.traefik_log), parse_traefik_line, since, now, source='traefik', source_timezone=args.traefik_source_timezone)
    authelia, authelia_diag = _source_result('authelia', Path(args.authelia_log), parse_authelia_line, since, now, source='authelia', source_timezone=args.authelia_source_timezone)
    opnsense_path = Path(args.opnsense_log)
    if rotated_input_paths(opnsense_path):
        opnsense_funnel, opnsense_diag = stream_opnsense(opnsense_path, since, now, set(filter(None, (valid_ip(value.strip()) for value in args.opnsense_wan_endpoints.split(',')))), set(filter(None, (value.strip() for value in args.opnsense_wan_interfaces.split(',')))), args.opnsense_window_seconds)
        invalid = sum(value for key, value in opnsense_funnel.get('excluded_reasons', {}).items() if key not in ('outside_time_window', 'future_timestamp'))
        opnsense_diag.update({'source': 'opnsense', 'status': 'active' if opnsense_funnel['parsed'] else ('invalid' if invalid else 'idle'), 'invalid': invalid, **opnsense_funnel})
        opnsense_events = parse_opnsense(opnsense_path, since, source='opnsense', until=now)
    else:
        opnsense_diag = {'source': 'opnsense', 'status': 'missing', 'total': 0, 'parsed': 0, 'excluded_reasons': {}}; opnsense_events = []
    source_diags = {item['source']: item for item in (npm_diag, traefik_diag, authelia_diag, opnsense_diag)}
    status = overall_status({name: diag['status'] for name, diag in source_diags.items()})
    findings = detect(npm + traefik, authelia, opnsense_events, args.web_scan_min_4xx, args.web_scan_min_paths, args.web_scan_window_seconds, args.auth_window_seconds)
    candidates = opnsense_diag.get('scan_candidates', [])
    diagnostics = {'status': status, 'sources': source_diags, 'timezone': {'npm': args.npm_source_timezone, 'traefik': args.traefik_source_timezone, 'authelia': args.authelia_source_timezone, 'opnsense': args.opnsense_source_timezone}}
    state_path = Path(args.notification_state_file); notified: set[str] = set(); new: list[dict[str, Any]] = []; duplicate: list[dict[str, Any]] = []; telegram_sent = False
    lock_path = state_path.with_suffix('.lock'); lock_fd = None
    try:
        if not args.dry_run:
            lock_fd = notification_lock(lock_path)
        notified = load_notified_fingerprints(state_path)
        new, duplicate = partition_findings(findings, notified)
        if not args.dry_run and (new or not findings):
            telegram_sent = send_telegram(deterministic_report(new, candidates, diagnostics, status))
            if telegram_sent:
                save_notified_fingerprints(state_path, notified | {f['fingerprint'] for f in new})
    except FileExistsError:
        diagnostics['notification_lock'] = 'busy'; notified = load_notified_fingerprints(state_path); new, duplicate = [], findings
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
            try: lock_path.unlink()
            except FileNotFoundError: pass
    report = deterministic_report(findings, candidates, diagnostics, status)
    bundle = {'schema_version': 2, 'generated_at': now.isoformat(), 'window_start': since.isoformat(), 'window_hours': args.hours, 'dry_run': args.dry_run, 'status': status, 'findings': findings, 'candidates': candidates, 'diagnostics': diagnostics, 'deterministic_report': report, 'rendered_report': report, 'new_findings_count': len(new), 'duplicate_findings_count': len(duplicate), 'cloud_used': False, 'telegram_sent': telegram_sent, 'runtime_metrics': {'elapsed_seconds': round(time.monotonic() - started, 3), 'max_rss_mib': round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 3)}}
    output = Path(args.output_dir); output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (output / 'report.txt').write_text(report + '\n', encoding='utf-8'); print(report); return 0


def main() -> int:
    parser = argparse.ArgumentParser(description='Local deterministic security digest')
    parser.add_argument('--hours', type=int, default=24)
    parser.add_argument('--npm-log', default='/input/npm.log'); parser.add_argument('--authelia-log', default='/input/authelia.json'); parser.add_argument('--opnsense-log', default='/input/filterlog.log'); parser.add_argument('--traefik-log', default='/input/traefik.json'); parser.add_argument('--output-dir', default='/output'); parser.add_argument('--notification-state-file', default='/output/state/notified-findings.json')
    parser.add_argument('--npm-source-timezone', default=os.getenv('SECURITY_DIGEST_NPM_SOURCE_TIMEZONE', 'UTC')); parser.add_argument('--traefik-source-timezone', default=os.getenv('SECURITY_DIGEST_TRAEFIK_SOURCE_TIMEZONE', 'UTC')); parser.add_argument('--authelia-source-timezone', default=os.getenv('SECURITY_DIGEST_AUTHELIA_SOURCE_TIMEZONE', 'UTC')); parser.add_argument('--opnsense-source-timezone', default=os.getenv('SECURITY_DIGEST_OPNSENSE_SOURCE_TIMEZONE', 'UTC'))
    parser.add_argument('--npm-trusted-proxy-peers', default=os.getenv('SECURITY_DIGEST_NPM_TRUSTED_PROXY_PEERS', '')); parser.add_argument('--npm-lan-networks', default=os.getenv('SECURITY_DIGEST_NPM_LAN_NETWORKS', '')); parser.add_argument('--opnsense-wan-endpoints', default=os.getenv('SECURITY_DIGEST_OPNSENSE_WAN_ENDPOINTS', '')); parser.add_argument('--opnsense-wan-interfaces', default=os.getenv('SECURITY_DIGEST_OPNSENSE_WAN_INTERFACES', ''))
    parser.add_argument('--web-scan-min-4xx', type=int, default=int(os.getenv('SECURITY_DIGEST_WEB_SCAN_MIN_4XX', WEB_SCAN_MIN_4XX))); parser.add_argument('--web-scan-min-paths', type=int, default=int(os.getenv('SECURITY_DIGEST_WEB_SCAN_MIN_PATHS', WEB_SCAN_MIN_PATHS))); parser.add_argument('--web-scan-window-seconds', type=int, default=int(os.getenv('SECURITY_DIGEST_WEB_SCAN_WINDOW_SECONDS', WEB_SCAN_WINDOW_SECONDS))); parser.add_argument('--auth-window-seconds', type=int, default=int(os.getenv('SECURITY_DIGEST_AUTH_WINDOW_SECONDS', AUTH_WINDOW_SECONDS))); parser.add_argument('--opnsense-window-seconds', type=int, default=int(os.getenv('SECURITY_DIGEST_OPNSENSE_WINDOW_SECONDS', WEB_SCAN_WINDOW_SECONDS))); parser.add_argument('--dry-run', action='store_true', default=dry_run_from_env())
    args = parser.parse_args()
    if args.hours <= 0 or any(value <= 0 for value in (args.web_scan_min_4xx, args.web_scan_min_paths, args.web_scan_window_seconds, args.auth_window_seconds, args.opnsense_window_seconds)):
        parser.error('hours and detector windows/thresholds must be positive')
    try:
        validate_address_list(args.npm_trusted_proxy_peers)
        validate_address_list(args.npm_lan_networks, networks=True)
        validate_address_list(args.opnsense_wan_endpoints)
    except ValueError as exc:
        parser.error(str(exc))
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
