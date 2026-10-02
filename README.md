# homelab-security-digest

A local, deterministic security digest for self-hosted environments. It reads
NPM/Nginx, Traefik, Authelia and OPNsense logs, emits privacy-bounded JSON and
text reports, and never changes the systems whose logs it reads.

The project has no runtime dependency, cloud backend or automatic blocking.
Optional Telegram delivery is disabled by default and requires an explicit
network-enabled deployment.

## Quick start

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
python -m homelab_security_digest --help
```

Run offline against the synthetic TEST-NET inputs:

```sh
python -m homelab_security_digest \
  --npm-log ./examples/input/npm.log \
  --authelia-log ./examples/input/authelia.json \
  --opnsense-log ./examples/input/filterlog.log \
  --traefik-log ./examples/input/traefik.json \
  --output-dir ./output
```

Configuration is intentionally CLI/env-only in v0.1. There is no YAML
configuration loader. See `.env.example` for supported environment names.
The four source files have independent status values: `active`, `idle`,
`missing`, `invalid` or `unavailable`. The aggregate status is `ready`,
`degraded` or `unavailable`; a degraded run never reports an all-clear result.

## Output model

`evidence.json` contains three separate sections:

- `findings`: events that pass an operational detector policy;
- `candidates`: OPNsense port/network scan behaviour requiring review;
- `diagnostics`: source state, parser exclusions, timezone assumptions and
  pipeline quality.

OPNsense processing reads the current and `.1` file, deduplicates overlapping
rotation records by stable event hash, keeps active scan state bounded by the
analysis window, and does not turn candidates into findings automatically.

Implemented findings are web scans, blocked sensitive probes, successful
non-empty sensitive-path exposure, authentication brute force and ordered
failure-then-success sequences. HTTP detectors operate on both NPM and
Traefik events. Dynamic resource identifiers are canonicalized, query strings
are removed, and evidence references contain only bounded IDs, hashes, source,
line and UTC timestamp fields.

## Client IP and time

An offline parser cannot verify the original TCP peer or a forwarded-header
chain unless the input format supplies that information. Events therefore use
`client_ip`, `client_ip_source` and `client_ip_trust` (`verified`, `configured`
or `unknown`). Only configured/verified events participate in client-attributed
HTTP detectors. Every parser preserves the original timestamp, records its
explicit or assumed timezone, normalizes to UTC and reports unparseable input
in diagnostics.

## Container

The supplied Compose service uses a non-root UID, a read-only root filesystem,
read-only input, `cap_drop: ALL`, `no-new-privileges`, a memory limit and
`network_mode: none` by default. Telegram requires changing the network mode
and setting `SECURITY_DIGEST_TELEGRAM_ENABLED=true`.

## Provenance and license

This implementation is authored for this repository and is licensed under
Apache License 2.0. It is based on experience operating self-hosted systems
and contains only sanitized synthetic fixtures. Contributions must preserve
this provenance and add compatible license notices for any third-party
component.
