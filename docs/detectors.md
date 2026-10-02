# Detector policy

`web_scan` uses a configurable security-status threshold, a distinct
semantic-path threshold and a sliding window. Dynamic numeric resource IDs and
UUIDs are canonicalized, while sensitive names remain visible to
classification. Client attribution is used only for events whose trust state
is `configured` or `verified`; no user-agent is a trust signal.

`blocked_probe` classifies high-confidence suspicious paths with blocked HTTP
statuses. `sensitive_path_exposed` requires a 2xx response and a positive body
byte count. Frontend localization and asset routes are excluded without
excluding generic configuration files. Both detectors apply to NPM and
Traefik events.

Authelia failure counts and failure-to-success sequences are deterministic,
ordered and limited by a configurable time window. OPNsense candidates are
separate diagnostic scan candidates only; the tool never blocks or changes
firewall state.
