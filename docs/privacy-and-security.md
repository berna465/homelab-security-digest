# Privacy and security

The default execution has no network, no cloud provider and no notification.
Inputs are read-only, the Compose process is non-root, drops all Linux
capabilities, uses `no-new-privileges` and has a configurable memory limit.
The tool is a detector and reporting utility, not an enforcement boundary.

Use TEST-NET addresses and `example.com` in documentation and tests. Never
commit real logs, public addresses, identifiers, tokens, cookies, credentials,
fingerprints or sensitive authorization data. Telegram uses its bot token in
the API URL; deployments must ensure intermediaries do not log complete URLs.
