# Operations

Run the daily job from a systemd timer or an external scheduler. Mount source
logs read-only and give the process only a writable output directory. Review
`evidence.json` before acting on a finding. Keep Telegram disabled during
testing. Roll back by stopping the timer and removing only the installed
standalone files; the tool does not modify source logs or firewall state.

For a local smoke test, use the synthetic fixture-driven unit tests and the
example command in the README. There is no live-host procedure in this public
repository.
