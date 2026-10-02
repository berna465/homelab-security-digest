# Evidence model

Evidence is a minimal JSON bundle containing the analysis window, source
diagnostics, findings, candidates, deterministic report and runtime metrics.
Finding evidence is limited to IDs, hashes, source, line and timestamp
references. Paths appear only in bounded canonical summaries; query strings
are removed.

Dynamic IDs do not create separate web-scan identities, while distinct paths,
IP addresses and analysis windows remain distinguishable. Notification state is
locked and written atomically only after successful delivery. No cursor or
raw-log database is created.
