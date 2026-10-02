# Architecture

The public project is deliberately split into a pure Python core, CLI/env
configuration, source adapters, packaging and synthetic tests. A local log
collector or bind mount supplies files; the digest parses them without
modifying or deleting inputs. Detection happens before any optional delivery.

States used in this repository are explicit: `configured` means represented
in files, `validated` means covered by local tests, `deployed` is not claimed
by this repository, and `proposed` is future work.

Deployment automation is intentionally separate. This repository does not
know hostnames, storage layouts, networks or inventory details from any
particular homelab.
