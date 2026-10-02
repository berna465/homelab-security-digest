# Integrations

The parser contracts are local file contracts:

- Nginx/NPM access lines with client and status fields;
- Traefik JSON access events;
- Authelia JSON or syslog envelopes;
- OPNsense filterlog records, including current and `.1` rotated files.

The project does not install rsyslog, configure a reverse proxy, discover
containers, access Docker sockets, call cloud APIs or configure Telegram.
Operators may mount or copy sanitized inputs into the configured paths.
Telegram is a deliberately optional outbound integration and is disabled in
the default Compose network namespace.
