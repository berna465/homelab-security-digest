# Deployment separation

The reusable parser and detector core is separate from host-specific mounts,
automation, inventories, secrets and service managers. The public project
accepts operator-owned files through documented CLI and environment settings.
