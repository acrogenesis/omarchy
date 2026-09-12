# Rootless Docker

Omarchy runs ordinary development containers in a per-user rootless Docker daemon while retaining a separate rootful Docker daemon for the Windows VM. This keeps the Docker CLI, Compose, Buildx, and image format unchanged while removing the root-equivalent `docker` group from the development path.

## Runtime boundary

The user daemon is `docker.service` from `docker-rootless-extras`. It listens on `$XDG_RUNTIME_DIR/docker.sock`, stores engine data below `~/.local/share/docker`, and reads daemon configuration from `~/.config/docker/daemon.json`. `default/systemd/user-environment-generators/60-omarchy-rootless-docker` and `default/bash/env-bootstrap` export `DOCKER_HOST` only after `~/.local/state/omarchy/rootless-docker/enabled` exists.

The system daemon remains socket-activated for `omarchy-windows-vm`. Its vendor drop-in makes `/run/docker.sock` root-owned with mode `0600`, and the Windows command always selects that socket explicitly after authenticating with `sudo` or `pkexec`. User Docker settings and `DOCKER_HOST` cannot redirect the privileged VM command.

## Fresh installs and additional users

The root setup allocates each account a nonoverlapping subordinate UID and GID range of at least 65,536 IDs, enables the rootless service globally, and writes `/var/lib/omarchy/rootless-docker/enabled`. User finalization then creates the private marker and daemon config before first login starts the service.

The migration's machine-wide enabled marker is written only after the shared rootful inventory has migrated and `/run/docker.sock` has been restricted. When another account later runs the per-user migration, it initializes that account's rootless daemon and returns before inspecting the retained rootful recovery store.

## Existing-install migration

`migrations/1789164756.sh` installs the rootless runtime, allocates subordinate IDs, starts and proves the rootless daemon, claims the machine-wide source inventory for one account, restricts the old API socket to root, and preflights every rootful development container. A container named `omarchy-windows` is exempt only when its image, Compose identity, devices, capabilities, ports, and mounts match Omarchy's managed VM. A blocker in any source prevents the batch from stopping its first container.

The automatic path accepts stock bridge networking with localhost-only unprivileged published ports, private local named volumes, supported resource limits, containers that run as root with Docker's default capability ceiling or stricter settings, numeric non-root image users that already drop every capability, and the stock runtime and namespace boundaries. It rejects privileged containers, added capabilities, devices, host or shared mounts, named image users whose effective UID is ambiguous, numeric non-root image users whose capability ceiling cannot be reproduced exactly, custom networks, namespace sharing, custom runtimes, altered confinement, custom logging, reserved migration labels, and unknown nondefault host settings.

For each accepted container, the migrator stops the source cleanly, commits its writable layer, transfers that image through Docker's native save/load format, copies named-volume contents and metadata inside the RootlessKit user and mount namespace, and recreates the container with explicit private and restrictive settings. It verifies environment, application config, limits, capabilities, mounts, ports, restart policy, logging, volume fingerprints, and lifecycle before writing a receipt bound to full source and destination snapshots.

Before the destination is first started, an error removes only the exact journal-owned destination container and restores the source. Journal-owned volumes remain available for fingerprint verification and safe reuse on retry, avoiding destructive cleanup when another client could have claimed a predictable volume name. Once a destination start has been attempted, both copies remain stopped or in their observed state for manual recovery because either side may contain new writes. Successful sources remain stopped with their restart policy disabled; they are retained in the rootful engine as recovery copies.
