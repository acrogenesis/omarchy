# Podman migration boundaries

The automatic migration handles stock Omarchy development databases and the Windows disk handover. It rejects unsupported workloads before stopping any container. Successful custom migrations require an explicit plan; they are not evidence that the automatic path supports arbitrary Docker configuration.

## Findings carried into the implementation

| Observed during host migration | General implementation |
| --- | --- |
| `podman volume import` changed the volume root's mode | Transfer with native GNU tar in `podman unshare`, preserving numeric ownership, PAX timestamps, ACLs, xattrs, sparse files and links. Compare content/metadata manifests before creating the container. |
| Committed images did not reliably retain runtime health checks | Recreate health commands, intervals, timeouts, start periods and retries explicitly. Reject unsupported start intervals during batch preflight. |
| Podman's default PID limit differs from Docker's unlimited default | Explicitly retain the unlimited limit for accepted stock databases. Custom PID limits remain outside the automatic path. |
| A newly created volume may receive image data when first mounted | Mount restored volumes with `nocopy`. |
| A successful `docker stop` can still mean forced termination | Inspect the stopped state and refuse to copy an originally running database after SIGKILL or a segmentation fault; restart the source on failure. |
| Desktop's Linux extension starts another service on systemd's API socket and removes it on exit | The Omarchy launcher gives Desktop a scoped Podman subprocess adapter that reuses the user socket. Other commands dispatch to the real Podman binary. Recover an already-unlinked API socket without stopping containers. |
| Docker CLI compatibility does not configure Docker SDK clients | Settings packages provide a user-manager `DOCKER_HOST` generator. It activates only after `podman-docker` replaces Docker, preserving explicit endpoints and contexts; migration refreshes activation after workload transfer. |

The volume manifest includes file contents, types, permissions, numeric IDs, nanosecond modification times, xattrs (including POSIX ACLs), symlink targets, hardlink relationships, and device numbers. Transient Unix sockets are excluded because tar does not copy them. A mismatch aborts the transfer and retains the Docker source.

## Explicit custom migration work

Custom Compose networks, shared volumes, bind mounts and moved host paths, GPUs/CDI, privileged Docker-in-Docker, persistent BuildKit, low host ports, and nondefault resource settings need their own configuration and verification. Preserve source image versions instead of applying a newer Compose definition that changes database major versions. Moving all cached images and unattached volumes is also outside the automatic stock-database transfer.

Rootful and rootless stores are independent. Keep privileged services rootful when required, and use scoped privileges. User lingering and rootful service startup are operator choices for these workloads; a desktop database restart policy normally resumes on login. Check actual workload readiness, data and startup after reboot.

Stock transfers let Podman allocate its default network. Explicit custom transfers may need different subnets while Docker networks still exist. The updater retires only managed Docker firewall rules and asks for a reboot to clear transient engine state without flushing unrelated administrator rules.

Snapshots, package archives and development-only package holds are recovery/deployment choices, not changes to the ordinary migration's package selection. A root snapshot can exclude the home subvolume and its rootless data. Retained Docker data is a checkpoint; preserve subsequent Podman writes before rolling back.

## Verification

Focused shell tests cover preflight, transfer failures, forced shutdown, volume metadata and environment defaults. The graphical acceptance suite exercises Desktop open/close and API reactivation on the same socket. The companion ISO `podman-migration` integration scenario creates real legacy Redis/PostgreSQL fixtures in a disposable guest, checks data/metadata and health preservation, rejects an unsupported workload before mutation, retries after engine removal, and verifies running/stopped state after reboot.
