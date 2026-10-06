# aijailer-agent (guest agent)

PID 1 inside every cell. Static Go binary (stdlib + `x/sys`), ~2.8 MB, no cgo.

## Protocol
Length-prefixed JSON over virtio-vsock (default port 5000): `uint32 BE length || JSON`.
Host-initiated only; the agent never dials out. Health = host polls `ping`.

| op | request fields | reply |
|---|---|---|
| `ping` | | `{ok, version, time}` |
| `exec` | `cmd, timeout, user, cwd, env` | `{exit_code, stdout, stderr, duration_ms, cpu_ms, memory_peak_mb, timed_out, output_truncated}` |
| `put_file` | `path, data(b64), mode, user` | `{ok, bytes}` |
| `get_file` | `path` | `{data(b64), size, mode}` |

Any failure replies `{"error": "..."}`. The host treats replies as untrusted guest input
(frame cap, base64 validation, JSON-object check) — see `engine/firecracker.py`.

## Security behaviour (each covered by a test)
- Accepts only vsock peers with CID 2 (host).
- Workloads run as an unprivileged user from `/etc/passwd`; uid 0 and unknown users are refused.
- `PR_SET_NO_NEW_PRIVS` on the agent, inherited by every workload (setuid binaries can't escalate).
- Clean environment per exec (agent's env never leaks); explicit `env` only.
- Timeout SIGKILLs the whole process group; background jobs never outlive their request;
  orphans are reaped (group reap + PID-1 reaper that never steals a direct child's status).
- stdout/stderr capped at 4 MiB each (child is never SIGPIPE'd); 16 MiB frame cap; max 16 concurrent execs.
- `put_file` is atomic temp+rename (a planted symlink is replaced, never followed);
  `get_file` uses `O_NOFOLLOW|O_NONBLOCK` and only regular files.
- As PID 1: mounts /proc(hidepid=2) /sys /dev /dev/pts /tmp(nosuid,nodev), powers off on SIGINT/SIGTERM
  (Firecracker `SendCtrlAltDel`), never exits.

## Build / install
```
make test
make rootfs-install ROOTFS_MNT=/mnt/rootfs   # installs /sbin/aijailer-agent
```
Base images must contain an `agent` user (non-zero uid) in `/etc/passwd`. Kernel cmdline: `init=/sbin/aijailer-agent`
(already set by `FirecrackerEngine`).

## Not yet done
- Not exercised inside a real Firecracker guest (needs KVM host + kernel + rootfs).
- No file/process/network event streaming (spec's "event reporter"); planned as a host-polled `events` op.
- cgroup/PID limits inside the guest are not set by the agent; resource limits are enforced on the host (jailer cgroups).
