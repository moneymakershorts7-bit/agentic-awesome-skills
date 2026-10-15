# Docker Rootless Daemon & Podman Isolation Runbook

## High-Level Architecture & Core Concepts

### Rootless Docker Architecture
Rootless Docker executes the `dockerd` and container processes inside a user namespace (`userns`), mapping container UID/GID 0 to an unprivileged host UID/GID via `/etc/subuid` and `/etc/subgid`.
*   **Daemon**: Runs as systemd user service (`docker.service`), not PID 1.
*   **Socket**: `unix:///run/user/$UID/docker.sock` (owned by user, no `docker` group required).
*   **Networking**: `slirp4netns` (default, user-mode TCP/IP stack) or `VPNKit`/`pasta` (rootlesskit backends). No `NET_ADMIN` on host.
*   **Storage**: Fuse-overlayfs (default) or native overlayfs (requires kernel 5.11+ `overlayfs` in userns support).

### Podman Daemonless Architecture
*   **No Daemon**: `podman` CLI forks `conmon` + OCI runtime (`crun`/`runc`) directly from user session.
*   **Audit Trail**: Container processes retain `audituid` of originating user (vs Docker rootless where `dockerd` masks origin).
*   **Rootless Networking**: `slirp4netns` (default), `pasta` (modern, better performance, no port forwarding helpers needed), `netavark` backend.
*   **Systemd Integration**: `podman generate systemd --new --name <ctr> --user` creates user units; `loginctl enable-linger $USER` enables persistence.

### Isolation Primitives (Shared)
| Primitive | Mechanism | Scope |
| :--- | :--- | :--- |
| **User Namespace** | `clone(CLONE_NEWUSER)` + `/etc/subuid` mapping | UID/GID 0 -> Unprivileged Host UID |
| **Capabilities** | `--cap-drop=ALL --cap-add=<minimal>` | Bounding set reduction |
| **Seccomp** | `--security-opt seccomp=<profile.json>` | Syscall filtering (default: `default.json`) |
| **AppArmor/SELinux** | `--security-opt apparmor=<profile>` / `--security-opt label=type:<type>` | MAC enforcement |
| **No New Privs** | `--security-opt=no-new-privileges` | Blocks `setuid`/`setgid`/`file_caps` escalation |
| **Read-Only RootFS** | `--read-only --tmpfs /run --tmpfs /tmp` | Immutable container filesystem |

---

## Diagnostics & Analysis Commands

### Verify Rootless Environment Prerequisites
```bash
# 1. Kernel & Module Support
grep -E '^CONFIG_USER_NS=|^CONFIG_OVERLAY_FS=|^CONFIG_CGROUP_|^CONFIG_CGROUP_USER=' /boot/config-$(uname -r)
# Expected: =y or =m

# 2. Subuid/Subgid Allocation (Must exist for user)
grep "^$(whoami):" /etc/subuid /etc/subgid
# Expected: user:100000:65536 (65k IDs minimum)

# 3. Unprivileged User NS Enabled
sysctl kernel.unprivileged_userns_clone
# Expected: 1 (Debian/Ubuntu default 0 -> set to 1 in /etc/sysctl.d/99-userns.conf)

# 4. Cgroup v2 Delegation (Required for systemd --user / rootless cgroups)
cat /proc/self/cgroup
# Expected: 0::/user.slice/user-$(id -u).slice/session-<id>.scope (Unified hierarchy)
```

### Docker Rootless Daemon Diagnostics
```bash
# Daemon Status & Logs
systemctl --user status docker
journalctl --user -u docker -f

# Socket & Client Connectivity
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock
docker version --format '{{.Server.Os}}/{{.Server.Arch}}'
docker info --format '{{.SecurityOptions}} {{.CgroupDriver}} {{.CgroupVersion}}'

# Rootlesskit Network Namespace Inspection
# Find rootlesskit PID (parent of dockerd)
pgrep -af rootlesskit
nsenter -t <rootlesskit_pid> -n ip addr show
nsenter -t <rootlesskit_pid> -n ip route show

# Verify UID Mapping Inside Container
docker run --rm alpine id
# Expected: uid=0(root) gid=0(root) groups=0(root),65533(nogroup) -> Mapped to host subuid range
docker run --rm alpine cat /proc/self/uid_map
# Expected: 0 <host_start> 65536
```

### Podman Diagnostics
```bash
# System Info & Rootless Verification
podman info --format '{{.Host.Security.Rootless}} {{.Host.CgroupManager}} {{.Host.NetworkBackend}}'
# Expected: true systemd netavark/pasta

# Active Containers & PIDs (Audit Trail Verification)
podman ps --format '{{.ID}} {{.PID}} {{.User}}'
ps -fp $(podman inspect -f '{{.State.Pid}}' <ctr_name>)
# Verify 'audituid' via ausearch (if auditd running)
ausearch -m SYSCALL -ui $(id -u) --interpret -ts recent

# Network Namespace Inspection (pasta/slirp4netns)
podman unshare cat /proc/self/uid_map
nsenter -t $(podman inspect -f '{{.State.Pid}}' <ctr>) -n ip addr
```

### Security Posture Validation
```bash
# Capabilities Drop Verification
docker run --rm --cap-drop=ALL alpine capsh --print
# Expected: Current: =ep (empty effective/permitted/inheritable)

# Seccomp Profile Verification
docker run --rm --security-opt seccomp=unconfined alpine grep Seccomp /proc/self/status
# Compare Seccomp mode: 2 (strict) vs 1 (filter) vs 0 (disabled)

# No-New-Privs Verification
docker run --rm --security-opt=no-new-privileges alpine su -c 'id' nobody
# Expected: su: must be suid to work (fails silently or permission denied)

# Read-Only FS Verification
docker run --rm --read-only --tmpfs /tmp alpine touch /test
# Expected: Read-only file system
docker run --rm --read-only --tmpfs /tmp alpine touch /tmp/test && echo "OK"
```

---

## Production Configuration Recipes & Hardening Files

### 1. Host Kernel & SubID Configuration (`/etc/sysctl.d/99-rootless.conf`, `/etc/subuid`, `/etc/subgid`)
```ini
# /etc/sysctl.d/99-rootless.conf
# Enable unprivileged user namespaces (Debian/Ubuntu default 0)
kernel.unprivileged_userns_clone = 1
# Allow unprivileged overlayfs mounts (Kernel 5.11+)
kernel.unprivileged_overlayfs = 1
# Increase user namespace limits for dense tenancy
user.max_user_namespaces = 28633
user.max_net_namespaces = 28633
user.max_ipc_namespaces = 28633
user.max_uts_namespaces = 28633
user.max_pid_namespaces = 28633
user.max_cgroup_namespaces = 28633
# Cgroup v2 delegation requirements
kernel.cgroup_reclaim = 1
```
```bash
# Apply immediately
sysctl --system

# /etc/subuid & /etc/subgid (Add via usermod or manually)
# Format: user:start_id:count
# Allocate 65536 IDs per user (standard). Ensure no overlaps.
usermod --add-subuids 100000-165535 --add-subgids 100000-165535 <username>
# Verify
cat /etc/subuid
# <username>:100000:65536
```

### 2. Docker Rootless Installation & Systemd User Service
```bash
# Install Rootless Dependencies (Debian/Ubuntu/RHEL)
# uidmap, dbus-user-session, slirp4netns, fuse-overlayfs
apt-get update && apt-get install -y uidmap dbus-user-session slirp4netns fuse-overlayfs

# Install Docker Rootless (Non-interactive)
curl -fsSL https://get.docker.com/rootless | sh
# OR Manual:
# dockerd-rootless-setuptool.sh install

# Enable Lingering (Survives logout)
loginctl enable-linger $(whoami)

# Start
