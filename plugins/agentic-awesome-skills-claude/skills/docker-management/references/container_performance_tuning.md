# Container Performance Tuning, Cgroups Limits & Non-Exec Debugging

## High-Level Architecture & Core Concepts

### Cgroups v2 Unified Hierarchy & Docker Integration
Docker (v20.10+) defaults to cgroups v2 unified hierarchy (`/sys/fs/cgroup`). Resource constraints map directly to kernel controllers:
*   **cpu**: `cpu.max` (quota/period), `cpu.weight` (shares)
*   **memory**: `memory.max`, `memory.swap.max`, `memory.low` (reservation), `memory.oom_control`
*   **io**: `io.max` (weight/bps/iops), `io.stat`
*   **pids**: `pids.max`

**Docker Flag -> Cgroups v2 File Mapping**
| Docker Flag | Cgroups v2 File | Description |
| :--- | :--- | :--- |
| `--cpus=N` | `cpu.max` | Quota = N * 100000 (period=100000us). Hard limit. |
| `--cpu-shares=W` | `cpu.weight` | Weight = 1 + (W * 9999 / 262144). Range [1, 10000]. Default 100 (1024 shares). |
| `--memory=B` | `memory.max` | Hard limit. OOM kill on breach. |
| `--memory-swap=B` | `memory.swap.max` | Combined RAM+Swap limit. Must be > `--memory`. `-1` = unlimited. |
| `--memory-reservation=B` | `memory.low` | Soft limit. Reclaim pressure applied only under host memory pressure. |
| `--oom-kill-disable` | `memory.oom_control` | Disables OOM killer for this cgroup (tasks hang on OOM). |
| `--pids-limit=N` | `pids.max` | Prevents fork bombs. |

### CFS Bandwidth Control (CPU Throttling)
*   **Period**: 100ms (100,000 us) default.
*   **Quota**: `--cpus * Period`.
*   **Throttling**: Occurs when `usage_usec` >= `quota_usec` within a period. Task enters `THROTTLED` state until next period.
*   **Bursting**: Not supported natively in CFS quota; quota is per-period hard cap.

### OOM Kill Semantics
*   Triggered when `memory.current` >= `memory.max` and reclaim fails.
*   Kernel selects victim via `oom_score` (RSS + Swap + oom_score_adj).
*   Container PID 1 receives `SIGKILL`. Container exits `137`.
*   **Distroless/Scratch**: No shell, no `dmesg` access inside container. Diagnosis *must* happen host-side or via sidecar.

---

## Diagnostics & Analysis Commands

### 1. Cgroups v2 Inspection (Host Namespace)
```bash
# Locate container cgroup path (systemd driver)
CID=$(docker inspect -f '{{.Id}}' <container_name>)
CGROUP_PATH="/sys/fs/cgroup/docker/${CID}"

# Locate container cgroup path (cgroupfs driver)
CGROUP_PATH="/sys/fs/cgroup/${CID}"

# Verify CPU Limits (quota/period in microseconds)
cat ${CGROUP_PATH}/cpu.max
# Output: "50000 100000"  -> 0.5 CPUs (50ms/100ms)
# Output: "max 100000"    -> No limit (--cpus not set)

# Verify CPU Weight (shares)
cat ${CGROUP_PATH}/cpu.weight
# Output: "100" (default)

# Verify Memory Limits (bytes)
cat ${CGROUP_PATH}/memory.max
cat ${CGROUP_PATH}/memory.swap.max
cat ${CGROUP_PATH}/memory.low      # Reservation
cat ${CGROUP_PATH}/memory.current  # Current usage (RSS + Cache + Kernel)

# Verify OOM Status
cat ${CGROUP_PATH}/memory.oom_control
# Output contains: oom_kill 1 (count), under_oom 0

# Verify PIDs Limit
cat ${CGROUP_PATH}/pids.max
cat ${CGROUP_PATH}/pids.current
```

### 2. Diagnosing CFS CPU Throttling
```bash
# Read throttling stats (cgroups v2)
cat ${CGROUP_PATH}/cpu.stat
# Output fields:
# usage_usec <total_cpu_time_us>
# user_usec <user_time>
# system_usec <kernel_time>
# nr_periods <number_of_periods_elapsed>
# nr_throttled <times_throttled>
# throttled_usec <total_time_throttled_us>

# Calculate Throttle Percentage (bc required)
NR_THROTTLED=$(grep nr_throttled ${CGROUP_PATH}/cpu.stat | awk '{print $2}')
THROTTLED_USEC=$(grep throttled_usec ${CGROUP_PATH}/cpu.stat | awk '{print $2}')
NR_PERIODS=$(grep nr_periods ${CGROUP_PATH}/cpu.stat | awk '{print $2}')
PERIOD_USEC=100000

echo "Throttle Events: ${NR_THROTTLED}"
echo "Throttle Time %: $(echo "scale=4; ${THROTTLED_USEC} / (${NR_PERIODS} * ${PERIOD_USEC}) * 100" | bc)%"

# Real-time throttling watch (requires bpftrace)
bpftrace -e 'tracepoint:cgroup:cgroup_throttle { @[comm] = count(); } interval:s:5 { print(@); clear(@); }'
```

### 3. Diagnosing OOM Kills
```bash
# Host kernel log (immediate source of truth)
dmesg -T | grep -i -e oom -e "out of memory" | tail -20

# Cgroups OOM event counter (persistent across container restarts if cgroup persists)
cat ${CGROUP_PATH}/memory.events
# Output:
# low 0
# high 0
# max 5          <-- Hard limit hits (OOM kills)
# oom 5          <-- OOM kill count
# oom_kill 5     <-- Alias for oom

# Correlate with container exit code
docker inspect -f '{{.State.ExitCode}} {{.State.OOMKilled}}' <container_name>
# ExitCode 137 + OOMKilled=true = OOM Kill
```

### 4. Container Metrics & Real-Time Monitoring

#### `docker stats` (CLI)
```bash
# All containers, no stream (scripting), custom format
docker stats --no-stream --format "table {{.Container}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"

# Specific container, specific columns
docker stats --no-stream --format "{{.CPUPerc}} {{.MemPerc}}" <container_name>
```

#### cAdvisor Integration (Sidecar)
```yaml
# docker-compose.yml snippet
services:
  cadvisor:
    image: gcr.io/cadvisor/cadvisor:v0.49.1
    container_name: cadvisor
    privileged: true
    devices:
      - /dev/kmsg:/dev/kmsg  # Required for kernel stats on some kernels
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    ports:
      - "8080:8080"
    command: --docker_only --housekeeping_interval=10s
```
*Metrics exposed at `http://<host>:8080/metrics` (Prometheus format).*

#### Dockerd Prometheus Metrics Endpoint
```json
// /etc/docker/daemon.json
{
  "metrics-addr": "0.0.0.0:9323",
  "experimental": true
}
```
```bash
systemctl restart docker
curl -s http://localhost:9323/metrics | grep -E 'engine_daemon_container_(cpu|memory|network|blkio)'
```
*Key Metrics: `engine_daemon_container_cpu_usage_seconds_total`, `engine_daemon_container_memory_usage_bytes`, `engine_daemon_container_network_*`,
