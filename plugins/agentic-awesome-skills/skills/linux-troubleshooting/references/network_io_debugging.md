# Linux Network & Socket Exhaustion Debugging (ss, tcpdump & firewalls)

## High-Level Architecture & Core Concepts

### Connection Limitation Vectors
| Layer | Limiting Factor | Kernel Tunable / Config | Exhaustion Symptom |
| :--- | :--- | :--- | :--- |
| **Process** | Open File Descriptors (RLIMIT_NOFILE) | `ulimit -n`, `/etc/security/limits.conf` | `EMFILE` / `ENFILE` in app logs; `Too many open files` |
| **Socket Listen Queue** | Pending connections (SYN_RECV + ESTABLISHED waiting for `accept()`) | `net.core.somaxconn`, `net.ipv4.tcp_max_syn_backlog`, App `listen(backlog)` | Connection timeouts; `SYN_RECV` pileup in `ss -l` |
| **Network Stack Processing** | Packet processing backlog (softirq) | `net.core.netdev_max_backlog`, `net.core.netdev_budget` | Packet drops (`/proc/net/softnet_stat` `dropped` counter increments) |
| **Ephemeral Ports** | Client-side source port tuple exhaustion (IP, Port, Proto) | `net.ipv4.ip_local_port_range` | `EADDRNOTAVAIL` / `Cannot assign requested address` on `connect()` |
| **TCP State Machine** | `TIME_WAIT` bucket saturation (2MSL default 60s) | `net.ipv4.tcp_fin_timeout`, `net.ipv4.tcp_tw_reuse` | High `TIME_WAIT` count; port reuse collisions |
| **Connection Tracking** | `nf_conntrack` table saturation (stateful firewall/NAT) | `net.netfilter.nf_conntrack_max`, `net.netfilter.nf_conntrack_buckets` | `nf_conntrack: table full, dropping packet` in `dmesg`; new connections silently dropped |
| **Hardware** | NIC Ring Buffers, CPU (softirq), RAM (skb/mbuf) | `ethtool -G`, RSS/RPS/XPS config | `RX-DRP` / `RX-OVR` in `ethtool -S`; `ksoftirqd` CPU saturation |

### Critical Kernel Parameters (Runtime & Persistent)
```bash
# /etc/sysctl.d/99-network-tuning.conf
# File Descriptors (System-wide)
fs.file-max = 2097152
fs.nr_open = 1048576

# Socket Listen Queues
net.core.somaxconn = 65535                  # Max listen() backlog (clamped by app)
net.core.netdev_max_backlog = 65535         # Packets queued to NAPI poll
net.ipv4.tcp_max_syn_backlog = 65535        # SYN_RECV queue (half-open)

# Ephemeral Port Range (Client/Outbound heavy workloads)
net.ipv4.ip_local_port_range = 1024 65535   # ~64K ports per IP; expand if NAT/Proxy

# TIME_WAIT Management (Use with extreme caution)
net.ipv4.tcp_fin_timeout = 15               # Default 60s; Time to hold socket in FIN_WAIT_2 / TIME_WAIT
net.ipv4.tcp_tw_reuse = 1                   # Safe: Reuse TIME_WAIT sockets for new OUTGOING connections (requires timestamps/RFC 1323)
# net.ipv4.tcp_tw_recycle = 0               # DEPRECATED/REMOVED (Kernel 4.12+). Causes NAT timestamp issues.

# Connection Tracking (Required for stateful firewalling / K8s / Docker)
net.netfilter.nf_conntrack_max = 1048576    # Hash table size (buckets * 8 typically)
net.netfilter.nf_conntrack_buckets = 262144 # Hash buckets (auto-tuned by max usually)
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_established = 432000

# Memory Pressure / Buffer Tuning
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mtu_probing = 1
```

**Apply:** `sysctl --system` or `sysctl -p /etc/sysctl.d/99-network-tuning.conf`

---

## Diagnostics & Analysis Commands

### 1. Socket Exhaustion & State Analysis (`ss`)
`ss` (socket statistics) replaces `netstat`. Use `-n` (numeric), `-e` (extended), `-p` (process), `-i` (tcp info), `-s` (summary).

#### Summary & Protocol Counts
```bash
ss -s
# Output Interpretation:
# TCP:   12345 (estab 11000, closed 500, orphaned 10, synrecv 0, timewait 800/0), ports 500
# 'timewait 800/0' -> 800 sockets in TIME_WAIT, 0 recycled.
# 'orphaned 10'    -> Sockets not owned by process (kernel cleaning up).
```

#### Detailed Listener & Connection Inventory
```bash
# All TCP/UDP listeners + established + process info + timer info
ss -tunaep -o state established '( dport = :80 or sport = :80 )'

# Filter by specific states (Critical for exhaustion)
ss -tan state time-wait       # Count: watch -n1 'ss -tan state time-wait | wc -l'
ss -tan state syn-recv        # SYN flood / Backlog full indicator
ss -tan state fin-wait-1
ss -tan state fin-wait-2
ss -tan state close-wait      # APP BUG: App not calling close() on received FIN

# Diagnose Recv-Q / Send-Q (Buffer Pressure)
# Recv-Q > 0 on ESTABLISHED = App not reading fast enough (Backpressure)
# Send-Q > 0 on ESTABLISHED = Network congestion / Window full / App writing faster than NIC
ss -tnepi state established | grep -E 'Recv-Q|Send-Q|rtt|retrans'
# Key TCP Info fields (ss -i):
# rtt:1.5/0.2   -> RTT 1.5ms, variance 0.2ms
# rto:204       -> Retransmission Timeout (ms)
# retrans:3/10  -> Retransmitted segments / max retries
# cwnd:10       -> Congestion Window (MSS units)
# delivery_rate 1.2Mbps -> BBR/CUBIC measured throughput
```

#### Ephemeral Port Exhaustion Diagnosis
```bash
# 1. Check current range
sysctl net.ipv4.ip_local_port_range
# 2. Count unique client tuples (src ip:port) for a specific server port
ss -tan 'sport > 32767' state established | awk '{print $5}' | cut -d: -f2 | sort -u | wc -l
# 3. Check kernel port allocator pressure (failures)
grep -i "port.*exhaust\|out of.*port" /var/log/kern.log /var/log/syslog
# 4. BPFtrace: Trace connect() failures (EADDRNOTAVAIL)
bpftrace -e 'tracepoint:syscalls:sys_enter_connect /args->sa_family == 2/ { @[comm] = count(); } tracepoint:syscalls:sys_exit_connect /retval == -11/ { @err[comm] = count(); }'
```

### 2. Packet Inspection & Latency Analysis (`tcpdump` / `tshark`)

#### Capture Filters (Kernel BPF - High Performance)
```bash
# Write to rotating ring buffer (prevents disk fill), snaplen 1514 (ethernet), no promisc if not needed
tcpdump -nnvv -i any -s 1514 -C 100 -W 10 -w /var/tmp/capture_%Y%m%d_%H%M%S.pcap \
  'tcp port 80 or tcp port 443'

# Handshake Analysis: SYN, SYN-ACK, RST, FIN only (Low volume)
tcpdump -nnvv -i any 'tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0'

# Retransmission Detection (Data segments with same SEQ)
# Requires tshark/wireshark display filter usually, but tcpdump can catch fast retrans via flags:
tcpdump -nnvv -i any 'tcp[tcpflags] & tcp-push != 0 and tcp[tcpflags] & tcp-ack != 0' # PSH+ACK data packets

# Latency: Capture SYN -> SYN-ACK delta (requires post-processing with tshark)
tshark -r capture.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e frame.time_relative -e ip.src -e tcp.srcport
tshark -r capture.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==1" -T fields -e frame.time_relative -e ip.dst -e tcp.dstport
# Correlate via Stream Index: tshark -r capture.pcap -z io,stat,1,"tcp.stream eq 0"
```

#### Advanced `tshark` Analysis (Post-Capture)
```bash
# TCP Retransmissions & Out-of-Order
tshark -
