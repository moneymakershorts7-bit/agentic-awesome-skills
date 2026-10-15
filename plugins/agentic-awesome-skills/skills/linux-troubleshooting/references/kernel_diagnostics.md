# Linux Kernel Diagnostics, Resource Bottlenecks & Sysctl Tuning
## High-Level Architecture & Core Concepts

* Linux kernel diagnostics and performance bottleneck analysis
* CPU and memory resource bottlenecks
* Disk I/O resource bottlenecks
* Sysctl tuning for performance optimization

## Diagnostics & Analysis Commands

### CPU and Memory Resource Bottlenecks

* `top` command:
```bash
top -b -n 1 | grep Cpu
top -b -n 1 | grep Mem
```
* `vmstat` command:
```bash
vmstat 1 10
```
* `ps` command:
```bash
ps -eo pid,ppid,pcpu,pmem | sort -k 4 -rn | head
```
* `pmap` command:
```bash
pmap -d <pid>
```
* `dmesg` command:
```bash
dmesg | grep -i oom
```
* `sysctl` command:
```bash
sysctl -a | grep vm
```

### Disk I/O Resource Bottlenecks

* `iostat` command:
```bash
iostat -xz 1 10
```
* `df` command:
```bash
df -h
```
* `du` command:
```bash
du -h
```
* `fstrim` command:
```bash
fstrim -v /
```
* `sysctl` command:
```bash
sysctl -a | grep fs
```

### Sysctl Tuning

* `sysctl` command:
```bash
sysctl -a | grep vm
sysctl -a | grep fs
```
* `sysctl -w` command:
```bash
sysctl -w vm.swappiness=10
sysctl -w vm.dirty_ratio=10
sysctl -w vm.dirty_background_ratio=5
sysctl -w vm.max_map_count=65536
sysctl -w fs.file-max=100000
sysctl -w kernel.pid_max=65536
```
* `/etc/sysctl.d/99-tuning.conf` file:
```bash
vm.swappiness=10
vm.dirty_ratio=10
vm.dirty_background_ratio=5
vm.max_map_count=65536
fs.file-max=100000
kernel.pid_max=65536
```

## Production Configuration Recipes & Hardening Files

### CPU and Memory Resource Bottlenecks

* `/etc/sysctl.conf` file:
```bash
vm.swappiness=10
vm.dirty_ratio=10
vm.dirty_background_ratio=5
vm.max_map_count=65536
```
* `/etc/security/limits.conf` file:
```bash
* soft memlock unlimited
* hard memlock unlimited
```

### Disk I/O Resource Bottlenecks

* `/etc/sysctl.conf` file:
```bash
fs.file-max=100000
```
* `/etc/security/limits.conf` file:
```bash
* soft nofile 100000
* hard nofile 100000
```

### Sysctl Tuning

* `/etc/sysctl.d/99-tuning.conf` file:
```bash
vm.swappiness=10
vm.dirty_ratio=10
vm.dirty_background_ratio=5
vm.max_map_count=65536
fs.file-max=100000
kernel.pid_max=65536
```

## Failure Modes, Symptoms & Remediation Runbook

### CPU and Memory Resource Bottlenecks

* Failure mode: CPU or memory resource bottleneck
* Symptoms:
 + High CPU usage
 + High memory usage
 + System slowdown
* Remediation:
 + Increase CPU or memory resources
 + Optimize system configuration
 + Monitor system performance

### Disk I/O Resource Bottlenecks

* Failure mode: Disk I/O resource bottleneck
* Symptoms:
 + High disk I/O usage
 + System slowdown
 + Disk errors
* Remediation:
 + Increase disk I/O resources
 + Optimize system configuration
 + Monitor system performance

### Sysctl Tuning

* Failure mode: Sysctl tuning failure
* Symptoms:
 + System performance degradation
 + System errors
 + Disk errors
* Remediation:
 + Review sysctl configuration
 + Optimize sysctl settings
 + Monitor system performance

## Quick Reference Cheat Sheet

| Command | Description |
| --- | --- |
| `top` | Display system information |
| `vmstat` | Display virtual memory statistics |
| `ps` | Display process information |
| `pmap` | Display process memory map |
| `dmesg` | Display kernel messages |
| `sysctl` | Display and set kernel parameters |
| `iostat` | Display disk I/O statistics |
| `df` | Display disk usage statistics |
| `du` | Display disk usage statistics |
| `fstrim` | Trim disk free space |
| `/etc/sysctl.conf` | System configuration file |
| `/etc/security/limits.conf` | Security configuration file |
| `/etc/sysctl.d/99-tuning.conf` | Sysctl tuning configuration file |
