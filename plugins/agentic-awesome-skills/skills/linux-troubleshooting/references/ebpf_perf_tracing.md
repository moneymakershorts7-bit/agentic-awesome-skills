# Linux Deep Performance Tracing with eBPF, perf & strace
## High-Level Architecture & Core Concepts

### eBPF Overview

* eBPF (extended Berkeley Packet Filter) is a Linux kernel technology that allows running sandboxed programs inside the kernel safely and efficiently.
* eBPF programs are triggered by various events occurring within the kernel, such as system calls, network events, or function calls.
* eBPF programs are typically written in a restricted C dialect and compiled into bytecode, which is then loaded into the kernel.

### BCC (BPF Compiler Collection)

* BCC is a collection of ready-to-run eBPF tracing tools that target specific performance questions.
* BCC includes over 100 command-line utilities, such as `opensnoop`, `biolatency`, and `tcprtt`.
* BCC provides Python and C APIs for custom eBPF programs.

### bpftrace

* bpftrace is a high-level tracing language that makes eBPF accessible through concise one-liners.
* bpftrace excels at answering specific questions immediately with concise one-liners.
* bpftrace handles compiling to eBPF bytecode, loading into the kernel, and displaying results.

### perf

* perf is a Linux tool for profiling and tracing the performance of applications and the kernel.
* perf provides various commands, such as `perf top`, `perf record`, and `perf report`, for analyzing performance data.
* perf can generate On-CPU and Off-CPU flamegraphs and measure hardware cache misses and instructions per cycle.

### strace

* strace is a Linux tool for inspecting system calls and other kernel-level events.
* strace can be used to analyze system call time accounting and minimize overhead.
* strace provides various options, such as `-e trace=network,file -s 256 -T -tt -f -p <PID>`, for customizing its behavior.

## Diagnostics & Analysis Commands

### eBPF Tools

* `execsnoop`: tracks short-lived processes
* `opensnoop`: tracks file descriptor leaks and slow open
* `biolatency`: generates block device latency distribution histograms
* `tcprtt`: measures TCP round-trip latency
* `memleak`: detects memory allocations without free

```bash
# execsnoop
execsnoop -p <PID>

# opensnoop
opensnoop -p <PID>

# biolatency
biolatency -p <PID>

# tcprtt
tcprtt -p <PID>

# memleak
memleak -p <PID>
```

### perf Commands

* `perf top`: displays the top CPU consumers
* `perf record -F 99 -g -p <PID>`: records performance data with a sampling frequency of 99 Hz and generates a call graph
* `perf report`: displays the performance data in a report format

```bash
# perf top
perf top -p <PID>

# perf record
perf record -F 99 -g -p <PID>

# perf report
perf report -p <PID>
```

### strace Commands

* `strace -e trace=network,file -s 256 -T -tt -f -p <PID>`: inspects system calls with tracing enabled and a maximum string length of 256 characters
* `strace -c -p <PID>`: displays system call time accounting

```bash
# strace
strace -e trace=network,file -s 256 -T -tt -f -p <PID>

# strace -c
strace -c -p <PID>
```

## Production Configuration Recipes & Hardening Files

### sysctl Settings

* `kernel.perf_event_max_sample_rate`: sets the maximum sampling rate for perf events
* `kernel.perf_event_max_stack`: sets the maximum stack size for perf events

```bash
# sysctl settings
sysctl -w kernel.perf_event_max_sample_rate=1000
sysctl -w kernel.perf_event_max_stack=1024
```

### Dockerfile

* `RUN apt-get update && apt-get install -y linux-perf`
* `RUN mkdir -p /sys/kernel/debug/tracing`

```dockerfile
# Dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y linux-perf
RUN mkdir -p /sys/kernel/debug/tracing
```

### YAML File

* `perf:`
	+ `sample_rate: 1000`
	+ `stack_size: 1024`

```yml
# YAML file
perf:
  sample_rate: 1000
  stack_size: 1024
```

## Failure Modes, Symptoms & Remediation Runbook

### Failure Mode 1: eBPF Program Crash

* Symptoms: eBPF program crashes with a kernel panic
* Remediation: check the eBPF program for errors and recompile it

### Failure Mode 2: perf Event Overflow

* Symptoms: perf event overflow with a high sampling rate
* Remediation: reduce the sampling rate or increase the event buffer size

### Failure Mode 3: strace Overhead

* Symptoms: strace overhead with a high system call rate
* Remediation: reduce the strace overhead by using a lower sampling rate or disabling tracing

## Quick Reference Cheat Sheet

| Command | Description |
| --- | --- |
| `execsnoop` | tracks short-lived processes |
| `opensnoop` | tracks file descriptor leaks and slow open |
| `biolatency` | generates block device latency distribution histograms |
| `tcprtt` | measures TCP round-trip latency |
| `memleak` | detects memory allocations without free |
| `perf top` | displays the top CPU consumers |
| `perf record` | records performance data with a sampling frequency of 99 Hz and generates a call graph |
| `perf report` | displays the performance data in a report format |
| `strace -e trace=network,file -s 256 -T -tt -f -p <PID>` | inspects system calls with tracing enabled and a maximum string length of 256 characters |
| `strace -c -p <PID>` | displays system call time accounting |

Note: This cheat sheet is not exhaustive and is intended to provide a quick reference for common eBPF, perf, and strace commands.
