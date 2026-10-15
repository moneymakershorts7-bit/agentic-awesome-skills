"""Kernel Version Detection and Security Capability Matrix"""
import os
import re
from dataclasses import dataclass, field

# Distribution signature regex
_DISTRO_PATTERNS = [
    (re.compile(r'\.el(\d+)'), "rhel"),       # CentOS/RHEL
    (re.compile(r'-generic'), "ubuntu"),        # Ubuntu
    (re.compile(r'-amd64|\.deb'), "debian"),    # Debian
    (re.compile(r'\.amzn\d'), "amazon"),        # Amazon Linux
    (re.compile(r'\.fc(\d+)'), "fedora"),       # Fedora
    (re.compile(r'\.oe\d'), "openeuler"),       # openEuler
]


@dataclass
class KernelInfo:
    """Kernel version information"""
    major: int = 0
    minor: int = 0
    patch: int = 0
    release: str = ""
    distro_hint: str = ""


@dataclass
class KernelCapabilities:
    """Kernel Security Monitoring Capability Matrix"""
    proc_fs: bool = False
    audit_log: bool = False
    inotify: bool = False
    cn_proc: bool = False
    fanotify: bool = False
    ebpf_basic: bool = False
    ebpf_kprobe: bool = False
    ebpf_tracepoint: bool = False
    ebpf_xdp: bool = False
    ebpf_btf: bool = False
    ebpf_ringbuf: bool = False
    ebpf_lsm: bool = False
    level: str = "none"
    details: dict = field(default_factory=dict)


def parse_kernel_version(release: str) -> KernelInfo:
    """Parse kernel version string

    Supported formats:
    - 3.10.0-1160.el7.x86_64 (CentOS 7)
    - 5.15.0-91-generic (Ubuntu)
    - 6.1.0-18-amd64 (Debian)
    - 6.6.87.2-microsoft-standard-WSL2 (WSL)
    """
    info = KernelInfo(release=release)

    match = re.match(r'(\d+)\.(\d+)\.(\d+)', release)
    if match:
        info.major = int(match.group(1))
        info.minor = int(match.group(2))
        info.patch = int(match.group(3))

    for pattern, distro in _DISTRO_PATTERNS:
        if pattern.search(release):
            info.distro_hint = distro
            break

    if not info.distro_hint:
        if "microsoft" in release.lower():
            info.distro_hint = "wsl"
        elif "cloud" in release.lower() or "ali" in release.lower():
            info.distro_hint = "alibaba"

    return info


def _version_ge(info: KernelInfo, major: int, minor: int) -> bool:
    """Check if kernel version >= major.minor"""
    return (info.major, info.minor) >= (major, minor)


def detect_capabilities(info: KernelInfo = None) -> KernelCapabilities:
    """Detect kernel security monitoring capabilities

    Combines static version number judgment and filesystem runtime detection
    """
    if info is None:
        info = parse_kernel_version(os.uname().release)

    caps = KernelCapabilities()

    # Static version judgment
    caps.proc_fs = _version_ge(info, 2, 6)          # /proc all versions
    caps.audit_log = _version_ge(info, 2, 6)         # audit 2.6.6+
    caps.inotify = _version_ge(info, 2, 6)           # inotify 2.6.13+
    caps.cn_proc = _version_ge(info, 2, 6)           # Netlink cn_proc 2.6.15+
    caps.fanotify = _version_ge(info, 2, 6)          # fanotify 2.6.37+, but rough judgment for 2.6
    caps.ebpf_basic = _version_ge(info, 3, 15)       # Basic eBPF
    caps.ebpf_kprobe = _version_ge(info, 4, 1)       # eBPF kprobe
    caps.ebpf_tracepoint = _version_ge(info, 4, 7)   # eBPF tracepoint
    caps.ebpf_xdp = _version_ge(info, 4, 8)          # XDP
    caps.ebpf_btf = _version_ge(info, 4, 18)         # BTF
    caps.ebpf_lsm = _version_ge(info, 5, 7)          # LSM hook
    caps.ebpf_ringbuf = _version_ge(info, 5, 8)      # Ring buffer

    # Runtime detection supplement (filesystem existence)
    runtime = {}
    runtime["bpf_syscall"] = os.path.exists("/proc/sys/kernel/unprivileged_bpf_disabled")
    runtime["btf_vmlinux"] = os.path.exists("/sys/kernel/btf/vmlinux")
    runtime["bpf_fs"] = os.path.exists("/sys/fs/bpf")
    runtime["tracefs"] = (
        os.path.exists("/sys/kernel/tracing") or
        os.path.exists("/sys/kernel/debug/tracing")
    )
    runtime["kprobes"] = os.path.exists("/sys/kernel/debug/kprobes/enabled")
    caps.details = runtime

    # If runtime not supported, downgrade to static judgment
    if caps.ebpf_basic and not runtime.get("bpf_syscall"):
        caps.ebpf_basic = False
        caps.ebpf_kprobe = False
        caps.ebpf_tracepoint = False
        caps.ebpf_xdp = False
        caps.ebpf_btf = False
        caps.ebpf_lsm = False
        caps.ebpf_ringbuf = False

    if caps.ebpf_btf and not runtime.get("btf_vmlinux"):
        caps.ebpf_btf = False

    # Determine capability level
    if caps.ebpf_lsm and caps.ebpf_ringbuf:
        caps.level = "advanced"   # 5.8+ full function
    elif caps.ebpf_tracepoint:
        caps.level = "full"       # 4.7+ complete eBPF
    elif caps.ebpf_basic:
        caps.level = "basic"      # 3.15+ basic eBPF
    elif caps.proc_fs:
        caps.level = "limited"    # 2.6+ baseline only
    else:
        caps.level = "none"

    return caps


def get_kernel_summary() -> dict:
    """Return dictionary summary of kernel info and capabilities, for embedding in reports"""
    info = parse_kernel_version(os.uname().release)
    caps = detect_capabilities(info)

    available = []
    if caps.proc_fs:
        available.append("/proc filesystem")
    if caps.audit_log:
        available.append("audit logs")
    if caps.inotify:
        available.append("inotify file monitoring")
    if caps.cn_proc:
        available.append("Netlink process events")
    if caps.ebpf_tracepoint:
        available.append("eBPF tracepoint")
    if caps.ebpf_kprobe:
        available.append("eBPF kprobe")
    if caps.ebpf_btf:
        available.append("BTF type information")
    if caps.ebpf_lsm:
        available.append("eBPF LSM hook")

    return {
        "kernel_version": f"{info.major}.{info.minor}.{info.patch}",
        "kernel_release": info.release,
        "distro_hint": info.distro_hint,
        "ebpf_level": caps.level,
        "capabilities": available,
        "runtime_probes": caps.details,
    }
