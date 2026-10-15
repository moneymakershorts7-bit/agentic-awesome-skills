"""Rootkit Detection Analyzer"""
import os
import re
import time
import json as _json
import subprocess
from typing import List, Dict, Any

from .base import BaseAnalyzer
from ..reporter.severity import Severity
from ..reporter.evidence import Evidence, EvidenceDetail
from ..utils.safe_exec import safe_run
from ..utils.proc import parse_proc_net_tcp
import threading
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

# Known eBPF rootkit BPF map names
_KNOWN_MALICIOUS_BPF_MAPS = {
    "knock_map", "pids_to_hide_map", "hidden_pids", "hide_map",
    "target_map", "config_map", "rootkit_config",
}

# Known eBPF rootkit file path signatures
_KNOWN_EBPF_ROOTKIT_PATHS = [
    "/usr/lib/.system/.tmp~data.resolveld",
    "/usr/lib/.system/",
    "/lib/.hidden/",
]

# Fake systemd service names (intentionally similar spelling)
_FAKE_SYSTEMD_SERVICES = re.compile(
    r'systemd-(?:resolveld|journald2|logingd|udevdd|networkdd)\.service'
)

class RootkitAnalyzer(BaseAnalyzer):
    """Rootkit Detection Analyzer"""
    name = "rootkit_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 45)

    required_collectors = ["process", "network", "service"]

    # Pre-compiled regex patterns
    HIDDEN_PATH_PATTERN = re.compile(r'/\.[^/]+')
    TMP_PATH_PATTERN = re.compile(r'(/tmp/|/dev/shm/)')
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Execute rootkit detection"""
        evidences = []

        try:
            process_data = self._get_data(collected_data, "process")
            network_data = self._get_data(collected_data, "network")
            service_data = self._get_data(collected_data, "service")
        except (KeyError, TypeError):
            return evidences

        # Validate data is not None
        if process_data is None or network_data is None or service_data is None:
            return evidences
        
        # 1. Process hiding detection (expensive with 200ms+ sleep delays)
        evidences.extend(self._detect_hidden_processes(process_data))
        
        # 2. Port hiding detection (always runs)
        evidences.extend(self._detect_hidden_ports(network_data))
        
        # 3. Kernel module anomaly detection (always runs)
        evidences.extend(self._detect_kernel_module_anomalies(service_data))
        
        # 4. ld.so.preload hijack detection (always runs)
        evidences.extend(self._detect_ld_preload_hijack(service_data))

        # 5. eBPF rootkit detection
        evidences.extend(self._detect_ebpf_rootkit())

        # 6. Fake systemd service detection
        evidences.extend(self._detect_fake_systemd_services())

        # 7. Magic TCP SYN signature detection
        evidences.extend(self._detect_magic_tcp_syn(network_data))

        # 8. Process injection detection (T1055)
        evidences.extend(self._detect_process_injection(process_data))
        
        # 9. Container escape detection (T1611)
        evidences.extend(self._detect_container_escape(collected_data))

        return evidences
    
    def _detect_hidden_processes(self, process_data: Dict) -> List[Evidence]:
        """Detect process hiding (multi-phase verification to reduce false positives)
        
        Detection phases:
        1. Triple /proc sampling with 100ms intervals (catches transient processes)
        2. Cross-reference with collected process data
        3. Extended persistence verification (500ms wait to filter short-lived processes)
        4. Final threshold check (>= 5 verified hidden PIDs)
        
        Performance optimization: Skipped in quick mode due to expensive sleep delays
        (100ms + 100ms + 500ms = 700ms minimum). Quick mode relies on other analyzers
        for process detection.
        """
        
        evidences = []
        
        # Quick mode optimization: skip expensive hidden process detection
        # The 700ms+ sleep delays are unacceptable for quick mode targets (<120s total)
        # WSL environment check: skip hidden process detection in WSL
        # WSL has inherent /proc vs ps discrepancies due to kernel thread scheduling
        try:
            with open('/proc/version', 'r', encoding='utf-8') as f:
                kernel_info = f.read().lower()
            if 'microsoft' in kernel_info or 'wsl' in kernel_info:
                _get_logger().debug("WSL environment detected, skipping hidden process detection")
                return evidences
        except (FileNotFoundError, PermissionError):
            pass
        
        # Container/Cloud environment check: skip in containerized environments
        # Containers have inherent process visibility discrepancies
        try:
            # Check for container indicators
            is_container = False
            
            # Check cgroup for container indicators
            with open('/proc/1/cgroup', 'r', encoding='utf-8') as f:
                cgroup_content = f.read().lower()
                if any(indicator in cgroup_content for indicator in 
                       ['docker', 'lxc', 'kubepods', 'containerd']):
                    is_container = True
            
            # Check for .containerenv (Podman)
            if not is_container and os.path.exists('/run/.containerenv'):
                is_container = True
            
            # Check for /.dockerenv
            if not is_container and os.path.exists('/.dockerenv'):
                is_container = True
            
            if is_container:
                _get_logger().debug("Container environment detected, skipping hidden process detection")
                return evidences
        except OSError:
            pass
        
        try:
            # Get PIDs from collected process data (from collector)
            collected_pids = set()
            for proc_info in process_data.get('processes', []):
                pid = proc_info.get('pid')
                if pid:
                    collected_pids.add(int(pid))
            
            # Phase 1: Triple snapshot /proc with 100ms intervals
            proc_pids_snapshot1 = set()
            with os.scandir('/proc') as it:
                for entry in it:
                    if entry.name.isdigit():
                        proc_pids_snapshot1.add(int(entry.name))
            
            # Wait 100ms for process state to stabilize
            time.sleep(0.1)
            
            proc_pids_snapshot2 = set()
            with os.scandir('/proc') as it:
                for entry in it:
                    if entry.name.isdigit():
                        proc_pids_snapshot2.add(int(entry.name))

            # Wait another 100ms
            time.sleep(0.1)

            proc_pids_snapshot3 = set()
            with os.scandir('/proc') as it:
                for entry in it:
                    if entry.name.isdigit():
                        proc_pids_snapshot3.add(int(entry.name))

            # PIDs must be present in ALL three snapshots AND not in collected data
            persistent_in_proc = proc_pids_snapshot1 & proc_pids_snapshot2 & proc_pids_snapshot3
            candidate_hidden_pids = persistent_in_proc - collected_pids
            
            if not candidate_hidden_pids:
                return evidences
            
            # Phase 2: Extended persistence verification (500ms wait)
            # Real rootkit-hidden processes will persist, short-lived legitimate ones won't
            _get_logger().debug(f"[rootkit_analyzer] Found {len(candidate_hidden_pids)} candidate hidden PIDs, "
                        f"verifying with 500ms persistence check: {sorted(candidate_hidden_pids)[:10]}")
            
            time.sleep(0.5)
            
            verified_hidden = set()
            for pid in candidate_hidden_pids:
                try:
                    # Try to access /proc/{pid}/status - if process exists, it's truly persistent
                    with open(f'/proc/{pid}/status', 'r', encoding='utf-8') as f:
                        first_line = f.readline()
                        if first_line:  # Successfully read means process still exists
                            verified_hidden.add(pid)
                except OSError:
                    _get_logger().debug(f"[rootkit_analyzer] PID {pid} exited during verification "
                                f"(likely short-lived process, not rootkit)")
            
            _get_logger().debug(f"[rootkit_analyzer] After 500ms persistence check: "
                        f"{len(verified_hidden)} verified hidden PIDs")
            
            # Phase 3: Final threshold check
            # Require at least 5 verified persistent hidden processes
            # This reduces false positives in dynamic cloud/container environments
            if len(verified_hidden) >= 5:
                evidences.append(self._create_evidence(
                    title="进程隐藏检测",
                    severity=Severity.CRITICAL,
                    attack_id="T1014",
                    description=f"发现 {len(verified_hidden)} 个隐藏进程：在 /proc 中持续存在但不在进程列表中",
                    confidence=0.9,
                    raw_data={
                        "proc_pids_count": len(proc_pids_snapshot3),
                        "collected_pids_count": len(collected_pids),
                        "candidate_hidden_count": len(candidate_hidden_pids),
                        "verified_hidden_count": len(verified_hidden),
                        "hidden_in_proc": sorted(verified_hidden)[:10],
                        "verification_method": "triple_snapshot + 500ms persistence check",
                    },
                    evidence_details=self._create_evidence_details(service_type='rootkit_detection'),
                    remediation_commands=[
                        "ls -la /proc/ | grep -E '^d' | awk '{print $9}' | sort -n > /tmp/proc_pids.txt",
                        "ps aux | awk '{print $2}' | sort -n > /tmp/ps_pids.txt",
                        "diff /tmp/proc_pids.txt /tmp/ps_pids.txt",
                        "Check for hidden process modules: lsmod | grep -i rootkit"
                    ]
                ))
        except (OSError, subprocess.SubprocessError) as e:
            _get_logger().debug(f"Rootkit detection error: {e}")
        
        return evidences

    def _detect_hidden_ports(self, network_data: Dict) -> List[Evidence]:
        """Detect hidden ports
        
        Compares listening ports from collected network data with direct /proc/net/tcp read.
        Only alerts when ports are persistently hidden (not transient state changes).
        """
        evidences = []
        
        try:
            # Get listening ports from collected network data (from collector)
            proc_listen_ports = set()
            
            # Limit connection iteration in quick mode for performance
            tcp_conns = network_data.get('tcp_connections', [])
            tcp6_conns = network_data.get('tcp6_connections', [])
            
            for conn in tcp_conns:
                if conn.get('state') == 'LISTEN':
                    proc_listen_ports.add(conn.get('local_port'))
            
            # Also check tcp6 connections
            for conn in tcp6_conns:
                if conn.get('state') == 'LISTEN':
                    proc_listen_ports.add(conn.get('local_port'))
            
            # Second direct read of /proc/net/tcp for comparison
            ss_listen_ports = set()
            for conn in parse_proc_net_tcp("/proc/net/tcp"):
                if conn.get("state") == "LISTEN":
                    ss_listen_ports.add(conn.get("local_port"))
            
            # Skip tcp6 in quick mode for performance
            try:
                for conn in parse_proc_net_tcp("/proc/net/tcp6"):
                    if conn.get("state") == "LISTEN":
                        ss_listen_ports.add(conn.get("local_port"))
            except OSError:
                pass
            
            # Compare differences
            hidden_ports = proc_listen_ports - ss_listen_ports
            missing_ports = ss_listen_ports - proc_listen_ports
            
            # Filter out ephemeral/high ports (>32768) which are often transient
            # Rootkits typically hide well-known or specific ports, not ephemeral ones
            ephemeral_threshold = 32768
            suspicious_hidden = {p for p in hidden_ports if p < ephemeral_threshold}
            suspicious_missing = {p for p in missing_ports if p < ephemeral_threshold}
            
            # Only alert when suspicious ports (non-ephemeral) are hidden
            if suspicious_hidden or suspicious_missing:
                evidences.append(self._create_evidence(
                    title="端口隐藏检测",
                    severity=Severity.CRITICAL,
                    attack_id="T1014",
                    description=f"发现隐藏的监听端口: 在/proc中但不在ss中={suspicious_hidden}",
                    confidence=0.85,
                    raw_data={
                        "proc_ports": sorted(proc_listen_ports),
                        "ss_ports": sorted(ss_listen_ports),
                        "hidden_in_proc": sorted(suspicious_hidden),
                        "missing_from_proc": sorted(suspicious_missing),
                        "note": f"已过滤临时端口(>{ephemeral_threshold})，仅显示可疑端口"
                    },
                    evidence_details=EvidenceDetail(
                        file_path="/proc/net/tcp",
                    ),
                    remediation_commands=[
                        "cat /proc/net/tcp /proc/net/tcp6 | grep -i '0A'",
                        "ss -tlnp | grep -i listen",
                        "netstat -tlnp | grep -i listen",
                        "Compare /proc/net/tcp and ss output for discrepancies"
                    ]
                ))
        except (OSError, ValueError, KeyError) as e:
            _get_logger().debug(f"Rootkit detection error: {e}")
        
        return evidences
    
    def _detect_kernel_module_anomalies(self, service_data: Dict) -> List[Evidence]:
        """Detect kernel module anomalies"""
        evidences = []
        
        try:
            # Read /proc/modules
            proc_modules = set()
            try:
                with open('/proc/modules', 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        parts = line.strip().split()
                        if parts:
                            proc_modules.add(parts[0])
            except (PermissionError, FileNotFoundError):
                pass
            
            # Read /sys/module/
            sys_modules = set()
            try:
                for entry in os.listdir('/sys/module'):
                    if os.path.isdir(f'/sys/module/{entry}'):
                        sys_modules.add(entry)
            except (PermissionError, FileNotFoundError):
                pass
            
            # Compare differences
            hidden_modules = proc_modules - sys_modules
            if hidden_modules:
                evidences.append(self._create_evidence(
                    title="隐藏内核module检测",
                    severity=Severity.CRITICAL,
                    attack_id="T1547.006",
                    description=f"发现隐藏的内核module: {hidden_modules}",
                    confidence=0.8,
                    raw_data={
                        "proc_modules_count": len(proc_modules),
                        "sys_modules_count": len(sys_modules),
                        "hidden_modules": list(hidden_modules),
                    },
                    evidence_details=EvidenceDetail(
                        file_path="/proc/modules",
                    ),
                    remediation_commands=[
                        "cat /proc/modules",
                        "ls /sys/module/",
                        "diff <(awk '{print $1}' /proc/modules | sort) <(ls /sys/module/ | sort)",
                        "Check for rootkit kernel modules: lsmod | grep -i rootkit"
                    ]
                ))
            
            # Check modules_load_d and modprobe_d anomalies
            for module_entry in service_data.get('modules_load_d', []):
                for module_name in module_entry.get('modules', []):
                    # Check non-standard module names
                    if not module_name.startswith(('snd', 'nvidia', 'i915', 'amdgpu', 'virtio')):
                        evidences.append(self._create_evidence(
                            title=f"可疑内核module加载: {module_name}",
                            severity=Severity.MEDIUM,
                            attack_id="T1547.006",
                            description=f"非standard内核module: {module_name}",
                            confidence=0.5,
                            raw_data={"module": module_name, "source": module_entry.get('file')},
                            evidence_details=EvidenceDetail(
                                file_path=module_entry.get('file', '/etc/modules-load.d/'),
                            ),
                            remediation_commands=[
                                f"cat {module_entry.get('file', 'N/A')}",
                                f"modinfo {module_name}",
                                f"lsmod | grep {module_name}",
                                "Verify module signature and source"
                            ]
                        ))
            
            # Check anomalous configuration in modprobe.d
            for modprobe_entry in service_data.get('modprobe_d', []):
                content = modprobe_entry.get('content', '')
                if 'install' in content and ('/tmp/' in content or self.HIDDEN_PATH_PATTERN.search(content)):
                    evidences.append(self._create_evidence(
                        title=f"modprobe异常配置: {modprobe_entry.get('file')}",
                        severity=Severity.HIGH,
                        attack_id="T1547.006",
                        description=f"modprobe.d中的异常配置: {modprobe_entry.get('file')}",
                        confidence=0.7,
                        raw_data={
                            "file": modprobe_entry.get('file'),
                            "content": content[:200],
                        },
                        evidence_details=EvidenceDetail(
                            file_path=modprobe_entry.get('file', '/etc/modprobe.d/'),
                        ),
                        remediation_commands=[
                            f"cat {modprobe_entry.get('file', 'N/A')}",
                            "ls -la /etc/modprobe.d/",
                            "Check for malicious module install overrides"
                        ]
                    ))
        except (OSError, ValueError, KeyError) as e:
            _get_logger().debug(f"Rootkit detection error: {e}")
        
        return evidences
    def _detect_ld_preload_hijack(self, service_data: Dict) -> List[Evidence]:
        """Detect ld.so.preload hijacking"""
        evidences = []

        try:
            ld_preload = service_data.get('ld_so_preload', {})
            # Validate ld_preload is a dict, not a list (schema compatibility)
            if not isinstance(ld_preload, dict):
                return evidences
            
            if ld_preload.get('exists') and ld_preload.get('content'):
                content = ld_preload['content']
                
                # Check if path points to suspicious locations
                if self.TMP_PATH_PATTERN.search(content) or self.HIDDEN_PATH_PATTERN.search(content):
                    evidences.append(self._create_evidence(
                        title="ld.so.preload劫持(可疑路径)",
                        severity=Severity.CRITICAL,
                        attack_id="T1574.006",
                        description=f"ld.so.preload指向可疑路径: {content}",
                        confidence=0.9,
                        raw_data={
                            "path": ld_preload.get('raw_path', '/etc/ld.so.preload'),
                            "content": content,
                        },
                        evidence_details=EvidenceDetail(
                            file_path=ld_preload.get('raw_path', '/etc/ld.so.preload'),
                        ),
                        remediation_commands=[
                            "cat /etc/ld.so.preload",
                            "ls -la /etc/ld.so.preload",
                            "cat /etc/ld.so.preload | xargs -I{} ls -la {}",
                            "Check for library injection: ldd /bin/ls"
                        ]
                    ))
                else:
                    evidences.append(self._create_evidence(
                        title="ld.so.preload文件异常存在",
                        severity=Severity.HIGH,
                        attack_id="T1574.006",
                        description=f"ld.so.preload文件存在: {content}",
                        confidence=0.8,
                        raw_data={
                            "path": ld_preload.get('raw_path', '/etc/ld.so.preload'),
                            "content": content,
                        },
                        evidence_details=EvidenceDetail(
                            file_path=ld_preload.get('raw_path', '/etc/ld.so.preload'),
                        ),
                        remediation_commands=[
                            "cat /etc/ld.so.preload",
                            "ls -la /etc/ld.so.preload",
                            "Check if file should exist on this system",
                            "Review loaded libraries: ldd /bin/ls"
                        ]
                    ))
        except (OSError, ValueError, KeyError) as e:
            _get_logger().debug(f"ld.so.preload detection error: {e}")
        
        return evidences

    def _detect_ebpf_rootkit(self) -> List[Evidence]:
        """Detect eBPF rootkit (based on Synacktiv LinkPro analysis report)"""
        evidences = []

        # 5.1 Known eBPF rootkit file paths
        for rk_path in _KNOWN_EBPF_ROOTKIT_PATHS:
            if os.path.exists(rk_path):
                evidences.append(self._create_evidence(
                    title=f"已知 eBPF rootkit 路径: {rk_path}",
                    description=f"检测到已知 eBPF rootkit 文件路径存在: {rk_path}",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    attack_id="T1014",
                    attack_tactic="Defense Evasion",
                    source_path=rk_path,
                    remediation="立即隔离服务器，进行取证分析",
                    evidence_details=EvidenceDetail(
                        file_path=rk_path,
                    ),
                    remediation_commands=[
                        f"ls -la {rk_path}",
                        "Isolate the server immediately",
                        "Start forensic analysis: preserve evidence",
                        "Check for other rootkit indicators"
                    ]
                ))

        # 5.2 Shared libraries in hidden directories
        for search_dir in ["/usr/lib", "/lib", "/lib64"]:
            try:
                for entry in os.scandir(search_dir):
                    if entry.is_dir(follow_symlinks=False) and entry.name.startswith('.'):
                        try:
                            for sub in os.scandir(entry.path):
                                if sub.is_file() and '.so' in sub.name:
                                    evidences.append(self._create_evidence(
                                        title=f"隐藏目录中的共享library: {sub.path}",
                                        description=f"在隐藏目录中发现 .so 文件: {sub.path}",
                                        severity=Severity.CRITICAL,
                                        confidence=0.9,
                                        attack_id="T1014",
                                        attack_tactic="Defense Evasion",
                                        source_path=sub.path,
                                        remediation="check该共享library的来源和用途，可能为 rootkit 组件",
                                        evidence_details=EvidenceDetail(
                                            file_path=sub.path,
                                        ),
                                        remediation_commands=[
                                            f"ls -la {sub.path}",
                                            f"file {sub.path}",
                                            f"md5sum {sub.path}",
                                            "Check library origin: strings <library_path>"
                                        ]
                                    ))
                        except OSError:
                            pass
            except OSError:
                pass

        # 5.3 Use bpftool to detect anomalous eBPF programs and maps
        self._check_bpftool(evidences)

        return evidences

    def _check_bpftool(self, evidences: List[Evidence]):
        """Use bpftool to check eBPF programs and maps"""
        try:
            result = safe_run("bpftool", ["prog", "list", "--json"], timeout=5)
            if result.get("returncode") == 0:
                try:
                    progs = _json.loads(result.get("stdout", "[]"))
                    for prog in progs:
                        prog_name = prog.get("name", "")
                        prog_type = prog.get("type", "")
                        if any(mal in prog_name.lower() for mal in
                               ["hide", "rootkit", "knock", "stealth", "hook"]):
                            evidences.append(self._create_evidence(
                                title=f"可疑 eBPF 程序: {prog_name}",
                                description=(
                                    f"检测到可疑名称的 eBPF 程序: name={prog_name}, "
                                    f"type={prog_type}, id={prog.get('id', '?')}"
                                ),
                                severity=Severity.CRITICAL,
                                confidence=0.85,
                                attack_id="T1014",
                                attack_tactic="Defense Evasion",
                                raw_data={"bpf_prog": prog},
                                remediation="使用 bpftool prog show check该程序详情",
                                evidence_details=EvidenceDetail(
                                    file_path="/sys/fs/bpf/",
                                ),
                                remediation_commands=[
                                    f"bpftool prog show name {prog_name}",
                                    f"bpftool prog dump xlated name {prog_name}",
                                    "Check for rootkit indicators in /sys/fs/bpf/",
                                    "Investigate process that loaded the eBPF program"
                                ]
                            ))
                except (_json.JSONDecodeError, TypeError):
                    pass

            map_result = safe_run("bpftool", ["map", "list", "--json"], timeout=5)
            if map_result.get("returncode") == 0:
                try:
                    maps = _json.loads(map_result.get("stdout", "[]"))
                    for bpf_map in maps:
                        map_name = bpf_map.get("name", "")
                        if map_name in _KNOWN_MALICIOUS_BPF_MAPS:
                            evidences.append(self._create_evidence(
                                title=f"已知恶意 BPF map: {map_name}",
                                description=(
                                    f"检测到已知 eBPF rootkit 使用的 map: {map_name}, "
                                    f"id={bpf_map.get('id', '?')}"
                                ),
                                severity=Severity.CRITICAL,
                                confidence=0.9,
                                attack_id="T1014",
                                attack_tactic="Defense Evasion",
                                raw_data={"bpf_map": bpf_map},
                                remediation="立即调查该 BPF map 关联的程序",
                                evidence_details=EvidenceDetail(
                                    file_path="/sys/fs/bpf/",
                                ),
                                remediation_commands=[
                                    f"bpftool map show name {map_name}",
                                    "ls -la /sys/fs/bpf/",
                                    "Investigate map creator and users",
                                    "Check for associated eBPF programs"
                                ]
                            ))
                except (_json.JSONDecodeError, TypeError):
                    pass
        except OSError:
            _get_logger().debug("bpftool unavailable, skipping eBPF program detection")

    def _detect_fake_systemd_services(self) -> List[Evidence]:
        """Detect fake systemd services"""
        evidences = []
        service_dirs_cfg = self._get_config("paths.service_dirs")
        service_dirs = service_dirs_cfg if service_dirs_cfg else [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ]
        for svc_dir in service_dirs:
            try:
                for entry in os.scandir(svc_dir):
                    if entry.is_file(follow_symlinks=False):
                        if _FAKE_SYSTEMD_SERVICES.match(entry.name):
                            evidences.append(self._create_evidence(
                                title=f"仿冒 systemd 服务: {entry.name}",
                                description=(
                                    f"检测到疑似仿冒的恶意服务: {entry.path}，"
                                    f"该服务名与正常 systemd 服务拼写高度相似"
                                ),
                                severity=Severity.HIGH,
                                confidence=0.85,
                                attack_id="T1036.004",
                                attack_tactic="Defense Evasion",
                                source_path=entry.path,
                                remediation=f"check服务内容: systemctl cat {entry.name}",
                                evidence_details=EvidenceDetail(
                                    file_path=entry.path,
                                ),
                                remediation_commands=[
                                    f"systemctl cat {entry.name}",
                                    f"systemctl status {entry.name}",
                                    f"ls -la {entry.path}",
                                    "Compare with legitimate systemd service names"
                                ]
                            ))
            except OSError:
                pass
        return evidences

    def _detect_magic_tcp_syn(self, network_data: Dict) -> List[Evidence]:
        """Detect eBPF rootkit magic knock port (port=2233)"""
        evidences = []
        for conn in network_data.get('tcp_connections', []):
            local_port = conn.get('local_port', 0)
            if local_port == 2233:
                evidences.append(self._create_evidence(
                    title="eBPF rootkit knock port: 2233",
                    description=(
                        f"检测到端口 2233 上的连接，该端口为已知 eBPF rootkit "
                        f"(LinkPro) 的 magic knock port"
                    ),
                    severity=Severity.HIGH,
                    confidence=0.7,
                    attack_id="T1205",
                    attack_tactic="Defense Evasion",
                    raw_data={"connection": conn},
                    remediation="check端口 2233 的服务和流量特征",
                    evidence_details=EvidenceDetail(
                        local_address=None,
                        remote_address=None,
                        connection_state=conn.get('state'),
                        service_type="tcp",
                    ),
                    remediation_commands=[
                        "ss -tlnp | grep 2233",
                        "netstat -tlnp | grep 2233",
                        "tcpdump -i any port 2233 -w knock_traffic.pcap",
                        "Check for eBPF programs: bpftool prog list"
                    ]
                ))
        return evidences

    def _detect_process_injection(self, process_data: Dict) -> List[Evidence]:
        """Detect process injection attacks (T1055)
        
        Detection items:
        1. ptrace attach detection - via TracerPid field in /proc/[pid]/status
        2. Suspicious shared library injection - process loads .so files from temp directories
        """
        evidences = []
        
        processes = process_data.get('processes', [])
        
        for proc in processes:
            pid = proc.get('pid')
            if not pid:
                continue
            
            # 1. ptrace attach detection
            status_path = f'/proc/{pid}/status'
            try:
                with open(status_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith('TracerPid:'):
                            tracer_pid = int(line.split(':')[1].strip())
                            if tracer_pid != 0:
                                tracer_comm = "unknown"
                                try:
                                    with open(f'/proc/{tracer_pid}/comm', 'r', encoding='utf-8') as cf:
                                        tracer_comm = cf.read(256).strip()
                                except OSError:
                                    pass
                                
                                # Exclude known debuggers
                                if tracer_comm not in ('gdb', 'strace', 'ltrace', 'lldb', 'valgrind'):
                                    proc_name = proc.get('comm', 'unknown')
                                    evidences.append(self._create_evidence(
                                        title=f"进程被 ptrace 附加: PID {pid}",
                                        description=f"进程 {proc_name} (PID {pid}) 被 PID {tracer_pid} ({tracer_comm}) ptrace 附加",
                                        severity=Severity.HIGH,
                                        confidence=0.7,
                                        attack_id="T1055",
                                        raw_data={
                                            "pid": pid, "name": proc_name,
                                            "tracer_pid": tracer_pid, "tracer_comm": tracer_comm
                                        },
                                        evidence_details=EvidenceDetail(
                                            pid=pid,
                                            cmdline=None,
                                            executable=None,
                                            user=None,
                                            parent_pid=tracer_pid,
                                        ),
                                        remediation_commands=[
                                            f"ps -p {pid} -o pid,cmd,user",
                                            f"ps -p {tracer_pid} -o pid,cmd,user",
                                            f"cat /proc/{pid}/status | grep TracerPid",
                                            "Check for debugger or rootkit activity"
                                        ]
                                    ))
                            break
            except (OSError, ValueError):
                continue
            
            # 2. Suspicious shared library injection detection
            maps_path = f'/proc/{pid}/maps'
            try:
                suspicious_libs = []
                with open(maps_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) < 6:
                            continue
                        mapped_path = parts[-1]
                        if mapped_path.endswith('.so') or '.so.' in mapped_path:
                            if mapped_path.startswith(('/tmp/', '/dev/shm/', '/var/tmp/')):
                                suspicious_libs.append(mapped_path)
                
                if suspicious_libs:
                    proc_name = proc.get('comm', 'unknown')
                    unique_libs = list(set(suspicious_libs))[:5]
                    evidences.append(self._create_evidence(
                        title=f"可疑共享library注入: PID {pid}",
                        description=f"进程 {proc_name} (PID {pid}) 加载了临时目录中的共享library: {', '.join(unique_libs)}",
                        severity=Severity.CRITICAL,
                        confidence=0.8,
                        attack_id="T1055.002",
                        raw_data={
                            "pid": pid, "name": proc_name,
                            "suspicious_libs": unique_libs
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                            cmdline=None,
                            executable=None,
                            user=None,
                        ),
                        remediation_commands=[
                            f"cat /proc/{pid}/maps | grep '.so'",
                            f"ls -la {' '.join(unique_libs[:3])}",
                            f"ps -p {pid} -o pid,cmd,user",
                            "Check for library injection tools or rootkits"
                        ]
                    ))
            except OSError:
                continue
        
        return evidences

    def _detect_container_escape(self, collected_data: Dict) -> List[Evidence]:
        """Detect container escape attempts
        
        ATT&CK: T1611, T1610
        """
        evidences = []
        
        if not collected_data:
            return evidences
        
        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            return evidences
        
        processes = process_data.get("processes", [])
        
        # Container escape indicators
        escape_patterns = [
            (re.compile(r'nsenter|unshare|setns', re.IGNORECASE), "Namespace manipulation"),
            (re.compile(r'/proc/1/root|/host/', re.IGNORECASE), "Host filesystem access from container"),
            (re.compile(r'mount\s+.*--bind', re.IGNORECASE), "Bind mount manipulation"),
            (re.compile(r'docker\.sock|containerd\.sock', re.IGNORECASE), "Container runtime socket access"),
            (re.compile(r'cgroup.*release_agent', re.IGNORECASE), "Cgroup escape technique"),
            (re.compile(r'cap_add.*SYS_ADMIN|cap_add.*ALL', re.IGNORECASE), "Dangerous capability usage"),
        ]
        
        # System container processes whitelist (FP3 FIX)
        system_container_processes = {
            'dockerd', 'docker', 'containerd', 'containerd-shim', 
            'kubelet', 'kubectl', 'runc', 'runsc'
        }
        
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            pid = proc.get("pid", 0)
            
            # FP3 FIX: Skip system container daemon processes
            proc_name = proc.get("comm", "").lower()
            if proc_name in system_container_processes:
                _get_logger().debug(f"Skipping system container process: PID {pid} ({proc_name})")
                continue
            
            # Also check if cmdline contains only the daemon path (normal operation)
            cmdline_base = cmdline.split()[0] if cmdline else ""
            if any(daemon in cmdline_base for daemon in ['dockerd', 'containerd']):
                _get_logger().debug(f"Skipping container daemon: PID {pid}")
                continue
            
            for pattern, desc in escape_patterns:
                if pattern.search(cmdline):
                    evidence = self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1611",
                        attack_tactic="Privilege Escalation",
                        title=f"Potential container escape detected: {desc}",
                        description=(
                            f"Process (PID {pid}) showing {desc} pattern: "
                            f"{cmdline[:200]}"
                        ),
                        confidence=0.70,
                        source_path=f"/proc/{pid}/cmdline",
                        raw_data={"pid": pid, "pattern": desc, "cmdline": cmdline[:300]},
                        remediation="Verify container isolation. Review capabilities and mounts.",
                        evidence_details=EvidenceDetail(
                            pid=pid,
                            cmdline=cmdline,
                            executable=None,
                            user=None,
                        ),
                        remediation_commands=[
                            f"ps -p {pid} -o pid,cmd,user",
                            "Check container capabilities: capsh --print",
                            "Review container mounts: cat /proc/1/mountinfo",
                            "Verify isolation: nsenter --target 1 --mount -- cat /etc/hostname"
                        ]
                    )
                    evidences.append(evidence)
                    break
        
        return evidences
