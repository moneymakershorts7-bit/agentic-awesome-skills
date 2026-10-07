"""Kernel Taint Module Detection Analyzer

Detects kernel pollution events and out-of-tree kernel module loading that may
indicate rootkit installation or kernel-level compromise.

ATT&CK mapping:
- T1014 - Rootkit (kernel-level rootkit via loadable module)
- T1547.006 - Kernel Modules and Extensions (malicious kernel module)

References:
- Elastic Security Labs (2026-02): "Hooked on Linux: Rootkit Detection Engineering"
- Medium Article (2025): "Kernel Taint Rootkit: Detection"
- MITRE ATT&CK v17+ Linux/macOS techniques
"""
import os
import re
import json
import glob
from pathlib import Path
from typing import List, Dict, Any, Set, Optional
from ..reporter.severity import Severity
from ..reporter.evidence import Evidence
from .base import BaseAnalyzer
from ..utils.safe_exec import safe_run
from ..utils.remediation_generator import generate_generic_remediation
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

KERNEL_TAINT_FILE = '/proc/sys/kernel/tainted'
MODULE_SIG_FILE = '/proc/module_sig'
CUSTOM_WHITELIST_PATH = '/data/sec-userspace/workspace/kernel_modules_whitelist.json'
TAINT_FLAGS = {0: 'proprietary_module', 1: 'module_force_load', 2: 'smp_processor_id_out_of_range', 3: 'forced_unload_improperly', 4: 'machine_check_exception', 5: 'bad_page_reference', 6: 'request_by_user', 7: 'kernel_died', 8: 'acpi_table_override', 9: 'kernel_warning_occurred', 10: 'staging_driver_loaded', 11: 'external_module_loaded', 12: 'unsigned_module_loaded', 13: 'soft_lockup_occurred', 14: 'kernel_live_patched', 15: 'auxiliary_taint', 16: 'struct_randomization_plugin', 17: 'user_namespace_enabled', 18: 'page_size_at_boot_different', 19: 'out_of_tree_module_loaded', 20: 'unsigned_firmware_loaded', 21: 'workaround_for_bug_in_cpu', 22: 'test_module_loaded', 23: 'kernel_memory_corrupted', 24: 'random_trust_cpu_seed', 25: 'random_trust_bootloader_seed'}
OUT_OF_TREE_INDICATORS = [re.compile('loading out-of-tree module taints kernel', re.IGNORECASE), re.compile('module:.*taints kernel', re.IGNORECASE), re.compile('tainted:.*[Oo].*out.of.tree', re.IGNORECASE)]
TAINT_FLAG_SEVERITY = {'CRITICAL': {0, 11, 12, 19}, 'HIGH': {1, 3, 7, 14}, 'MEDIUM': {4, 5, 8, 9, 13}, 'LOW': {2, 6, 10, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25}}
CLOUD_PROVIDER_INDICATORS = {'aws': ['aliyun', 'ec2', 'amazon', 'aws'], 'azure': ['azure', 'microsoft'], 'gcp': ['google', 'gcp', 'gce'], 'alibaba': ['alibaba', 'aliyun', 'ecs']}
KNOWN_SAFE_MODULES: Set[str] = {'ext4', 'xfs', 'btrfs', 'vfat', 'ntfs', 'nfs', 'cifs', 'fuse', 'iptable_filter', 'ip_tables', 'nf_conntrack', 'nf_defrag_ipv4', 'br_netfilter', 'overlay', 'vxlan', 'wireguard', 'tcp_diag', 'inet_diag', 'udp_diag', 'ipv6', 'llc', 'stp', 'bridge', 'e1000', 'e1000e', 'igb', 'ixgbe', 'i40e', 'mlx4_core', 'mlx5_core', 'mlx4_en', 'mlx5_en', 'bnxt_en', 'tg3', 'bnx2', 'bnx2x', 'cxgb4', 'sfc', 'qlcnic', 'be2net', 'r8169', 'ahci', 'nvme', 'sd_mod', 'sr_mod', 'megaraid_sas', 'mpt3sas', 'hpsa', 'smartpqi', 'aacraid', 'arcmsr', 'qla2xxx', 'lpfc', 'nvidia', 'nvidia_uvm', 'nvidia_drm', 'nvidia_modeset', 'i915', 'amdgpu', 'radeon', 'nouveau', 'usbhid', 'xhci_hcd', 'ehci_hcd', 'ohci_hcd', 'kvm', 'kvm_intel', 'kvm_amd', 'vboxdrv', 'vboxnetflt', 'vboxnetadp', 'vboxpci', 'vmmon', 'vmnet', 'vmw_pvscsi', 'vmxnet3', 'vmw_vmci', 'veth', 'bridge', 'stp', 'llc', 'ip_vs', 'ip_vs_rr', 'ip_vs_wrr', 'ip_vs_sh', 'ip_vs_lc', 'ip_vs_wlc', 'ip_vs_fo', 'ip_vs_ovf', 'overlay', 'aufs', 'aesni_intel', 'aes_x86_64', 'ghash_clmulni_intel', 'sha256_ssse3', 'sha512_ssse3', 'sha1_ssse3', 'crc32_pclmul', 'crc32c_intel', 'crct10dif_pclmul', 'polyval_clmulni', 'polyval_generic', 'ena', 'ena_rdma', 'ena_express', 'nvme', 'xen_blkfront', 'xen_netfront', 'hv_netvsc', 'hv_storvsc', 'hv_vmbus', 'hv_utils', 'hv_balloon', 'hv_mouse', 'hv_keyboard', 'hv_sock', 'gve', 'gvnic', 'virtio_net', 'virtio_blk', 'virtio_pci', 'virtio_scsi', 'virtio_console', 'virtio_rng', 'virtio_balloon', 'virtio_input', 'virtio_gpu', 'virtio_fs', 'xen_netfront', 'xen_blkfront', 'xenfs', 'xen_platform_pci', 'xen_gntdev', 'xen_evtchn', 'xen_privcmd', 'vmw_pvscsi', 'vmxnet3', 'vmw_vmci', 'containerd', 'crio', 'kata_shim', 'runsc', 'flannel', 'calico', 'weave', 'canal', 'cilium', 'cilium_lb', 'cilium_host', 'istio_cni', 'linkerd_proxy', 'ebs_csi', 'aws_ebs', 'azure_disk', 'gce_pd', 'alicloud_disk', 'csi_block', 'aliyun_virtio', 'aliyun_eni', 'aliyun_assist', 'aliyun_rdma', 'aliyun_nvme', 'rook_ceph', 'longhorn', 'openebs', 'ceph', 'rbd', 'libceph', 'nvidia_fabricmanager', 'nvidia_peermem', 'bpf_testmod', 'ib_core', 'ib_cm', 'iw_cm', 'rdma_cm', 'rdma_ucm', 'mlx5_ib', 'ocrdma', 'qedr', 'uio', 'vfio', 'vfio_pci', 'vfio_iommu_type1', 'fuse', 'cuse', 'drm', 'drm_kms_helper', 'syscopyarea', 'sysfillrect', 'sysimgblt', 'fb_sys_fops'}

def load_custom_whitelist() -> Set[str]:
    """Load custom kernel module whitelist from configuration file

    Reads from CUSTOM_WHITELIST_PATH and returns additional safe modules.
    Supports both exact module names and glob patterns.

    Configuration format:
    {
        "modules": ["module1", "module2"],
        "patterns": ["/lib/modules/*/extra/*.ko"],
        "cloud_providers": ["alibaba", "aws", "azure", "gcp"]
    }

    Returns:
        Set of additional module names to whitelist
    """
    try:
        whitelist_path = Path(CUSTOM_WHITELIST_PATH)
        if not whitelist_path.exists():
            _get_logger().debug(f'[kernel_taint_analyzer] Custom whitelist not found at {CUSTOM_WHITELIST_PATH}')
            return set()
        with open(whitelist_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        custom_modules = set()
        if 'modules' in config and isinstance(config['modules'], list):
            for module in config['modules']:
                if isinstance(module, str) and module.strip():
                    custom_modules.add(module.strip().lower())
        if 'patterns' in config and isinstance(config['patterns'], list):
            for pattern in config['patterns']:
                if isinstance(pattern, str) and pattern.strip():
                    expanded = glob.glob(pattern)
                    for path in expanded:
                        module_name = Path(path).stem
                        custom_modules.add(module_name.lower())
        if 'cloud_providers' in config and isinstance(config['cloud_providers'], list):
            detected_cloud = _detect_cloud_provider()
            if detected_cloud and detected_cloud in config['cloud_providers']:
                cloud_modules = _get_cloud_provider_modules(detected_cloud)
                custom_modules.update(cloud_modules)
                _get_logger().info(f'[kernel_taint_analyzer] Auto-loaded {len(cloud_modules)} modules for cloud provider: {detected_cloud}')
        _get_logger().info(f'[kernel_taint_analyzer] Loaded {len(custom_modules)} custom whitelist entries')
        return custom_modules
    except (json.JSONDecodeError, OSError) as e:
        _get_logger().warning(f'[kernel_taint_analyzer] Failed to load custom whitelist: {e}')
        return set()
    except (ValueError, KeyError, TypeError) as e:
        _get_logger().error(f'[kernel_taint_analyzer] Unexpected error loading whitelist: {e}')
        return set()

def _detect_cloud_provider() -> Optional[str]:
    """Detect current cloud provider environment

    Returns:
        Cloud provider name ('aws', 'azure', 'gcp', 'alibaba') or None
    """
    try:
        dmi_paths = ['/sys/class/dmi/id/product_name', '/sys/class/dmi/id/sys_vendor', '/sys/class/dmi/id/board_vendor']
        for dmi_path in dmi_paths:
            if os.path.exists(dmi_path):
                with open(dmi_path, 'r', encoding='utf-8') as f:
                    content = f.read().lower()
                    for provider, indicators in CLOUD_PROVIDER_INDICATORS.items():
                        if any((ind in content for ind in indicators)):
                            return provider
        if os.path.exists('/proc/cpuinfo'):
            with open('/proc/cpuinfo', 'r', encoding='utf-8') as f:
                cpuinfo = f.read().lower()
                for provider, indicators in CLOUD_PROVIDER_INDICATORS.items():
                    if any((ind in cpuinfo for ind in indicators)):
                        return provider
        return None
    except OSError:
        return None

def _get_cloud_provider_modules(provider: str) -> Set[str]:
    """Get known safe modules for a specific cloud provider

    Args:
        provider: Cloud provider name ('aws', 'azure', 'gcp', 'alibaba')

    Returns:
        Set of module names known to be safe for this provider
    """
    cloud_modules = {'aws': {'ena', 'ena_rdma', 'ena_express', 'nvme', 'xen_blkfront', 'xen_netfront', 'grub_xen', 'xenfs', 'xen_privcmd'}, 'azure': {'hv_netvsc', 'hv_storvsc', 'hv_vmbus', 'hv_utils', 'hv_balloon', 'hv_sock', 'hv_mouse', 'hv_keyboard'}, 'gcp': {'gve', 'gvnic'}, 'alibaba': {'aliyun_virtio', 'aliyun_eni', 'aliyun_assist', 'aliyun_rdma', 'aliyun_nvme'}}
    return cloud_modules.get(provider, set())

def check_module_signature(module_name: str) -> Dict[str, Any]:
    """Check kernel module signature status
    
    Verifies if a kernel module has a valid signature when CONFIG_MODULE_SIG
    is enabled. This helps distinguish between signed third-party modules
    and completely unsigned/suspicious modules.
    
    Args:
        module_name: Name of the kernel module to check
        
    Returns:
        Dictionary with signature information:
        {
            'signed': bool,
            'signature_type': str or None,
            'valid': bool,
            'error': str or None
        }
    """
    result = {'signed': False, 'signature_type': None, 'valid': False, 'error': None}
    try:
        sig_file = Path(MODULE_SIG_FILE)
        if not sig_file.exists():
            result['error'] = 'Module signature info not available'
            return result
        with open(sig_file, 'r', encoding='utf-8') as f:
            content = f.read()
        for line in content.splitlines():
            if module_name in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    sig_info = parts[1].strip()
                    result['signed'] = True
                    if 'PKCS#7' in sig_info:
                        result['signature_type'] = 'PKCS#7'
                    elif 'RSA' in sig_info:
                        result['signature_type'] = 'RSA'
                    else:
                        result['signature_type'] = 'unknown'
                    if 'valid' in sig_info.lower():
                        result['valid'] = True
                    elif 'invalid' in sig_info.lower():
                        result['valid'] = False
                break
        if not result['signed']:
            result['error'] = 'No signature found for module'
    except OSError as e:
        result['error'] = f'Failed to read signature info: {str(e)}'
    except (ValueError, KeyError, TypeError) as e:
        result['error'] = f'Unexpected error checking signature: {str(e)}'
    return result

class KernelTaintAnalyzer(BaseAnalyzer):
    """Kernel Taint and Out-of-Tree Module Detection Analyzer
    
    Monitors kernel taint state and detects suspicious kernel module loading
    that may indicate rootkit installation or kernel-level compromise.
    """
    name = 'kernel_taint_analyzer'
    timeout = 30
    required_collectors = ['log', 'service']
    ATTACK_ID = 'T1547.006'
    ATTACK_TACTIC = 'Persistence'

    def should_skip(self) -> tuple:
        """Run kernel taint check in quick mode"""
        return (False, '')

    def analyze(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Execute kernel taint detection"""
        evidences = []
        try:
            log_data = self._get_data(collected_data, 'log')
            service_data = self._get_data(collected_data, 'service')
        except KeyError as e:
            _get_logger().warning(f'[{self.name}] Required collector data missing: {e}')
            return evidences
        evidences.extend(self._check_kernel_taint_status())
        evidences.extend(self._check_dmesg_for_taint())
        evidences.extend(self._check_kernel_logs(log_data))
        evidences.extend(self._check_loaded_modules(service_data))
        return evidences

    def _check_kernel_taint_status(self) -> List[Evidence]:
        """Check /proc/sys/kernel/tainted for non-zero value"""
        evidences = []
        try:
            if not os.path.exists(KERNEL_TAINT_FILE):
                _get_logger().debug(f'[{self.name}] {KERNEL_TAINT_FILE} does not exist')
                return evidences
            with open(KERNEL_TAINT_FILE, 'r', encoding='utf-8') as f:
                taint_value_str = f.read().strip()
            try:
                taint_value = int(taint_value_str)
            except ValueError:
                _get_logger().warning(f'[{self.name}] Invalid taint value: {taint_value_str}')
                return evidences
            if taint_value == 0:
                _get_logger().debug(f'[{self.name}] Kernel is not tainted')
                return evidences
            tainted_flags = self._decode_taint_flags(taint_value)
            is_cloud_env = self._detect_cloud_environment()
            max_severity, confidence, critical_flags = self._classify_taint_severity(tainted_flags, is_cloud_env)
            if is_cloud_env and max_severity == Severity.MEDIUM:
                _get_logger().debug(f'[{self.name}] Skipping MEDIUM taint flags in cloud environment: taint_value={taint_value}')
                return evidences
            flag_names = [TAINT_FLAGS.get(flag, f'unknown_{flag}') for flag in tainted_flags]
            critical_flag_names = [TAINT_FLAGS.get(f, f'unknown_{f}') for f in critical_flags]
            has_unsigned_only = set(tainted_flags).issubset({11, 12}) and is_cloud_env
            description_parts = [f'Kernel taint value: {taint_value}.', f"Active taint flags: {', '.join(flag_names)}."]
            if critical_flag_names:
                description_parts.append(f"Critical/High severity flags: {', '.join(critical_flag_names)}.")
            if is_cloud_env:
                description_parts.append('Detected cloud environment.')
                if has_unsigned_only:
                    description_parts.append('Taint is from unsigned/external kernel modules which are common in cloud environments due to vendor custom kernel modules. This is likely a false positive if running on Alibaba Cloud Linux, AWS Amazon Linux, or other vendor-customized distributions.')
            evidence = self._create_evidence(title='Kernel Taint Detected', description=' '.join(description_parts), severity=max_severity, confidence=confidence, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path=KERNEL_TAINT_FILE, raw_data={'taint_value': taint_value, 'taint_flags': flag_names, 'critical_flags': critical_flag_names, 'is_cloud_environment': is_cloud_env, 'taint_details': {flag: {'name': TAINT_FLAGS.get(flag, 'unknown'), 'severity': self._get_flag_severity_level(flag)} for flag in tainted_flags}}, remediation=f"Review loaded kernel modules using 'lsmod'. Verify all modules are from trusted sources. Check /var/log/kern.log for module loading events. If in cloud environment, verify taint is from cloud provider modules. Consider adding legitimate cloud vendor modules to custom whitelist at {CUSTOM_WHITELIST_PATH}.", evidence_details=self._create_evidence_details(service_type='kernel_taint'), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'kernel_taint_analyzer'}))
            evidences.append(evidence)
            _get_logger().info(f'[{self.name}] Kernel taint detected: value={taint_value}, severity={max_severity.value}, cloud_env={is_cloud_env}')
        except OSError as e:
            _get_logger().debug(f'[{self.name}] Cannot read kernel taint status: {e}')
        except (ValueError, KeyError, TypeError) as e:
            _get_logger().error(f'[{self.name}] Unexpected error checking proc taint: {e}', exc_info=True)
        return evidences

    def _detect_cloud_environment(self) -> bool:
        """Detect if running in a cloud environment
        
        Checks multiple indicators to determine if the system is running
        in a cloud provider environment (AWS, Azure, GCP, Alibaba Cloud).
        
        Returns:
            bool: True if cloud environment detected, False otherwise
        """
        try:
            dmi_paths = ['/sys/class/dmi/id/product_name', '/sys/class/dmi/id/sys_vendor', '/sys/class/dmi/id/board_vendor']
            for dmi_path in dmi_paths:
                if os.path.exists(dmi_path):
                    with open(dmi_path, 'r', encoding='utf-8') as f:
                        content = f.read().lower()
                        for provider, indicators in CLOUD_PROVIDER_INDICATORS.items():
                            if any((ind in content for ind in indicators)):
                                _get_logger().debug(f'[{self.name}] Cloud environment detected: {provider} via {dmi_path}')
                                return True
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r', encoding='utf-8') as f:
                    cpuinfo = f.read().lower()
                    cloud_hypervisors = ['hypervisor', 'xen', 'kvm', 'amazon', 'alibaba']
                    if any((h in cpuinfo for h in cloud_hypervisors)):
                        for provider, indicators in CLOUD_PROVIDER_INDICATORS.items():
                            if any((ind in cpuinfo for ind in indicators)):
                                _get_logger().debug(f'[{self.name}] Cloud environment detected: {provider} via cpuinfo')
                                return True
            hostname_file = '/etc/hostname'
            if os.path.exists(hostname_file):
                with open(hostname_file, 'r', encoding='utf-8') as f:
                    hostname = f.read().lower()
                    for provider, indicators in CLOUD_PROVIDER_INDICATORS.items():
                        if any((ind in hostname for ind in indicators)):
                            _get_logger().debug(f'[{self.name}] Cloud environment detected: {provider} via hostname')
                            return True
            _get_logger().debug(f'[{self.name}] No cloud environment indicators detected')
            return False
        except (OSError, ValueError) as e:
            _get_logger().warning(f'[{self.name}] Error detecting cloud environment: {e}')
            return False

    def _classify_taint_severity(self, tainted_flags: List[int], is_cloud_env: bool) -> tuple:
        """Classify taint severity based on flag importance and environment

        In cloud environments, unsigned module loading (flag 12) and external
        module loading (flag 11) are common due to cloud vendor custom kernels.
        These flags are downgraded from CRITICAL to MEDIUM in cloud environments.

        Args:
            tainted_flags: List of active taint flag bit positions
            is_cloud_env: Whether running in cloud environment

        Returns:
            tuple: (max_severity, confidence, critical_flags)
                - max_severity: Highest severity level detected
                - confidence: Confidence score (0.0-1.0)
                - critical_flags: List of CRITICAL/HIGH severity flags
        """
        if not tainted_flags:
            return (Severity.LOW, 0.5, [])
        effective_critical_flags = TAINT_FLAG_SEVERITY['CRITICAL'].copy()
        if is_cloud_env:
            effective_critical_flags = effective_critical_flags - {11, 12}
        max_severity = Severity.LOW
        critical_flags = []
        for flag in tainted_flags:
            if flag in effective_critical_flags:
                max_severity = Severity.CRITICAL
                critical_flags.append(flag)
            elif flag in TAINT_FLAG_SEVERITY['HIGH'] and max_severity != Severity.CRITICAL:
                max_severity = Severity.HIGH
                critical_flags.append(flag)
            elif flag in TAINT_FLAG_SEVERITY['MEDIUM'] and max_severity == Severity.LOW:
                max_severity = Severity.MEDIUM
        if is_cloud_env and set(tainted_flags).issubset({11, 12}) and tainted_flags:
            max_severity = Severity.MEDIUM
        confidence = 0.7
        if len(critical_flags) >= 2:
            confidence = 0.9
        elif len(critical_flags) == 1:
            confidence = 0.85
        elif max_severity == Severity.HIGH:
            confidence = 0.8
        elif max_severity == Severity.MEDIUM:
            confidence = 0.7
        if is_cloud_env and max_severity == Severity.MEDIUM:
            confidence = 0.5
        if is_cloud_env and set(tainted_flags).issubset({11, 12}):
            confidence = 0.4
        return (max_severity, confidence, critical_flags)

    def _get_flag_severity_level(self, flag: int) -> str:
        """Get severity level string for a single taint flag
        
        Args:
            flag: Taint flag bit position
            
        Returns:
            str: Severity level ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        """
        for level, flags in TAINT_FLAG_SEVERITY.items():
            if flag in flags:
                return level
        return 'UNKNOWN'

    def _decode_taint_flags(self, taint_value: int) -> List[int]:
        """Decode kernel taint value into individual flag bit positions"""
        flags = []
        for bit in range(len(TAINT_FLAGS)):
            if taint_value & 1 << bit:
                flags.append(bit)
        return flags

    def _check_dmesg_for_taint(self) -> List[Evidence]:
        """Analyze dmesg output for kernel taint messages"""
        evidences = []
        try:
            result = safe_run(['dmesg'], timeout=10)
            if not result.get('success', False):
                _get_logger().debug(f"[{self.name}] dmesg command failed: {result.get('stderr')}")
                return evidences
            dmesg_output = result.get('stdout', '')
            if not dmesg_output:
                _get_logger().debug(f'[{self.name}] No dmesg output available')
                return evidences
            taint_events = []
            for line in dmesg_output.splitlines():
                for pattern in OUT_OF_TREE_INDICATORS:
                    if pattern.search(line):
                        taint_events.append(line.strip())
                        break
            if taint_events:
                unique_events = list(set(taint_events))[:10]
                evidence = self._create_evidence(title='Out-of-Tree Module Loading Detected in dmesg', description=f'Found {len(unique_events)} dmesg log entries indicating out-of-tree module loading that taints the kernel.', severity=Severity.HIGH, confidence=0.9, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path='dmesg', raw_data={'taint_events': unique_events, 'event_count': len(unique_events)}, remediation='Investigate which modules caused kernel taint. Review module signatures and sources. Consider using only signed, in-tree modules.', evidence_details=self._create_evidence_details(service_type='kernel_taint'), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'kernel_taint_analyzer'}))
                evidences.append(evidence)
                _get_logger().info(f'[{self.name}] Found {len(unique_events)} taint events in dmesg')
        except OSError as e:
            _get_logger().debug(f'[{self.name}] Failed to execute dmesg: {e}')
        except (ValueError, KeyError, TypeError) as e:
            _get_logger().error(f'[{self.name}] Error analyzing dmesg: {e}', exc_info=True)
        return evidences

    def _check_kernel_logs(self, log_data: Dict) -> List[Evidence]:
        """Check system logs for kernel module loading events"""
        evidences = []
        try:
            log_messages = log_data.get('messages', []) if isinstance(log_data, dict) else []
            if not log_messages:
                _get_logger().debug(f'[{self.name}] No log messages available')
                return evidences
            taint_events = []
            for log_entry in log_messages:
                message = (log_entry.get('message') or '') if isinstance(log_entry, dict) else str(log_entry)
                for pattern in OUT_OF_TREE_INDICATORS:
                    if pattern.search(message):
                        taint_events.append({'log_source': 'system_log', 'message': message.strip()[:500]})
                        break
            if taint_events:
                unique_events = []
                seen_messages = set()
                for event in taint_events:
                    msg = event['message']
                    if msg not in seen_messages:
                        seen_messages.add(msg)
                        unique_events.append(event)
                unique_events = unique_events[:10]
                evidence = self._create_evidence(title='Kernel Taint Events Found in System Logs', description=f'Found {len(unique_events)} kernel taint events in system logs. These indicate out-of-tree or unsigned module loading.', severity=Severity.HIGH, confidence=0.85, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path='/var/log/kern.log', raw_data={'taint_events': unique_events, 'total_events': len(taint_events)}, remediation='Review system logs for unauthorized module loading. Implement module signing enforcement. Monitor for suspicious module activity.', evidence_details=self._create_evidence_details(service_type='kernel_taint'), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'kernel_taint_analyzer'}))
                evidences.append(evidence)
                _get_logger().info(f'[{self.name}] Found {len(unique_events)} taint events in system logs')
        except (OSError, ValueError, KeyError) as e:
            _get_logger().error(f'[{self.name}] Error checking system logs: {e}', exc_info=True)
        return evidences

    def _check_loaded_modules(self, service_data: Dict) -> List[Evidence]:
        """Analyze loaded kernel modules for suspicious characteristics
        
        Uses both static KNOWN_SAFE_MODULES whitelist and dynamic custom
        whitelist from configuration file. Also performs module signature
        verification when CONFIG_MODULE_SIG is enabled.
        """
        evidences = []
        try:
            modules_output = service_data.get('modules', '') if isinstance(service_data, dict) else ''
            if not modules_output:
                _get_logger().debug(f'[{self.name}] No kernel modules data available')
                return evidences
            custom_whitelist = load_custom_whitelist()
            effective_whitelist = KNOWN_SAFE_MODULES | custom_whitelist
            lines = modules_output.strip().splitlines()
            if lines and lines[0].startswith('Module'):
                lines = lines[1:]
            suspicious_modules = []
            whitelisted_by_signature = []
            for line in lines:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                module_name = parts[0]
                module_name_lower = module_name.lower()
                if module_name_lower in effective_whitelist:
                    continue
                sig_info = check_module_signature(module_name)
                if sig_info['signed'] and sig_info['valid']:
                    whitelisted_by_signature.append({'name': module_name, 'signature_type': sig_info['signature_type'], 'full_line': line.strip()})
                    continue
                if self._is_suspicious_module(module_name, line):
                    suspicious_modules.append({'name': module_name, 'size': parts[1], 'used_by': parts[3] if len(parts) > 3 else 'unknown', 'full_line': line.strip(), 'signature_status': sig_info})
            if whitelisted_by_signature:
                _get_logger().debug(f'[{self.name}] {len(whitelisted_by_signature)} modules whitelisted by valid signature')
            if suspicious_modules:
                severity = Severity.MEDIUM
                confidence = 0.6
                if len(suspicious_modules) > 5:
                    severity = Severity.HIGH
                    confidence = 0.75
                evidence = self._create_evidence(title='Suspicious Kernel Modules Detected', description=f'Found {len(suspicious_modules)} kernel modules not in the known safe modules whitelist. These may be out-of-tree or custom modules. {len(whitelisted_by_signature)} modules were whitelisted by valid signature.', severity=severity, confidence=confidence, attack_id='T1014', attack_tactic='Defense Evasion', source_path='/proc/modules', raw_data={'suspicious_modules': suspicious_modules[:20], 'whitelisted_by_signature': whitelisted_by_signature[:20], 'total_count': len(suspicious_modules), 'custom_whitelist_count': len(custom_whitelist)}, remediation=f"Verify each module is from a trusted source. Check module signatures with 'modinfo <module>'. Review module source code if available. Add legitimate modules to custom whitelist at {CUSTOM_WHITELIST_PATH}.", evidence_details=self._create_evidence_details(service_type='kernel_taint'), remediation_commands=generate_generic_remediation(attack_id='1014', context={'analyzer': 'kernel_taint_analyzer'}))
                evidences.append(evidence)
                _get_logger().info(f'[{self.name}] Found {len(suspicious_modules)} suspicious modules')
        except (OSError, ValueError, KeyError) as e:
            _get_logger().error(f'[{self.name}] Error analyzing kernel modules: {e}', exc_info=True)
        return evidences

    def _is_suspicious_module(self, module_name: str, module_line: str) -> bool:
        """Check if a kernel module has suspicious characteristics"""
        suspicious_indicators = ['/tmp/', '/dev/shm/', '/var/tmp/', '.ko.xz', '.ko.gz']
        for indicator in suspicious_indicators:
            if indicator in module_line:
                return True
        return False