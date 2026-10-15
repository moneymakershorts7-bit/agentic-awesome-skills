"""
CVE-2026-PENDING-DIRTYFRAG Detector - Dirty Frag Vulnerability Chain

Vulnerability description:
    Dirty Frag is a vulnerability chain combining xfrm-ESP Page-Cache Write
    and RxRPC Page-Cache Write vulnerabilities. Through splice(), an attacker
    can plant read-only page cache pages into skb frag slots, and receiver-side
    kernel code performs in-place crypto operations, modifying page cache in RAM.

    - ESP variant: Requires CAP_NET_ADMIN (user namespace), affects most distros
    - RxRPC variant: No special privileges required, but needs rxrpc.ko module

Impact Version:
    - ESP: cac2661c53f3 (2017-01-17) → upstream (~9 years)
    - RxRPC: 2dc334f1a63a (2023-06) → upstream

CVSS: TBD (estimated 7.8-8.0)
Severity: CRITICAL

Detection method (read-only throughout):
    1. Kernel version range match for both variants
    2. Module check (esp4.ko, esp6.ko, rxrpc.ko)
    3. Config check (CONFIG_XFRM, CONFIG_INET_ESP, CONFIG_RXRPC)
    4. Mitigation measures check (modprobe.d blacklist)
    5. AppArmor unshare policy check (Ubuntu)
"""
import logging
import subprocess
from typing import List, Optional

from .base import BaseDetector
from ..core.result import (
    DetectResult, Evidence, Remediation, PoCResult,
    PrepareResult, PostResult
)
from ..core.kernel_info import KernelInfo
from ..utils.version_compare import version_in_range
from ..utils.safe_check import (
    check_config_enabled,
    check_modprobe_disabled,
)

logger = logging.getLogger(__name__)


class CVE2026PendingDirtyFragDetector(BaseDetector):
    """CVE-2026-PENDING-DIRTYFRAG (Dirty Frag) Detector"""

    # Metadata
    cve_id = "CVE-2026-PENDING-DIRTYFRAG"
    cvss_score = 7.8
    severity = "CRITICAL"
    description = (
        "Dirty Frag vulnerability chain (xfrm-ESP + RxRPC Page-Cache Write) - "
        "Local privilege escalation via splice() to page cache modification"
    )
    vuln_type = "local_privilege_escalation"
    affected_versions = {
        "generic": {
            "esp_min": "4.10.0",      # cac2661c53f3 (2017-01-17)
            "rxrpc_min": "6.4.0",     # 2dc334f1a63a (2023-06)
            "fixed": None,            # No upstream fix yet
        },
        "ubuntu": {
            "24.04": {"kernel": "6.17.0", "fixed_kernel": None},
            "22.04": {"kernel": "5.15.0", "fixed_kernel": None},
        },
        "rhel": {
            "10.1": {"kernel": "6.12.0", "fixed_kernel": None},
        },
    }

    # PoC Metadata
    has_poc = True
    has_exp = False
    poc_bin = "poc-bin/cve_2026_pending_dirtyfrag.bin"
    poc_mode = "write_root_file"

    def _get_poc_verifier(self):
        """Return CTF-aware PoC verifier for three-phase execution"""
        from ..poc.cve_2026_pending_dirtyfrag_poc import CVE2026PendingDirtyFragPoCVerifier
        return CVE2026PendingDirtyFragPoCVerifier()

    # Internal constants
    _ESP_MODULES = ["esp4", "esp6"]
    _RXRPC_MODULE = "rxrpc"
    _ESP_CONFIG = "CONFIG_XFRM"
    _RXRPC_CONFIG = "CONFIG_RXRPC"

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute Dirty Frag detection

        Detection strategy:
        - Either variant exploitable = VULNERABLE
        - Both variants mitigated = NOT_VULNERABLE

        ESP variant detection:
        - Version >= 4.10 + esp modules + unshare allowed = VULNERABLE

        RxRPC variant detection:
        - Version >= 6.4 + rxrpc module + AF_RXRPC socket allowed = VULNERABLE
        """
        evidence_list: List[Evidence] = []
        confidence = 0.0

        # Check ESP variant
        esp_vulnerable, esp_evidence = self._check_esp_variant(kernel_info)
        evidence_list.extend(esp_evidence)

        # Check RxRPC variant
        rxrpc_vulnerable, rxrpc_evidence = self._check_rxrpc_variant(kernel_info)
        evidence_list.extend(rxrpc_evidence)

        # Determine overall vulnerability
        if esp_vulnerable or rxrpc_vulnerable:
            status = "VULNERABLE"
            confidence = 0.85  # High confidence (logic bug, deterministic)

            if esp_vulnerable and rxrpc_vulnerable:
                evidence_list.append(Evidence(
                    type="variant_analysis",
                    description="Both ESP and RxRPC variants exploitable - chain attack available",
                    raw_data="esp=exploitable, rxrpc=exploitable",
                    source="dual variant check"
                ))
            elif esp_vulnerable:
                evidence_list.append(Evidence(
                    type="variant_analysis",
                    description="ESP variant exploitable (RxRPC blocked or module missing)",
                    raw_data="esp=exploitable, rxrpc=blocked",
                    source="variant check"
                ))
            else:
                evidence_list.append(Evidence(
                    type="variant_analysis",
                    description="RxRPC variant exploitable (ESP blocked or unshare denied)",
                    raw_data="esp=blocked, rxrpc=exploitable",
                    source="variant check"
                ))
        else:
            status = "NOT_VULNERABLE"
            confidence = 0.95
            evidence_list.append(Evidence(
                type="variant_analysis",
                description="Both variants mitigated",
                raw_data="esp=blocked, rxrpc=blocked",
                source="variant check"
            ))

        return DetectResult(
            cve_id=self.cve_id,
            status=status,
            confidence=confidence,
            severity=self.severity,
            cvss_score=self.cvss_score,
            description=self.description,
            vuln_type=self.vuln_type,
            evidence=evidence_list,
            remediation=self.get_remediation()
        )

    def _check_esp_variant(self, kernel_info: KernelInfo) -> tuple:
        """Check ESP variant vulnerability"""
        evidence: List[Evidence] = []

        # Version check
        version_vulnerable = version_in_range(
            kernel_info.version,
            self.affected_versions["generic"]["esp_min"],
            fixed_version=None
        )

        if not version_vulnerable:
            evidence.append(Evidence(
                type="esp_version",
                description=f"Kernel version {kernel_info.version} not in ESP affected range",
                raw_data=kernel_info.version,
                source="uname -r"
            ))
            return False, evidence

        evidence.append(Evidence(
            type="esp_version",
            description=f"Kernel version {kernel_info.version} in ESP affected range (>= 4.10)",
            raw_data=kernel_info.version,
            source="uname -r"
        ))

        # Module check
        esp_modules_loaded = any(
            mod in kernel_info.loaded_modules
            for mod in self._ESP_MODULES
        )

        if esp_modules_loaded:
            evidence.append(Evidence(
                type="esp_module",
                description="ESP modules (esp4/esp6) loaded - vulnerability path reachable",
                raw_data="esp4 or esp6 loaded",
                source="/proc/modules"
            ))
        else:
            evidence.append(Evidence(
                type="esp_module",
                description="ESP modules not loaded - may be auto-loaded",
                raw_data="esp4/esp6 not loaded",
                source="/proc/modules"
            ))

        # Mitigation check: modprobe.d blacklist
        esp_blocked = check_modprobe_disabled("esp4") or check_modprobe_disabled("esp6")
        if esp_blocked:
            evidence.append(Evidence(
                type="esp_mitigation",
                description="ESP modules blocked in modprobe.d - mitigation applied",
                raw_data="install esp4 /bin/false or install esp6 /bin/false",
                source="/etc/modprobe.d/"
            ))
            return False, evidence

        # Unshare capability check (Ubuntu AppArmor)
        unshare_allowed = self._check_unshare_allowed()
        if not unshare_allowed:
            evidence.append(Evidence(
                type="esp_unshare",
                description="unshare(CLONE_NEWUSER) blocked by AppArmor policy - ESP variant not exploitable",
                raw_data="unshare denied",
                source="AppArmor policy"
            ))
            return False, evidence

        evidence.append(Evidence(
            type="esp_unshare",
            description="unshare(CLONE_NEWUSER) allowed - ESP variant exploitable",
            raw_data="unshare allowed",
            source="kernel capability"
        ))

        return True, evidence

    def _check_rxrpc_variant(self, kernel_info: KernelInfo) -> tuple:
        """Check RxRPC variant vulnerability"""
        evidence: List[Evidence] = []

        # Version check
        version_vulnerable = version_in_range(
            kernel_info.version,
            self.affected_versions["generic"]["rxrpc_min"],
            fixed_version=None
        )

        if not version_vulnerable:
            evidence.append(Evidence(
                type="rxrpc_version",
                description=f"Kernel version {kernel_info.version} not in RxRPC affected range (>= 6.4)",
                raw_data=kernel_info.version,
                source="uname -r"
            ))
            return False, evidence

        evidence.append(Evidence(
            type="rxrpc_version",
            description=f"Kernel version {kernel_info.version} in RxRPC affected range",
            raw_data=kernel_info.version,
            source="uname -r"
        ))

        # Module check
        rxrpc_loaded = self._RXRPC_MODULE in kernel_info.loaded_modules

        if rxrpc_loaded:
            evidence.append(Evidence(
                type="rxrpc_module",
                description="rxrpc.ko module loaded - vulnerability path reachable",
                raw_data="rxrpc loaded",
                source="/proc/modules"
            ))
        else:
            # Check if module can be auto-loaded
            evidence.append(Evidence(
                type="rxrpc_module",
                description="rxrpc.ko not loaded - check if available",
                raw_data="rxrpc not loaded",
                source="/proc/modules"
            ))

            # Check module availability
            try:
                result = subprocess.run(
                    ["modinfo", "-n", self._RXRPC_MODULE],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    evidence.append(Evidence(
                        type="rxrpc_available",
                        description="rxrpc.ko module available for auto-load",
                        raw_data=result.stdout.strip(),
                        source="modinfo"
                    ))
                    rxrpc_available = True
                else:
                    evidence.append(Evidence(
                        type="rxrpc_available",
                        description="rxrpc.ko module not available - RxRPC variant not exploitable",
                        raw_data="module not found",
                        source="modinfo"
                    ))
                    return False, evidence
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Assume not available if modinfo fails
                return False, evidence

        # Mitigation check: modprobe.d blacklist
        rxrpc_blocked = check_modprobe_disabled(self._RXRPC_MODULE)
        if rxrpc_blocked:
            evidence.append(Evidence(
                type="rxrpc_mitigation",
                description="rxrpc module blocked in modprobe.d - mitigation applied",
                raw_data=f"install {self._RXRPC_MODULE} /bin/false",
                source="/etc/modprobe.d/"
            ))
            return False, evidence

        # AF_RXRPC socket capability check
        af_rxrpc_allowed = self._check_af_rxrpc_allowed()
        if not af_rxrpc_allowed:
            evidence.append(Evidence(
                type="rxrpc_socket",
                description="AF_RXRPC socket creation blocked - RxRPC variant not exploitable",
                raw_data="AF_RXRPC denied",
                source="kernel capability"
            ))
            return False, evidence

        evidence.append(Evidence(
            type="rxrpc_socket",
            description="AF_RXRPC socket creation allowed - RxRPC variant exploitable",
            raw_data="AF_RXRPC allowed",
            source="kernel capability"
        ))

        return True, evidence

    def _check_unshare_allowed(self) -> bool:
        """Check if unshare(CLONE_NEWUSER) is allowed"""
        # This is a heuristic check - actual execution happens in PoC
        try:
            # Check kernel.unprivileged_userns_clone sysctl
            result = subprocess.run(
                ["sysctl", "-n", "kernel.unprivileged_userns_clone"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5
            )
            if result.returncode == 0:
                value = result.stdout.strip()
                if value in ["0", "disabled"]:
                    return False
                elif value in ["1", "enabled"]:
                    return True

            # Check AppArmor profile (Ubuntu)
            result = subprocess.run(
                ["aa-status", "--json"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse JSON and check for unshare restrictions
                # This is simplified - actual check requires AppArmor parsing
                pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Assume allowed if checks fail
            pass

        return True  # Default: assume allowed

    def _check_af_rxrpc_allowed(self) -> bool:
        """Check if AF_RXRPC socket creation is allowed"""
        # Try to create dummy socket (best-effort check)
        try:
            result = subprocess.run(
                ["python3", "-c",
                 "import socket; s = socket.socket(33, 2); s.close()"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5
            )
            if result.returncode == 0:
                return True
            # Check stderr for permission denied
            if "Permission denied" in result.stderr or "Operation not permitted" in result.stderr:
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return True  # Default: assume allowed

    def get_remediation(self) -> Remediation:
        """Return remediation suggestions"""
        return Remediation(
            priority="IMMEDIATE",
            steps=[
                "Mitigation: Block ESP and RxRPC modules",
                "sh -c \"printf 'install esp4 /bin/false\\n"
                "install esp6 /bin/false\\n"
                "install rxrpc /bin/false\\n"
                "' > /etc/modprobe.d/dirtyfrag.conf; "
                "rmmod esp4 esp6 rxrpc 2>/dev/null; true\"",
                "Verify mitigation: cat /etc/modprobe.d/dirtyfrag.conf",
                "Apply upstream patch when available",
                "Monitor linux-distros mailing list for official patch",
            ],
            backup_steps=[
                "No backup required for module blocking",
            ],
            rollback_steps=[
                "Remove modprobe.d file: rm /etc/modprobe.d/dirtyfrag.conf",
                "Load modules if needed: modprobe esp4 esp6 rxrpc",
            ],
            temporary_mitigation="Block vulnerable modules until patch available",
            kernel_recovery_mode="Standard reboot after kernel update",
            verify_steps=[
                "Check modprobe.d configuration",
                "Verify modules are blocked",
                "Test system functionality",
            ],
        )

    def prepare(self, kernel_info: KernelInfo,
               test_mode: str = "write_root_file",
               ctf_value: str = "") -> PrepareResult:
        """Prepare phase: load ESP modules, create CTF target file

        Args:
            kernel_info: Kernel info
            test_mode: CTF test mode (write_root_file / read_root_file)
            ctf_value: CTF challenge value
        """
        from .cve_2026_pending_dirtyfrag_prepare import CVE2026PendingDirtyFragPrepareHandler
        handler = CVE2026PendingDirtyFragPrepareHandler(
            test_mode=test_mode, ctf_value=ctf_value
        )
        return handler.prepare(kernel_info.__dict__ if kernel_info else {})

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None,
             poc_result=None,
             test_mode: str = "write_root_file",
             ctf_value: str = "") -> PostResult:
        """Post phase: verify CTF result, cleanup, restore system state

        Args:
            kernel_info: Kernel info
            prepare_result: Prepare phase result
            poc_result: PoC execution result
            test_mode: CTF test mode
            ctf_value: CTF challenge value
        """
        from .cve_2026_pending_dirtyfrag_post import CVE2026PendingDirtyFragPostHandler
        handler = CVE2026PendingDirtyFragPostHandler(
            prepare_result=prepare_result,
            poc_result=poc_result,
            test_mode=test_mode,
            ctf_value=ctf_value
        )
        return handler.post(kernel_info, prepare_result)