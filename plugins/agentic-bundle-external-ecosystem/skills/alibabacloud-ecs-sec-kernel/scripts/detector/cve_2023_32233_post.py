"""
CVE-2023-32233 Post phase handler

Cleanup PoC execution residuals, verify system state is restored.
Checks for residual netlink sockets, processes, and kernel log anomalies.

UAF mode verification:
- Self-check: verify no residual netlink sockets or processes from spray
- Global verify: rollback module load, check dmesg for nf_tables anomalies
"""
import glob
import logging
import os
import re
import subprocess
from typing import List

from ..poc.phases.post import BasePostHandler
from ..core.result import (
    PrepareResult,
    PoCResult,
    SelfCheckResult,
    GlobalVerifyResult,
)

logger = logging.getLogger(__name__)

# Anomaly keywords in kernel log (nf_tables related)
_KERNEL_ANOMALY_KEYWORDS = [
    "BUG:",
    "WARNING:",
    "Oops:",
    "panic",
    "nf_tables",
    "nft_set",
    "use-after-free",
    "KASAN",
]

_TMP_DIR_PATTERN = "/tmp/sec-kernel-poc-*"


class CVE202332233PostHandler(BasePostHandler):
    """CVE-2023-32233 Post phase: UAF cleanup, socket verification, system recovery"""

    def __init__(self, prepare_result: PrepareResult = None,
                 poc_result: PoCResult = None,
                 timeout: int = 30):
        super().__init__(prepare_result=prepare_result, timeout=timeout)
        self._poc_result = poc_result

    def self_check(self, run_user: str) -> SelfCheckResult:
        """Check for PoC residuals after UAF execution

        Specifically checks for:
        1. Residual temp files
        2. Residual processes
        3. Leaked netlink sockets from spray phase

        Args:
            run_user: Username that ran the PoC

        Returns:
            SelfCheckResult: Self-check result
        """
        issues: List[str] = []

        # 1. Check for residual files in temp directory
        self._check_tmp_residue(issues)

        # 2. Check for residual sec-kernel-poc processes
        self._check_residual_processes(issues)

        # 3. Check for residual netlink sockets (spray cleanup)
        self._check_residual_netlink_sockets(issues)

        clean = len(issues) == 0
        if not clean:
            logger.warning("Self-check found %d issues: %s", len(issues), issues)

        return SelfCheckResult(clean=clean, issues=issues)

    def global_verify(self, prepare_result: PrepareResult) -> GlobalVerifyResult:
        """Rollback, verify UAF result, verify system recovery

        Args:
            prepare_result: Prepare phase result

        Returns:
            GlobalVerifyResult: Global verification result
        """
        warnings: List[str] = []

        # 1. Verify UAF PoC output (spray count and corruption)
        uaf_verified = self._verify_uaf_result()
        if not uaf_verified:
            warnings.append("UAF verification: no corruption detected in PoC output")

        # 2. Execute rollback in reverse order
        self._rollback_operations(prepare_result.operations)

        # 3. Verify netlink socket count is back to baseline
        system_restored = self._verify_netlink_state(prepare_result.state_snapshot)

        # 4. Check dmesg for nf_tables anomalies
        kernel_warnings = self._check_kernel_log()
        warnings.extend(kernel_warnings)
        kernel_log_clean = len(kernel_warnings) == 0

        if not kernel_log_clean:
            logger.warning(
                "Kernel log anomalies found after PoC: %s", kernel_warnings
            )

        return GlobalVerifyResult(
            system_restored=system_restored,
            kernel_log_clean=kernel_log_clean,
            warnings=warnings,
        )

    def _verify_uaf_result(self) -> bool:
        """Verify UAF PoC result from stdout output.

        Parses UAF_SPRAY_COUNT and UAF_CORRUPTED from PoC stdout.

        Returns:
            True if UAF exploitation was detected
        """
        if not self._poc_result or not hasattr(self._poc_result, 'stdout'):
            return False

        stdout = self._poc_result.stdout or ""
        spray_count = 0
        corrupted = 0

        for line in stdout.split("\n"):
            if line.startswith("UAF_SPRAY_COUNT:"):
                try:
                    spray_count = int(line[len("UAF_SPRAY_COUNT:"):].strip())
                except ValueError:
                    pass
            elif line.startswith("UAF_CORRUPTED:"):
                try:
                    corrupted = int(line[len("UAF_CORRUPTED:"):].strip())
                except ValueError:
                    pass

        logger.info(
            "UAF result: spray_count=%d, corrupted=%d",
            spray_count, corrupted
        )

        return corrupted > 0 or spray_count > 0

    def _check_tmp_residue(self, issues: List[str]) -> None:
        """Check for residual files in /tmp/sec-kernel-poc-* directories"""
        try:
            dirs = glob.glob(_TMP_DIR_PATTERN)
            for d in dirs:
                if os.path.isdir(d):
                    contents = os.listdir(d)
                    if contents:
                        issues.append(
                            f"Residual files in {d}: {contents[:5]}"
                        )
                    # Clean empty directories
                    else:
                        try:
                            os.rmdir(d)
                        except OSError:
                            pass
        except OSError as e:
            issues.append(f"Failed to check tmp residue: {e}")

    def _check_residual_processes(self, issues: List[str]) -> None:
        """Check for residual sec-kernel-poc processes"""
        try:
            result = subprocess.run(
                ["ps", "aux"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "sec-kernel-poc" in line and "grep" not in line:
                        issues.append(f"Residual process: {line.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _check_residual_netlink_sockets(self, issues: List[str]) -> None:
        """Check for residual netlink sockets from UAF spray phase.

        Compares current netlink socket count with expected baseline.
        A significant increase indicates spray sockets were not cleaned.
        """
        try:
            # Use ss to check netlink sockets
            result = subprocess.run(
                ["ss", "-f", "netlink", "-a"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Count lines with NETLINK_NETFILTER (protocol 12)
                nf_count = 0
                for line in result.stdout.split("\n"):
                    if "netfilter" in line.lower() or "12" in line:
                        nf_count += 1
                if nf_count > 10:  # Threshold for residual detection
                    issues.append(
                        f"Residual netlink sockets detected: {nf_count} "
                        f"NETLINK_NETFILTER connections (spray leak?)"
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # ss not available, try /proc/net/netlink
            try:
                count = 0
                with open("/proc/net/netlink", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("sk"):
                            continue
                        # Protocol 12 = NETLINK_NETFILTER
                        parts = line.strip().split()
                        if len(parts) >= 3 and parts[2] == "12":
                            count += 1
                if count > 10:
                    issues.append(
                        f"Residual NETLINK_NETFILTER sockets: {count} in /proc/net/netlink"
                    )
            except OSError:
                pass

    def _verify_netlink_state(self, state_snapshot: dict) -> bool:
        """Verify netlink socket count is back to baseline

        Args:
            state_snapshot: Prepare phase state snapshot

        Returns:
            True if system state appears restored
        """
        baseline = state_snapshot.get("netlink_socket_count_before", -1)
        if baseline < 0:
            # Baseline not recorded, assume OK
            return True

        # Count current netlink sockets
        current_count = 0
        try:
            with open("/proc/net/netlink", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("sk"):
                        continue
                    current_count += 1
        except OSError:
            return True  # Cannot verify, assume OK

        # Allow some variance (other system activity)
        if current_count > baseline + 20:
            logger.warning(
                "Netlink socket count increased: before=%d, after=%d (delta=%d)",
                baseline, current_count, current_count - baseline
            )
            return False

        logger.debug(
            "Netlink state OK: before=%d, after=%d",
            baseline, current_count
        )
        return True

    def _check_kernel_log(self) -> List[str]:
        """Check dmesg for nf_tables related anomalies"""
        warnings: List[str] = []

        try:
            result = subprocess.run(
                ["dmesg"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode != 0:
                return warnings

            lines = result.stdout.strip().split("\n")
            # Only check last 50 lines
            tail_lines = lines[-50:] if len(lines) > 50 else lines

            for line in tail_lines:
                has_anomaly = any(kw in line for kw in _KERNEL_ANOMALY_KEYWORDS)
                if has_anomaly:
                    warnings.append(line.strip())
        except subprocess.TimeoutExpired:
            warnings.append("dmesg read timeout")
        except (FileNotFoundError, OSError) as e:
            warnings.append(f"dmesg read failed: {e}")

        return warnings
