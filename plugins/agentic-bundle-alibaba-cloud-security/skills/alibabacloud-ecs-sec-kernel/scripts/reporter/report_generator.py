"""
ReportGenerator

Format detection results as Markdown or JSON report.
Contains remediation suggestions and backup measures.
"""
import os
import json
import time
import logging
from typing import List, Optional, Dict

from ..core.result import DetectResult, Evidence, Remediation, PoCResult
from ..core.kernel_info import KernelInfo
from ..core.priority_scorer import (
    score_results, format_priority_table, format_priority_json,
)
from ..utils.output_dir import ensure_output_dir, chown_to_caller

logger = logging.getLogger(__name__)


def _read_version() -> str:
    """Read version from VERSION file in project root."""
    try:
        base_dir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        version_file = os.path.join(base_dir, 'VERSION')
        if os.path.exists(version_file):
            with open(version_file, 'r', encoding='utf-8') as f:
                return f.read().strip()
    except (OSError, IOError):
        pass
    return "unknown"


_VERSION = _read_version()


class ReportGenerator:
    """Detection report generator"""

    def __init__(self, output_dir: str = "./workspace", format: str = "markdown"):
        """
        Args:
            output_dir: Report output directory
            format: Report format ("markdown" | "json")
        """
        self.output_dir = output_dir
        self.format = format

    def generate(self, results: List[DetectResult],
                 kernel_info: KernelInfo,
                 execution_time: float = 0,
                 poc_enabled: bool = False,
                 cve_metadata: dict = None) -> str:
        """
        Generate detection report

        Args:
            results: Detection result list (already sorted by CVSS descending)
            kernel_info: Kernel info
            execution_time: Detection time cost (seconds)
            poc_enabled: Whether PoC verification is enabled
            cve_metadata: Optional CVE metadata for priority scoring

        Returns:
            Report file path
        """
        # Ensure output directory exists with correct permissions
        output_dir = ensure_output_dir(self.output_dir)

        if self.format == "json":
            content = self._generate_json(results, kernel_info, execution_time,
                                          poc_enabled, cve_metadata)
            filename = "sec-kernel-report.json"
        else:
            content = self._generate_markdown(results, kernel_info, execution_time,
                                              poc_enabled, cve_metadata)
            filename = "sec-kernel-report.md"

        filepath = os.path.join(output_dir, filename)
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        except (PermissionError, OSError):
            # File already exists and cannot be overwritten, use timestamped filename
            ts = time.strftime("%Y%m%d_%H%M%S")
            base, ext = os.path.splitext(filename)
            filename = f"{base}_{ts}{ext}"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

        # Transfer file ownership to the calling user
        chown_to_caller(filepath)
        logger.info(f"Report generated: {filepath}")
        return filepath

    def _generate_markdown(self, results: List[DetectResult],
                           kernel_info: KernelInfo,
                           execution_time: float,
                           poc_enabled: bool,
                           cve_metadata: dict = None) -> str:
        """Generate Markdown format report"""
        lines = []
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # header
        lines.append("# Linux Kernel CVE Vulnerability Detection Report")
        lines.append("")
        lines.append(f"> Generated: {timestamp}")
        lines.append(f"> Detection Tool: sec-kernel v{_VERSION}")
        lines.append(f"> Detection Duration: {execution_time:.2f}s")
        lines.append("")

        # System information
        lines.append("## System Information")
        lines.append("")
        lines.append(f"| Item | Value |")
        lines.append(f"|------|-------|")
        lines.append(f"| Kernel Version | {kernel_info.version} |")
        lines.append(f"| Architecture | {kernel_info.arch} |")
        lines.append(f"| Distribution | {kernel_info.distro} {kernel_info.distro_version} |")
        lines.append(f"| Run Environment | {kernel_info.run_env} |")
        lines.append(f"| PoC Verification | {'Enabled' if poc_enabled else 'Disabled'} |")
        lines.append("")

        # Detection Results Summary
        total = len(results)
        exploitable = sum(1 for r in results
                         if r.poc_result and r.poc_result.status == "EXPLOITABLE")
        # vulnerable must include all PoC-confirmed exploitable CVEs
        vulnerable = sum(1 for r in results
                        if r.status == "VULNERABLE" or
                           (r.poc_result and r.poc_result.status == "EXPLOITABLE"))
        not_vuln = sum(1 for r in results if r.status == "NOT_VULNERABLE")
        uncertain = sum(1 for r in results if r.status == "UNCERTAIN")

        lines.append("## Detection Results Summary")
        lines.append("")
        lines.append(f"| Metric | Count |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total CVEs Checked | {total} |")
        lines.append(f"| **Confirmed Vulnerable** | **{vulnerable}** |")
        if exploitable:
            lines.append(f"| **Confirmed Exploitable** | **{exploitable}** |")
        lines.append(f"| Not Affected | {not_vuln} |")
        lines.append(f"| Uncertain | {uncertain} |")
        lines.append("")

        # Severity distribution
        severity_counts: Dict[str, int] = {}
        for r in results:
            if r.status == "VULNERABLE":
                severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
        if severity_counts:
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            severity_str = ", ".join(
                f"{k}: {v}" for k, v in
                sorted(severity_counts.items(),
                       key=lambda x: severity_order.get(x[0], 4)))
            lines.append(f"**Severity Distribution**: {severity_str}")
            lines.append("")

        # Vulnerability Details
        lines.append("## Vulnerability Details (Sorted by Severity Descending)")
        lines.append("")

        for result in results:
            if result.status == "NOT_VULNERABLE":
                continue  # Only show vulnerable entries

            lines.extend(self._format_vuln_detail(result, poc_enabled))
            lines.append("")

        # No vulnerabilities found
        if vulnerable == 0:
            lines.append("**No known vulnerabilities detected.**")
            lines.append("")

        # Priority scoring section
        if vulnerable > 0:
            scored = score_results(results, cve_metadata)
            if scored:
                priority_section = format_priority_table(scored)
                lines.append(priority_section)

        # Comprehensive Remediation
        if vulnerable > 0:
            lines.extend(self._format_remediation_summary(results))

        return "\n".join(lines)

    def _format_vuln_detail(self, result: DetectResult, poc_enabled: bool) -> List[str]:
        """Format single vulnerability detail"""
        lines = []

        # header
        status_icon = "🔴" if result.status == "VULNERABLE" else "🟡"
        lines.append(f"### {status_icon} [{result.severity}] {result.cve_id}")
        lines.append("")

        # Basic info
        lines.append(f"- **CVSS**: {result.cvss_score}")
        lines.append(f"- **Status**: {result.status} (Confidence: {result.confidence*100:.0f}%)")
        if result.vuln_type:
            vuln_type_en = {
                "local_privilege_escalation": "Local Privilege Escalation",
                "remote_code_exec": "Remote Code Execution",
                "information_disclosure": "Information Disclosure",
                "denial_of_service": "Denial of Service",
            }.get(result.vuln_type, result.vuln_type)
            lines.append(f"- **Type**: {vuln_type_en}")
        if result.description:
            lines.append(f"- **Description**: {result.description}")

        # PoC Result
        if result.poc_result:
            poc = result.poc_result
            if poc.status == "EXPLOITABLE":
                lines.append(f"- **Exploitability**: ⚠️ **EXPLOITABLE** (PoC verification passed)")
                ctf_flag = getattr(poc, 'ctf_flag', '')
                evidence_text = getattr(poc, 'evidence_text', '')
                if ctf_flag:
                    lines.append(f"- **CTF Flag Evidence**: `{ctf_flag}`")
                elif evidence_text:
                    lines.append(f"- **Exploitation Evidence**: {evidence_text}")
            elif poc.status == "NOT_EXPLOITABLE":
                lines.append(f"- **Exploitability**: ✅ NOT_EXPLOITABLE (PoC verification failed)")
            if poc.execution_time:
                lines.append(f"- **PoC Execution Time**: {poc.execution_time:.2f}s")

        # Detection Evidence
        if result.evidence:
            lines.append("")
            lines.append("**Detection Evidence:**")
            lines.append("")
            for j, ev in enumerate(result.evidence, 1):
                lines.append(f"  {j}. {ev.description}")
                lines.append(f"     - Source: `{ev.source}`")

        # Remediation
        if result.remediation:
            lines.append("")
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(f"Priority: **{result.remediation.priority}**")
            lines.append("")
            if result.remediation.temporary_mitigation:
                lines.append("Temporary Mitigation:")
                lines.append("```bash")
                lines.append(result.remediation.temporary_mitigation)
                lines.append("```")

        lines.append("")
        lines.append("---")

        return lines

    def _format_remediation_summary(self, results: List[DetectResult]) -> List[str]:
        """Format comprehensive remediation summary"""
        lines = [
            "",
            "## Comprehensive Remediation",
            "",
            "### Pre-Fix Backup Measures (Mandatory)",
            "",
            "```bash",
            "# 1. Backup critical configuration",
            "sudo cp -a /etc /etc.bak.$(date +%Y%m%d)",
            "",
            "# 2. Backup current kernel",
            "sudo cp /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r).bak",
            "sudo cp /boot/initrd.img-$(uname -r) /boot/initrd.img-$(uname -r).bak 2>/dev/null || true",
            "",
            "# 3. Verify GRUB fallback kernel is available",
            "grep -c 'menuentry' /boot/grub/grub.cfg",
            "",
            "# 4. Recommended: Create disk snapshot (LVM environment)",
            "# sudo lvcreate --snapshot --name snap_pre_fix --size 10G /dev/vg0/root",
            "",
            "# 5. Record current system state",
            "uname -a > ~/system_state_backup.txt",
            "cat /proc/cmdline >> ~/system_state_backup.txt",
            "```",
            "",
        ]

        # Per-vulnerability fix steps
        vuln_results = [r for r in results if r.status == "VULNERABLE" and r.remediation]
        if vuln_results:
            lines.append("### Fix Steps")
            lines.append("")
            for result in vuln_results:
                lines.append(f"#### {result.cve_id}")
                lines.append("")
                lines.append("```bash")
                for step in result.remediation.steps:
                    lines.append(step)
                lines.append("```")
                lines.append("")

            # Rollback Plan
            lines.append("### Rollback Plan")
            lines.append("")
            lines.append("If the system becomes unstable after patching:")
            lines.append("")
            lines.append("1. Select the old kernel from GRUB menu at boot time")
            lines.append("2. After booting into old kernel, restore configuration backup")
            lines.append("3. If LVM snapshot exists: `lvconvert --merge /dev/vg0/snap_pre_fix`")
            lines.append("")

        return lines

    def _generate_json(self, results: List[DetectResult],
                       kernel_info: KernelInfo,
                       execution_time: float,
                       poc_enabled: bool,
                       cve_metadata: dict = None) -> str:
        """Generate JSON format report"""
        scored = score_results(results, cve_metadata)

        report = {
            "metadata": {
                "tool": "sec-kernel",
                "version": _VERSION,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "execution_time_sec": round(execution_time, 2),
                "poc_enabled": poc_enabled,
            },
            "system": {
                "kernel_version": kernel_info.version,
                "arch": kernel_info.arch,
                "distro": kernel_info.distro,
                "distro_version": kernel_info.distro_version,
                "run_env": kernel_info.run_env,
            },
            "summary": {
                "total_checked": len(results),
                "vulnerable": sum(
                    1 for r in results
                    if r.status == "VULNERABLE" or
                       (r.poc_result and r.poc_result.status == "EXPLOITABLE")),
                "not_vulnerable": sum(1 for r in results if r.status == "NOT_VULNERABLE"),
                "uncertain": sum(1 for r in results if r.status == "UNCERTAIN"),
                "exploitable": sum(1 for r in results
                                  if r.poc_result and r.poc_result.status == "EXPLOITABLE"),
            },
            "results": [self._result_to_dict(r) for r in results],
            "priority_scoring": format_priority_json(scored),
        }

        return json.dumps(report, indent=2, ensure_ascii=False)

    def _result_to_dict(self, result: DetectResult) -> Dict:
        """Convert DetectResult to dictionary"""
        d = {
            "cve_id": result.cve_id,
            "status": result.status,
            "confidence": result.confidence,
            "severity": result.severity,
            "cvss_score": result.cvss_score,
            "description": result.description,
            "vuln_type": result.vuln_type,
            "evidence": [
                {
                    "type": e.type,
                    "description": e.description,
                    "source": e.source,
                    "raw_data": e.raw_data,
                }
                for e in result.evidence
            ],
        }

        if result.poc_result:
            poc_dict = {
                "status": result.poc_result.status,
                "confidence": result.poc_result.confidence,
                "execution_time": result.poc_result.execution_time,
                "error_message": result.poc_result.error_message,
            }
            ctf_flag = getattr(result.poc_result, 'ctf_flag', '')
            if ctf_flag:
                poc_dict["ctf_flag"] = ctf_flag
            evidence_text = getattr(result.poc_result, 'evidence_text', '')
            if evidence_text:
                poc_dict["evidence"] = evidence_text
            d["poc_result"] = poc_dict

        if result.remediation:
            d["remediation"] = {
                "priority": result.remediation.priority,
                "temporary_mitigation": result.remediation.temporary_mitigation,
                "steps_count": len(result.remediation.steps),
                "backup_steps_count": len(result.remediation.backup_steps),
            }

        return d
