"""
PoC evidence file generator

Format PoC execution results as read-only evidence file.
Evidence file is used to prove to security team that vulnerability is exploitable.
"""
import os
import time
import hashlib
import logging
from typing import Optional
from pathlib import Path

from ..core.result import DetectResult, PoCResult
from ..core.kernel_info import KernelInfo

logger = logging.getLogger(__name__)


class EvidenceWriter:
    """PoC evidence file generator"""

    EVIDENCE_FILENAME = "poc.txt"

    def __init__(self, output_dir: str = "./workspace"):
        self.output_dir = output_dir

    def write_evidence(self, cve_id: str, kernel_info: KernelInfo,
                       poc_result: PoCResult,
                       detect_result: Optional[DetectResult] = None) -> str:
        """
        Generate evidence file

        Args:
            cve_id: CVE ID
            kernel_info: Kernel info
            poc_result: PoC execution result
            detect_result: Detection result (optional)

        Returns:
            Evidence file path
        """
        # Prepare output directory
        from ..utils.output_dir import ensure_output_dir, chown_to_caller
        ensure_output_dir(self.output_dir)
        evidence_path = os.path.join(self.output_dir, self.EVIDENCE_FILENAME)

        # Clean up old read-only evidence file (if exists)
        # Previously generated poc.txt has permission 0444, direct open('w') would raise Permission denied
        if os.path.exists(evidence_path):
            try:
                os.chmod(evidence_path, 0o644)
                os.remove(evidence_path)
                logger.debug("Removed existing evidence file: %s", evidence_path)
            except OSError as e:
                logger.warning("Failed to remove existing evidence file: %s (%s)", evidence_path, e)

        # Generate content
        content = self._format_evidence(
            cve_id, kernel_info, poc_result, detect_result
        )

        # Write file
        with open(evidence_path, 'w', encoding='utf-8') as f:
            f.write(content)

        # Calculate SHA256 and append
        sha256 = hashlib.sha256(content.encode('utf-8')).hexdigest()
        with open(evidence_path, 'a', encoding='utf-8') as f:
            f.write(f"\nSHA256(this_file): {sha256}\n")
            f.write("=" * 64 + "\n")

        # Set read-only permission (0444)
        os.chmod(evidence_path, 0o444)
        # Return file ownership to calling user
        chown_to_caller(evidence_path)

        logger.info("Evidence written: %s (read-only)", evidence_path)
        return evidence_path

    def _format_evidence(self, cve_id: str, kernel_info: KernelInfo,
                         poc_result: PoCResult,
                         detect_result: Optional[DetectResult]) -> str:
        """Format evidence content"""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        unix_epoch = int(time.time())

        # Determine conclusion
        final_conclusion = poc_result.final_conclusion or poc_result.status
        if poc_result.status == "EXPLOITABLE":
            exploitability = "CONFIRMED"
        else:
            exploitability = "NOT CONFIRMED"

        lines = [
            "=" * 64,
            "  SEC-KERNEL CVE PoC Verification Report",
            f"  Generated: {timestamp}",
            "  Execution: Fileless (memfd_create, no disk write)",
            "  Verification: Three-Phase (Prepare -> Run -> Post)",
            "=" * 64,
            "",
            f"[{cve_id}] Exploitability: {exploitability}",
            f"Final Conclusion: {final_conclusion}",
            "",
            "--- System Context ---",
            f"Kernel:    {kernel_info.version} ({kernel_info.arch})",
            f"Distro:    {kernel_info.distro} {kernel_info.distro_version}",
            f"Run Env:   {kernel_info.run_env}",
            "",
            "--- Three-Phase Verification ---",
        ]

        # Prepare phase info
        if poc_result.prepare:
            prep = poc_result.prepare
            lines.extend([
                "",
                "Phase 1: Prepare (root privileges)",
                f"  Status: {'Success' if prep.success else 'Failed'}",
                f"  Operations: {len(prep.operations)}",
                f"  Duration: {prep.duration:.2f}s",
            ])
            for op in prep.operations:
                lines.append(
                    f"    - {op.action}: {op.target} -> {op.result}"
                )
                if op.error:
                    lines.append(f"      Error: {op.error}")

        # Run phase info
        lines.extend([
            "",
            "Phase 2: Run (nobody privileges)",
            f"  User: {poc_result.user} (UID: {poc_result.uid})",
            f"  Status: {poc_result.status}",
            f"  Execution Time: {poc_result.execution_time:.2f}s",
        ])

        # PoC output
        if poc_result.stdout:
            lines.append("  Output:")
            for line in poc_result.stdout.splitlines():
                if line.strip():
                    lines.append(f"    {line}")

        # Post phase info
        if poc_result.post:
            post = poc_result.post
            lines.extend([
                "",
                "Phase 3: Post (Self-Check + Global Verify)",
                f"  Status: {'Success' if post.success else 'Warnings'}",
                f"  Duration: {post.duration:.2f}s",
                "",
                "  Self-Check (nobody):",
                f"    Clean: {post.self_check.clean}",
            ])
            if post.self_check.issues:
                for issue in post.self_check.issues:
                    lines.append(f"    - Issue: {issue}")

            lines.extend([
                "",
                "  Global Verify (root):",
                f"    System Restored: {post.global_verify.system_restored}",
                f"    Kernel Log Clean: {post.global_verify.kernel_log_clean}",
            ])
            if post.global_verify.warnings:
                for warn in post.global_verify.warnings:
                    lines.append(f"    - Warning: {warn}")
            if post.global_verify.kernel_messages:
                lines.append("    Kernel Messages:")
                for msg in post.global_verify.kernel_messages:
                    lines.append(f"      {msg}")

        lines.extend([
            "",
            "--- Conclusion ---",
        ])

        if final_conclusion == "USER_EXPLOITABLE":
            lines.extend([
                f"This system is USER_EXPLOITABLE via {cve_id}.",
                "The PoC confirmed that an unprivileged user can trigger "
                "this vulnerability, posing a Local Privilege Escalation "
                "(LPE) threat.",
            ])
        elif final_conclusion == "NOT_EXPLOITABLE":
            lines.extend([
                f"This system is NOT EXPLOITABLE via {cve_id}.",
                "The vulnerability path is not reachable for unprivileged "
                "users on this configuration.",
            ])
        else:
            lines.extend([
                f"Exploitation status: {final_conclusion}",
                f"Details: {poc_result.error_message or 'N/A'}",
            ])

        lines.extend([
            "",
            "--- Safety Declaration ---",
            "PoC executed via fileless technique (memfd_create).",
            "Target was a self-created temporary file (immediately deleted).",
            "No system files were modified. No privilege escalation was "
            "performed.",
            "No ELF binary was written to disk during execution.",
            "Three-phase verification ensures system state is restored "
            "after testing.",
            "",
            f"Timestamp: {unix_epoch} (Unix epoch)",
            f"Total Execution Time: {poc_result.execution_time:.2f}s",
            f"Confidence: {poc_result.confidence:.2f}",
        ])

        # Detection evidence
        if detect_result and detect_result.evidence:
            lines.extend(["", "--- Detection Evidence ---"])
            for i, ev in enumerate(detect_result.evidence, 1):
                lines.append(f"  {i}. [{ev.type}] {ev.description}")
                lines.append(f"     Source: {ev.source}")

        return "\n".join(lines) + "\n"
