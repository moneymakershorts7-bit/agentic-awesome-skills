"""Console output formatter for sec-kernel detection results.

Provides structured, readable terminal output including:
- Detection summary banner
- PoC execution statistics (delegated to PoCExecutionStats)
- Vulnerability evidence details
- Failure analysis report
"""
import logging
import os

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
    except Exception:
        pass
    return "unknown"


# sec-kernel version constant (read from VERSION file)
_VERSION = _read_version()


class ConsolePrinter:
    """Formats and prints detection results to terminal."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def print_banner(self, kernel_info, mode: str):
        """Print the header banner with system info."""
        sep = "=" * 62
        print(f"\n{sep}")
        print(f"  sec-kernel v{_VERSION} - Linux Kernel CVE Detection")
        print(sep)
        print(f"  Kernel: {kernel_info.version} ({kernel_info.arch})")
        print(f"  Mode: {mode} (Linux Server)")
        print(f"{sep}\n")

    def print_detection_summary(self, results: list, stats, execution_time: float):
        """Print detection result summary table.

        Args:
            results: List of DetectResult objects
            stats: PoCExecutionStats instance (may be None)
            execution_time: Total orchestrator execution time in seconds
        """
        total = len(results)
        vulnerable = sum(
            1 for r in results
            if r.status == "VULNERABLE" or
               (r.poc_result and r.poc_result.status == "EXPLOITABLE"))
        not_vulnerable = sum(1 for r in results if r.status == "NOT_VULNERABLE")
        uncertain = sum(1 for r in results if r.status == "UNCERTAIN")
        exploitable = stats.poc_exploitable_count if stats else 0

        sep = "=" * 62
        print(sep)
        print("  Detection Summary")
        print(sep)
        print(f"  Total CVEs checked:     {total}")
        print(f"  Vulnerable:             {vulnerable}")
        print(f"  Not Vulnerable:         {not_vulnerable}")
        print(f"  Uncertain:              {uncertain}")
        print(f"  PoC Exploitable:        {exploitable}")
        print(f"  Execution time:         {execution_time:.2f}s")
        print(sep)
        print()

        # Per-CVE status line
        for r in results:
            status_icon = "\U0001f534" if r.status == "VULNERABLE" else "\U0001f7e2"
            poc_info = ""
            if r.poc_result:
                if r.poc_result.status == "EXPLOITABLE":
                    ctf_flag = getattr(r.poc_result, 'ctf_flag', '')
                    if ctf_flag:
                        poc_info = f" [EXPLOITABLE] Flag: {ctf_flag}"
                    else:
                        poc_info = " [EXPLOITABLE]"
                elif r.poc_result.status == "NOT_EXPLOITABLE":
                    poc_info = " [NOT_EXPLOITABLE]"
            print(
                f"  {status_icon} {r.cve_id} ({r.severity}, CVSS "
                f"{r.cvss_score}) - {r.status}{poc_info}"
            )
        print()

    def print_poc_statistics(self, stats):
        """Delegate to PoCExecutionStats.print_summary() and print_detailed_report().

        Args:
            stats: PoCExecutionStats instance
        """
        if stats is None:
            return
        stats.print_summary()
        if self.verbose:
            stats.print_detailed_report()

    def print_vulnerability_details(self, results: list, stats, poc_output_dir: str):
        """Print detailed evidence chain for all VULNERABLE CVEs.

        Shows tree-style evidence chain including:
        - Version match, module/config check, mitigation status
        - PoC execution result or skip reason
        - CTF Flag (if available)

        Args:
            results: Detection results list
            stats: PoCExecutionStats instance
            poc_output_dir: PoC evidence output directory
        """
        vulnerable_results = [
            r for r in results
            if r.status == "VULNERABLE"
        ]
        if not vulnerable_results:
            return

        bar = "=" * 72
        sep = "-" * 72

        print(f"\n{bar}")
        print("  \U0001F6A8 EXPLOITABLE VULNERABILITY DETAILS")
        print(
            f"  {len(vulnerable_results)} CVE(s) detected as VULNERABLE "
            f"with evidence chain below."
        )
        print(bar)

        for idx, r in enumerate(vulnerable_results, 1):
            has_poc_evidence = (
                r.poc_result and self._poc_has_evidence(r.poc_result)
            )
            # Header
            severity_tag = r.severity
            print()
            print(
                f"  {r.cve_id} [{severity_tag}] - {r.description}"
            )

            # --- Tree-style evidence chain ---
            evidence_items = self._build_evidence_tree(r, stats)
            for i, (marker, text) in enumerate(evidence_items):
                if i == len(evidence_items) - 1:
                    print(f"  \u2514\u2500\u2500 {text}")
                else:
                    print(f"  \u251C\u2500\u2500 {text}")

            # If exploitable, show three-phase details in verbose mode
            if has_poc_evidence and self.verbose:
                poc = r.poc_result
                print()
                print("  \u25B6 PoC Three-Phase Verification:")
                self._print_phase_prepare(poc)
                self._print_phase_run(poc)
                self._print_phase_post(poc)

        print()
        print(bar)
        print("  ACTION REQUIRED: Patch the above CVE(s) immediately!")
        print(bar + "\n")

    def _build_evidence_tree(self, result, stats) -> list:
        """Build tree-style evidence chain items for a single CVE result.

        Returns list of (marker, text) tuples for display.
        """
        items = []

        # 1. Detection evidence from detector (version, module, config, mitigation)
        if result.evidence:
            for ev in result.evidence:
                icon = self._evidence_icon(ev.type)
                items.append(
                    ("|", f"{icon} {self._evidence_label(ev.type)}: {ev.description}")
                )
        else:
            # Fallback: show basic detection info
            if result.affected_versions:
                items.append(
                    ("|", f"\u2713 Version match: kernel in affected range {result.affected_versions}")
                )
            if result.detection_method:
                items.append(
                    ("|", f"\u2713 Detection: {result.detection_method}")
                )

        # 2. Mitigation status
        if result.mitigations:
            for m in result.mitigations:
                items.append(("|", f"\u26A0 Mitigation: {m}"))
        elif result.evidence:
            # Check if any evidence is about mitigation
            has_mitigation_ev = any(
                ev.type in ("mitigation_found", "mitigation_absent")
                for ev in result.evidence
            )
            if not has_mitigation_ev:
                items.append(("|", "\u2713 Mitigation: none detected"))

        # 3. PoC status
        has_poc_evidence = (
            result.poc_result and self._poc_has_evidence(result.poc_result)
        )

        if has_poc_evidence:
            poc = result.poc_result
            conclusion = poc.final_conclusion or poc.status or "EXPLOITABLE"
            items.append(
                ("|", f"\u2713 PoC verification: {conclusion} "
                 f"(confidence: {poc.confidence:.0%})")
            )
            # Evidence display based on mode
            evidence_text = getattr(poc, 'evidence_text', '')
            ctf_flag = self._get_ctf_flag(result.cve_id, poc, stats)
            if ctf_flag:
                items.append(("|", f"\U0001F3F4 CTF Flag: {ctf_flag}"))
            if evidence_text and not ctf_flag:
                # UAF or other mode evidence
                items.append(("|", f"\U0001F50D Evidence: {evidence_text}"))
            elif evidence_text and ctf_flag:
                # Both present (unlikely but handle gracefully)
                pass  # CTF flag is sufficient
        elif result.poc_result and not has_poc_evidence:
            # PoC ran but was NOT_EXPLOITABLE or ERROR
            poc = result.poc_result
            conclusion = poc.final_conclusion or poc.status or "UNKNOWN"
            items.append(
                ("|", f"\u26A0 PoC verification: {conclusion}")
            )
        elif result.poc_skip_reason:
            # PoC was not executed - show reason
            items.append(
                ("|", f"\u26A0 PoC status: not executed ({result.poc_skip_reason})")
            )
            # Add suggestion based on reason
            suggestion = self._get_poc_suggestion(result)
            if suggestion:
                items.append(("|", f"\U0001F4A1 Suggestion: {suggestion}"))
        else:
            items.append(("|", "\u26A0 PoC status: not executed (PoC not enabled)"))

        return items

    @staticmethod
    def _evidence_icon(ev_type: str) -> str:
        """Get icon for evidence type."""
        icons = {
            "version_match": "\u2713",
            "module_loaded": "\u2713",
            "config_enabled": "\u2713",
            "mitigation_found": "\u26A0",
            "mitigation_absent": "\u2713",
            "patch_applied": "\u2717",
        }
        return icons.get(ev_type, "\u2713")

    @staticmethod
    def _evidence_label(ev_type: str) -> str:
        """Get human-readable label for evidence type."""
        labels = {
            "version_match": "Version match",
            "module_loaded": "Module check",
            "config_enabled": "Config check",
            "mitigation_found": "Mitigation",
            "mitigation_absent": "Mitigation",
            "patch_applied": "Patch status",
        }
        return labels.get(ev_type, ev_type)

    @staticmethod
    def _get_ctf_flag(cve_id: str, poc_result, stats) -> str:
        """Extract CTF flag from poc_result or stats records."""
        # First try poc_result directly
        if poc_result and poc_result.ctf_flag:
            return poc_result.ctf_flag
        # Then try stats records
        if stats:
            for rec in stats.get_exploitable_records():
                if rec.cve_id == cve_id and rec.ctf_flag:
                    return rec.ctf_flag
        return ""

    @staticmethod
    def _get_poc_suggestion(result) -> str:
        """Generate suggestion for how to run PoC based on skip reason."""
        reason = result.poc_skip_reason
        if not reason:
            return ""
        if "binary missing" in reason or "No PoC binary" in reason:
            return (
                f"Compile PoC: gcc -o poc-bin/{result.cve_id.lower().replace('-', '_')}.elf "
                f"poc-src/{result.cve_id.lower().replace('-', '_')}/exploit.c -static"
            )
        if "timed out" in reason:
            return (
                f"Use --poc-timeout 60 --cve-id {result.cve_id} "
                f"to extend timeout"
            )
        return ""

    def print_failure_analysis(self, stats):
        """Print failure analysis for failed PoCs.

        Args:
            stats: PoCExecutionStats instance
        """
        if stats is None:
            return

        analyses = stats.analyze_failures()
        if not analyses:
            return

        bar = "=" * 62
        inner = "-" * 62

        print(f"\n{bar}")
        print(f"  PoC Failure Analysis ({len(analyses)} issue(s))")
        print(bar)

        for a in analyses:
            impl_tag = " [PoC-IMPL]" if a.is_poc_implementation_issue else ""
            # Box style output
            print(f"\n  {inner}")
            print(f"  {a.cve_id} | {a.failure_type.value}{impl_tag}")
            print(f"  Analysis: {a.root_cause}")
            print(f"  Recommendation: {a.recommendation}")
            print(
                f"  Implementation Issue: "
                f"{'Yes' if a.is_poc_implementation_issue else 'No'}"
            )
            print(f"  {inner}")

        print()

    def print_full_report(self, results: list, stats,
                          kernel_info, mode: str, execution_time: float,
                          poc_output_dir: str = "./workspace"):
        """Print complete formatted output (called from main).

        Args:
            results: List of DetectResult objects
            stats: PoCExecutionStats instance (may be None)
            kernel_info: KernelInfo object
            mode: Run mode string
            execution_time: Total orchestrator execution time
            poc_output_dir: PoC evidence output directory
        """
        self.print_banner(kernel_info, mode)
        self.print_detection_summary(results, stats, execution_time)
        self.print_poc_statistics(stats)

        # Show vulnerability details for all VULNERABLE CVEs
        vulnerable_count = sum(
            1 for r in results
            if r.status == "VULNERABLE" or
               (r.poc_result and r.poc_result.status == "EXPLOITABLE")
        )
        if vulnerable_count > 0:
            self.print_vulnerability_details(results, stats, poc_output_dir)

        if stats and stats.poc_failed_count > 0:
            self.print_failure_analysis(stats)

        # Final warning
        vulnerable_count = sum(
            1 for r in results
            if r.status == "VULNERABLE" or
               (r.poc_result and r.poc_result.status == "EXPLOITABLE")
        )
        if vulnerable_count > 0:
            print(
                f"  WARNING: {vulnerable_count} vulnerable CVE(s) detected!"
                f" See report for details.\n"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _poc_has_evidence(poc_result) -> bool:
        """Return True if PoC produced exploitation evidence."""
        final_conclusion = (
            poc_result.final_conclusion or poc_result.status or ""
        )
        return final_conclusion in ("EXPLOITABLE", "USER_EXPLOITABLE")

    @staticmethod
    def _extract_vuln_markers(stdout: str) -> list:
        """Extract PoC output lines that carry exploitation evidence markers."""
        if not stdout:
            return []
        lines = []
        for raw in stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            if (line.startswith("[VULN]") or
                    line.startswith("POC_RESULT:EXPLOITABLE")):
                lines.append(line)
        return lines

    def _print_phase_prepare(self, poc):
        """Print Phase 1: Prepare details."""
        if poc.prepare is not None:
            prep = poc.prepare
            prep_status = "Success" if prep.success else "Failed"
            print(
                f"    Phase 1 Prepare : {prep_status}  "
                f"({len(prep.operations)} ops, {prep.duration:.2f}s)"
            )
            for op in prep.operations:
                marker = (
                    "\u2713" if op.result == "success" else "\u2717"
                )
                print(
                    f"      {marker} {op.action}: "
                    f"{op.target} -> {op.result}"
                )
                if op.error:
                    print(f"        Error: {op.error}")
        else:
            print("    Phase 1 Prepare : (skipped)")

    def _print_phase_run(self, poc):
        """Print Phase 2: Run details."""
        print(
            f"    Phase 2 Run     : {poc.status} as user {poc.user} "
            f"(UID={poc.uid})  {poc.execution_time:.2f}s"
        )
        vuln_lines = self._extract_vuln_markers(poc.stdout)
        if vuln_lines:
            for line in vuln_lines[:5]:
                print(f"      Output: {line}")
            if len(vuln_lines) > 5:
                print(f"      ... ({len(vuln_lines) - 5} more lines)")

    def _print_phase_post(self, poc):
        """Print Phase 3: Post details."""
        if poc.post is not None:
            post = poc.post
            post_status = "Success" if post.success else "Warnings"
            self_check = (
                "clean" if post.self_check.clean else "issues"
            )
            restored = (
                "restored" if post.global_verify.system_restored
                else "not_restored"
            )
            kernel_clean = (
                "clean" if post.global_verify.kernel_log_clean
                else "dirty"
            )
            print(
                f"    Phase 3 Post    : {post_status}  "
                f"(self-check {self_check}, system {restored}, "
                f"kernel {kernel_clean}, {post.duration:.2f}s)"
            )
            post_warnings = []
            if post.self_check.issues:
                post_warnings.extend(post.self_check.issues)
            if post.global_verify.warnings:
                post_warnings.extend(post.global_verify.warnings)
            for w in post_warnings[:3]:
                print(f"      Warning: {w}")
        else:
            print("    Phase 3 Post    : (skipped)")
