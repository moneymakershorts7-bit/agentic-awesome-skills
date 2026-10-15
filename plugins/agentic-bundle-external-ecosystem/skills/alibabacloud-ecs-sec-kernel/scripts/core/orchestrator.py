"""Detection Orchestrator - Orchestrate all CVE detector execution flow

Execution flow:
1. Collect kernel info
2. Discover and load all detectors
3. Execute detection sequentially (version info for report reference)
4. Execute PoC verification for all enabled CVEs
5. Sort results by CVSS score descending
6. Generate report
"""
import logging
import os
import re
import subprocess
import time
from datetime import datetime
from typing import List, Optional
from .kernel_info import KernelInfo, KernelInfoCollector
from .result import DetectResult
from .poc_stats import PoCExecutionStats, PoCRunStatus
from ..detector.registry import get_registry
from ..cve_db.loader import CVEDatabase

logger = logging.getLogger(__name__)


class DetectionOrchestrator:
    """Detection orchestrator"""

    def __init__(self, config: dict = None):
        self._config = config or {}
        self._registry = get_registry()
        self._results: List[DetectResult] = []
        self._kernel_info: Optional[KernelInfo] = None
        self._start_time: float = 0
        self._end_time: float = 0
        self.stats: Optional[PoCExecutionStats] = None

    def run(self, poc_output_dir: str = "./workspace",
            cve_id_filter: str = None,
            host_proc: str = "/proc",
            host_boot: str = "/boot",
            poc_enable_prepare: bool = True,
            poc_enable_post: bool = True,
            poc_user: str = "nobody",
            poc_force_demote: bool = True) -> List[DetectResult]:
        """
        Execute complete detection flow

        All enabled CVEs will have PoC executed. The only skip condition is
        enabled: false in kernel_cves.yaml.

        Args:
            poc_output_dir: PoC evidence output directory
            cve_id_filter: Only detect specified CVE
            host_proc: Host /proc path
            host_boot: Host /boot path
            poc_enable_prepare: Whether to enable Prepare phase
            poc_enable_post: Whether to enable Post phase
            poc_user: Run phase execution user
            poc_force_demote: Whether to force privilege drop

        Returns:
            Detection result list sorted by CVSS descending
        """
        self._start_time = time.time()
        self._results = []

        # Initialize statistics
        stats = PoCExecutionStats()

        # Step 1: Collect kernel info
        logger.info("Collecting kernel information...")
        collector = KernelInfoCollector(host_proc=host_proc, host_boot=host_boot)
        self._kernel_info = collector.collect()
        logger.info(f"Kernel: {self._kernel_info.version} ({self._kernel_info.arch})")

        # Step 2: Get detectors
        detectors = self._registry.get_all()
        if cve_id_filter:
            detector = self._registry.get_by_cve_id(cve_id_filter)
            detectors = [detector] if detector else []
            if not detectors:
                logger.warning(f"Detector for {cve_id_filter} not found")

        logger.info(f"Running {len(detectors)} detector(s)...")

        # Record stats totals
        stats.total_detectors = len(detectors)
        stats.poc_enabled_count = sum(1 for d in detectors if d.has_poc)
        stats.start()

        # Step 3: Execute detection (respect YAML enabled switch)
        for detector in detectors:
            # Check enabled flag in YAML database (covers all detector types)
            cve_entry = CVEDatabase.get(detector.cve_id, enabled_only=False)
            is_disabled_in_db = cve_entry and not cve_entry.get('enabled', True)

            if is_disabled_in_db:
                logger.debug(f"Skipping disabled detector: {detector.cve_id}")
                continue

            try:
                logger.debug(f"Running detector: {detector.cve_id}")
                result = detector.detect(self._kernel_info)

                # Step 4: PoC Verification (all enabled CVEs with PoC)
                should_run = self._should_run_poc(detector)

                if should_run:
                    logger.info(
                        f"Running PoC for {detector.cve_id} "
                        f"(detector status: {result.status})...")

                    try:
                        # Prepare: Initialize PoC log before execution
                        # This ensures every PoC attempt has a log from start
                        self._init_poc_log(
                            detector, poc_output_dir)

                        poc_result = detector.run_poc(
                            self._kernel_info, poc_output_dir,
                            enable_prepare=poc_enable_prepare,
                            enable_post=poc_enable_post,
                            poc_user=poc_user,
                            force_demote=poc_force_demote,
                        )
                        result.poc_result = poc_result

                        # Append conclusion to log (covers short-circuit paths
                        # where binary was not executed)
                        self._append_poc_log_conclusion(
                            detector, poc_result, poc_output_dir)

                        # Evaluate final conclusion for status update
                        # (may downgrade poc_result if evidence is insufficient)
                        self._update_result_from_poc(
                            result, poc_result, detector, poc_output_dir)

                        # Record PoC execution to stats AFTER downgrade
                        # so stats reflect the final verdict
                        self._record_poc_result(
                            stats, detector, poc_result)

                    except FileNotFoundError as e:
                        logger.error(
                            f"PoC binary not found for {detector.cve_id}: {e}")
                        stats.record(
                            cve_id=detector.cve_id,
                            status=PoCRunStatus.FAILED_MISSING_BIN,
                            error_message=str(e),
                            poc_mode=getattr(detector, 'poc_mode', ''),
                        )
                        result.poc_skip_reason = (
                            f"PoC binary missing: {e}"
                        )
                    except PermissionError as e:
                        logger.error(
                            f"Permission denied for {detector.cve_id}: {e}")
                        stats.record(
                            cve_id=detector.cve_id,
                            status=PoCRunStatus.FAILED_PERMISSION,
                            error_message=str(e),
                            poc_mode=getattr(detector, 'poc_mode', ''),
                        )
                        result.poc_skip_reason = (
                            f"Permission denied: {e}"
                        )
                    except subprocess.TimeoutExpired as e:
                        logger.error(
                            f"PoC timed out for {detector.cve_id}: {e}")
                        stats.record(
                            cve_id=detector.cve_id,
                            status=PoCRunStatus.FAILED_TIMEOUT,
                            error_message=str(e),
                            poc_mode=getattr(detector, 'poc_mode', ''),
                        )
                        result.poc_skip_reason = (
                            "PoC execution timed out (30s limit)"
                        )
                    except Exception as e:
                        logger.error(
                            f"PoC execution failed for {detector.cve_id}: {e}")
                        stats.record(
                            cve_id=detector.cve_id,
                            status=PoCRunStatus.FAILED_CRASH,
                            error_message=str(e),
                            poc_mode=getattr(detector, 'poc_mode', ''),
                        )
                        result.poc_skip_reason = (
                            f"PoC execution error: {e}"
                        )

                # Record PoC skip reason for CVEs where PoC was not attempted
                if not should_run and not result.poc_skip_reason:
                    if not detector.has_poc:
                        result.poc_skip_reason = (
                            "No PoC binary available for this CVE"
                        )

                self._results.append(result)
            except Exception as e:
                logger.error(f"Detector {detector.cve_id} failed: {e}")
                # Single detector failure doesn't affect other executions
                self._results.append(DetectResult(
                    cve_id=detector.cve_id,
                    status="UNCERTAIN",
                    confidence=0.0,
                    severity=detector.severity,
                    cvss_score=detector.cvss_score,
                    description=f"Detection failed: {e}"
                ))

        # Step 5: Sort by CVSS descending
        self._results.sort(key=lambda r: (-r.cvss_score, r.cve_id))

        self._end_time = time.time()
        stats.finish()
        self.stats = stats

        logger.info(
            f"Detection complete: {len(self._results)} result(s) "
            f"in {self._end_time - self._start_time:.2f}s")

        return self._results

    def _should_run_poc(self, detector) -> bool:
        """Determine if PoC should be executed for this detector.

        All enabled CVEs with PoC capability will run PoC.
        The only skip condition is enabled: false in kernel_cves.yaml
        (handled earlier in the loop).
        """
        return detector.has_poc

    def _init_poc_log(self, detector, poc_output_dir: str):
        """Initialize PoC log file at Prepare stage (before PoC execution).

        Creates the log file and records initial conditions: kernel version,
        CVE metadata, and execution prerequisites. This ensures every PoC
        attempt has a log from the very start of its lifecycle.

        Args:
            detector: The CVE detector instance
            poc_output_dir: Workspace directory for PoC output
        """
        workspace_dir = os.path.abspath(poc_output_dir)
        log_file = os.path.join(workspace_dir, f"poc-{detector.cve_id}.log")

        try:
            os.makedirs(workspace_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Collect pre-conditions
            kernel_ver = self._kernel_info.version if self._kernel_info else "unknown"
            kernel_arch = self._kernel_info.arch if self._kernel_info else "unknown"
            min_ver = getattr(detector, '_MIN_VERSION', 'N/A')
            fixed_ver = getattr(detector, '_FIXED_VERSION', 'N/A')
            has_poc = getattr(detector, 'has_poc', False)
            poc_bin = getattr(detector, 'poc_bin', 'N/A')
            severity = getattr(detector, 'severity', 'N/A')
            cvss = getattr(detector, 'cvss_score', 0.0)

            lines = [
                f"[{ts}] === {detector.cve_id} PoC Verification Log ===",
                f"[{ts}] [Prepare] Log initialized by framework",
                f"[{ts}] [Prepare] Kernel: {kernel_ver} ({kernel_arch})",
                f"[{ts}] [Prepare] Affected range: [{min_ver}, {fixed_ver})",
                f"[{ts}] [Prepare] Severity: {severity} (CVSS {cvss})",
                f"[{ts}] [Prepare] PoC binary: {poc_bin} (available={has_poc})",
                f"[{ts}] [Prepare] Checking execution prerequisites...",
                "",
            ]

            with open(log_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))

            # Make writable by nobody for binary append
            os.chmod(log_file, 0o666)

            logger.debug("Initialized PoC log: %s", log_file)
        except OSError as e:
            logger.warning(
                "Failed to initialize PoC log for %s: %s",
                detector.cve_id, e
            )

    def _append_poc_log_conclusion(self, detector, poc_result,
                                   poc_output_dir: str):
        """Append PoC conclusion to log file after execution completes.

        This covers cases where the detector's run_poc() short-circuits
        (e.g., version precheck fails) without executing the binary.
        The binary's own output (if executed) is already in the log.

        Args:
            detector: The CVE detector instance
            poc_result: The PoCResult from run_poc()
            poc_output_dir: Workspace directory for PoC output
        """
        workspace_dir = os.path.abspath(poc_output_dir)
        log_file = os.path.join(workspace_dir, f"poc-{detector.cve_id}.log")

        if not os.path.exists(log_file):
            return

        try:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conclusion = getattr(poc_result, 'final_conclusion', '') or poc_result.status
            error_msg = getattr(poc_result, 'error_message', '') or ''
            exec_time = getattr(poc_result, 'execution_time', 0.0)

            lines = [
                f"[{ts}] [Conclusion] Status: {conclusion}",
            ]
            if error_msg:
                lines.append(f"[{ts}] [Conclusion] Detail: {error_msg}")
            if exec_time > 0:
                lines.append(
                    f"[{ts}] [Conclusion] Execution time: {exec_time:.3f}s")
            lines.append("")

            with open(log_file, 'a', encoding='utf-8') as f:
                f.write('\n'.join(lines))
        except OSError as e:
            logger.warning(
                "Failed to append conclusion to PoC log for %s: %s",
                detector.cve_id, e
            )


    def _record_poc_result(self, stats: PoCExecutionStats, detector,
                           poc_result):
        """Convert PoC result to stats record"""
        final_conclusion = poc_result.final_conclusion or poc_result.status

        # Map PoC conclusion to PoCRunStatus
        if final_conclusion in ("EXPLOITABLE", "USER_EXPLOITABLE"):
            status = PoCRunStatus.SUCCESS_EXPLOITABLE
        elif final_conclusion == "NOT_EXPLOITABLE":
            status = PoCRunStatus.SUCCESS_NOT_EXPLOITABLE
        elif final_conclusion in ("ERROR", "POC_ERROR"):
            # Distinguish error subcategories
            status = self._classify_poc_error(poc_result)
        else:
            # Unknown conclusion -> treat as not exploitable
            status = PoCRunStatus.SUCCESS_NOT_EXPLOITABLE

        stats.record(
            cve_id=detector.cve_id,
            status=status,
            duration=getattr(poc_result, 'execution_time', 0.0),
            stdout=getattr(poc_result, 'stdout', ''),
            stderr=getattr(poc_result, 'stderr', ''),
            return_code=getattr(poc_result, 'returncode', -1),
            error_message=getattr(poc_result, 'error_message', ''),
            poc_mode=getattr(detector, 'poc_mode', ''),
            ctf_flag=getattr(poc_result, 'ctf_flag', ''),
            evidence=getattr(poc_result, 'evidence_file', ''),
        )

    def _classify_poc_error(self, poc_result) -> PoCRunStatus:
        """Classify a PoC error into a specific failure status"""
        error_msg = getattr(poc_result, 'error_message', '') or ''
        error_lower = error_msg.lower()

        if 'timeout' in error_lower or 'timed out' in error_lower:
            return PoCRunStatus.FAILED_TIMEOUT
        if 'not found' in error_lower or 'no such file' in error_lower:
            return PoCRunStatus.FAILED_MISSING_BIN
        if 'permission' in error_lower or 'denied' in error_lower:
            return PoCRunStatus.FAILED_PERMISSION

        rc = getattr(poc_result, 'returncode', -1)
        if rc in (-9, -11):
            return PoCRunStatus.FAILED_CRASH

        # Check for parse error (output present but no valid result marker)
        stdout = getattr(poc_result, 'stdout', '') or ''
        if stdout and 'POC_RESULT:' not in stdout:
            return PoCRunStatus.FAILED_PARSE_ERROR

        return PoCRunStatus.FAILED_CRASH

    def _update_result_from_poc(self, result, poc_result, detector,
                                poc_output_dir: str):
        """Update detection result based on PoC execution outcome.

        Enforces evidence requirements:
        - write_root_file/read_root_file: Must have CTF flag
        - uaf: Must have UAF evidence in stdout
        No evidence = no EXPLOITABLE verdict.
        """
        final_conclusion = poc_result.final_conclusion or poc_result.status

        # Also check poc_result.status directly as fallback for exploitability
        is_exploitable = (
            final_conclusion in ("EXPLOITABLE", "USER_EXPLOITABLE") or
            poc_result.status in ("EXPLOITABLE", "USER_EXPLOITABLE")
        )

        if is_exploitable:
            # --- Evidence validation gate ---
            poc_mode = getattr(detector, 'poc_mode', '')
            downgrade = False
            downgrade_reason = ""

            # Universal: CTF_FAIL always means not exploitable
            if "CTF_FAIL:" in (poc_result.stdout or ""):
                downgrade = True
                downgrade_reason = "PoC explicitly reported failure via CTF_FAIL"

            if not downgrade and poc_mode in ("write_root_file", "read_root_file"):
                # Must have CTF flag as evidence
                if not poc_result.ctf_flag:
                    downgrade = True
                    downgrade_reason = (
                        f"{poc_mode} mode requires CTF flag evidence, "
                        f"but none was provided"
                    )
                else:
                    # CTF flag consistency validation: output must match challenge
                    ctf_challenge = getattr(poc_result, 'ctf_challenge', '')
                    if ctf_challenge:
                        challenge_inner = self._extract_flag_inner(ctf_challenge)
                        result_inner = self._extract_flag_inner(poc_result.ctf_flag)
                        if (challenge_inner and result_inner and
                                challenge_inner != result_inner):
                            downgrade = True
                            downgrade_reason = (
                                "CTF flag mismatch: PoC output does not match "
                                "framework challenge value "
                                "(possible hardcoded/fake flag)"
                            )
                    if not downgrade:
                        poc_result.evidence_text = (
                            f"CTF Flag: {poc_result.ctf_flag}"
                        )
            elif not downgrade and poc_mode == "uaf":
                # Must have UAF evidence in stdout
                from ..poc.safe_executor import extract_uaf_evidence
                uaf_evidence = extract_uaf_evidence(poc_result.stdout)
                if not uaf_evidence:
                    downgrade = True
                    downgrade_reason = (
                        "UAF mode requires exploitation evidence in "
                        "PoC output, but none was found"
                    )
                else:
                    poc_result.evidence_text = uaf_evidence
            else:
                # Unknown mode - if CTF flag present, use it; otherwise stdout
                if poc_result.ctf_flag:
                    poc_result.evidence_text = (
                        f"CTF Flag: {poc_result.ctf_flag}"
                    )
                else:
                    from ..poc.safe_executor import extract_uaf_evidence
                    evidence = extract_uaf_evidence(poc_result.stdout)
                    if evidence:
                        poc_result.evidence_text = evidence

            if downgrade:
                # Downgrade both PoC verdict AND detection result
                # For kernel CVE detection, accuracy is paramount:
                # If PoC cannot confirm exploitation, do not report as vulnerable
                logger.info(
                    "%s: PoC verdict downgraded to NOT_EXPLOITABLE - %s. "
                    "Detection result also downgraded (high-accuracy mode).",
                    detector.cve_id, downgrade_reason,
                )
                poc_result.status = "NOT_EXPLOITABLE"
                poc_result.confidence = 0.0
                poc_result.error_message = downgrade_reason
                poc_result.final_conclusion = "NOT_EXPLOITABLE"
                # Also downgrade detection result - only report confirmed exploitable CVEs
                result.status = "NOT_VULNERABLE"
                result.confidence = 0.0
                return

            # PoC confirmed exploitable with valid evidence
            result.status = "VULNERABLE"
            result.confidence = max(result.confidence, 0.95)
            # Escalate severity: confirmed exploitation = CRITICAL risk
            result.severity = "CRITICAL"
            # Generate PoC evidence file
            from ..poc.evidence_writer import EvidenceWriter
            evidence_writer = EvidenceWriter(output_dir=poc_output_dir)
            evidence_path = evidence_writer.write_evidence(
                cve_id=detector.cve_id,
                kernel_info=self._kernel_info,
                poc_result=poc_result,
                detect_result=result
            )
            result.poc_result.evidence_file = evidence_path
            logger.info(f"PoC evidence file: {evidence_path}")

        elif final_conclusion in ("NOT_EXPLOITABLE",):
            # PoC confirmed not exploitable -> downgrade to NOT_VULNERABLE
            logger.info(
                "%s: PoC confirmed NOT_EXPLOITABLE, setting "
                "status to NOT_VULNERABLE (PoC is gold standard)",
                detector.cve_id,
            )
            result.status = "NOT_VULNERABLE"
            result.confidence = max(
                result.confidence, poc_result.confidence
            )

        elif (poc_result.confidence == 0.0 and
              final_conclusion in ("ERROR", "POC_ERROR")):
            # PoC could not verify exploitability - avoid false positive
            logger.warning(
                "%s: PoC errored with confidence=0 (%s), "
                "setting status to NOT_VULNERABLE to avoid "
                "false positive",
                detector.cve_id, final_conclusion,
            )
            result.status = "NOT_VULNERABLE"
            result.confidence = 0.0

        elif final_conclusion in ("UNKNOWN",):
            # PoC result inconclusive -> keep UNCERTAIN
            logger.debug(
                "%s: PoC result inconclusive, keeping UNCERTAIN",
                detector.cve_id,
            )
            result.status = "UNCERTAIN"
            result.confidence = max(result.confidence, 0.3)

    @property
    def kernel_info(self) -> Optional[KernelInfo]:
        """Get collected kernel info"""
        return self._kernel_info

    @property
    def execution_time(self) -> float:
        """Get execution time (seconds)"""
        if self._end_time and self._start_time:
            return self._end_time - self._start_time
        return 0

    @staticmethod
    def _extract_flag_inner(flag_str: str) -> str:
        """Extract inner value from CTF flag string (content inside {}).

        Only compares content inside braces to tolerate page cache
        pollution residual outside the braces.

        Args:
            flag_str: Flag string like 'ctf{a3f8b2c1}' or with trailing residue

        Returns:
            Inner value string, or empty string if not found
        """
        match = re.search(r'\{([^}]+)\}', flag_str)
        return match.group(1) if match else ""
