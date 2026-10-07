"""
PoC Execution Statistics Module

Collects, analyzes, and reports PoC execution results across all CVE detectors.
Provides structured failure analysis and formatted summary output.
"""
import time
from enum import Enum
import sys
if sys.version_info < (3, 7):
    from ..thirdparties.dataclasses_backport import dataclass, field
else:
    from dataclasses import dataclass, field
from typing import List


class PoCRunStatus(Enum):
    """PoC execution status categories"""
    SUCCESS_EXPLOITABLE = "SUCCESS_EXPLOITABLE"
    SUCCESS_NOT_EXPLOITABLE = "SUCCESS_NOT_EXPLOITABLE"
    FAILED_TIMEOUT = "FAILED_TIMEOUT"
    FAILED_CRASH = "FAILED_CRASH"
    FAILED_MISSING_BIN = "FAILED_MISSING_BIN"
    FAILED_PERMISSION = "FAILED_PERMISSION"
    FAILED_PARSE_ERROR = "FAILED_PARSE_ERROR"
    SKIPPED_NO_MODULE = "SKIPPED_NO_MODULE"


@dataclass
class PoCRunRecord:
    """Single PoC execution record"""
    cve_id: str
    status: PoCRunStatus
    duration: float = 0.0
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    error_message: str = ""
    poc_mode: str = ""
    ctf_flag: str = ""
    evidence: str = ""


@dataclass
class FailureAnalysis:
    """Analysis result for a failed PoC execution"""
    cve_id: str
    failure_type: PoCRunStatus
    root_cause: str
    recommendation: str
    is_poc_implementation_issue: bool


class PoCExecutionStats:
    """PoC execution statistics collector and analyzer"""

    def __init__(self):
        self.records: List[PoCRunRecord] = []
        self.total_detectors: int = 0
        self.poc_enabled_count: int = 0
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    def start(self):
        """Mark execution start time"""
        self.start_time = time.time()

    def finish(self):
        """Mark execution end time"""
        self.end_time = time.time()

    def record(self, cve_id: str, status: PoCRunStatus,
               duration: float = 0.0, stdout: str = "",
               stderr: str = "", return_code: int = -1,
               error_message: str = "", poc_mode: str = "",
               ctf_flag: str = "",
               evidence: str = ""):
        """Record a single PoC execution result"""
        rec = PoCRunRecord(
            cve_id=cve_id,
            status=status,
            duration=duration,
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
            error_message=error_message,
            poc_mode=poc_mode,
            ctf_flag=ctf_flag,
            evidence=evidence,
        )
        self.records.append(rec)

    @property
    def poc_executed_count(self) -> int:
        """Total number of PoC executions recorded"""
        return len(self.records)

    @property
    def poc_success_count(self) -> int:
        """SUCCESS_EXPLOITABLE + SUCCESS_NOT_EXPLOITABLE"""
        return sum(
            1 for r in self.records
            if r.status in (PoCRunStatus.SUCCESS_EXPLOITABLE,
                            PoCRunStatus.SUCCESS_NOT_EXPLOITABLE)
        )

    @property
    def poc_failed_count(self) -> int:
        """All FAILED_* statuses"""
        return sum(
            1 for r in self.records
            if r.status.value.startswith("FAILED_")
        )

    @property
    def poc_skipped_count(self) -> int:
        """All SKIPPED_* statuses"""
        return sum(
            1 for r in self.records
            if r.status.value.startswith("SKIPPED_")
        )

    @property
    def poc_exploitable_count(self) -> int:
        """Count all exploitable statuses"""
        return sum(
            1 for r in self.records
            if r.status == PoCRunStatus.SUCCESS_EXPLOITABLE
        )

    @property
    def poc_not_exploitable_count(self) -> int:
        """Only SUCCESS_NOT_EXPLOITABLE"""
        return sum(
            1 for r in self.records
            if r.status == PoCRunStatus.SUCCESS_NOT_EXPLOITABLE
        )

    @property
    def execution_time(self) -> float:
        """Total execution time in seconds"""
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return 0.0

    def get_failed_records(self) -> List[PoCRunRecord]:
        """Get all failed PoC records"""
        return [
            r for r in self.records
            if r.status.value.startswith("FAILED_")
        ]

    def get_exploitable_records(self) -> List[PoCRunRecord]:
        """Get all exploitable PoC records"""
        return [
            r for r in self.records
            if r.status == PoCRunStatus.SUCCESS_EXPLOITABLE
        ]

    def analyze_failures(self) -> List[FailureAnalysis]:
        """Analyze failure reasons for all failed PoCs

        Returns a list of FailureAnalysis with root cause and recommendations.
        """
        analyses: List[FailureAnalysis] = []

        for rec in self.get_failed_records():
            root_cause = ""
            recommendation = ""
            is_impl_issue = False

            if rec.status == PoCRunStatus.FAILED_PARSE_ERROR:
                if rec.stdout and "POC_RESULT:" not in rec.stdout:
                    root_cause = (
                        "PoC produced output but missing POC_RESULT: prefix. "
                        "Output protocol violation."
                    )
                    recommendation = (
                        "Update PoC to emit 'POC_RESULT: VULNERABLE' or "
                        "'POC_RESULT: NOT_VULNERABLE' on stdout."
                    )
                    is_impl_issue = True
                else:
                    root_cause = "PoC produced no parseable output."
                    recommendation = (
                        "Check PoC binary execution and ensure stdout is not "
                        "suppressed or redirected."
                    )
                    is_impl_issue = True

            elif rec.status == PoCRunStatus.FAILED_TIMEOUT:
                root_cause = (
                    "PoC execution exceeded timeout. Possible causes: "
                    "kernel already patched causing PoC to block indefinitely, "
                    "or implementation contains infinite loop."
                )
                recommendation = (
                    "Verify PoC has proper timeout handling internally. "
                    "Check if target kernel version is patched."
                )
                is_impl_issue = False

            elif rec.status == PoCRunStatus.FAILED_CRASH:
                if rec.return_code == -9:
                    root_cause = "Process killed by SIGKILL (OOM or external kill)."
                    recommendation = (
                        "Check system memory pressure. Review PoC memory usage."
                    )
                elif rec.return_code == -11:
                    root_cause = (
                        "Segmentation fault (SIGSEGV). PoC triggered kernel "
                        "vulnerability or has memory corruption bug."
                    )
                    recommendation = (
                        "Review PoC for null pointer dereferences. "
                        "Check if exploit offsets match running kernel."
                    )
                else:
                    root_cause = (
                        f"PoC exited with return code {rec.return_code}."
                    )
                    recommendation = (
                        "Check PoC stderr for error details. "
                        "Verify kernel version compatibility."
                    )
                is_impl_issue = rec.return_code not in (-9, -11)

            elif rec.status == PoCRunStatus.FAILED_MISSING_BIN:
                root_cause = "PoC ELF binary not found in poc-bin/ directory."
                recommendation = (
                    "Recompile PoC source: "
                    "gcc -o poc-bin/<cve_id>.elf poc-src/<cve_id>/exploit.c -static"
                )
                is_impl_issue = True

            elif rec.status == PoCRunStatus.FAILED_PERMISSION:
                root_cause = (
                    "Insufficient permissions to execute PoC. "
                    "May require root or specific capabilities (CAP_SYS_ADMIN, "
                    "CAP_NET_ADMIN)."
                )
                recommendation = (
                    "Run with sudo or grant required capabilities. "
                    "Check if Prepare phase sets up proper permissions."
                )
                is_impl_issue = False

            analyses.append(FailureAnalysis(
                cve_id=rec.cve_id,
                failure_type=rec.status,
                root_cause=root_cause,
                recommendation=recommendation,
                is_poc_implementation_issue=is_impl_issue,
            ))

        return analyses

    def _count_by_status(self, status: PoCRunStatus) -> int:
        """Count records with a specific status"""
        return sum(1 for r in self.records if r.status == status)

    def print_summary(self):
        """Print formatted summary to stdout"""
        force_note = ""

        timeout_count = self._count_by_status(PoCRunStatus.FAILED_TIMEOUT)
        crash_count = self._count_by_status(PoCRunStatus.FAILED_CRASH)
        missing_bin_count = self._count_by_status(PoCRunStatus.FAILED_MISSING_BIN)
        parse_error_count = self._count_by_status(PoCRunStatus.FAILED_PARSE_ERROR)
        permission_count = self._count_by_status(PoCRunStatus.FAILED_PERMISSION)
        no_module_count = self._count_by_status(PoCRunStatus.SKIPPED_NO_MODULE)

        sep = "=" * 64
        line = "-" * 60

        lines = [
            sep,
            "  sec-kernel PoC Execution Statistics",
            sep,
            f"  Total Detectors:     {self.total_detectors:<6}(with PoC capability)",
            f"  PoC Executed:        {self.poc_executed_count:<6}{force_note}",
            f"  {line}",
            f"  SUCCESS (ran correctly):     {self.poc_success_count}",
            f"    +- EXPLOITABLE:            {self.poc_exploitable_count:<4}(vulnerability confirmed)",
            f"    +- NOT_EXPLOITABLE:        {self.poc_not_exploitable_count:<4}(kernel patched/mitigated)",
            f"  {line}",
            f"  FAILED (execution error):    {self.poc_failed_count}",
            f"    +- TIMEOUT:                {timeout_count}",
            f"    +- CRASH:                  {crash_count}",
            f"    +- MISSING_BIN:            {missing_bin_count}",
            f"    +- PARSE_ERROR:            {parse_error_count}",
            f"    +- PERMISSION:             {permission_count}",
            f"  {line}",
            f"  SKIPPED:                     {self.poc_skipped_count}",
            f"    +- NO_MODULE:              {no_module_count}",
            f"  {line}",
            f"  Execution Time:         {self.execution_time:.2f}s",
            sep,
        ]
        print("\n".join(lines))

    def print_detailed_report(self):
        """Print detailed per-CVE report"""
        print("=" * 64)
        print("  sec-kernel PoC Detailed Report")
        print("=" * 64)

        # Group by status category
        categories = [
            ("EXPLOITABLE", self.get_exploitable_records()),
            ("FAILED", self.get_failed_records()),
        ]

        for category_name, records in categories:
            if not records:
                continue
            print(f"\n  [{category_name}] ({len(records)} CVE(s))")
            print("  " + "-" * 58)
            for rec in records:
                print(f"    {rec.cve_id}")
                print(f"      Status:      {rec.status.value}")
                print(f"      Duration:    {rec.duration:.2f}s")
                if rec.poc_mode:
                    print(f"      Mode:        {rec.poc_mode}")
                if rec.return_code != -1:
                    print(f"      Return Code: {rec.return_code}")
                if rec.error_message:
                    print(f"      Error:       {rec.error_message}")
                if rec.ctf_flag:
                    print(f"      CTF Flag:    {rec.ctf_flag}")
                if rec.evidence:
                    print(f"      Evidence:    {rec.evidence}")
                print()

        # Print failure analysis
        analyses = self.analyze_failures()
        if analyses:
            print(f"\n  [FAILURE ANALYSIS] ({len(analyses)} issue(s))")
            print("  " + "-" * 58)
            for a in analyses:
                impl_tag = " [PoC-IMPL]" if a.is_poc_implementation_issue else ""
                print(f"    {a.cve_id}{impl_tag}")
                print(f"      Type:           {a.failure_type.value}")
                print(f"      Root Cause:     {a.root_cause}")
                print(f"      Recommendation: {a.recommendation}")
                print()

    def export_json(self) -> dict:
        """Export stats as JSON-serializable dict"""
        return {
            "summary": {
                "total_detectors": self.total_detectors,
                "poc_enabled_count": self.poc_enabled_count,
                "poc_executed": self.poc_executed_count,
                "poc_success": self.poc_success_count,
                "poc_exploitable": self.poc_exploitable_count,
                "poc_not_exploitable": self.poc_not_exploitable_count,
                "poc_failed": self.poc_failed_count,
                "poc_skipped": self.poc_skipped_count,
                "execution_time": round(self.execution_time, 2),
            },
            "records": [
                {
                    "cve_id": r.cve_id,
                    "status": r.status.value,
                    "duration": round(r.duration, 3),
                    "return_code": r.return_code,
                    "stderr": r.stderr,
                    "error_message": r.error_message,
                    "poc_mode": r.poc_mode,
                    "ctf_flag": r.ctf_flag,
                    "evidence": r.evidence,
                }
                for r in self.records
            ],
            "failure_analysis": [
                {
                    "cve_id": a.cve_id,
                    "failure_type": a.failure_type.value,
                    "root_cause": a.root_cause,
                    "recommendation": a.recommendation,
                    "is_poc_implementation_issue": a.is_poc_implementation_issue,
                }
                for a in self.analyze_failures()
            ],
        }
