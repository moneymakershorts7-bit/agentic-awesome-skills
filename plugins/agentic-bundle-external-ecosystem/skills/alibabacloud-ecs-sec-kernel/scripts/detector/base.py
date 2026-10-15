"""
BaseDetector - CVE Detector Plugin base class

Each new CVE detector only needs to inherit this class and implement required methods.
Supports two modes:
- Version match only (all CVE detectors must implement)
- PoC/Exp verification (optional when C ELF available, supports three-phase verification)
"""
import os
import sys
from typing import Dict, Optional
from ..core.result import DetectResult, PoCResult, Remediation, PrepareResult, PostResult
from ..core.kernel_info import KernelInfo


class BaseDetector:
    """
    CVE Detector Plugin base class

    Subclass must set metadata attributes and implement detect() and get_remediation() methods.
    Detectors with PoC can override run_poc() method.
    """

    # === Metadata (subclass required) ===
    cve_id: str = ""                 # "CVE-2026-31431"
    cvss_score: float = 0.0          # 7.8
    severity: str = ""               # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    description: str = ""            # Vulnerability description
    vuln_type: str = ""              # "local_privilege_escalation" | "remote_code_exec" | ...
    affected_versions: Dict = {}     # Affected kernel version range

    # === PoC/Exp Metadata (required when has PoC) ===
    has_poc: bool = False            # Whether has PoC ELF
    has_exp: bool = False            # Whether has Exp ELF
    poc_bin: str = ""                # PoC Binary relative path ("poc-bin/cve_2026_31431.bin")
    exp_bin: str = ""                # Exp Binary relative path

    def detect(self, kernel_info: KernelInfo) -> DetectResult:
        """
        Execute vulnerability detection - pure read-only operation

        Must implement. Detection logic only contains version match and configuration check,
        does not execute any operation that could impact system stability.

        Args:
            kernel_info: Already collected kernel info

        Returns:
            DetectResult: Detection result (including evidence and remediation suggestions)
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement detect()")

    def _standard_detect_flow(self, kernel_info: KernelInfo) -> DetectResult:
        """Standard detection flow: version check -> PoC trigger on uncertainty.

        Provides a reusable default detect logic for detectors that follow the
        standard pattern of: check version range, return UNCERTAIN if unknown or
        inconclusive to trigger PoC verification.

        Subclasses can override _get_affected_version_range() to supply version
        data, otherwise PoC verification is always triggered.

        Args:
            kernel_info: Already collected kernel info

        Returns:
            DetectResult with appropriate status
        """
        kernel_version = getattr(kernel_info, 'version', '0.0.0')
        affected_range = self._get_affected_version_range()

        if affected_range is None:
            # No version info available - return UNCERTAIN to trigger PoC
            return DetectResult(
                cve_id=self.cve_id,
                status="UNCERTAIN",
                confidence=0.3,
                severity=self.severity,
                cvss_score=self.cvss_score,
                description="Version information unavailable, PoC verification required"
            )

        is_vulnerable = self._check_version_in_range(kernel_version, affected_range)

        if is_vulnerable is True:
            status = "VULNERABLE"
            confidence = 0.7
        elif is_vulnerable is False:
            status = "NOT_VULNERABLE"
            confidence = 0.95
        else:
            # Inconclusive - trigger PoC
            status = "UNCERTAIN"
            confidence = 0.3

        return DetectResult(
            cve_id=self.cve_id,
            status=status,
            confidence=confidence,
            severity=self.severity,
            cvss_score=self.cvss_score
        )

    def _get_affected_version_range(self) -> Optional[Dict]:
        """Return affected version range {min, fixed} or None if unknown.

        Subclasses should override to provide version info.
        Return None to trigger PoC verification.
        """
        return None

    def _check_version_in_range(self, version: str, affected_range: Dict):
        """Check if version is in affected range.

        Returns:
            True: version is in affected range (vulnerable)
            False: version is definitely not affected
            None: inconclusive (trigger PoC)
        """
        if affected_range is None:
            return None

        try:
            from ..utils.version_compare import version_in_range
            min_ver = affected_range.get('min')
            fixed_ver = affected_range.get('fixed')

            if min_ver and fixed_ver:
                return version_in_range(version, min_ver, fixed_version=fixed_ver)
            elif min_ver:
                return version_in_range(version, min_ver)
            else:
                return None  # Inconclusive
        except Exception:
            return None  # Inconclusive, trigger PoC

    def get_remediation(self) -> Remediation:
        """
        Return remediation suggestions (including backup measures)

        Must implement. Remediation suggestions must contain:
        1. Configuration file backup steps
        2. Disk backup suggestion
        3. Kernel recovery mode instructions
        4. Remediation steps
        5. Verification steps
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement get_remediation()")

    def prepare(self, kernel_info: KernelInfo) -> PrepareResult:
        """
        Prepare phase - environment preparation with root privileges.

        Default implementation returns empty success.
        Subclasses should override for CVE-specific preparation.

        Args:
            kernel_info: Kernel info

        Returns:
            PrepareResult with preparation status
        """
        return PrepareResult(
            success=True,
            operations=[],
            state_snapshot={}
        )

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None) -> PostResult:
        """
        Post phase - self-check and global verification.

        Default implementation uses generic PostHandler.
        Subclasses should override for CVE-specific verification.

        Args:
            kernel_info: Kernel info
            prepare_result: Prepare phase result for rollback

        Returns:
            PostResult with verification status
        """
        from ..poc.phases.post import PostHandler

        handler = PostHandler(
            prepare_result=prepare_result,
            timeout=10
        )
        return handler.execute()

    def run_poc(self, kernel_info: KernelInfo, output_dir: str,
                enable_prepare: bool = True,
                enable_post: bool = True,
                poc_user: str = "nobody",
                force_demote: bool = True,
                **kwargs) -> PoCResult:
        """
        Execute PoC verification and exploitability (Support three-phase Verification)

        Optional when has PoC. Default implementation executes via three-phase flow.
        Subclass can override to add pre-check or post-handle.
        Three-phase flow: If subclass PoC verifier provides prepare/post handlers,
        will auto use for three-phase flow.

        Args:
            kernel_info: Already collected kernel info
            output_dir: PoC evidence output directory
            enable_prepare: Whether to enable Prepare phase
            enable_post: Whether to enable Post phase
            poc_user: Run phase execution user
            force_demote: Whether to force privilege drop

        Returns:
            PoCResult: PoC execution result (including three-phase info)
        """
        if not self.has_poc:
            return PoCResult(status="NO_POC", confidence=0.0)

        # Check if there's an associated PoC verifier with three-phase handlers
        verifier = self._get_poc_verifier()
        if verifier is not None:
            return verifier.verify(
                kernel_info, output_dir,
                poc_user=poc_user,
                enable_prepare=enable_prepare,
                enable_post=enable_post,
                force_demote=force_demote,
            )

        from ..poc.phases.conclusion import ConclusionEngine
        from ..poc.elf_loader import FilelessELFLoader

        poc_path = self._resolve_poc_path()
        if not poc_path or not os.path.exists(poc_path):
            return PoCResult(
                status="ERROR",
                error_message=f"PoC binary not found: {poc_path}"
            )

        # Stage 1: Prepare
        prepare_result: Optional[PrepareResult] = None
        if enable_prepare:
            prepare_result = self.prepare(kernel_info)
            if not prepare_result.success:
                # Continue anyway but record failure
                pass

        # Stage 2: Run (with privilege demotion via FilelessELFLoader)
        loader = FilelessELFLoader(poc_path)
        post_result: Optional[PostResult] = None
        try:
            if force_demote and poc_user:
                # Execute as unprivileged user (restores ELF magic + su to user)
                stdout, stderr, rc = loader.execute_as_user(
                    poc_user,
                    args=[],
                    env={"SEC_KERNEL_OUTPUT": output_dir},
                    timeout=10
                )
            else:
                stdout, stderr, rc = loader.load_and_execute(
                    args=[],
                    env={"SEC_KERNEL_OUTPUT": output_dir},
                    timeout=10
                )
            result = self._parse_poc_output(stdout, stderr, rc)
        except Exception as e:
            result = PoCResult(
                status="ERROR",
                error_message=str(e)
            )
        finally:
            # Stage 3: Post - always run to ensure system recovery
            if enable_post:
                post_result = self.post(kernel_info, prepare_result)

        # Calculate final conclusion
        engine = ConclusionEngine()
        conclusion_data = engine.calculate(
            run_status=result.status,
            prepare_result=prepare_result,
            post_result=post_result
        )

        # Enrich result with phase data
        result.prepare = prepare_result
        result.post = post_result
        result.final_conclusion = conclusion_data.get("final_conclusion", "UNKNOWN")
        result.confidence = conclusion_data.get("confidence", 0.0)
        result.user = poc_user

        return result

    def _get_poc_verifier(self):
        """Get associated PoC Verifier, subclass can override to return BasePoCVerifier subclass instance"""
        return None

    def _resolve_poc_path(self) -> str:
        """Resolve PoC binary path, compatible with plain and zipapp mode"""
        poc_filename = f'{self.cve_id.lower().replace("-", "_")}.bin'

        # Strategy 1: Environment variable override (highest priority)
        env_root = os.environ.get('SEC_KERNEL_ROOT')
        if env_root and os.path.isdir(env_root):
            poc_path = os.path.join(env_root, 'poc-bin', poc_filename)
            if os.path.exists(poc_path):
                return poc_path

        # Strategy 2: Walk up from __file__ (plain mode)
        # base.py is at scripts/detector/base.py, walk up to find poc-bin/
        current = os.path.abspath(__file__)
        for _ in range(5):
            parent = os.path.dirname(current)
            candidate = os.path.join(parent, 'poc-bin', poc_filename)
            if os.path.exists(candidate):
                return candidate
            current = parent

        # Strategy 3: Derive from sys.argv[0] (zipapp mode)
        # sys.argv[0] is the main.pyz path, e.g. /path/sec-kernel/scripts/main.pyz
        if sys.argv and sys.argv[0]:
            argv0 = os.path.abspath(sys.argv[0])
            # Walk up from pyz directory
            current = argv0
            for _ in range(3):
                parent = os.path.dirname(current)
                candidate = os.path.join(parent, 'poc-bin', poc_filename)
                if os.path.exists(candidate):
                    return candidate
                current = parent

        # Strategy 4: Search from CWD
        candidate = os.path.join(os.getcwd(), 'poc-bin', poc_filename)
        if os.path.exists(candidate):
            return candidate

        # Fallback: Use legacy poc_bin attribute for backward compatibility
        if self.poc_bin:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            fallback = os.path.join(base_dir, self.poc_bin)
            if os.path.exists(fallback):
                return fallback

        return ""  # Not found

    def _parse_poc_output(self, stdout: str, stderr: str, rc: int) -> PoCResult:
        """Parse C PoC program standard output"""
        result = PoCResult(
            stdout=stdout,
            stderr=stderr,
            returncode=rc,
            status="ERROR"
        )

        if "POC_RESULT:EXPLOITABLE" in stdout:
            result.status = "EXPLOITABLE"
            result.confidence = 0.95
        elif "POC_RESULT:NOT_EXPLOITABLE" in stdout:
            result.status = "NOT_EXPLOITABLE"
            result.confidence = 0.9
        else:
            result.error_message = f"Unexpected PoC output (rc={rc})"

        return result

    @property
    def name(self) -> str:
        """Detector name"""
        return f"{self.cve_id} Detector"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} cve_id={self.cve_id} severity={self.severity}>"
