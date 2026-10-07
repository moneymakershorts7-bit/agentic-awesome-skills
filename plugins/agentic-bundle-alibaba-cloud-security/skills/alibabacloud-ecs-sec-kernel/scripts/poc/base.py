"""
BasePoCVerifier - PoC verifier base class

Provide base class for CVEs requiring custom PoC Orchestration Logic.
Supports CTF three-phase verification: Prepare -> Run -> Post

CTF mode: Python framework generates CTF challenge (creates root file,
generates write_value), then verifies PoC completed the challenge.
"""
import os
import secrets
import logging
from typing import Optional, Dict

from ..core.result import PoCResult, PrepareResult, PostResult
from ..core.kernel_info import KernelInfo
from .safe_executor import SafePoCExecutor
logger = logging.getLogger(__name__)


class BasePoCVerifier:
    """
    PoC verifier base class with CTF mode support

    CTF three-phase verification:
    1. Prepare (root): Create CTF challenge environment
    2. Run (nobody): Execute PoC ELF with CLI args
    3. Post (root): Verify CTF result + cleanup

    Subclass can override to add:
    - Pre-condition Check
    - Custom CTF parameters
    - Prepare/Post phase Handler (three-phase Verification)
    """

    cve_id: str = ""
    poc_bin: str = ""
    timeout: int = 10
    test_modes: list = None  # Available test modes from cve_db.yaml
    retry_count: int = 3

    def get_prepare_handler(self):
        """Return Prepare phase handler, Default None (skip Prepare)"""
        return None

    def get_post_handler(self):
        """Return Post phase handler, Default None (skip Post)"""
        return None

    def verify(self, kernel_info: KernelInfo,
               output_dir: str = "workspace",
               enable_prepare: bool = True,
               enable_post: bool = True,
               poc_user: str = "nobody",
               force_demote: bool = True,
               test_mode: str = None,
               **kwargs) -> PoCResult:
        """
        Execute CTF three-phase PoC verification

        CTF flow:
        1. Prepare (root): Create CTF challenge environment
        2. Run (nobody): Execute PoC ELF with CLI args
        3. Post (root): Verify CTF result + cleanup

        Args:
            kernel_info: Kernel info
            output_dir: Evidence output directory
            enable_prepare: Whether to enable Prepare phase
            enable_post: Whether to enable Post phase
            poc_user: Run phase execution user
            force_demote: Whether to force privilege drop
            test_mode: CTF test mode override (None = use default from config)

        Returns:
            PoCResult: PoC execution result (inclusive three-phase info)
        """
        # Determine test mode (from parameter or config)
        if test_mode is None:
            test_mode = self._get_default_test_mode()

        # Generate CTF challenge value
        ctf_value = self._generate_ctf_value()
        logger.info("CTF challenge: mode=%s, value=%s...", test_mode, ctf_value[:12])

        prepare_result: Optional[PrepareResult] = None

        # Stage 1: Prepare (root privileges)
        if enable_prepare:
            prepare_result = self.prepare(
                kernel_info, test_mode=test_mode, ctf_value=ctf_value
            )
            if not prepare_result.success:
                logger.warning(
                    "Prepare phase failed for %s", self.cve_id
                )
                # Continue to Run phase anyway, but record the failure

        # Ensure workspace directory is writable by nobody (Run phase)
        workspace_dir = self._get_workspace_dir()
        os.makedirs(workspace_dir, exist_ok=True)
        os.chmod(workspace_dir, 0o777)

        # Stage 2: Run (nobody privileges)
        poc_path = self._resolve_path()
        if not poc_path:
            result = PoCResult(
                status="ERROR",
                error_message=f"PoC binary not found: {self.poc_bin}"
            )
            return self._wrap_with_phases(
                result, prepare_result, None
            )

        executor = SafePoCExecutor(
            poc_bin_path=poc_path,
            output_dir=output_dir,
            timeout=self.timeout
        )

        # Determine root_file from prepare result
        root_file = ""
        if prepare_result and prepare_result.state_snapshot:
            root_file = prepare_result.state_snapshot.get("target_file", "")

        log_file = self._get_log_path()

        # Execute with CTF parameters
        result = executor.execute(
            test_mode=test_mode,
            root_file=root_file,
            write_value=ctf_value if test_mode == "write_root_file" else "",
            log_file=log_file,
            poc_user=poc_user,
            retry_count=self._get_retry_count(),
            env_extra=self.get_extra_env(kernel_info),
            force_demote=force_demote,
        )

        # Stage 3: Post (self-check + global verify + CTF verification)
        post_result: Optional[PostResult] = None
        if enable_post:
            post_result = self.post(
                kernel_info, prepare_result, result,
                test_mode=test_mode, ctf_value=ctf_value
            )

        # Calculate final conclusion (CTF-aware)
        final_conclusion = self._compute_conclusion(
            result, post_result, test_mode, ctf_value
        )

        # Enrich result with phase data
        result = self._wrap_with_phases(
            result, prepare_result, post_result,
            final_conclusion=final_conclusion
        )

        # Post-process
        result = self.post_process(result, kernel_info)

        # Store CTF challenge value on result for downstream consistency validation
        result.ctf_challenge = ctf_value

        return result

    def prepare(self, kernel_info: KernelInfo,
                test_mode: str = "write_root_file",
                ctf_value: str = "") -> PrepareResult:
        """
        Prepare phase - environment preparation with root privileges.

        Default implementation returns empty success.
        Subclasses should override for CVE-specific preparation.

        Args:
            kernel_info: Kernel info
            test_mode: CTF test mode
            ctf_value: CTF challenge value

        Returns:
            PrepareResult with preparation status
        """
        # Default: no preparation needed
        return PrepareResult(
            success=True,
            operations=[],
            state_snapshot={}
        )

    def post(self, kernel_info: KernelInfo,
             prepare_result: Optional[PrepareResult] = None,
             poc_result: Optional[PoCResult] = None,
             test_mode: str = "write_root_file",
             ctf_value: str = "") -> PostResult:
        """
        Post phase - self-check, CTF verification, and global verification.

        Default implementation uses generic PostHandler.
        Subclasses should override for CVE-specific verification.

        Args:
            kernel_info: Kernel info
            prepare_result: Prepare phase result for rollback
            poc_result: PoC execution result for CTF verification
            test_mode: CTF test mode
            ctf_value: CTF challenge value for verification

        Returns:
            PostResult with verification status
        """
        from .phases.post import PostHandler

        handler = PostHandler(
            prepare_result=prepare_result,
            timeout=self.timeout
        )
        return handler.execute()

    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Pre-condition Check

        Returns:
            None: Pre-check passed, continue execution
            PoCResult: Pre-check failed, return this result directly
        """
        return None

    def get_extra_env(self, kernel_info: KernelInfo) -> Dict[str, str]:
        """Get additional environment variables (backward compatibility)"""
        return {}

    def post_process(self, result: PoCResult,
                     kernel_info: KernelInfo) -> PoCResult:
        """Post-process result after all phases complete"""
        return result

    # --- CTF Helper Methods ---

    def _generate_ctf_value(self) -> str:
        """Generate CTF challenge value: ctf{8-byte random hex}

        Returns:
            Random CTF value string (e.g. "ctf{a1b2c3d4e5f6a7b8}")
        """
        return f"ctf{{{secrets.token_hex(8)}}}"

    def _get_default_test_mode(self) -> str:
        """Get default test mode from config (first available mode)

        Returns:
            Default test mode string
        """
        modes = self.test_modes or ['write_root_file']
        return modes[0] if modes else 'write_root_file'

    def _get_retry_count(self) -> int:
        """Get retry count for PoC execution

        Returns:
            Retry count integer
        """
        return self.retry_count if self.retry_count else 3

    def _get_log_path(self) -> str:
        """Generate PoC log path: workspace/poc-{CVE}.log

        Returns:
            Log file path string
        """
        workspace = self._get_workspace_dir()
        return os.path.join(workspace, f"poc-{self.cve_id}.log")

    def _get_workspace_dir(self) -> str:
        """Get workspace directory"""
        return os.path.abspath("workspace")

    def _compute_conclusion(self, result: PoCResult,
                            post_result: Optional[PostResult],
                            test_mode: str, ctf_value: str) -> str:
        """
        CTF verification logic to compute final conclusion

        Verification depends on test_mode:
        - read_root_file: PoC output CTF_FLAG == root file actual content
        - write_root_file: root file current content == ctf_value

        Args:
            result: PoC execution result
            post_result: Post phase result
            test_mode: CTF test mode
            ctf_value: Expected CTF value

        Returns:
            Final conclusion string
        """
        if result.status != "EXPLOITABLE":
            return "NOT_EXPLOITABLE"

        # Post phase validates CTF result
        if post_result and post_result.success:
            return "USER_EXPLOITABLE"

        # PoC reported EXPLOITABLE but post verification failed.
        # If CTF flag evidence exists in stdout, still consider EXPLOITABLE.
        if result.ctf_flag:
            return "EXPLOITABLE"

        return "NOT_EXPLOITABLE"

    def _resolve_path(self) -> str:
        """Resolve PoC binary absolute path

        Supports two run modes:
        - plain: __file__ as normal .py path, go up 3 levels to project root
        - zipapp: __file__ includes .pyz, extract .pyz path then up 1 level
        """
        abs_file = os.path.abspath(__file__)

        if '.pyz' in abs_file:
            # zipapp mode
            pyz_path = abs_file[:abs_file.index('.pyz') + 4]
            base = os.path.dirname(os.path.dirname(pyz_path))
        else:
            # plain mode: __file__ = .../scripts/poc/base.py -> up 3 levels
            base = os.path.dirname(
                os.path.dirname(
                    os.path.dirname(abs_file)
                )
            )

        full_path = os.path.join(base, self.poc_bin)
        if os.path.exists(full_path):
            return full_path
        return ""

    @staticmethod
    def _wrap_with_phases(
        result: PoCResult,
        prepare_result: Optional[PrepareResult],
        post_result: Optional[PostResult],
        final_conclusion: str = None,
        confidence: float = None,
    ) -> PoCResult:
        """Wrap a PoCResult with phase information"""
        result.prepare = prepare_result
        result.post = post_result
        if final_conclusion:
            result.final_conclusion = final_conclusion
        if confidence is not None:
            result.confidence = confidence
        return result
