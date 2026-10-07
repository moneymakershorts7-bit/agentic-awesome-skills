"""
PoC safe execution controller (CTF mode)

Provides safe wrapper for PoC/Exp execution:
- CTF CLI argument construction
- Retry mechanism
- Timeout control
- Output parsing (CTF protocol + legacy protocol)
- Resource limits (optional)
- Output directory management
- Cleanup guarantee
"""
import os
import re
import time
import logging
from typing import Optional, Dict
from pathlib import Path

from .elf_loader import FilelessELFLoader
from ..core.result import PoCResult, PrepareResult
from .phases import PrivilegeManager, ConclusionEngine

logger = logging.getLogger(__name__)


def extract_ctf_flag(stdout: str) -> str:
    """Extract CTF flag value from PoC stdout (CTF_FLAG:xxx)

    Args:
        stdout: PoC standard output

    Returns:
        Extracted flag string, or empty string if not found
    """
    match = re.search(r"CTF_FLAG:(.+?)(?:\n|$)", stdout)
    if match:
        return match.group(1).strip()
    return ""


def extract_ctf_flag_inner(stdout: str) -> str:
    """Extract inner value from CTF flag (value inside {}).

    Robust against trailing residue from page cache pollution.
    e.g. CTF_FLAG:ctf{a3f8b2c1}RESIDUAL -> 'a3f8b2c1'

    Args:
        stdout: PoC standard output

    Returns:
        Inner value string, or empty string if not found
    """
    flag = extract_ctf_flag(stdout)
    if flag:
        inner_match = re.search(r'\{([^}]+)\}', flag)
        if inner_match:
            return inner_match.group(1)
    return ""


def extract_ctf_fail(stdout: str) -> str:
    """Extract CTF failure reason from PoC stdout (CTF_FAIL:xxx)

    Args:
        stdout: PoC standard output

    Returns:
        Extracted failure reason, or empty string if not found
    """
    match = re.search(r"CTF_FAIL:(.+?)(?:\n|$)", stdout)
    if match:
        return match.group(1).strip()
    return ""


def extract_ctf_read_before(stdout: str) -> str:
    """Extract CTF_READ_BEFORE value from PoC stdout

    Args:
        stdout: PoC standard output

    Returns:
        Read-before content, or empty string if not found
    """
    match = re.search(r"CTF_READ_BEFORE:(.+?)(?:\n|$)", stdout)
    if match:
        return match.group(1).strip()
    return ""


def extract_ctf_read_after(stdout: str) -> str:
    """Extract CTF_READ_AFTER value from PoC stdout

    Args:
        stdout: PoC standard output

    Returns:
        Read-after content, or empty string if not found
    """
    match = re.search(r"CTF_READ_AFTER:(.+?)(?:\n|$)", stdout)
    if match:
        return match.group(1).strip()
    return ""


def extract_uaf_evidence(stdout: str) -> str:
    """Extract UAF exploitation evidence from PoC stdout.

    UAF PoC typically outputs lines indicating:
    - UAF trigger confirmation
    - Privilege escalation success
    - UID change to root
    - CTF_FLAG (if UAF PoC also uses CTF protocol)

    Args:
        stdout: PoC standard output

    Returns:
        Semicolon-separated evidence summary (max 3 lines), or empty string
    """
    if not stdout:
        return ""
    evidence_keywords = [
        'UAF', 'use-after-free', 'triggered', 'freed',
        'escalat', 'uid=0', 'root', 'privilege',
        'CTF_FLAG', 'POC_RESULT:EXPLOITABLE',
        '[VULN]', 'overwrite', 'spray',
    ]
    evidence_lines = []
    for line in stdout.split('\n'):
        stripped = line.strip()
        if not stripped:
            continue
        if any(kw.lower() in stripped.lower() for kw in evidence_keywords):
            evidence_lines.append(stripped)
    return '; '.join(evidence_lines[:3])


class SafePoCExecutor:
    """
    Safe PoC executor with CTF mode support

    Wraps FilelessELFLoader with additional safety controls:
    - CTF CLI argument construction
    - Pre-execution verification
    - Timeout control
    - Retry mechanism
    - Output directory preparation
    - CTF + legacy output protocol parsing
    """

    def __init__(self, poc_bin_path: str, output_dir: str = "./workspace",
                 timeout: int = 10):
        self.poc_bin_path = poc_bin_path
        self.output_dir = output_dir
        self.timeout = timeout
        self._loader: Optional[FilelessELFLoader] = None

    def execute(self, test_mode: str = "write_root_file",
                root_file: str = "", write_value: str = "",
                log_file: str = "", poc_user: str = "nobody",
                retry_count: int = 3, env_extra: Dict[str, str] = None,
                force_demote: bool = True) -> PoCResult:
        """
        Execute PoC with CTF CLI arguments

        Args:
            test_mode: CTF test mode (write_root_file, read_root_file)
            root_file: Target root-owned file path for CTF challenge
            write_value: CTF value to write (for write mode)
            log_file: PoC log file path
            poc_user: User to execute PoC as (Run phase)
            retry_count: Number of retries on failure
            env_extra: Extra environment variables (backward compatibility)
            force_demote: Force privilege demotion

        Returns:
            PoCResult: execution result
        """
        start_time = time.time()

        # 1. Verify PoC binary
        if not os.path.exists(self.poc_bin_path):
            return PoCResult(
                status="ERROR",
                error_message=f"PoC binary not found: {self.poc_bin_path}"
            )

        self._loader = FilelessELFLoader(self.poc_bin_path)
        if not self._loader.verify_binary():
            error_msg = (
                f"Invalid masked ELF: {self.poc_bin_path} "
                f"(expected CVE\\x00 magic header, binary will NOT be executed)"
            )
            logger.error(error_msg)
            return PoCResult(
                status="ERROR",
                error_message=error_msg
            )

        # 2. Prepare output directory
        self._prepare_output_dir()

        # 3. Build CTF CLI arguments
        cli_args = self._build_cli_args(test_mode, root_file, write_value, log_file)

        # 4. Build environment (backward compatibility)
        env = {"SEC_KERNEL_OUTPUT": os.path.abspath(self.output_dir)}
        if env_extra:
            env.update(env_extra)

        # 5. Execute (supports privilege drop to regular user)
        logger.info("Executing PoC: %s (mode=%s, retry=%d)",
                    os.path.basename(self.poc_bin_path), test_mode, retry_count)
        try:
            if force_demote and poc_user:
                stdout, stderr, rc = self._loader.execute_as_user(
                    user=poc_user, cli_args=cli_args, env=env,
                    timeout=self.timeout, retry_count=retry_count
                )
                # Resolve UID for result
                from .phases.privilege import PrivilegeManager
                pm = PrivilegeManager(target_user=poc_user, force_demote=force_demote)
                _, uid = pm.resolve_user()
            else:
                stdout, stderr, rc = self._loader.load_and_execute(
                    cli_args=cli_args,
                    env=env,
                    timeout=self.timeout,
                    retry_count=retry_count
                )
                uid = os.getuid()
        except Exception as e:
            return PoCResult(
                status="ERROR",
                error_message=str(e),
                execution_time=time.time() - start_time
            )

        execution_time = time.time() - start_time

        # 6. Parse results (CTF protocol first, then legacy)
        result = self._parse_output(stdout, stderr, rc, poc_user, uid)
        result.execution_time = execution_time

        logger.info(
            "PoC result: %s (confidence=%.2f, time=%.2fs, ctf_flag=%s)",
            result.status, result.confidence, execution_time,
            result.ctf_flag[:16] + "..." if len(result.ctf_flag) > 16 else result.ctf_flag
        )

        return result

    def _build_cli_args(self, test_mode: str, root_file: str,
                        write_value: str, log_file: str) -> list:
        """Build CTF CLI arguments for PoC binary

        Args:
            test_mode: CTF test mode
            root_file: Target file path
            write_value: Value to write
            log_file: Log file path

        Returns:
            List of CLI argument strings
        """
        cli_args = [
            "--mode", test_mode,
            "--root-file", root_file,
            "--log-file", log_file,
        ]
        if write_value and test_mode == "write_root_file":
            cli_args.extend(["--write-value", write_value])
        return cli_args

    def _prepare_output_dir(self):
        """Prepare output directory"""
        from ..utils.output_dir import ensure_output_dir
        ensure_output_dir(self.output_dir)

    def _parse_output(self, stdout: str, stderr: str, rc: int,
                      user: str = "nobody", uid: int = -1) -> PoCResult:
        """Parse PoC output - CTF protocol first, then legacy protocol

        CTF protocol:
        - CTF_FLAG:<value> -> EXPLOITABLE with ctf_flag
        - CTF_FAIL:<reason> -> NOT_EXPLOITABLE
        - CTF_UNSUPPORTED:<msg> -> NOT_EXPLOITABLE (mode not supported)

        Legacy protocol:
        - POC_RESULT:EXPLOITABLE -> EXPLOITABLE
        - POC_RESULT:NOT_EXPLOITABLE -> NOT_EXPLOITABLE
        - POC_RESULT:ERROR -> ERROR
        """
        result = PoCResult(
            status="ERROR",
            stdout=stdout,
            stderr=stderr,
            returncode=rc,
            user=user,
            uid=uid
        )

        # CTF protocol (priority)
        if "CTF_FLAG:" in stdout:
            flag = extract_ctf_flag(stdout)
            result.status = "EXPLOITABLE"
            result.confidence = 0.95
            result.ctf_flag = flag
            # Also extract read-before/read-after for evidence
            result.ctf_read_before = extract_ctf_read_before(stdout)
            result.ctf_read_after = extract_ctf_read_after(stdout)
            return result

        if "CTF_FAIL:" in stdout:
            reason = extract_ctf_fail(stdout)
            result.status = "NOT_EXPLOITABLE"
            result.confidence = 0.85
            result.error_message = reason
            return result

        if "CTF_UNSUPPORTED:" in stdout:
            result.status = "NOT_EXPLOITABLE"
            result.confidence = 0.5
            result.error_message = "Mode not supported"
            return result

        # Legacy protocol (backward compatibility)
        if "POC_RESULT:EXPLOITABLE" in stdout:
            result.status = "EXPLOITABLE"
            result.confidence = 0.95
        elif "POC_RESULT:NOT_EXPLOITABLE" in stdout:
            result.status = "NOT_EXPLOITABLE"
            result.confidence = 0.85
        elif "POC_RESULT:PARTIALLY_EXPLOITABLE" in stdout:
            # Legacy compatibility: treat as EXPLOITABLE if CTF flag present,
            # otherwise NOT_EXPLOITABLE (binary judgment)
            ctf_flag = extract_ctf_flag(stdout)
            if ctf_flag:
                result.status = "EXPLOITABLE"
                result.confidence = 0.70
                result.ctf_flag = ctf_flag
            else:
                result.status = "NOT_EXPLOITABLE"
                result.confidence = 0.70
        elif "POC_RESULT:ERROR" in stdout or "POC_RESULT:ERROR" in stderr:
            result.status = "ERROR"
            result.confidence = 0.0
            for line in (stdout + stderr).splitlines():
                if "Error" in line or "error" in line:
                    result.error_message = line.strip()
                    break
        elif rc == 124:
            result.status = "ERROR"
            result.error_message = "PoC execution timed out"
        else:
            result.status = "ERROR"
            result.error_message = f"Unexpected output (rc={rc})"
            result.confidence = 0.0

        return result

    def _get_log_path(self, cve_id: str) -> str:
        """Generate PoC log path: workspace/poc-{CVE}.log

        Args:
            cve_id: CVE identifier (e.g. "CVE-2026-31431")

        Returns:
            Absolute log file path
        """
        workspace = self._get_workspace_dir()
        return os.path.join(workspace, f"poc-{cve_id}.log")

    def _get_workspace_dir(self) -> str:
        """Get workspace directory (absolute path)"""
        return os.path.abspath(self.output_dir)
