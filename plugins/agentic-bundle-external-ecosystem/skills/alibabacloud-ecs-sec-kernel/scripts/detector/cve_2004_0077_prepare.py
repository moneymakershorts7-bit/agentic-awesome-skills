"""
CVE-2004-0077 Prepare Phase Handler

Ensures mremap and memory management environment is ready for PoC verification:
- Records current ASLR setting
- Checks mremap syscall availability
- Creates temporary test directory
- Creates root-owned target file for CTF challenge
- Records system state snapshot
"""
import logging
import os
import secrets
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)


class CVE20040077PrepareHandler(BasePrepareHandler):
    """CVE-2004-0077 Prepare phase: ensure mremap + MMU environment ready"""

    def __init__(self, timeout: int = 30, test_mode: str = "write_root_file",
                 ctf_value: str = ""):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._target_file = ""
        self._aslr_original = "0"
        self._mremap_available = False
        self._test_mode = test_mode
        self._ctf_value = ctf_value
        self._initial_content = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return preparation operations list

        Args:
            kernel_info: Kernel info dict

        Returns:
            List of PrepareOperation
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Record current ASLR setting
        self._aslr_original = self._get_aslr_setting()
        operations.append(PrepareOperation(
            action="snapshot",
            target="aslr_state",
            result="pending",
        ))

        # Operation 2: Check mremap syscall availability
        self._mremap_available = self._check_mremap()
        operations.append(PrepareOperation(
            action="check_syscall",
            target="mremap",
            result="pending",
        ))

        # Operation 3: Create temporary test directory
        self._tmp_dir = os.path.join(
            tempfile.gettempdir(),
            f"sec-kernel-poc-{os.getpid()}"
        )
        operations.append(PrepareOperation(
            action="create_dir",
            target=self._tmp_dir,
            result="pending",
            rollback_cmd=f"rm -rf {self._tmp_dir}",
        ))

        # Operation 4: Create root-owned target file for CTF challenge
        # This file will be root:root 0644 - nobody can read but NOT write
        self._target_file = os.path.join(self._tmp_dir, "poc_target_canary")
        operations.append(PrepareOperation(
            action="create_target_file",
            target=self._target_file,
            result="pending",
            rollback_cmd=f"rm -f {self._target_file}",
        ))

        # Operation 5: System state snapshot
        operations.append(PrepareOperation(
            action="snapshot",
            target="system_state",
            result="pending",
        ))

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Execute operation with CVE-specific logic

        Args:
            op: Prepare operation object

        Returns:
            Updated operation object
        """
        if op.action == "snapshot" and op.target == "aslr_state":
            return self._snapshot_aslr(op)
        elif op.action == "check_syscall" and op.target == "mremap":
            return self._check_mremap_op(op)
        elif op.action == "create_target_file":
            return self._create_target_file(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            return super()._execute_operation(op)

    def _snapshot_aslr(self, op: PrepareOperation) -> PrepareOperation:
        """Record current ASLR setting"""
        try:
            aslr = self._get_aslr_setting()
            op.result = "success"
            logger.debug("ASLR state: %s", aslr)
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
        return op

    def _check_mremap_op(self, op: PrepareOperation) -> PrepareOperation:
        """Check if mremap syscall is available"""
        if not self._mremap_available:
            op.result = "failed"
            op.error = "mremap syscall not available"
            logger.warning("mremap syscall not available")
            return op

        op.result = "success"
        logger.info("mremap syscall available")
        return op

    def _create_target_file(self, op: PrepareOperation) -> PrepareOperation:
        """Create root-owned target file for CTF challenge.

        CTF mode determines file content and permissions:
        - read_root_file: Write ctf_value as flag, set 0400 (nobody cannot access)
        - write_root_file: Write writeme_{hex} initial content, set 0644
        """
        target_path = op.target
        try:
            # Determine content and permissions based on CTF test mode
            if self._test_mode == "read_root_file":
                # PoC needs to read this value out as CTF flag
                content = self._ctf_value
                file_mode = 0o400  # nobody cannot access at all
            else:
                # write_root_file: generate writeme_{hex} as initial content
                self._initial_content = f"writeme_{secrets.token_hex(8)}"
                content = self._initial_content
                file_mode = 0o644  # nobody can read not write

            fd = os.open(
                target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode
            )
            os.write(fd, content.encode("utf-8"))
            os.close(fd)

            # Ensure ownership is root:root (prepare runs as root)
            os.chown(target_path, 0, 0)
            # Enforce permissions explicitly
            os.chmod(target_path, file_mode)

            # Verify setup
            st = os.stat(target_path)
            if st.st_uid != 0:
                op.result = "failed"
                op.error = f"Target file uid={st.st_uid}, expected 0 (root)"
                return op

            op.result = "success"
            logger.info(
                "Created CTF target: %s (mode=%s, uid=%d, perm=%o, size=%d, content=%s)",
                target_path, self._test_mode,
                st.st_uid, st.st_mode & 0o777, st.st_size,
                content[:30],
            )
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
            logger.error(
                "Failed to create target file %s: %s", target_path, e
            )

        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot (uname, ASLR, mremap status)"""
        snapshot_parts = []

        # uname -r
        try:
            result = subprocess.run(
                ["uname", "-r"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                snapshot_parts.append(f"kernel={result.stdout.strip()}")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("kernel=unknown")

        # ASLR setting
        try:
            aslr = self._get_aslr_setting()
            snapshot_parts.append(f"aslr={aslr}")
        except OSError:
            snapshot_parts.append("aslr=unknown")

        # mremap status
        snapshot_parts.append(f"mremap={'available' if self._mremap_available else 'not_available'}")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _get_aslr_setting(self) -> str:
        """Get current ASLR setting

        Returns:
            ASLR value as string, '0' if not available
        """
        try:
            with open("/proc/sys/kernel/randomize_va_space", "r", encoding="utf-8") as f:
                return f.read().strip()
        except (OSError, IOError):
            return "0"  # Default: ASLR disabled

    def _check_mremap(self) -> bool:
        """Check if mremap syscall is available

        Returns:
            True if mremap is available
        """
        # Check /proc/self/maps as a proxy for memory management
        if not os.path.exists("/proc/self/maps"):
            return False

        # Try to read /proc/kallsyms for mremap
        try:
            with open("/proc/kallsyms", "r", encoding="utf-8") as f:
                for line in f:
                    if "mremap" in line.lower():
                        return True
        except (OSError, IOError, PermissionError):
            pass

        # Fallback: mremap is a standard syscall, assume available
        return True

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["aslr_original"] = self._aslr_original
        base_snapshot["mremap_available"] = self._mremap_available
        base_snapshot["tmp_dir"] = self._tmp_dir
        base_snapshot["target_file"] = self._target_file
        base_snapshot["test_mode"] = self._test_mode
        base_snapshot["ctf_value"] = self._ctf_value
        base_snapshot["initial_content"] = self._initial_content
        return base_snapshot
