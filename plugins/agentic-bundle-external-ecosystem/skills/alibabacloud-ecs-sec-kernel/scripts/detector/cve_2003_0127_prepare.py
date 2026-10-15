"""
CVE-2003-0127 Prepare Phase Handler

Ensures ptrace and kmod environment is ready for PoC verification:
- Records current ptrace scope setting
- Checks kmod/modprobe availability
- Creates temporary test directory
- Records system state snapshot
"""
import logging
import os
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)


class CVE20030127PrepareHandler(BasePrepareHandler):
    """CVE-2003-0127 Prepare phase: ensure ptrace + kmod environment ready"""

    def __init__(self, timeout: int = 30):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._ptrace_scope_original = "0"
        self._modprobe_path = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return preparation operations list

        Args:
            kernel_info: Kernel info dict

        Returns:
            List of PrepareOperation
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Record current ptrace scope state
        self._ptrace_scope_original = self._get_ptrace_scope()
        operations.append(PrepareOperation(
            action="snapshot",
            target="ptrace_scope_state",
            result="pending",
        ))

        # Operation 2: Check and record modprobe path
        self._modprobe_path = self._find_modprobe()
        operations.append(PrepareOperation(
            action="check_binary",
            target=self._modprobe_path or "modprobe",
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

        # Operation 4: System state snapshot
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
        if op.action == "snapshot" and op.target == "ptrace_scope_state":
            return self._snapshot_ptrace_scope(op)
        elif op.action == "check_binary" and op.target:
            return self._check_modprobe(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            return super()._execute_operation(op)

    def _snapshot_ptrace_scope(self, op: PrepareOperation) -> PrepareOperation:
        """Record current ptrace_scope value"""
        try:
            scope = self._get_ptrace_scope()
            op.result = "success"
            logger.debug("ptrace_scope state: %s", scope)
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
        return op

    def _check_modprobe(self, op: PrepareOperation) -> PrepareOperation:
        """Check if modprobe binary is available"""
        if not self._modprobe_path:
            op.result = "failed"
            op.error = "modprobe not found in standard locations"
            logger.warning("modprobe binary not found")
            return op

        try:
            result = subprocess.run(
                [self._modprobe_path, "--version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                op.result = "success"
                logger.info("modprobe found: %s", self._modprobe_path)
            else:
                op.result = "failed"
                op.error = result.stderr.strip() or f"returncode={result.returncode}"
                logger.warning("modprobe --version failed: %s", op.error)
        except subprocess.TimeoutExpired:
            op.result = "failed"
            op.error = "modprobe version check timeout"
        except FileNotFoundError:
            op.result = "failed"
            op.error = "modprobe command not found"
        except OSError as e:
            op.result = "failed"
            op.error = str(e)

        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot (uname, ptrace_scope, modprobe path)"""
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

        # ptrace_scope
        try:
            scope = self._get_ptrace_scope()
            snapshot_parts.append(f"ptrace_scope={scope}")
        except OSError:
            snapshot_parts.append("ptrace_scope=unknown")

        # modprobe path
        snapshot_parts.append(f"modprobe={self._modprobe_path or 'not_found'}")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _get_ptrace_scope(self) -> str:
        """Get current ptrace_scope value

        Returns:
            ptrace_scope value as string, '0' if not available
        """
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope", "r", encoding="utf-8") as f:
                return f.read().strip()
        except (OSError, IOError):
            return "0"  # Default: unrestricted

    def _find_modprobe(self) -> str:
        """Find modprobe binary path

        Returns:
            Full path to modprobe or empty string
        """
        # First check /proc/sys/kernel/modprobe
        try:
            with open("/proc/sys/kernel/modprobe", "r", encoding="utf-8") as f:
                path = f.read().strip()
                if path and os.path.exists(path):
                    return path
        except (OSError, IOError):
            pass

        # Check standard locations
        modprobe_paths = [
            "/sbin/modprobe",
            "/usr/sbin/modprobe",
            "/bin/modprobe",
            "/usr/bin/modprobe",
        ]
        for p in modprobe_paths:
            if os.path.exists(p):
                return p

        return ""

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["ptrace_scope_original"] = self._ptrace_scope_original
        base_snapshot["modprobe_path"] = self._modprobe_path
        base_snapshot["tmp_dir"] = self._tmp_dir
        return base_snapshot
