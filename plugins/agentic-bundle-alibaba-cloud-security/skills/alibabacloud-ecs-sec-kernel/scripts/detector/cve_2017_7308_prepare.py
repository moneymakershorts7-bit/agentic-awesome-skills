"""
CVE-2017-7308 Prepare phase handler

Record system state snapshot, create temp test directory.
AF_PACKET isCoreKernelSuccesscan，noneedLoadAdditionalModule。
"""
import logging
import os
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)


class CVE20177308PrepareHandler(BasePrepareHandler):
    """CVE-2017-7308 Prepare phase: record system state and create test environment"""

    def __init__(self, timeout: int = 30):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations

        Args:
            kernel_info: Kernel info dictionary

        Returns:
            List of operations
        """
        operations: List[PrepareOperation] = []

        # Operation 1: System state snapshot
        operations.append(PrepareOperation(
            action="snapshot",
            target="system_state",
            result="pending",
        ))

        # Operation 2: Create temporary test directory
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

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Override execution logic to handle CVE-specific scenarios

        Args:
            op: Prepare operation object

        Returns:
            Operation object after execution
        """
        if op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            # Other operations use base class default logic
            return super()._execute_operation(op)

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot (uname, dmesg tail)"""
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

        # dmesg tail 10
        try:
            result = subprocess.run(
                ["dmesg"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                tail = lines[-10:] if len(lines) >= 10 else lines
                snapshot_parts.append(f"dmesg_tail={len(tail)} lines")
            else:
                snapshot_parts.append("dmesg_tail=unavailable")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("dmesg_tail=read_failed")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """BuildStateSnapshot"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["tmp_dir"] = self._tmp_dir
        return base_snapshot
