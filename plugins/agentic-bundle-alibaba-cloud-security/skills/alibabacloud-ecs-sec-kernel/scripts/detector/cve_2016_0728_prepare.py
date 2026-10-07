"""
CVE-2016-0728 Prepare phase handler

Record system state snapshot, create temp test directory.
"""
import logging
import os
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)


class CVE20160728PrepareHandler(BasePrepareHandler):
    """CVE-2016-0728 Prepare handler"""

    def __init__(self, timeout: int = 30):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        operations: List[PrepareOperation] = []

        operations.append(PrepareOperation(
            action="snapshot", target="system_state", result="pending",
        ))

        self._tmp_dir = os.path.join(
            tempfile.gettempdir(), f"sec-kernel-poc-{os.getpid()}"
        )
        operations.append(PrepareOperation(
            action="create_dir", target=self._tmp_dir, result="pending",
            rollback_cmd=f"rm -rf {self._tmp_dir}",
        ))

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        if op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        return super()._execute_operation(op)

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        snapshot_parts = []
        try:
            result = subprocess.run(["uname", "-r"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
            if result.returncode == 0:
                snapshot_parts.append(f"kernel={result.stdout.strip()}")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("kernel=unknown")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["tmp_dir"] = self._tmp_dir
        return base_snapshot
