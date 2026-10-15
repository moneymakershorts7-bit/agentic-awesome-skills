"""
CVE-2013-2094 Prepare phase handler

Record current perf_event_paranoid value, system state snapshot, create temp test directory.
"""
import logging
import os
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)


class CVE20132094PrepareHandler(BasePrepareHandler):
    """CVE-2013-2094 Prepare phase: record system state and create test environment"""

    def __init__(self, timeout: int = 30):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._paranoid_value = None

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations

        Args:
            kernel_info: Kernel info dictionary

        Returns:
            List of operations
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Record current perf_event_paranoid value
        self._paranoid_value = self._get_paranoid_value()
        operations.append(PrepareOperation(
            action="snapshot",
            target="paranoid_state",
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

        # Operation 3: System state snapshot
        operations.append(PrepareOperation(
            action="snapshot",
            target="system_state",
            result="pending",
        ))

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Override execution logic to handle CVE-specific scenarios

        Args:
            op: Prepare operation object

        Returns:
            Operation object after execution
        """
        if op.action == "snapshot" and op.target == "paranoid_state":
            return self._snapshot_paranoid_state(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            # Other operations use base class default logic
            return super()._execute_operation(op)

    def _snapshot_paranoid_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record current perf_event_paranoid value"""
        try:
            value = self._get_paranoid_value()
            op.result = "success"
            logger.debug(
                "perf_event_paranoid state: %s",
                value if value is not None else "unknown",
            )
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
        return op

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

        # perf_event_paranoid
        try:
            result = subprocess.run(
                ["sysctl", "kernel.perf_event_paranoid"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                snapshot_parts.append(f"perf_paranoid={result.stdout.strip()}")
            else:
                snapshot_parts.append("perf_paranoid=unknown")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("perf_paranoid=check_failed")

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

    def _get_paranoid_value(self):
        """Read current perf_event_paranoid value

        Returns:
            int Valueor None（Cannot readWhen）
        """
        try:
            with open("/proc/sys/kernel/perf_event_paranoid", "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["paranoid_value"] = self._paranoid_value
        base_snapshot["tmp_dir"] = self._tmp_dir
        return base_snapshot
