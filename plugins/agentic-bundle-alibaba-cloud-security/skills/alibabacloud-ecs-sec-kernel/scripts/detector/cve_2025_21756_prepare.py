"""
CVE-2025-21756 Prepare phase handler

Ensure vsock ModuleAvailable，Create temporary test directory，RecordSystem state snapshot。
"""
import logging
import os
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)

_MODULE_NAME = "vsock"


class CVE202521756PrepareHandler(BasePrepareHandler):
    """CVE-2025-21756 Prepare phase：Ensure vsock ModuleAvailable"""

    def __init__(self, timeout: int = 30):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._module_was_loaded = False

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations

        Args:
            kernel_info: Kernel info dictionary

        Returns:
            List of operations
        """
        operations: List[PrepareOperation] = []

        # Operation 1: RecordCurrentModuleState（snapshot）
        self._module_was_loaded = self._is_module_loaded()
        operations.append(PrepareOperation(
            action="snapshot",
            target="module_state",
            result="pending",
        ))

        # Operation 2: Load vsock Module（such asResultnot loaded）
        if self._module_was_loaded:
            operations.append(PrepareOperation(
                action="load_module",
                target=_MODULE_NAME,
                result="pending",
                rollback_cmd="",  # noneedRollback
            ))
        else:
            operations.append(PrepareOperation(
                action="load_module",
                target=_MODULE_NAME,
                result="pending",
                rollback_cmd=f"rmmod {_MODULE_NAME}",
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
        """Override execution logic to handle CVE-specific scenarios"""
        if op.action == "snapshot" and op.target == "module_state":
            return self._snapshot_module_state(op)
        elif op.action == "load_module" and op.target == _MODULE_NAME:
            return self._handle_load_module(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            return super()._execute_operation(op)

    def _snapshot_module_state(self, op: PrepareOperation) -> PrepareOperation:
        """RecordCurrentModuleState"""
        try:
            loaded = self._is_module_loaded()
            op.result = "success"
            logger.debug(
                "Module %s state: %s",
                _MODULE_NAME,
                "loaded" if loaded else "not loaded",
            )
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
        return op

    def _handle_load_module(self, op: PrepareOperation) -> PrepareOperation:
        """HandleModuleLoad"""
        if self._module_was_loaded:
            op.result = "success"
            logger.debug("Module %s already loaded, skipping", _MODULE_NAME)
            return op

        try:
            result = subprocess.run(
                ["modprobe", _MODULE_NAME],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=10,
            )
            if result.returncode == 0:
                op.result = "success"
                logger.info("Module %s loaded successfully", _MODULE_NAME)
            else:
                op.result = "failed"
                op.error = result.stderr.strip() or f"returncode={result.returncode}"
                op.rollback_cmd = ""
                logger.warning(
                    "Failed to load module %s: %s", _MODULE_NAME, op.error
                )
        except subprocess.TimeoutExpired:
            op.result = "failed"
            op.error = "modprobe timeout (10s)"
            op.rollback_cmd = ""
        except FileNotFoundError:
            op.result = "failed"
            op.error = "modprobe command not found"
            op.rollback_cmd = ""
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
            op.rollback_cmd = ""

        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """RecordSystem state snapshot（uname, lsmod, dmesg tail）"""
        snapshot_parts = []

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

        try:
            result = subprocess.run(
                "lsmod | grep vsock",
                shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                snapshot_parts.append(f"vsock_modules={result.stdout.strip()}")
            else:
                snapshot_parts.append("vsock_modules=none")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("vsock_modules=check_failed")

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

    def _is_module_loaded(self) -> bool:
        """Check vsock if module is already loaded"""
        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith(_MODULE_NAME + " "):
                        return True
        except OSError:
            pass
        return False

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["module_was_loaded"] = self._module_was_loaded
        base_snapshot["tmp_dir"] = self._tmp_dir
        return base_snapshot
