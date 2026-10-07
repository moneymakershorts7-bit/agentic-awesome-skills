"""
PrepareHandler - Prepare Phase Handler

Handles environment preparation for PoC execution with root privileges.
Records all operations for Post phase rollback.
"""
import os
import time
import logging
import subprocess
from typing import List, Optional, Dict

from ...core.result import PrepareResult, PrepareOperation

logger = logging.getLogger(__name__)


class BasePrepareHandler:
    """Prepare phase base class, subclasses implement get_operations"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def prepare(self, kernel_info: dict) -> PrepareResult:
        """Template method: execute Prepare phase"""
        start_time = time.time()
        operations: List[PrepareOperation] = []
        success = True

        try:
            planned_ops = self.get_operations(kernel_info)
        except Exception as e:
            logger.error("Failed to get operations: %s", e)
            return PrepareResult(
                success=False,
                operations=[],
                state_snapshot={},
                duration=time.time() - start_time,
            )

        for op in planned_ops:
            executed_op = self._execute_operation(op)
            operations.append(executed_op)

            if executed_op.result == "failed":
                success = False
                logger.warning("Operation failed: %s %s - %s", op.action, op.target, op.error)

        # Build state snapshot
        state_snapshot = self._build_state_snapshot(operations)

        duration = time.time() - start_time

        return PrepareResult(
            success=success,
            operations=operations,
            state_snapshot=state_snapshot,
            duration=duration,
        )

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Get preparation operations (subclasses override)"""
        return []

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Execute a single preparation operation"""
        cmd = self._build_command(op)
        if not cmd:
            op.result = "skipped"
            op.error = "no command for action"
            return op

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=10,
            )
            if result.returncode == 0:
                op.result = "success"
                logger.debug("Operation success: %s %s", op.action, op.target)
            else:
                op.result = "failed"
                op.error = result.stderr.strip() or f"returncode={result.returncode}"
                logger.debug("Operation failed: %s %s - %s", op.action, op.target, op.error)
        except subprocess.TimeoutExpired:
            op.result = "failed"
            op.error = "operation timeout (10s)"
        except OSError as e:
            op.result = "failed"
            op.error = str(e)

        return op

    def _build_command(self, op: PrepareOperation) -> str:
        """Build shell command from operation"""
        action_map = {
            "load_module": f"modprobe {op.target}",
            "set_sysctl": f"sysctl -w {op.target}",
            "create_dir": f"mkdir -p {op.target}",
            "snapshot": f"cat /proc/version > /dev/null",
        }
        return action_map.get(op.action, "")

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build state snapshot from operations"""
        return {
            "total_operations": len(operations),
            "successful": sum(1 for op in operations if op.result == "success"),
            "failed": sum(1 for op in operations if op.result == "failed"),
            "skipped": sum(1 for op in operations if op.result == "skipped"),
        }


class PrepareHandler(BasePrepareHandler):
    """
    Prepare Phase Handler

    Executes environment preparation with root privileges.
    All operations are recorded for Post phase rollback.
    """

    ALLOWED_ACTIONS = frozenset([
        "load_module",
        "set_sysctl",
        "create_dir",
        "snapshot",
    ])

    FORBIDDEN_ACTIONS = frozenset([
        "insmod_custom",
        "modify_sysfs",
        "write_kernel_memory",
    ])

    def __init__(self, timeout: int = 30):
        super().__init__(timeout=timeout)
        self._operations: List[PrepareOperation] = []
        self._state_snapshot: Dict = {}

    def execute(self) -> PrepareResult:
        """Execute all preparation operations"""
        start_time = time.time()
        success = True

        logger.info("Starting Prepare phase (timeout=%ds)", self.timeout)

        try:
            if not self._check_sudo():
                return PrepareResult(
                    success=False,
                    operations=[],
                    state_snapshot={},
                    duration=0.0
                )

            ops = self._get_operations()
            for op in ops:
                op_result = self._execute_operation_from_dict(op)
                self._operations.append(op_result)
                if op_result.result == "failed":
                    success = False
                    logger.error("Prepare operation failed: %s -> %s",
                                 op.get('action'), op_result.error)

            self._state_snapshot = self._take_snapshot()

        except Exception as e:
            logger.error("Prepare phase exception: %s", e)
            success = False

        duration = time.time() - start_time
        logger.info("Prepare phase completed: success=%s, duration=%.2fs",
                    success, duration)

        return PrepareResult(
            success=success,
            operations=self._operations,
            state_snapshot=self._state_snapshot,
            duration=duration
        )

    def _check_sudo(self) -> bool:
        """Check if sudo is available"""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5
            )
            if result.returncode != 0:
                logger.warning(
                    "sudo not available or requires password. "
                    "Prepare phase may fail."
                )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("sudo command not found")
            return True

    def _get_operations(self) -> List[Dict]:
        """Get list of preparation operations"""
        return []

    def _execute_operation_from_dict(self, op: Dict) -> PrepareOperation:
        """Execute a single preparation operation from dict"""
        action = op.get("action", "")
        target = op.get("target", "")

        if action in self.FORBIDDEN_ACTIONS:
            return PrepareOperation(
                action=action, target=target, result="skipped",
                error=f"Action '{action}' is forbidden"
            )

        if action not in self.ALLOWED_ACTIONS:
            return PrepareOperation(
                action=action, target=target, result="skipped",
                error=f"Action '{action}' not in allowed list"
            )

        try:
            if action == "load_module":
                return self._load_module(target)
            elif action == "set_sysctl":
                return self._set_sysctl(op.get("key", ""), op.get("value", ""))
            elif action == "create_dir":
                return self._create_dir(target)
            elif action == "snapshot":
                return self._snapshot(target)
            else:
                return PrepareOperation(
                    action=action, target=target, result="skipped",
                    error=f"Unknown action: {action}"
                )
        except Exception as e:
            return PrepareOperation(
                action=action, target=target, result="failed",
                error=str(e)
            )

    def _load_module(self, module: str) -> PrepareOperation:
        """Load a kernel module"""
        try:
            result = subprocess.run(
                ["lsmod"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            if module in result.stdout:
                logger.debug("Module %s already loaded", module)
                return PrepareOperation(
                    action="load_module", target=module, result="success",
                    rollback_cmd=""
                )
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["sudo", "modprobe", module],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15
            )
            if result.returncode == 0:
                logger.info("Module %s loaded successfully", module)
                return PrepareOperation(
                    action="load_module", target=module, result="success",
                    rollback_cmd=f"sudo rmmod {module}"
                )
            else:
                return PrepareOperation(
                    action="load_module", target=module, result="failed",
                    error=result.stderr.strip()
                )
        except Exception as e:
            return PrepareOperation(
                action="load_module", target=module, result="failed",
                error=str(e)
            )

    def _set_sysctl(self, key: str, value: str) -> PrepareOperation:
        """Set a sysctl parameter"""
        try:
            result = subprocess.run(
                ["sysctl", "-n", key],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5
            )
            original_value = result.stdout.strip()
        except Exception:
            original_value = ""

        try:
            result = subprocess.run(
                ["sudo", "sysctl", "-w", f"{key}={value}"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            if result.returncode == 0:
                logger.info("Sysctl %s set to %s", key, value)
                return PrepareOperation(
                    action="set_sysctl", target=key, result="success",
                    rollback_cmd=f"sudo sysctl -w {key}={original_value}"
                )
            else:
                return PrepareOperation(
                    action="set_sysctl", target=key, result="failed",
                    error=result.stderr.strip()
                )
        except Exception as e:
            return PrepareOperation(
                action="set_sysctl", target=key, result="failed",
                error=str(e)
            )

    def _create_dir(self, path: str) -> PrepareOperation:
        """Create a directory"""
        try:
            os.makedirs(path, exist_ok=True)
            logger.debug("Directory created: %s", path)
            return PrepareOperation(
                action="create_dir", target=path, result="success",
                rollback_cmd=f"sudo rm -rf {path}"
            )
        except Exception as e:
            return PrepareOperation(
                action="create_dir", target=path, result="failed",
                error=str(e)
            )

    def _snapshot(self, target: str) -> PrepareOperation:
        """Take a system state snapshot"""
        try:
            result = subprocess.run(
                ["lsmod"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            result = subprocess.run(
                ["dmesg", "--tail=10"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            logger.debug("System state snapshot captured")
            return PrepareOperation(
                action="snapshot", target=target, result="success"
            )
        except Exception as e:
            return PrepareOperation(
                action="snapshot", target=target, result="failed",
                error=str(e)
            )

    def _take_snapshot(self) -> Dict:
        """Take comprehensive system state snapshot"""
        snapshot = {
            "timestamp": time.time(),
        }

        try:
            result = subprocess.run(
                ["lsmod"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            snapshot["loaded_modules"] = result.stdout.splitlines()
        except Exception:
            snapshot["loaded_modules"] = []

        try:
            result = subprocess.run(
                ["dmesg", "--tail=10"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            snapshot["dmesg_tail"] = result.stdout.strip()
        except Exception:
            snapshot["dmesg_tail"] = ""

        return snapshot
