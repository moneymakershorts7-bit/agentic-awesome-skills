"""
CVE-2009-2692 Prepare phase handler

Records system state snapshot (kernel version, PPPoE config, pppox module status),
creates temporary test directory, and creates CTF target files when CTF mode is active.
"""
import logging
import os
import random
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)


class CVE20092692PrepareHandler(BasePrepareHandler):
    """CVE-2009-2692 Prepare phase: record system state and create CTF environment"""

    def __init__(self, timeout: int = 30, test_mode: str = "", ctf_value: str = ""):
        super().__init__(timeout=timeout)
        self._test_mode = test_mode
        self._ctf_value = ctf_value
        self._tmp_dir = ""
        self._target_file = ""
        self._kernel_version = ""
        self._pppoe_enabled = False
        self._pppox_loaded = False

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return preparation operations

        Args:
            kernel_info: Kernel info dict

        Returns:
            List of operations
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Create temporary test directory
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

        # Operation 2: Create CTF target file if in CTF mode
        if self._test_mode:
            self._target_file = os.path.join(self._tmp_dir, "target.txt")
            operations.append(PrepareOperation(
                action="create_file",
                target=self._target_file,
                result="pending",
                rollback_cmd=f"rm -f {self._target_file}",
            ))

        # Operation 3: Record kernel version
        operations.append(PrepareOperation(
            action="snapshot",
            target="kernel_version_state",
            result="pending",
        ))

        # Operation 4: Record PPPoE config status
        self._pppoe_enabled = self._check_pppoe_config()
        operations.append(PrepareOperation(
            action="snapshot",
            target="pppoe_config_state",
            result="pending",
        ))

        # Operation 5: Record pppox module status
        self._pppox_loaded = self._check_pppox_module()
        operations.append(PrepareOperation(
            action="snapshot",
            target="pppox_module_state",
            result="pending",
        ))

        # Operation 6: System state snapshot
        operations.append(PrepareOperation(
            action="snapshot",
            target="system_state",
            result="pending",
        ))

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Override execution for CVE-specific scenarios"""
        if op.action == "snapshot" and op.target == "kernel_version_state":
            return self._snapshot_kernel_version(op)
        elif op.action == "snapshot" and op.target == "pppoe_config_state":
            return self._snapshot_pppoe_config(op)
        elif op.action == "snapshot" and op.target == "pppox_module_state":
            return self._snapshot_pppox_module(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        elif op.action == "create_file":
            return self._create_ctf_target_file(op)
        else:
            return super()._execute_operation(op)

    def _create_ctf_target_file(self, op: PrepareOperation) -> PrepareOperation:
        """Create CTF target file based on mode

        For CVE-2009-2692, CTF modes are unsupported, but we still create
        the file so the PoC binary receives valid CLI arguments.
        """
        try:
            random_hex = format(random.getrandbits(64), '016x')
            if self._test_mode == "write_root_file":
                # write mode: initial content that PoC should overwrite
                content = f"writeme_{random_hex}"
            else:
                # read mode: CTF flag for PoC to read
                content = f"ctf{{{random_hex}}}"

            # Page cache pollution PoCs need >= 4096 bytes
            # CVE-2009-2692 doesn't use page cache pollution, but we pad
            # for framework compatibility
            padded_content = content.ljust(4096, '\x00')

            with open(op.target, 'w', encoding='utf-8') as f:
                f.write(padded_content)

            # Set ownership to root:root
            os.chown(op.target, 0, 0)

            if self._test_mode == "read_root_file":
                os.chmod(op.target, 0o400)  # nobody can't read
            else:
                os.chmod(op.target, 0o644)  # nobody can read but not write

            op.result = "success"
            logger.debug("CTF target file created: %s", op.target)
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
            logger.error("Failed to create CTF target file: %s", e)
        return op

    def _snapshot_kernel_version(self, op: PrepareOperation) -> PrepareOperation:
        """Record kernel version"""
        try:
            result = subprocess.run(
                ["uname", "-r"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._kernel_version = result.stdout.strip()
                op.result = "success"
                logger.debug("kernel_version = %s", self._kernel_version)
            else:
                op.result = "failed"
                op.error = "uname failed"
        except (subprocess.TimeoutExpired, OSError) as e:
            op.result = "failed"
            op.error = str(e)
        return op

    def _snapshot_pppoe_config(self, op: PrepareOperation) -> PrepareOperation:
        """Record PPPoE configuration status"""
        self._pppoe_enabled = self._check_pppoe_config()
        op.result = "success"
        logger.debug("pppoe_enabled = %s", self._pppoe_enabled)
        return op

    def _snapshot_pppox_module(self, op: PrepareOperation) -> PrepareOperation:
        """Record pppox module load status"""
        self._pppox_loaded = self._check_pppox_module()
        op.result = "success"
        logger.debug("pppox_loaded = %s", self._pppox_loaded)
        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot"""
        snapshot_parts = []
        snapshot_parts.append(f"kernel={self._kernel_version}")
        snapshot_parts.append(f"pppoe_enabled={self._pppoe_enabled}")
        snapshot_parts.append(f"pppox_loaded={self._pppox_loaded}")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _check_pppoe_config(self) -> bool:
        """Check if PPPoE support is enabled in kernel config"""
        try:
            kernel_ver = self._kernel_version
            if not kernel_ver:
                result = subprocess.run(
                    ["uname", "-r"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    kernel_ver = result.stdout.strip()

            config_path = f"/boot/config-{kernel_ver}"
            with open(config_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("CONFIG_PPPOE=y") or line.startswith("CONFIG_PPPOE=m"):
                        return True
        except (OSError, IOError, subprocess.TimeoutExpired):
            pass
        return True  # Assume enabled if we can't check

    def _check_pppox_module(self) -> bool:
        """Check if pppox module is loaded"""
        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("pppox"):
                        return True
        except (OSError, IOError):
            pass

        try:
            result = subprocess.run(
                ["lsmod"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
                encoding="utf-8"
            )
            if result.returncode == 0:
                return "pppox" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return False

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["kernel_version"] = self._kernel_version
        base_snapshot["pppoe_enabled"] = self._pppoe_enabled
        base_snapshot["pppox_loaded"] = self._pppox_loaded
        base_snapshot["tmp_dir"] = self._tmp_dir
        base_snapshot["target_file"] = self._target_file
        base_snapshot["test_mode"] = self._test_mode
        base_snapshot["ctf_value"] = self._ctf_value
        return base_snapshot
