"""
CVE-2026-PENDING-DIRTYFRAG Prepare phase handler

Ensure ESP modules are available, create root-owned target file with
writeme_{random} canary content for page cache write verification.

The target file is owned by root:root with mode 0644 (read-only for others).
The PoC (running as nobody) cannot normally write to this file.
If the PoC manages to overwrite the canary via ESP/xfrm or RxRPC page cache
corruption, it proves the vulnerability is exploitable.
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

_ESP_MODULES = ["esp4", "esp6"]


class CVE2026PendingDirtyFragPrepareHandler(BasePrepareHandler):
    """CVE-2026-PENDING-DIRTYFRAG Prepare phase: load ESP modules + create CTF target"""

    def __init__(self, timeout: int = 30, test_mode: str = "write_root_file",
                 ctf_value: str = ""):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._target_file = ""
        self._esp_loaded = {}
        self._test_mode = test_mode
        self._ctf_value = ctf_value
        self._initial_content = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations

        Args:
            kernel_info: Kernel info dictionary

        Returns:
            List of operations
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Record current module state (snapshot)
        self._esp_loaded = {
            mod: self._is_module_loaded(mod)
            for mod in _ESP_MODULES
        }
        operations.append(PrepareOperation(
            action="snapshot",
            target="module_state",
            result="pending",
        ))

        # Operation 2: Load ESP modules (if not loaded)
        for mod in _ESP_MODULES:
            if not self._esp_loaded.get(mod, False):
                operations.append(PrepareOperation(
                    action="load_module",
                    target=mod,
                    result="pending",
                    rollback_cmd=f"rmmod {mod}",
                ))
            else:
                operations.append(PrepareOperation(
                    action="load_module",
                    target=mod,
                    result="pending",
                    rollback_cmd="",
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

        # Operation 4: Create root-owned target file with canary content
        self._target_file = os.path.join(self._tmp_dir, "poc_target_dirtyfrag")
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
        """Override execution logic to handle CVE-specific scenarios

        Args:
            op: Prepare operation object

        Returns:
            Operation object after execution
        """
        if op.action == "snapshot" and op.target == "module_state":
            return self._snapshot_module_state(op)
        elif op.action == "load_module":
            return self._handle_load_module(op)
        elif op.action == "create_target_file":
            return self._create_target_file(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            return super()._execute_operation(op)

    def _snapshot_module_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record current module state"""
        try:
            esp_states = ", ".join([
                f"{mod}={'loaded' if loaded else 'not_loaded'}"
                for mod, loaded in self._esp_loaded.items()
            ])
            logger.debug("Module state snapshot: esp [%s]", esp_states)
            op.result = "success"
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
        return op

    def _create_target_file(self, op: PrepareOperation) -> PrepareOperation:
        """Create root-owned target file for CTF challenge.

        CTF mode determines file content and permissions:
        - read_root_file: Write ctf_value as flag, set 0400 (nobody cannot access)
        - write_root_file: Write writeme_{random} canary, set 0644. The PoC
          overwrites this canary with ctf_value via page cache corruption,
          proving unprivileged write to root-owned file.
        """
        target_path = op.target
        try:
            # Determine content and permissions based on CTF test mode
            if self._test_mode == "read_root_file":
                content_bytes = self._ctf_value.encode("utf-8")
                file_mode = 0o400
            else:
                # write_root_file: writeme_{random} canary, PoC overwrites
                # via page cache corruption (ESP/xfrm or RxRPC/rxkad path)
                self._initial_content = "writeme_{}".format(secrets.token_hex(8))
                content_bytes = self._initial_content.encode('utf-8').ljust(
                    4096, b'\x00'
                )
                file_mode = 0o644

            fd = os.open(
                target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode
            )
            os.write(fd, content_bytes)
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
                "Created CTF target: %s (mode=%s, uid=%d, perm=%o, size=%d)",
                target_path, self._test_mode,
                st.st_uid, st.st_mode & 0o777, st.st_size,
            )
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
            logger.error(
                "Failed to create target file %s: %s", target_path, e
            )

        return op

    def _handle_load_module(self, op: PrepareOperation) -> PrepareOperation:
        """Handle module loading for ESP modules (best-effort, non-critical).

        Module loading is optional because:
        1. The kernel may have ESP support built-in (not as a module)
        2. When creating XFRM SA, the kernel auto-loads required algorithms
        3. The original PoC works without explicit modprobe in WSL2

        Failure here only logs a warning and marks the operation as 'skipped',
        it does NOT cause the overall Prepare phase to fail.
        """
        module_name = op.target

        # Check if already loaded
        was_loaded = self._esp_loaded.get(module_name, False)
        if was_loaded:
            op.result = "success"
            logger.debug("Module %s already loaded, skipping", module_name)
            return op

        # Attempt to load module (best-effort)
        try:
            result = subprocess.run(
                ["modprobe", module_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=10,
            )
            if result.returncode == 0:
                op.result = "success"
                logger.info("Module %s loaded successfully", module_name)
            else:
                # Non-critical: kernel may have built-in ESP support
                op.result = "skipped"
                op.error = result.stderr.strip() or f"returncode={result.returncode}"
                op.rollback_cmd = ""
                logger.warning(
                    "Module %s load failed (non-critical, kernel may have "
                    "built-in support): %s", module_name, op.error
                )
        except subprocess.TimeoutExpired:
            op.result = "skipped"
            op.error = "modprobe timeout (10s) - continuing without module"
            op.rollback_cmd = ""
            logger.warning("modprobe %s timed out (non-critical)", module_name)
        except FileNotFoundError:
            op.result = "skipped"
            op.error = "modprobe command not found - kernel may have built-in ESP"
            op.rollback_cmd = ""
            logger.warning(
                "modprobe not available; assuming kernel has built-in ESP support"
            )
        except OSError as e:
            op.result = "skipped"
            op.error = f"{e} - continuing without explicit module load"
            op.rollback_cmd = ""
            logger.warning(
                "OSError loading module %s (non-critical): %s", module_name, e
            )

        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot (uname, lsmod, dmesg tail)"""
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

        # lsmod | grep esp
        try:
            result = subprocess.run(
                "lsmod | grep -E 'esp|xfrm'",
                shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                snapshot_parts.append(f"esp_modules={result.stdout.strip()}")
            else:
                snapshot_parts.append("esp_modules=none")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("esp_modules=check_failed")

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

    def _is_module_loaded(self, module_name: str) -> bool:
        """Check if module is loaded

        Args:
            module_name: Module name to check

        Returns:
            True if loaded, False otherwise
        """
        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith(module_name + " "):
                        return True
        except OSError:
            pass
        return False

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot including CTF challenge info"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["esp_loaded"] = self._esp_loaded
        base_snapshot["tmp_dir"] = self._tmp_dir
        base_snapshot["target_file"] = self._target_file
        base_snapshot["test_mode"] = self._test_mode
        base_snapshot["ctf_value"] = self._ctf_value
        base_snapshot["initial_content"] = self._initial_content
        return base_snapshot
