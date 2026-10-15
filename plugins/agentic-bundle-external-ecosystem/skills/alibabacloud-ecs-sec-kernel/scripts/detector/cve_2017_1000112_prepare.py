"""
CVE-2017-1000112 Prepare phase handler

Create root-owned target file for CTF challenge.
CVE-2017-1000112 is a UFO (UDP Fragmentation Offload) heap overflow in
__ip_append_data, allowing out-of-bounds write that can corrupt adjacent
kernel memory (skb_shared_info) for local privilege escalation.

For CTF verification:
- write_root_file: PoC attempts to use heap overflow to bypass VFS write
  permissions via corrupted kernel structures
- read_root_file: Unsupported (this vulnerability is not read-oriented)

The target file is owned by root:root with mode 0644 (nobody can read but not write).
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


class CVE20171000112PrepareHandler(BasePrepareHandler):
    """CVE-2017-1000112 Prepare phase: create root-owned CTF target"""

    def __init__(self, timeout: int = 30, test_mode: str = "write_root_file",
                 ctf_value: str = ""):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._target_file = ""
        self._test_mode = test_mode
        self._ctf_value = ctf_value
        self._initial_content = ""

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations"""
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

        # Operation 2: Create root-owned target file for CTF challenge
        self._target_file = os.path.join(self._tmp_dir, "poc_target_canary")
        operations.append(PrepareOperation(
            action="create_target_file",
            target=self._target_file,
            result="pending",
            rollback_cmd=f"rm -f {self._target_file}",
        ))

        # Operation 3: System state snapshot
        operations.append(PrepareOperation(
            action="snapshot",
            target="system_state",
            result="pending",
        ))

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Override execution logic"""
        if op.action == "create_target_file":
            return self._create_target_file(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            return super()._execute_operation(op)

    def _create_target_file(self, op: PrepareOperation) -> PrepareOperation:
        """Create root-owned target file for CTF challenge.

        For write_root_file: 0644 root:root - nobody can read but not write.
        File must be >= 4096 bytes (one page) for mmap/splice operations.
        """
        import tempfile
        target_path = op.target
        try:
            if self._test_mode == "write_root_file":
                self._initial_content = f"writeme_{secrets.token_hex(8)}"
                file_mode = 0o644
            else:
                self._initial_content = f"ctf_{secrets.token_hex(8)}"
                file_mode = 0o400

            # Pad to at least one page (4096 bytes)
            padded_content = self._initial_content.ljust(4096, '\x00')

            fd = os.open(
                target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode
            )
            os.write(fd, padded_content.encode("utf-8"))
            os.close(fd)

            os.chown(target_path, 0, 0)
            os.chmod(target_path, file_mode)

            st = os.stat(target_path)
            if st.st_uid != 0:
                op.result = "failed"
                op.error = f"Target file uid={st.st_uid}, expected 0 (root)"
                return op

            if st.st_size < 4096:
                op.result = "failed"
                op.error = (
                    f"Target file size={st.st_size}, expected >= 4096 "
                    "(mmap requires full page)"
                )
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
            logger.error("Failed to create target file %s: %s", target_path, e)

        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot (kernel version, network subsystem)"""
        snapshot_parts = []

        try:
            result = subprocess.run(
                ["uname", "-r"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5,
            )
            if result.returncode == 0:
                snapshot_parts.append(f"kernel={result.stdout.strip()}")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("kernel=unknown")

        try:
            result = subprocess.run(
                ["cat", "/proc/sys/net/core/wmem_max"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5,
            )
            if result.returncode == 0:
                snapshot_parts.append(f"wnem_max={result.stdout.strip()}")
        except (subprocess.TimeoutExpired, OSError):
            snapshot_parts.append("wnem_max=unknown")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot including CTF challenge info"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["target_file"] = self._target_file
        base_snapshot["test_mode"] = self._test_mode
        base_snapshot["ctf_value"] = self._ctf_value
        base_snapshot["initial_content"] = self._initial_content
        return base_snapshot
