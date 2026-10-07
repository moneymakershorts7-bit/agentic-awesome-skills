"""
CVE-2008-0600 Prepare phase handler

Create root-owned target file for CTF challenge.
CVE-2008-0600 is a vmsplice local privilege escalation vulnerability.

For CTF verification:
- write_root_file: PoC attempts to write to root file via vmsplice page cache pollution
- read_root_file: Unsupported (this vulnerability is write-oriented)

The target file is owned by root:root with mode 0644 (nobody can read but not write).
If the PoC manages to write content via vmsplice page cache pollution, it proves the
vulnerability is exploitable.
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


class CVE20080600PrepareHandler(BasePrepareHandler):
    """CVE-2008-0600 Prepare phase: create root-owned CTF target"""

    def __init__(self, timeout: int = 30, test_mode: str = "write_root_file",
                 ctf_value: str = ""):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._target_file = ""
        self._test_mode = test_mode
        self._ctf_value = ctf_value
        self._initial_content = ""
        self._proc_mounted = False

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations

        Args:
            kernel_info: Kernel info dictionary

        Returns:
            List of operations
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Record proc filesystem state (snapshot)
        self._proc_mounted = self._check_proc_mounted()
        operations.append(PrepareOperation(
            action="snapshot",
            target="proc_state",
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

        # Operation 3: Create root-owned target file for CTF challenge
        # For write_root_file: 0644 root:root - nobody can read but not write
        self._target_file = os.path.join(self._tmp_dir, "poc_target_canary")
        operations.append(PrepareOperation(
            action="create_target_file",
            target=self._target_file,
            result="pending",
            rollback_cmd=f"rm -f {self._target_file}",
        ))

        # Operation 4: System state snapshot
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
        if op.action == "snapshot" and op.target == "proc_state":
            return self._snapshot_proc_state(op)
        elif op.action == "create_target_file":
            return self._create_target_file(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            # Other operations use base class default logic
            return super()._execute_operation(op)

    def _snapshot_proc_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record proc filesystem state"""
        try:
            mounted = self._check_proc_mounted()
            op.result = "success"
            logger.debug("procfs state: %s", "mounted" if mounted else "not mounted")
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
        return op

    def _create_target_file(self, op: PrepareOperation) -> PrepareOperation:
        """Create root-owned target file for CTF challenge.

        CVE-2008-0600 is a write-oriented vulnerability (vmsplice page cache pollution).
        Only write_root_file mode is supported.

        File permissions:
        - write mode (0644): nobody can read but not write - PoC must bypass VFS via
          the vmsplice page cache pollution to write content
        - File must be >= 4096 bytes (one page) for splice operations to succeed
          at arbitrary offsets
        """
        target_path = op.target
        try:
            if self._test_mode == "write_root_file":
                # Write initial content that PoC will overwrite
                self._initial_content = f"writeme_{secrets.token_hex(8)}"
                file_mode = 0o644  # nobody can read but not write
            else:
                # read_root_file is unsupported, but create file anyway
                self._initial_content = f"ctf_{secrets.token_hex(8)}"
                file_mode = 0o400

            # Pad to at least one page (4096 bytes) for splice operations
            # Page cache pollution requires target file >= page size
            padded_content = self._initial_content.ljust(4096, '\x00')

            fd = os.open(
                target_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode
            )
            os.write(fd, padded_content.encode("utf-8"))
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

            if st.st_size < 4096:
                op.result = "failed"
                op.error = (
                    f"Target file size={st.st_size}, expected >= 4096 "
                    "(page cache pollution requires full page)"
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
            logger.error(
                "Failed to create target file %s: %s", target_path, e
            )

        return op

    def _snapshot_system_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record system state snapshot (kernel version, proc mount, etc.)"""
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

        # proc mount status
        snapshot_parts.append(f"proc_mounted={self._proc_mounted}")

        # vmsplice syscall availability
        vmsplice_ok = self._check_vmsplice_available()
        snapshot_parts.append(f"vmsplice_available={vmsplice_ok}")

        op.result = "success"
        logger.debug("System state snapshot: %s", "; ".join(snapshot_parts))
        return op

    def _check_proc_mounted(self) -> bool:
        """Check if /proc filesystem is mounted"""
        try:
            with open("/proc/mounts", "r", encoding="utf-8") as f:
                for line in f:
                    if " /proc " in line:
                        return True
        except (OSError, IOError):
            pass
        return False

    def _check_environ_accessible(self) -> bool:
        """Check if /proc/self/environ is accessible"""
        try:
            with open("/proc/self/environ", "r", encoding="utf-8") as f:
                f.read(1)
                return True
        except (OSError, IOError, PermissionError):
            return False

    def _check_vmsplice_available(self) -> bool:
        """Check if vmsplice syscall is available"""
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            # syscall number for vmsplice is 275 on x86_64
            result = libc.syscall(275, 0, 0, 0, 0)
            # ENOSYS (38) means syscall exists but not implemented
            return result != -38
        except (OSError, ImportError):
            return True

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot including CTF challenge info"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["target_file"] = self._target_file
        base_snapshot["test_mode"] = self._test_mode
        base_snapshot["ctf_value"] = self._ctf_value
        base_snapshot["initial_content"] = self._initial_content
        base_snapshot["proc_mounted"] = getattr(self, '_proc_mounted', False)
        return base_snapshot
