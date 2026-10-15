"""
CVE-2023-32233 Prepare phase handler

Record system state snapshot, verify nf_tables module availability,
create temp test directory, and configure spray parameters.

nf_tables is a core kernel component but may be compiled as a module.
This handler ensures it is loaded and records rollback state.
"""
import logging
import os
import subprocess
import tempfile
from typing import List

from ..poc.phases.prepare import BasePrepareHandler
from ..core.result import PrepareOperation

logger = logging.getLogger(__name__)

_MODULE_NAME = "nf_tables"


class CVE202332233PrepareHandler(BasePrepareHandler):
    """CVE-2023-32233 Prepare phase: verify nf_tables, record state, create env"""

    def __init__(self, timeout: int = 30):
        super().__init__(timeout=timeout)
        self._tmp_dir = ""
        self._nf_tables_was_loaded = False
        self._netlink_socket_count_before = 0

    def get_operations(self, kernel_info: dict) -> List[PrepareOperation]:
        """Return list of prepare operations

        Args:
            kernel_info: Kernel info dictionary

        Returns:
            List of operations
        """
        operations: List[PrepareOperation] = []

        # Operation 1: Record nf_tables module state
        self._nf_tables_was_loaded = self._is_module_loaded()
        operations.append(PrepareOperation(
            action="snapshot",
            target="nf_tables_module_state",
            result="pending",
        ))

        # Operation 2: Load nf_tables module if not loaded
        if not self._nf_tables_was_loaded:
            operations.append(PrepareOperation(
                action="load_module",
                target=_MODULE_NAME,
                result="pending",
                rollback_cmd=f"rmmod {_MODULE_NAME}",
            ))

        # Operation 3: Record netlink socket count (for post-check baseline)
        operations.append(PrepareOperation(
            action="snapshot",
            target="netlink_socket_state",
            result="pending",
        ))

        # Operation 4: Create temporary test directory
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

        # Operation 5: System state snapshot
        operations.append(PrepareOperation(
            action="snapshot",
            target="system_state",
            result="pending",
        ))

        return operations

    def _execute_operation(self, op: PrepareOperation) -> PrepareOperation:
        """Override execution logic for CVE-specific scenarios

        Args:
            op: Prepare operation object

        Returns:
            Operation object after execution
        """
        if op.action == "snapshot" and op.target == "nf_tables_module_state":
            return self._snapshot_nf_tables_state(op)
        elif op.action == "load_module" and op.target == _MODULE_NAME:
            return self._handle_load_module(op)
        elif op.action == "snapshot" and op.target == "netlink_socket_state":
            return self._snapshot_netlink_state(op)
        elif op.action == "snapshot" and op.target == "system_state":
            return self._snapshot_system_state(op)
        else:
            return super()._execute_operation(op)

    def _snapshot_nf_tables_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record nf_tables module state"""
        try:
            loaded = self._is_module_loaded()
            self._nf_tables_was_loaded = loaded
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
        """Load nf_tables module if not already loaded"""
        if self._nf_tables_was_loaded:
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
                # nf_tables may be built-in, which is fine
                op.result = "success"
                op.error = result.stderr.strip() or f"rc={result.returncode}"
                op.rollback_cmd = ""  # No rollback needed if load failed
                logger.info(
                    "modprobe %s returned %d (may be built-in): %s",
                    _MODULE_NAME, result.returncode, op.error
                )
        except subprocess.TimeoutExpired:
            op.result = "failed"
            op.error = "modprobe timeout (10s)"
            op.rollback_cmd = ""
        except FileNotFoundError:
            # modprobe not available - nf_tables likely built-in
            op.result = "success"
            op.error = "modprobe not found (nf_tables likely built-in)"
            op.rollback_cmd = ""
        except OSError as e:
            op.result = "failed"
            op.error = str(e)
            op.rollback_cmd = ""

        return op

    def _snapshot_netlink_state(self, op: PrepareOperation) -> PrepareOperation:
        """Record baseline netlink socket count for post-check"""
        try:
            count = self._count_netlink_sockets()
            self._netlink_socket_count_before = count
            op.result = "success"
            logger.debug("Netlink socket count before PoC: %d", count)
        except OSError as e:
            self._netlink_socket_count_before = -1
            op.result = "success"  # Not critical
            logger.debug("Cannot count netlink sockets: %s", e)
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

        # nf_tables state
        snapshot_parts.append(
            f"nf_tables={'loaded' if self._nf_tables_was_loaded else 'not_loaded'}"
        )

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

    def _is_module_loaded(self) -> bool:
        """Check if nf_tables module is loaded

        Returns:
            True if loaded, False otherwise
        """
        try:
            with open("/proc/modules", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith(_MODULE_NAME + " "):
                        return True
        except OSError:
            pass

        # Also check /proc/net/netfilter as indicator
        return os.path.exists("/proc/net/netfilter")

    def _count_netlink_sockets(self) -> int:
        """Count current netlink sockets in /proc/net/netlink"""
        count = 0
        try:
            with open("/proc/net/netlink", "r", encoding="utf-8") as f:
                for line in f:
                    # Skip header
                    if line.startswith("sk"):
                        continue
                    count += 1
        except OSError:
            pass
        return count

    def _build_state_snapshot(self, operations: List[PrepareOperation]) -> dict:
        """Build enhanced state snapshot"""
        base_snapshot = super()._build_state_snapshot(operations)
        base_snapshot["tmp_dir"] = self._tmp_dir
        base_snapshot["nf_tables_was_loaded"] = self._nf_tables_was_loaded
        base_snapshot["netlink_socket_count_before"] = self._netlink_socket_count_before
        return base_snapshot
