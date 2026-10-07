"""Prepare handler for CVE-2026-PENDING-DIRTYFRAG

Creates writeme_{random} canary in root-owned target file.
The PoC overwrites this canary with ctf_value via page cache corruption
(ESP/xfrm or RxRPC/rxkad path), proving unprivileged write to root file.
"""
import logging, os, socket
from typing import Dict, Any
from ..phases.prepare import BasePrepareHandler, PrepareOperation

logger = logging.getLogger(__name__)


class CVE2026PendingDirtyfragPrepareHandler(BasePrepareHandler):
    def prepare(self, context) -> Dict[str, Any]:
        operations = []
        self.create_temp_dir(context, operations)
        if context.mode == "read_root_file":
            self._create_read_target(context, operations)
        elif context.mode == "write_root_file":
            self._create_write_target(context, operations)
        self._ensure_workspace_writable(operations)
        self._autoload_rxrpc(operations)
        return self._build_result(operations)

    def _create_read_target(self, context, operations):
        import random, string
        op = PrepareOperation(name="create_read_target")
        try:
            rh = ''.join(random.choices(string.hexdigits[:16], k=8))
            context.ctf_flag = "ctf{" + rh + "}"
            with open(context.target_file, 'w', encoding='utf-8') as f:
                f.write(context.ctf_flag)
            os.chmod(context.target_file, 0o644)
            os.chown(context.target_file, 0, 0)
            op.result = "success"
        except Exception as e:
            op.result = "failed"; op.message = str(e)
        operations.append(op)

    def _create_write_target(self, context, operations):
        """Create target file with writeme_{random} canary content.

        The PoC will overwrite this canary with write_value via page cache
        corruption, proving unprivileged write to root-owned file.
        """
        import random, string
        op = PrepareOperation(name="create_write_target")
        try:
            rh = ''.join(random.choices(string.hexdigits[:16], k=16))
            context.initial_content = "writeme_" + rh
            content = context.initial_content.ljust(4096, '\x00')
            with open(context.target_file, 'w', encoding='utf-8') as f:
                f.write(content)
            os.chmod(context.target_file, 0o644)
            os.chown(context.target_file, 0, 0)
            op.result = "success"
        except Exception as e:
            op.result = "failed"; op.message = str(e)
        operations.append(op)

    def _ensure_workspace_writable(self, operations):
        op = PrepareOperation(name="ensure_workspace_writable")
        try:
            ws = os.path.join(os.getcwd(), 'workspace')
            if os.path.exists(ws):
                os.chmod(ws, 0o777)
            op.result = "success"
        except Exception as e:
            op.result = "skipped"; op.message = str(e)
        operations.append(op)

    def _autoload_rxrpc(self, operations):
        """Try to autoload rxrpc kernel module via socket(AF_RXRPC)."""
        op = PrepareOperation(name="autoload_rxrpc")
        try:
            AF_RXRPC = 33
            s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
            s.close()
            op.result = "success"
            op.message = "rxrpc module autoloaded"
        except OSError as e:
            op.result = "skipped"
            op.message = "rxrpc autoload failed: {} (PoC will retry)".format(e)
        operations.append(op)
