"""Prepare handler for CVE-2024-26808"""
import logging, os, random, string
from typing import Dict, Any
from ..phases.prepare import BasePrepareHandler, PrepareOperation

logger = logging.getLogger(__name__)

class CVECve202426808PrepareHandler(BasePrepareHandler):
    def prepare(self, context) -> Dict[str, Any]:
        operations = []
        self.create_temp_dir(context, operations)
        if context.mode == "read_root_file":
            self._create_read_target(context, operations)
        elif context.mode == "write_root_file":
            self._create_write_target(context, operations)
        self._ensure_workspace_writable(operations)
        return self._build_result(operations)

    def _create_read_target(self, context, operations):
        op = PrepareOperation(name="create_read_target")
        try:
            rh = ''.join(random.choices(string.hexdigits[:16], k=8))
            context.ctf_flag = "ctf{" + rh + "}"
            with open(context.target_file, 'w', encoding='utf-8') as f: f.write(context.ctf_flag)
            os.chmod(context.target_file, 0o400); os.chown(context.target_file, 0, 0)
            op.result = "success"
        except Exception as e: op.result = "failed"; op.message = str(e)
        operations.append(op)

    def _create_write_target(self, context, operations):
        op = PrepareOperation(name="create_write_target")
        try:
            rh = ''.join(random.choices(string.hexdigits[:16], k=8))
            context.initial_content = "writeme_" + rh
            content = context.initial_content.ljust(4096, '\x00')
            with open(context.target_file, 'w', encoding='utf-8') as f: f.write(content)
            os.chmod(context.target_file, 0o644); os.chown(context.target_file, 0, 0)
            op.result = "success"
        except Exception as e: op.result = "failed"; op.message = str(e)
        operations.append(op)

    def _ensure_workspace_writable(self, operations):
        op = PrepareOperation(name="ensure_workspace_writable")
        try:
            ws = os.path.join(os.getcwd(), 'workspace')
            if os.path.exists(ws): os.chmod(ws, 0o777)
            op.result = "success"
        except Exception as e: op.result = "skipped"; op.message = str(e)
        operations.append(op)
