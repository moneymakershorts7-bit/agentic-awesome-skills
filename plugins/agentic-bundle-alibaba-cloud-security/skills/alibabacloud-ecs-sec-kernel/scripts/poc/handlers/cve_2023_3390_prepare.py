"""Prepare handler for CVE-2023-3390"""
import logging
import os
import random
import string
from typing import Dict, Any
from ..phases.prepare import BasePrepareHandler, PrepareOperation

logger = logging.getLogger(__name__)

class Cve20233390PrepareHandler(BasePrepareHandler):
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
            random_hex = ''.join(random.choices(string.hexdigits[:16], k=8))
            ctf_flag = "ctf{" + random_hex + "}"
            with open(context.target_file, 'w', encoding='utf-8') as f:
                f.write(ctf_flag)
            os.chmod(context.target_file, 0o400)
            os.chown(context.target_file, 0, 0)
            context.ctf_flag = ctf_flag
            op.result = "success"
        except Exception as e:
            op.result = "failed"
            op.message = str(e)
        operations.append(op)

    def _create_write_target(self, context, operations):
        op = PrepareOperation(name="create_write_target")
        try:
            random_hex = ''.join(random.choices(string.hexdigits[:16], k=8))
            initial_content = "writeme_" + random_hex
            padded_content = initial_content.ljust(4096, '\x00')
            with open(context.target_file, 'w', encoding='utf-8') as f:
                f.write(padded_content)
            os.chmod(context.target_file, 0o644)
            os.chown(context.target_file, 0, 0)
            context.initial_content = initial_content
            op.result = "success"
        except Exception as e:
            op.result = "failed"
            op.message = str(e)
        operations.append(op)

    def _ensure_workspace_writable(self, operations):
        op = PrepareOperation(name="ensure_workspace_writable")
        try:
            workspace = os.path.join(os.getcwd(), 'workspace')
            if os.path.exists(workspace):
                os.chmod(workspace, 0o777)
            op.result = "success"
        except Exception as e:
            op.result = "skipped"
            op.message = str(e)
        operations.append(op)
