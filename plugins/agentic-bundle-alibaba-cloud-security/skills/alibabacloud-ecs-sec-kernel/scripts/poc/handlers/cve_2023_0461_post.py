"""Post handler for CVE-2023-0461"""
import logging
import os
import re
import shutil
from ..phases.post import BasePostHandler

logger = logging.getLogger(__name__)

class Cve20230461PostHandler(BasePostHandler):
    def verify_ctf(self, context, poc_output) -> bool:
        if context.mode == "read_root_file":
            return self._verify_read(context, poc_output)
        elif context.mode == "write_root_file":
            return self._verify_write(context, poc_output)
        return False

    def _verify_read(self, context, poc_output) -> bool:
        if not poc_output.flag:
            return False
        expected = self._extract_inner_value(context.ctf_flag)
        actual = self._extract_inner_value(poc_output.flag)
        return expected == actual

    def _verify_write(self, context, poc_output) -> bool:
        try:
            with open(context.target_file, 'r', encoding='utf-8') as f:
                actual_content = f.read()
            expected_value = self._extract_inner_value(context.write_value)
            actual_value = self._extract_inner_value(actual_content)
            return expected_value == actual_value
        except Exception:
            return False

    def _extract_inner_value(self, text: str):
        if not text:
            return None
        match = re.search(r'\{([^}]+)\}', text)
        return match.group(1) if match else text

    def cleanup(self, context):
        self.remove_temp_dir(context)
        import glob
        for pattern in ['/tmp/.poc_*', '/tmp/sec-kernel-poc-*']:
            for path in glob.glob(pattern):
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    else:
                        os.remove(path)
                except Exception:
                    pass
