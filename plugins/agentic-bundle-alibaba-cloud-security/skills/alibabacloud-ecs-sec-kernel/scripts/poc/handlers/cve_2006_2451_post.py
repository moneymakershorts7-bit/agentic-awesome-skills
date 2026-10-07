"""Post handler for CVE-2006-2451"""
import logging, os, shutil, re
from ..phases.post import BasePostHandler

logger = logging.getLogger(__name__)

class CVE20062451PostHandler(BasePostHandler):
    def verify_ctf(self, context, poc_output) -> bool:
        if context.mode == "read_root_file": return self._verify_read(context, poc_output)
        elif context.mode == "write_root_file": return self._verify_write(context, poc_output)
        return False

    def _verify_read(self, context, poc_output) -> bool:
        if not poc_output.flag: return False
        return self._extract_inner_value(context.ctf_flag) == self._extract_inner_value(poc_output.flag)

    def _verify_write(self, context, poc_output) -> bool:
        try:
            with open(context.target_file, 'r', encoding='utf-8') as f: content = f.read()
            return self._extract_inner_value(context.write_value) == self._extract_inner_value(content)
        except Exception: return False

    def _extract_inner_value(self, text):
        if not text: return None
        m = re.search(r'\{([^}]+)\}', text)
        return m.group(1) if m else text

    def cleanup(self, context):
        self.remove_temp_dir(context)
        import glob
        for p in ['/tmp/.poc_*', '/tmp/sec-kernel-poc-*']:
            for path in glob.glob(p):
                try:
                    if os.path.isdir(path): shutil.rmtree(path, ignore_errors=True)
                    else: os.remove(path)
                except Exception: pass
