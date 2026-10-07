"""Post handler for CVE-2026-43284"""
import logging, os, shutil, re
from ..phases.post import BasePostHandler

logger = logging.getLogger(__name__)

class CVECve202643284PostHandler(BasePostHandler):
    def verify_ctf(self, context, poc_output) -> bool:
        if context.mode == "read_root_file": return self._verify_read(context, poc_output)
        elif context.mode == "write_root_file": return self._verify_write(context, poc_output)
        return False

    def _verify_read(self, context, poc_output) -> bool:
        if not poc_output.flag: return False
        return self._extract_inner_value(context.ctf_flag) == self._extract_inner_value(poc_output.flag)

    def _verify_write(self, context, poc_output) -> bool:
        try:
            if not os.path.exists(context.target_file):
                logger.warning("CTF target file not found: %s", context.target_file)
                return False

            with open(context.target_file, 'rb') as f:
                raw = f.read()

            # Method 1: Substring search in raw bytes
            # Brute-force + overlapping write produces
            # padding + ctf{flag_number} + padding, so the
            # expected_inner (hex value) may appear anywhere
            # in the file surrounded by random residue.
            expected_inner = self._extract_inner_value(context.write_value)
            if expected_inner:
                expected_inner_bytes = expected_inner.encode('utf-8')
                if expected_inner_bytes in raw:
                    logger.info(
                        "CTF write_root_file PASSED: "
                        "flag_number found via substring search (%s)",
                        expected_inner[:16]
                    )
                    return True

            # Method 2: Full write_value substring search
            write_bytes = context.write_value.encode('utf-8') if isinstance(context.write_value, str) else context.write_value
            if write_bytes in raw:
                logger.info("CTF write_root_file PASSED: full write_value found in file")
                return True

            # Method 3 (backward-compatible): exact ctf{...} match
            # Strip null padding (target file may be padded)
            content = raw.split(b'\x00', 1)[0].decode('utf-8', errors='replace').strip()
            actual_inner = self._extract_inner_value(content)
            if actual_inner and expected_inner and actual_inner == expected_inner:
                logger.info(
                    "CTF write_root_file PASSED: inner value matches (%s)",
                    expected_inner[:16]
                )
                return True

            logger.warning(
                "CTF write_root_file FAILED: expected_inner=%s, got_inner=%s",
                expected_inner[:16] if expected_inner else "",
                actual_inner[:16] if actual_inner else ""
            )
            return False
        except OSError as e:
            logger.error("Cannot read target file: %s", e)
            return False

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
