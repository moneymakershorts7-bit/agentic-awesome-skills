"""Web root recursive scanning mixin for FilesystemCollector"""
import logging
import os
import stat
from datetime import datetime

logger = logging.getLogger("sec-userspace")

# Maximum safe timestamp (2070-01-01)
_MAX_SAFE_TIMESTAMP = 32503680000


def _safe_timestamp_to_iso(timestamp: float) -> str:
    """Safely convert a Unix timestamp to ISO format"""
    safe_ts = max(0, min(timestamp, _MAX_SAFE_TIMESTAMP))
    return datetime.fromtimestamp(safe_ts).isoformat()


class WebrootScannerMixin:
    """Mixin providing web root file scanning."""

    def _scan_webroot_files(self) -> list:
        """Scan script files under web root directories"""
        webroot_files = []
        web_dirs = ["/var/www", "/opt", "/srv"]
        script_extensions = {'.php', '.jsp', '.asp', '.aspx', '.py', '.cgi', '.pl'}

        # Exclude sec-userspace's own installation directory
        self_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        exclude_dirs = {self_dir}

        for web_dir in web_dirs:
            if not os.path.isdir(web_dir):
                continue

            try:
                self._scan_web_dir_recursive(
                    web_dir, script_extensions, webroot_files,
                    depth=0, max_depth=5, max_files=5000,
                    exclude_dirs=exclude_dirs
                )
            except OSError:
                continue

        return webroot_files

    def _scan_web_dir_recursive(
        self,
        directory: str,
        script_extensions: set,
        result_list: list,
        depth: int,
        max_depth: int,
        max_files: int,
        exclude_dirs: set = None
    ) -> None:
        """Recursively scan web directories"""
        if depth > max_depth or len(result_list) >= max_files:
            return

        # Check whether directory is in the exclusion list
        if exclude_dirs:
            abs_dir = os.path.abspath(directory)
            for excl in exclude_dirs:
                if abs_dir == excl or abs_dir.startswith(excl + os.sep):
                    return

        try:
            with os.scandir(directory) as it:
                file_count = 0
                for entry in it:
                    if len(result_list) >= max_files or file_count >= 1000:
                        break

                    try:
                        # Direct stat, avoid TOCTOU race condition
                        st = entry.stat(follow_symlinks=False)

                        # Check if regular file
                        if stat.S_ISREG(st.st_mode):
                            _, ext = os.path.splitext(entry.name)
                            if ext.lower() in script_extensions:
                                mtime = _safe_timestamp_to_iso(st.st_mtime)
                                result_list.append({
                                    "path": entry.path,
                                    "extension": ext,
                                    "size": st.st_size,
                                    "mtime": mtime,
                                })
                            file_count += 1
                        elif stat.S_ISDIR(st.st_mode):
                            self._scan_web_dir_recursive(
                                entry.path, script_extensions, result_list,
                                depth + 1, max_depth, max_files, exclude_dirs
                            )
                    except OSError:
                        continue
        except OSError:
            pass
