"""Permission checking mixin for FilesystemCollector (SUID/SGID scanning)"""
import logging
import os
import stat

from ...utils import throttle

logger = logging.getLogger("sec-userspace")


class PermissionCheckerMixin:
    """Mixin providing SUID/SGID file scanning."""

    def _scan_special_perm_files(self, perm_flag: int) -> list:
        """Scan files with special permissions (SUID or SGID)

        Args:
            perm_flag: stat.S_ISUID or stat.S_ISGID
        """
        cached_files, cache_valid = self._get_cached_special_files(perm_flag)
        if cache_valid and cached_files:
            logger.debug(
                f"Filesystem collector: using cached {perm_flag} results ({len(cached_files)} files)"
            )
            return cached_files

        result_files = []
        # Scan critical system directories
        scan_dirs = [
            "/usr/bin", "/usr/sbin", "/bin", "/sbin",
            "/usr/local/bin", "/usr/local/sbin"
        ]

        throttle_ctrl = throttle.Throttle()
        count = 0
        check_interval = 200

        for scan_dir in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue

            try:
                with os.scandir(scan_dir) as it:
                    for entry in it:
                        try:
                            # Direct stat, avoid TOCTOU race condition
                            st = entry.stat(follow_symlinks=False)

                            # Check if regular file
                            if not stat.S_ISREG(st.st_mode):
                                continue

                            if st.st_mode & perm_flag:
                                result_files.append({
                                    "path": entry.path,
                                    "permissions": oct(stat.S_IMODE(st.st_mode)),
                                    "owner": str(st.st_uid),
                                    "size": st.st_size,
                                })
                        except OSError:
                            continue

                        count += 1
                        if count % check_interval == 0:
                            if throttle_ctrl:
                                throttle_ctrl.batch_sleep(count, check_interval)
            except OSError:
                continue

        return result_files
