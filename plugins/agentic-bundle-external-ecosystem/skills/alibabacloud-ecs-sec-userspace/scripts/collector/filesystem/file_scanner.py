"""File scanning mixin for FilesystemCollector"""
import logging
import os
import re
import stat
from datetime import datetime, timedelta
from ...utils.datetime_compat import fromisoformat

logger = logging.getLogger("sec-userspace")

# Maximum safe timestamp (2070-01-01)
_MAX_SAFE_TIMESTAMP = 32503680000


def _safe_timestamp_to_iso(timestamp: float) -> str:
    """Safely convert a Unix timestamp to ISO format

    Args:
        timestamp: Unix timestamp

    Returns:
        ISO 8601 formatted date string
    """
    safe_ts = max(0, min(timestamp, _MAX_SAFE_TIMESTAMP))
    return datetime.fromtimestamp(safe_ts).isoformat()


class FileScannerMixin:
    """Mixin providing file scanning methods (tmp, hidden, recent, history, shell, skill)."""

    def __init__(self):
        self._user_home_dirs = []
        self._scan_paths = self._get_config("scan_paths", [
            "/tmp", "/var/tmp", "/dev/shm"
        ])

    def _get_config(self, key: str, default=None):
        """Get configuration value. Override in main class if needed."""
        return default

    def _should_skip_due_to_timeout(self) -> bool:
        """Check if we should skip remaining collection due to approaching timeout."""
        return False

    def _get_user_home_dirs(self) -> list:
        """Parse user home directory list from /etc/passwd

        Returns:
            [{"username": str, "home_dir": str}, ...] containing only root and users with uid >= 1000
        """
        users = []
        try:
            with open("/etc/passwd", "r", errors='replace', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        try:
                            uid = int(parts[2])
                            if uid < 1000 and uid != 0:
                                continue
                        except ValueError:
                            continue

                        home_dir = parts[5]
                        if not home_dir or not os.path.isdir(home_dir):
                            continue

                        users.append({
                            "username": parts[0],
                            "home_dir": home_dir,
                        })
        except OSError:
            pass
        return users

    def _scan_tmp_executables(self) -> list:
        """Scan executable files in temporary directories"""
        tmp_executables = []
        tmp_dirs = self._scan_paths

        max_files_per_dir = 1000

        for tmp_dir in tmp_dirs:
            if not os.path.isdir(tmp_dir):
                continue

            try:
                with os.scandir(tmp_dir) as it:
                    file_count = 0
                    for entry in it:
                        if file_count >= max_files_per_dir:
                            break

                        if file_count % 100 == 0:
                            if self._should_skip_due_to_timeout():
                                logger.warning(f"Filesystem collector: timeout during tmp exec scan ({file_count} files)")
                                return tmp_executables

                        try:
                            # Direct stat, avoid TOCTOU race condition
                            st = entry.stat(follow_symlinks=False)

                            # Check if regular file
                            if not stat.S_ISREG(st.st_mode):
                                continue

                            if st.st_mode & 0o111:  # Executable permission
                                mtime = _safe_timestamp_to_iso(st.st_mtime)
                                tmp_executables.append({
                                    "path": entry.path,
                                    "permissions": oct(stat.S_IMODE(st.st_mode)),
                                    "size": st.st_size,
                                    "mtime": mtime,
                                })
                        except OSError:
                            continue

                        file_count += 1
            except OSError:
                continue

        return tmp_executables

    def _scan_hidden_files(self) -> list:
        """Scan suspicious hidden files

        Filters out known benign patterns to reduce false positives:
        - Electron/Chrome cache files (.fcb*.so in /tmp)
        - IDE configuration directories (.idea, .vscode)
        - Common cache directories (.cache)
        """
        hidden_files = []
        # Scan critical directories
        scan_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/opt", "/var/log"]

        # Pre-compiled pattern for Electron/Chrome cache shared objects
        # Format: .fcb[16 hex chars]-[8 hex chars].so
        electron_cache_pattern = re.compile(r'^\.fcb[0-9a-f]{12}-[0-9a-f]{8}\.so$')

        # Known benign hidden file/directory patterns
        benign_patterns = {
            '.idea', '.vscode', '.cache', '.git', '.svn', '.hg',
            '.com.google.', '.org.chromium.', '.org.mozilla.',
            '.swf', '.tmp',
        }

        max_files_per_dir = 5000

        for scan_dir in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue

            try:
                with os.scandir(scan_dir) as it:
                    file_count = 0
                    for entry in it:
                        if file_count % 200 == 0:
                            if self._should_skip_due_to_timeout():
                                logger.warning(f"Filesystem collector: timeout during hidden file scan ({file_count} files)")
                                return hidden_files

                        try:
                            # Direct stat, avoid TOCTOU race condition
                            st = entry.stat(follow_symlinks=False)

                            # Check if regular file
                            if not stat.S_ISREG(st.st_mode):
                                continue

                            name = entry.name
                            if name in ('.', '..') or name == '.gitkeep':
                                continue

                            if name.startswith('.'):
                                # Skip known benign patterns
                                if any(pattern in name for pattern in benign_patterns):
                                    continue

                                # Skip Electron/Chrome cache .so files in /tmp
                                if scan_dir == "/tmp" and electron_cache_pattern.match(name):
                                    continue

                                if st.st_size > 0:
                                    mtime = _safe_timestamp_to_iso(st.st_mtime)
                                    hidden_files.append({
                                        "path": entry.path,
                                        "size": st.st_size,
                                        "mtime": mtime,
                                    })
                        except OSError:
                            continue

                        file_count += 1
                        # Enforce per-directory file limit
                        if file_count >= max_files_per_dir:
                            break
            except OSError:
                continue

        return hidden_files

    def _scan_recent_modified(self) -> list:
        """Scan files modified in the last 7 days in sensitive directories"""
        recent_modified = []
        sensitive_dirs = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        seven_days_ago = datetime.now() - timedelta(days=7)

        for scan_dir in sensitive_dirs:
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

                            mtime_iso = _safe_timestamp_to_iso(st.st_mtime)
                            mtime = fromisoformat(mtime_iso)

                            if mtime >= seven_days_ago:
                                recent_modified.append({
                                    "path": entry.path,
                                    "mtime": mtime_iso,
                                    "size": st.st_size,
                                })
                        except OSError:
                            continue
            except OSError:
                continue

        return recent_modified

    def _collect_history_files(self) -> dict:
        """Collect user history file information"""
        history_files = {}

        for user in self._user_home_dirs:
            username = user["username"]
            home_dir = user["home_dir"]

            # Check .bash_history
            bash_history = os.path.join(home_dir, ".bash_history")
            if os.path.exists(bash_history):
                try:
                    st = os.stat(bash_history)
                    history_files[bash_history] = {
                        "path": bash_history,
                        "username": username,
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                    }
                except OSError:
                    pass

        return history_files

    def _collect_shell_configs(self) -> dict:
        """Collect shell configuration file contents"""
        shell_configs = {}

        for user in self._user_home_dirs:
            home_dir = user["home_dir"]

            # Check .bashrc and .bash_profile
            for config_file in [".bashrc", ".bash_profile", ".profile"]:
                config_path = os.path.join(home_dir, config_file)
                if os.path.exists(config_path):
                    try:
                        file_size = os.path.getsize(config_path)
                        # Limit read size
                        if file_size > 1024 * 1024:  # 1MB
                            continue

                        with open(config_path, "r", errors='replace', encoding='utf-8') as f:
                            content = f.read(1024 * 1024)  # Read up to 1MB
                            shell_configs[config_path] = content
                    except OSError:
                        pass

        return shell_configs

    def _scan_skill_files(self) -> list:
        """Scan AI agent skill and configuration files

        Monitors directories:
        - $HOME/.qoder/skills/
        - $HOME/.claude/skills/
        - $HOME/.cursor/rules/
        - Common agent framework skill directories

        Returns:
            List of skill file metadata dicts with path, size, mtime
        """
        skill_files = []

        # Skill directory patterns to scan
        skill_dir_patterns = [
            '.qoder/skills',
            '.claude/skills',
            '.cursor/rules',
            'agents/skills',
            'agent/skills',
        ]

        # Skill file extensions
        skill_extensions = {'.md', '.markdown', '.yaml', '.yml', '.json', '.toml'}

        # Scan user home directories
        for user in self._user_home_dirs:
            home_dir = user["home_dir"]

            for skill_pattern in skill_dir_patterns:
                skill_dir = os.path.join(home_dir, skill_pattern)

                if not os.path.isdir(skill_dir):
                    continue

                try:
                    self._scan_skill_dir_recursive(
                        skill_dir, skill_extensions, skill_files,
                        depth=0, max_depth=3, max_files=1000
                    )
                except OSError:
                    continue

        return skill_files

    def _scan_skill_dir_recursive(
        self,
        directory: str,
        skill_extensions: set,
        result_list: list,
        depth: int,
        max_depth: int,
        max_files: int
    ) -> None:
        """Recursively scan skill directories"""
        if depth > max_depth or len(result_list) >= max_files:
            return

        try:
            with os.scandir(directory) as it:
                for entry in it:
                    if len(result_list) >= max_files:
                        break

                    try:
                        st = entry.stat(follow_symlinks=False)

                        if stat.S_ISREG(st.st_mode):
                            _, ext = os.path.splitext(entry.name)
                            if ext.lower() in skill_extensions:
                                mtime = _safe_timestamp_to_iso(st.st_mtime)
                                result_list.append({
                                    "path": entry.path,
                                    "size": st.st_size,
                                    "mtime": mtime,
                                    "username": os.path.basename(os.path.dirname(os.path.dirname(directory))),
                                })
                        elif stat.S_ISDIR(st.st_mode):
                            self._scan_skill_dir_recursive(
                                entry.path, skill_extensions, result_list,
                                depth + 1, max_depth, max_files
                            )
                    except OSError:
                        continue
        except OSError:
            pass
