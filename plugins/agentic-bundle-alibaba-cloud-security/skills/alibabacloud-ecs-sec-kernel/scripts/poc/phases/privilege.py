"""
PrivilegeManager - Privilege Switching Utilities

Provides utilities for:
- sudo verification and execution
- setuid/setgid demotion to unprivileged user
- User switching (su -c)
"""
import os
import sys
import pwd
import grp
import logging
import subprocess
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)

# Default unprivileged users (in order of preference)
DEFAULT_UNPRIVILEGED_USERS = ["nobody", "daemon"]


class PrivilegeManager:
    """
    Privilege Manager

    Handles privilege switching for three-phase PoC verification.
    """

    def __init__(self, target_user: str = "nobody",
                 fallback_user: str = "daemon",
                 force_demote: bool = True):
        """
        Args:
            target_user: Primary unprivileged user for Run phase
            fallback_user: Fallback user if target unavailable
            force_demote: Force demotion even if running as root
        """
        self.target_user = target_user
        self.fallback_user = fallback_user
        self.force_demote = force_demote
        self._resolved_user: Optional[str] = None
        self._resolved_uid: Optional[int] = None

    def resolve_user(self) -> Tuple[str, int]:
        """
        Resolve the user to execute PoC as.

        Returns:
            Tuple of (username, uid)

        Raises:
            RuntimeError: If no suitable user found
        """
        if self._resolved_user is not None:
            return self._resolved_user, self._resolved_uid

        # Try target user first
        user, uid = self._lookup_user(self.target_user)
        if user:
            self._resolved_user = user
            self._resolved_uid = uid
            return user, uid

        # Try fallback user
        user, uid = self._lookup_user(self.fallback_user)
        if user:
            self._resolved_user = user
            self._resolved_uid = uid
            logger.warning(
                "Target user '%s' not found, using fallback '%s'",
                self.target_user, self.fallback_user
            )
            return user, uid

        raise RuntimeError(
            f"No suitable unprivileged user found. "
            f"Tried: {self.target_user}, {self.fallback_user}"
        )

    def _lookup_user(self, username: str) -> Tuple[Optional[str], Optional[int]]:
        """Look up a user by name"""
        try:
            pw_entry = pwd.getpwnam(username)
            return username, pw_entry.pw_uid
        except KeyError:
            return None, None

    @staticmethod
    def check_sudo_available() -> bool:
        """Check if sudo is available"""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def execute_as_user(self, cmd: list, env: Dict[str, str] = None,
                        timeout: int = 10) -> subprocess.CompletedProcess:
        """
        Execute a command as the resolved unprivileged user.

        Args:
            cmd: Command list to execute
            env: Environment variables
            timeout: Execution timeout

        Returns:
            CompletedProcess result
        """
        user, uid = self.resolve_user()

        # Build su command
        su_cmd = ["su", "-s", "/bin/sh", user, "-c"]

        # Quote the command properly
        quoted_cmd = " ".join(_quote_arg(arg) for arg in cmd)
        su_cmd.append(quoted_cmd)

        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        logger.info(
            "Executing as user '%s' (UID %d): %s",
            user, uid, quoted_cmd
        )

        return subprocess.run(
            su_cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            timeout=timeout,
            env=exec_env
        )

    def execute_with_sudo(self, cmd: list, env: Dict[str, str] = None,
                          timeout: int = 10) -> subprocess.CompletedProcess:
        """
        Execute a command with sudo.

        Args:
            cmd: Command list (without sudo prefix)
            env: Environment variables
            timeout: Execution timeout

        Returns:
            CompletedProcess result

        Raises:
            RuntimeError: If sudo not available
        """
        if not self.check_sudo_available():
            raise RuntimeError(
                "sudo not available or requires password"
            )

        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        sudo_cmd = ["sudo", "-n"] + cmd

        logger.info("Executing with sudo: %s", " ".join(cmd))

        return subprocess.run(
            sudo_cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            timeout=timeout,
            env=exec_env
        )

    @staticmethod
    def demote_uid(uid: int, gid: int = -1) -> None:
        """
        Demote current process to specified UID/GID.

        WARNING: This is irreversible in the current process.
        Use only in child processes.

        Args:
            uid: Target UID
            gid: Target GID (defaults to UID's primary group)
        """
        if gid < 0:
            try:
                pw = pwd.getpwuid(uid)
                gid = pw.pw_gid
            except KeyError:
                gid = uid

        logger.debug("Demoting to UID=%d, GID=%d", uid, gid)

        # Set groups first (requires privileges)
        try:
            os.initgroups(pwd.getpwuid(uid).pw_name, gid)
        except (OSError, KeyError):
            # Ignore if not root
            pass

        os.setgid(gid)
        os.setuid(uid)

        # Verify demotion
        actual_uid = os.getuid()
        if actual_uid != uid:
            raise RuntimeError(
                f"UID demotion failed: expected {uid}, got {actual_uid}"
            )

    @staticmethod
    def verify_demotion(expected_uid: int) -> bool:
        """Verify current process UID"""
        return os.getuid() == expected_uid


def _quote_arg(arg: str) -> str:
    """Quote a shell argument safely"""
    # Use repr for safe quoting, then strip outer quotes
    quoted = repr(arg)
    if quoted.startswith("'") and quoted.endswith("'"):
        # Replace single quotes with properly escaped version
        return "'" + arg.replace("'", "'\\''") + "'"
    return quoted
