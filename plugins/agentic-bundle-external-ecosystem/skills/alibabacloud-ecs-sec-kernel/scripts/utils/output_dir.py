"""
Output Directory Tool - Safely Create Output Directory and assign correct Permission

sec-kernel To root Run（PoC prepare/post phaseneedneed），ButOutputFileshouldBelongs to
passed sudo CallforOriginalUser。passed SUDO_UID/SUDO_GID RestoreAllPrivilege。
"""
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def ensure_output_dir(path: str) -> str:
    """Ensure Output Directory Exists and Belongs to Calling User (non-root)

    Args:
        path: TargetDirectoryPath

    Returns:
        Actual writable Directory Path (can degrade to backup Directory after)
    """
    dir_path = Path(path)

    # AttemptCreateDirectory
    try:
        dir_path.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        pass

    # 归alsoAllPrivilegeto sudo BeforeOriginalUser
    _chown_to_caller(str(dir_path))

    # VerificationcanWrite
    if os.path.isdir(str(dir_path)) and os.access(str(dir_path), os.W_OK):
        return str(dir_path)

    # degradeSolution
    fallbacks = [
        os.path.expanduser("~/workspace"),
        "/tmp/sec-kernel-output",
    ]
    for fallback in fallbacks:
        try:
            Path(fallback).mkdir(parents=True, exist_ok=True)
            _chown_to_caller(fallback)
            if os.access(fallback, os.W_OK):
                logger.warning("Output dir %s not writable, using %s",
                               path, fallback)
                return fallback
        except (PermissionError, OSError):
            continue

    logger.warning("All output dirs failed, using current directory")
    return "."


def chown_to_caller(filepath: str) -> None:
    """willFile/DirectoryAllPrivilege归alsoto sudo Caller（公开接口）"""
    _chown_to_caller(filepath)


def _chown_to_caller(filepath: str) -> None:
    """willFile/DirectoryAllPrivilege归alsoto sudo Caller

    WhenTo root RunWhen，passed SUDO_UID/SUDO_GID GetOriginalUser，
    willCreateFile/Directory chown ReturnOriginalUser，避免普通Userno法Operation。
    """
    if os.geteuid() != 0:
        return

    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")

    if not sudo_uid or not sudo_gid:
        return

    try:
        uid = int(sudo_uid)
        gid = int(sudo_gid)
        os.chown(filepath, uid, gid)
    except (OSError, ValueError):
        pass
