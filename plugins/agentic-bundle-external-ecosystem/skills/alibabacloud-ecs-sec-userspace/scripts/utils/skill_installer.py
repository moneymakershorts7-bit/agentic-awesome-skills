"""Automatically install skill to common AI tool directories at runtime"""
import logging
import os
import pwd
from pathlib import Path

logger = logging.getLogger(__name__)

# Supported AI tools: (tool name, skill directory relative to home, detect directory relative to home)
AI_TOOLS = [
    ("Qoder", ".qoder/skills", ".qoder"),
    ("Claude Code", ".claude/skills", ".claude"),
    ("OpenClaw", ".openclaw/skills", ".openclaw"),
    ("Windsurf", ".codeium/windsurf/skills", ".codeium"),
    ("Cursor", ".cursor/skills", ".cursor"),
    ("Gemini", ".gemini/skills", ".gemini"),
    ("Trae", ".trae/skills", ".trae"),
]

# Generic cross-tool path (agentskills.io standard)
UNIVERSAL_SKILL_DIR = ".agents/skills"

SKILL_NAME = "sec-userspace"


def _get_real_home() -> str:
    """Get real user home directory (handles sudo scenarios)"""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        # When running with sudo, use real user's home
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


def _get_skill_dir() -> str:
    """Get the root directory of the current skill"""
    # skill_installer.py -> utils/ -> scripts/ -> sec-userspace/
    return str(Path(__file__).resolve().parent.parent.parent)


def _install_link(skill_dir: str, target: str) -> bool:
    """Create a symlink pointing to target under skill_dir

    Returns:
        True if installation succeeded or already exists, False if failed
    """
    link_path = os.path.join(skill_dir, SKILL_NAME)

    try:
        os.makedirs(skill_dir, exist_ok=True)
    except OSError:
        return False

    if os.path.islink(link_path):
        current = os.readlink(link_path)
        if current == target:
            return True  # already correctly installed
        # pointing to different target，update
        try:
            os.remove(link_path)
            os.symlink(target, link_path)
            logger.info("update symlink: %s -> %s", link_path, target)
            return True
        except OSError:
            return False
    elif os.path.exists(link_path):
        # Same-name file or directory already exists (not symlink), do not overwrite
        return False

    try:
        os.symlink(target, link_path)
        logger.info("Installing symlink: %s -> %s", link_path, target)
        return True
    except OSError:
        return False


def install_skill_links() -> dict:
    """Scan common AI tool directories and install symlinks

    Returns:
        dict: {"installed": [...], "skipped": [...], "failed": [...]}
    """
    home = _get_real_home()
    skill_root = _get_skill_dir()
    result = {"installed": [], "skipped": [], "failed": []}

    for tool_name, skill_rel, detect_rel in AI_TOOLS:
        detect_path = os.path.join(home, detect_rel)
        if not os.path.isdir(detect_path):
            result["skipped"].append(tool_name)
            continue

        skill_path = os.path.join(home, skill_rel)
        if _install_link(skill_path, skill_root):
            result["installed"].append(tool_name)
        else:
            result["failed"].append(tool_name)

    # always install to generic path
    universal_path = os.path.join(home, UNIVERSAL_SKILL_DIR)
    if _install_link(universal_path, skill_root):
        result["installed"].append("universal")
    else:
        result["failed"].append("universal")

    return result
