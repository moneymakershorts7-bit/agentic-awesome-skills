"""Workspace Management Tool"""
import os
import shutil
import subprocess
import datetime
import logging
from .datetime_compat import date_fromisoformat
import venv


logger = logging.getLogger("sec-userspace")

# Default workspace root directory
# Priority: 1. /data/sec-userspace/workspace (absolute) 2. ./sec-userspace/workspace (relative)
DEFAULT_BASE_DIR = "/data/sec-userspace/workspace"
# Fallback relative path
FALLBACK_BASE_DIR = "sec-userspace/workspace"
# Disk quota limit: 1GB
WORKSPACE_MAX_BYTES = 1 * 1024 * 1024 * 1024


def get_today_workspace(base_dir: str = DEFAULT_BASE_DIR) -> str:
    """Get today's workspace directory path: {base_dir}/{YYYY-MM-DD}/"""
    today = datetime.date.today().isoformat()
    return os.path.join(base_dir, today)


def create_workspace(base_dir: str = DEFAULT_BASE_DIR) -> str:
    """
    Create today's workspace directory structure
    Path: {base_dir}/{YYYY-MM-DD}/
    Subdirectories: report/, tmp/
    
    Note: .venv is created at base_dir root (unified venv), not in date subdirectory
    """
    workspace_dir = get_today_workspace(base_dir)
    
    try:
        # Create base directory first (for unified venv and marker file)
        os.makedirs(base_dir, exist_ok=True)
        
        # Global marker file (under base_dir)
        marker_file = os.path.join(base_dir, ".sec-userspace-workspace")
        if not os.path.isfile(marker_file):
            with open(marker_file, 'w', encoding='utf-8') as f:
                f.write(datetime.datetime.now().isoformat())
        
        # Create date subdirectory structure (report/ and tmp/ only, no .venv)
        os.makedirs(workspace_dir, exist_ok=True)
        os.makedirs(os.path.join(workspace_dir, "report"), exist_ok=True)
        os.makedirs(os.path.join(workspace_dir, "tmp"), exist_ok=True)
        
        logger.info(f"Workspace created successfully: {workspace_dir}")
        return os.path.abspath(workspace_dir)
    except OSError as e:
        logger.error(f"Failed to create workspace: {e}", exc_info=True)
        raise


def get_or_create_venv(base_dir: str = DEFAULT_BASE_DIR) -> str:
    """
    Get or create unified Python venv at workspace root (base_dir)
    - NOT in date subdirectory to avoid duplication
    - Initialize on first creation, reuse afterwards
    - with_pip=False: do not install pip (only use standard library)
    - clear=False: do not clear existing directory, support reuse
    
    Args:
        base_dir: Workspace root directory (not date subdirectory)
        
    Returns:
        venv directory path
    """
    try:
        # Unified venv at base_dir root, NOT in date subdirectory
        venv_dir = os.path.join(base_dir, ".venv")
        python_bin = os.path.join(venv_dir, "bin", "python3")
        
        # Reuse if exists and available, don't recreate
        if os.path.isfile(python_bin):
            logger.info(f"Reusing existing unified venv: {venv_dir}")
            return venv_dir
        
        # First creation
        builder = venv.EnvBuilder(
            system_site_packages=False,
            with_pip=False,
            clear=False,  # Do not clear existing directory
        )
        builder.create(venv_dir)
        
        logger.info(f"Unified Python venv created successfully: {venv_dir}")
        return venv_dir
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"Failed to create Python venv: {e}, does not affect main flow")
        return ""


def create_venv(workspace_dir: str) -> str:
    """
    Deprecated: Use get_or_create_venv() instead.
    This function is kept for backward compatibility.
    
    Creates venv at parent directory of workspace_dir (which is base_dir).
    """
    # Extract base_dir from workspace_dir (parent directory)
    base_dir = os.path.dirname(workspace_dir)
    return get_or_create_venv(base_dir)


def validate_workspace(workspace_dir: str) -> bool:
    """Check workspace integrity"""
    try:
        report_dir = os.path.join(workspace_dir, "report")
        tmp_dir = os.path.join(workspace_dir, "tmp")
        
        # Marker file is under base_dir, not in date directory
        base_dir = os.path.dirname(workspace_dir)
        marker_file = os.path.join(base_dir, ".sec-userspace-workspace")
        
        if not os.path.isdir(report_dir):
            logger.warning(f"Workspace missing report directory: {report_dir}")
            return False
        
        if not os.path.isdir(tmp_dir):
            logger.warning(f"Workspace missing tmp directory: {tmp_dir}")
            return False
        
        # Marker file is optional (for compatibility)
        if not os.path.isfile(marker_file):
            logger.debug(f"Workspace base_dir missing marker file: {marker_file}")
        
        return True
    except OSError as e:
        logger.error(f"Failed to validate workspace: {e}", exc_info=True)
        return False


def check_quota(base_dir: str = DEFAULT_BASE_DIR, limit_bytes: int = WORKSPACE_MAX_BYTES) -> tuple:
    """
    Check overall size of /data/sec-userspace/workspace/ directory
    If exceeds 1GB, automatically clean up oldest date directories (keep last 7 days)
    Returns: (within_limit: bool, total_bytes: int)
    """
    try:
        total_bytes = _calc_dir_size(base_dir)
        
        if total_bytes > limit_bytes:
            logger.warning(f"Workspace exceeds 1GB limit: {total_bytes / 1024 / 1024:.1f}MB")
            _cleanup_old_reports(base_dir, keep_days=7)
            total_bytes = _calc_dir_size(base_dir)
        
        within_limit = total_bytes <= limit_bytes
        return (within_limit, total_bytes)
    except OSError as e:
        logger.error(f"Failed to check workspace quota: {e}", exc_info=True)
        return (True, 0)


def _calc_dir_size(directory: str, max_depth: int = 10) -> int:
    """Recursively calculate total directory size (bytes), max depth 10 levels"""
    if max_depth <= 0:
        logger.debug(f"Directory depth exceeds limit: {directory}")
        return 0

    total_size = 0
    try:
        for entry in os.scandir(directory):
            if entry.is_file(follow_symlinks=False):
                total_size += entry.stat().st_size
            elif entry.is_dir(follow_symlinks=False):
                total_size += _calc_dir_size(entry.path, max_depth - 1)
    except OSError as e:
        logger.debug(f"Failed to calculate directory size {directory}: {e}")
    return total_size


def _cleanup_old_reports(base_dir: str, keep_days: int = 7):
    """
    Clean up historical report directories older than keep_days
    Strategy: Delete directories with dates earlier than cutoff, keep last keep_days days
    """
    try:
        cutoff = datetime.date.today() - datetime.timedelta(days=keep_days)
        cleaned_count = 0
        
        for entry in sorted(os.scandir(base_dir), key=lambda e: e.name):
            if not entry.is_dir():
                continue
            
            # Skip special directories
            if entry.name.startswith('.'):
                continue
            
            # Date directory name format: YYYY-MM-DD
            try:
                dir_date = date_fromisoformat(entry.name)
                if dir_date < cutoff:
                    shutil.rmtree(entry.path, ignore_errors=True)
                    logger.info(f"Cleaned up expired report directory: {entry.path}")
                    cleaned_count += 1
            except ValueError:
                continue  # Non-date format directory, skip
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} expired report directories")
    except OSError as e:
        logger.error(f"Failed to cleanup expired reports: {e}", exc_info=True)


def cleanup_tmp(workspace_dir: str):
    """Clean up all files under workspace_dir/tmp/ directory"""
    try:
        tmp_dir = os.path.join(workspace_dir, "tmp")
        
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)
        
        # Recreate empty tmp directory
        os.makedirs(tmp_dir, exist_ok=True)
        
        logger.info(f"Temporary files cleanup completed: {tmp_dir}")
    except OSError as e:
        logger.error(f"Failed to cleanup temporary files: {e}", exc_info=True)
