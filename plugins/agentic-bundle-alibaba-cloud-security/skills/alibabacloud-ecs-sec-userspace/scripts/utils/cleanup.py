"""
Report lifecycle management

- Auto-cleanup reports older than retention period
- Run at startup before scan
- Log cleanup activity
"""

import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple

logger = logging.getLogger("sec-userspace")

# Default retention period (days)
DEFAULT_RETENTION_DAYS = 180


def cleanup_old_reports(
    workspace_dir: str = "/data/sec-userspace/workspace",
    retention_days: int = DEFAULT_RETENTION_DAYS,
    dry_run: bool = False
) -> Tuple[int, int]:
    """
    Clean up reports older than retention period
    
    Args:
        workspace_dir: Workspace directory path
        retention_days: Number of days to retain reports
        dry_run: If True, only report what would be deleted
        
    Returns:
        Tuple of (deleted_count, freed_bytes)
    """
    workspace = Path(workspace_dir)
    if not workspace.exists():
        return 0, 0
    
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    cutoff_str = cutoff_date.strftime("%Y-%m-%d")
    
    deleted_count = 0
    freed_bytes = 0
    
    # Find date directories (YYYY-MM-DD format)
    for item in workspace.iterdir():
        if not item.is_dir():
            continue
        
        # Check if directory name is a date
        dir_name = item.name
        if not _is_date_directory(dir_name):
            continue
        
        # Check if older than retention
        if dir_name < cutoff_str:
            dir_size = _get_dir_size(item)
            
            if dry_run:
                logger.info(f"[DRY-RUN] Would delete: {item} ({_format_size(dir_size)})")
            else:
                logger.info(f"Deleting: {item} ({_format_size(dir_size)})")
                shutil.rmtree(item)
            
            deleted_count += 1
            freed_bytes += dir_size
    
    return deleted_count, freed_bytes


def _is_date_directory(name: str) -> bool:
    """Check if directory name is a date (YYYY-MM-DD)"""
    try:
        datetime.strptime(name, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def _get_dir_size(path: Path) -> int:
    """Get total size of directory in bytes"""
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            try:
                total += item.stat().st_size
            except OSError:
                pass
    return total


def _format_size(size: int) -> str:
    """Format size in human-readable format"""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"
