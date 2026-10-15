"""
LogID Generator for Evidence Tracking

Generates unique logid for each evidence in format: {YYYY-MM-DD}-case-{index}
Example: 2026-04-02-case-001
"""

from datetime import datetime
from pathlib import Path
from typing import Dict
import json
import threading


class LogIDGenerator:
    """Generate unique log IDs for evidence tracking"""

    def __init__(self, workspace_dir: str, date_str: str = None, persistent: bool = True):
        """
        Initialize LogID generator
        
        Args:
            workspace_dir: Workspace directory path (base_dir, not date subdirectory)
            date_str: Date string in YYYY-MM-DD format (defaults to today)
            persistent: If True, persist counters to disk. Set False for quick mode.
        """
        self.workspace_dir = Path(workspace_dir)
        self.date_str = date_str or datetime.now().strftime("%Y-%m-%d")
        self.counter_file = self.workspace_dir / ".logid_counter"
        self._counters: Dict[str, int] = {}
        self._persistent = persistent
        self._lock = threading.Lock()
        self._load_counters()
    
    def _load_counters(self):
        """Load counters from file"""
        if self.counter_file.exists():
            try:
                data = json.loads(self.counter_file.read_text(encoding='utf-8'))
                self._counters = data.get("counters", {})
            except (OSError, ValueError):
                self._counters = {}
    
    def _save_counters(self):
        """Save counters to file (only if persistent mode is enabled)"""
        if not self._persistent:
            return  # Skip file I/O in quick mode
        
        data = {
            "last_updated": datetime.now().isoformat(),
            "counters": self._counters
        }
        try:
            self.counter_file.parent.mkdir(parents=True, exist_ok=True)
            self.counter_file.write_text(json.dumps(data), encoding='utf-8')
        except OSError:
            pass
    
    def generate(self) -> str:
        """
        Generate a new unique log ID

        Format: {YYYY-MM-DD}-case-{index}
        Example: 2026-04-02-case-001

        Returns:
            Unique log ID string
        """
        with self._lock:
            if self.date_str not in self._counters:
                self._counters[self.date_str] = 0
            self._counters[self.date_str] += 1
            index = self._counters[self.date_str]
            self._save_counters()

        return f"{self.date_str}-case-{index:03d}"
    
    def reset(self):
        """Reset counter for new day"""
        self._counters[self.date_str] = 0
        self._save_counters()
    
    def get_current_count(self) -> int:
        """Get current counter value for today"""
        return self._counters.get(self.date_str, 0)
