"""Performance tracking and monitoring for sec-userspace analyzers

Tracks analyzer execution times, detects regressions, and generates alerts
when performance budgets are exceeded.
"""
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("sec-userspace")

# Performance budgets (seconds) - Quick Mode
PERFORMANCE_BUDGETS = {
    "process_analyzer": 2.0,
    "process_tree_analyzer": 2.0,
    "network_analyzer": 1.0,
    "file_analyzer": 5.0,
    "credential_analyzer": 5.0,
    "auth_analyzer": 2.0,
    "persistence_analyzer": 3.0,
    # log_analyzer disabled (confidence < 0.95)
    "threat_intel_analyzer": 1.0,
    "dga_detection_analyzer": 2.0,
    "rootkit_analyzer": 3.0,
    "malware_analyzer": 3.0,
    "webshell_analyzer": 2.0,
    "cloud_metadata_abuse_analyzer": 2.0,
    "cloud_storage_execution_analyzer": 2.0,
    "agent_token_theft_analyzer": 2.0,
    "agent_prompt_injection_analyzer": 2.0,
    "adversarial_ml_analyzer": 2.0,
    "autonomous_exploit_analyzer": 3.0,
    # Default budget for uncategorized analyzers
    "default": 2.0,
}

# Total scan time budgets
TOTAL_SCAN_BUDGETS = {
    "quick": 120.0,  # 2 minutes
    "full": 600.0,   # 10 minutes
}


class PerformanceTracker:
    """Track and analyze analyzer performance metrics"""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize performance tracker

        Args:
            db_path: Path to SQLite database. Defaults to workspace/perf.db
        """
        if db_path is None:
            # Use workspace directory for database (prefer user-writable locations)
            workspace_candidates = [
                Path("/data/sec-userspace/workspace"),
                Path.home() / "sec-userspace-workspace",
                Path.cwd() / "sec-userspace-workspace",
            ]
            
            workspace = None
            for candidate in workspace_candidates:
                try:
                    candidate.mkdir(parents=True, exist_ok=True)
                    # Test write permissions
                    test_file = candidate / ".write_test"
                    test_file.touch()
                    test_file.unlink()
                    workspace = candidate
                    break
                except OSError:
                    continue
            
            if workspace is None:
                # Last resort: use temp directory
                import tempfile
                workspace = Path(tempfile.gettempdir()) / "sec-userspace-perf"
                workspace.mkdir(parents=True, exist_ok=True)
            
            db_path = workspace / "perf.db"

        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database schema"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analyzer_performance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    analyzer_name TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    status TEXT NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    hostname TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_summary (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    total_duration_seconds REAL NOT NULL,
                    analyzer_count INTEGER NOT NULL,
                    success_count INTEGER NOT NULL,
                    failed_count INTEGER NOT NULL,
                    peak_memory_mb REAL,
                    hostname TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_analyzer_name
                ON analyzer_performance(analyzer_name)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_date
                ON analyzer_performance(scan_date)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_summary_date
                ON scan_summary(scan_date)
            """)

            conn.commit()

    def record_scan(self, report_data: Dict):
        """Record performance metrics from a scan report

        Args:
            report_data: Parsed JSON report data
        """
        try:
            scan_date = report_data.get("generated_at", datetime.now().isoformat())
            modules = report_data.get("modules", [])

            # Extract scan mode from report metadata if available
            scan_mode = "default"  # Single mode

            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()

                total_duration = 0.0
                success_count = 0
                failed_count = 0

                for module in modules:
                    name = module.get("name", "unknown")
                    duration = module.get("duration", 0.0)
                    status = module.get("status", "unknown")
                    findings = module.get("findings", 0)

                    total_duration += duration
                    if status == "success":
                        success_count += 1
                    else:
                        failed_count += 1

                    cursor.execute("""
                        INSERT INTO analyzer_performance
                        (scan_date, scan_mode, analyzer_name, duration_seconds,
                         status, findings_count, hostname)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_date,
                        scan_mode,
                        name,
                        duration,
                        status,
                        findings,
                        report_data.get("system", {}).get("hostname"),
                    ))

                cursor.execute("""
                    INSERT INTO scan_summary
                    (scan_date, scan_mode, total_duration_seconds,
                     analyzer_count, success_count, failed_count, hostname)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_date,
                    scan_mode,
                    total_duration,
                    len(modules),
                    success_count,
                    failed_count,
                    report_data.get("system", {}).get("hostname"),
                ))

                conn.commit()

            logger.debug(
                f"Recorded performance metrics for {len(modules)} analyzers "
                f"(total: {total_duration:.2f}s)"
            )

        except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as e:
            logger.error(f"Failed to record performance metrics: {e}")

    def get_analyzer_stats(
        self, analyzer_name: str, days: int = 7
    ) -> Dict[str, float]:
        """Get performance statistics for an analyzer

        Args:
            analyzer_name: Name of the analyzer
            days: Number of days to look back

        Returns:
            Dictionary with avg, max, min, p95 durations
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            cursor.execute("""
                SELECT
                    AVG(duration_seconds) as avg_duration,
                    MAX(duration_seconds) as max_duration,
                    MIN(duration_seconds) as min_duration,
                    COUNT(*) as sample_count
                FROM analyzer_performance
                WHERE analyzer_name = ? AND scan_date > ?
            """, (analyzer_name, cutoff_date))

            row = cursor.fetchone()

        if not row or row[0] is None:
            return {}

        return {
            "avg": row[0],
            "max": row[1],
            "min": row[2],
            "sample_count": row[3],
        }

    def check_budget_violations(self, report_data: Dict) -> List[Dict]:
        """Check if any analyzer exceeded its performance budget

        Args:
            report_data: Parsed JSON report data

        Returns:
            List of violation dictionaries
        """
        violations = []
        modules = report_data.get("modules", [])
        scan_mode = "default"  # Single mode

        for module in modules:
            name = module.get("name", "")
            duration = module.get("duration", 0.0)

            # Get budget for this analyzer
            budget = PERFORMANCE_BUDGETS.get(name, PERFORMANCE_BUDGETS["default"])

            if duration > budget:
                violations.append({
                    "analyzer": name,
                    "duration": duration,
                    "budget": budget,
                    "excess_percent": ((duration - budget) / budget) * 100,
                    "severity": "warning" if duration < budget * 1.5 else "critical",
                })

        # Check total scan time
        total_duration = sum(m.get("duration", 0.0) for m in modules)
        total_budget = TOTAL_SCAN_BUDGETS.get(scan_mode, 120.0)

        if total_duration > total_budget:
            violations.append({
                "analyzer": "TOTAL_SCAN",
                "duration": total_duration,
                "budget": total_budget,
                "excess_percent": ((total_duration - total_budget) / total_budget) * 100,
                "severity": "critical",
            })

        return violations

    def get_slowest_analyzers(
        self, days: int = 7, limit: int = 10
    ) -> List[Tuple[str, float]]:
        """Get the slowest analyzers by average duration

        Args:
            days: Number of days to look back
            limit: Maximum number of results

        Returns:
            List of (analyzer_name, avg_duration) tuples
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            cursor.execute("""
                SELECT
                    analyzer_name,
                    AVG(duration_seconds) as avg_duration
                FROM analyzer_performance
                WHERE scan_date > ?
                GROUP BY analyzer_name
                ORDER BY avg_duration DESC
                LIMIT ?
            """, (cutoff_date, limit))

            results = cursor.fetchall()

        return [(row[0], row[1]) for row in results]

    def get_performance_trend(
        self, analyzer_name: str, days: int = 30
    ) -> List[Dict]:
        """Get daily performance trend for an analyzer

        Args:
            analyzer_name: Name of the analyzer
            days: Number of days to look back

        Returns:
            List of daily average durations
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            cursor.execute("""
                SELECT
                    DATE(scan_date) as date,
                    AVG(duration_seconds) as avg_duration,
                    COUNT(*) as sample_count
                FROM analyzer_performance
                WHERE analyzer_name = ? AND scan_date > ?
                GROUP BY DATE(scan_date)
                ORDER BY date ASC
            """, (analyzer_name, cutoff_date))

            results = [
                {"date": row[0], "avg_duration": row[1], "samples": row[2]}
                for row in cursor.fetchall()
            ]

        return results
