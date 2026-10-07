"""False Positive Tracking System for sec-userspace.

This module provides thread-safe false positive tracking and reporting
capabilities to help manage detection accuracy in production environments.
"""

import json
import logging
import os
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


# Default config paths for FP exceptions
DEFAULT_FP_EXCEPTIONS_PATHS = [
    '/etc/sec-userspace/fp-exceptions.json',
    os.path.expanduser('~/.sec-userspace/fp-exceptions.json'),
    os.path.join(os.path.dirname(__file__), 'fp-exceptions.json'),
]


@dataclass
class FPRecord:
    """False positive record."""
    
    analyzer: str
    evidence_type: str
    timestamp: float = field(default_factory=time.time)
    context: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'analyzer': self.analyzer,
            'evidence_type': self.evidence_type,
            'timestamp': self.timestamp,
            'datetime': datetime.fromtimestamp(self.timestamp).isoformat(),
            'context': self.context
        }


class FpTracker:
    """Thread-safe False Positive Tracker.
    
    Features:
    - Per-analyzer FP counters
    - FP rate calculation (FP / total detections)
    - Configurable thresholds with alerts
    - Weekly FP trend report generation
    - File-based logging for persistence
    
    Usage:
        tracker = FpTracker()
        tracker.record_fp('credential_analyzer', 'aws_key_false_positive')
        tracker.get_fp_rate('credential_analyzer')  # Returns FP rate
        tracker.generate_report('/path/to/report.md')
    """
    
    # Default thresholds (configurable)
    DEFAULT_FP_THRESHOLD = 0.10  # 10% FP rate alert threshold
    DEFAULT_WEEKLY_THRESHOLD = 50  # Alert if >50 FPs per week
    
    def __init__(self, log_dir: Optional[str] = None, 
                 fp_threshold: float = DEFAULT_FP_THRESHOLD,
                 weekly_threshold: int = DEFAULT_WEEKLY_THRESHOLD,
                 exceptions_path: Optional[str] = None,
                 enable_suppression: bool = True):
        """Initialize FP Tracker.
        
        Args:
            log_dir: Directory for FP log files (default: /var/log/sec-userspace/fp/)
            fp_threshold: FP rate threshold for alerts (default: 0.10 = 10%)
            weekly_threshold: Weekly FP count threshold (default: 50)
            exceptions_path: Path to FP exceptions config file
            enable_suppression: Enable FP suppression based on exceptions (default: True)
        """
        self._lock = threading.Lock()
        self._fp_counts: Dict[str, int] = defaultdict(int)
        self._total_detections: Dict[str, int] = defaultdict(int)
        self._fp_records: List[FPRecord] = []
        self._log_dir = log_dir or '/var/log/sec-userspace/fp'
        self._fp_threshold = fp_threshold
        self._weekly_threshold = weekly_threshold
        self._enable_suppression = enable_suppression
        self._fp_exceptions: Dict[str, Dict] = {}  # Per-analyzer exceptions
        self._detection_frequency: Dict[str, int] = defaultdict(int)
        self._auto_fp_threshold = 10  # Suggest after 10 occurrences
        self._suggested_rules: Dict[str, bool] = {}  # Track already-suggested rules
        self._enable_auto_fp = False  # Disabled by default
        
        # Ensure log directory exists
        try:
            os.makedirs(self._log_dir, exist_ok=True)
        except PermissionError:
            # Fallback to temp directory if no permission
            self._log_dir = '/tmp/sec-userspace-fp'
            os.makedirs(self._log_dir, exist_ok=True)
        
        # Setup dedicated FP logger
        self._logger = self._setup_logger()
        
        # Load existing records if available
        self._load_existing_records()
        
        # Load FP exceptions configuration
        self._fp_exceptions = self._load_fp_exceptions(exceptions_path)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup dedicated FP logger."""
        logger = logging.getLogger('sec-userspace-fp-tracker')
        logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers
        if not logger.handlers:
            try:
                handler = logging.FileHandler(
                    os.path.join(self._log_dir, 'fp-tracker.log'),
                    encoding='utf-8'
                )
                handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(levelname)s - %(message)s'
                ))
                logger.addHandler(handler)
            except PermissionError:
                # Fallback to memory-only logging if no file permission
                self._log_dir = '/tmp/sec-userspace-fp'
                os.makedirs(self._log_dir, exist_ok=True)
                handler = logging.FileHandler(
                    os.path.join(self._log_dir, 'fp-tracker.log'),
                    encoding='utf-8'
                )
                handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(levelname)s - %(message)s'
                ))
                logger.addHandler(handler)
        
        return logger
    
    def _load_existing_records(self):
        """Load existing FP records from log file."""
        log_file = os.path.join(self._log_dir, 'fp-records.json')
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._fp_records = [
                        FPRecord(
                            analyzer=record['analyzer'],
                            evidence_type=record['evidence_type'],
                            timestamp=record.get('timestamp', time.time()),
                            context=record.get('context')
                        ) for record in data.get('records', [])
                    ]
                    for record in self._fp_records:
                        self._fp_counts[record.analyzer] += 1
            except (json.JSONDecodeError, OSError, KeyError, TypeError):
                # Start fresh if file is corrupted
                self._fp_records = []
    
    def _load_fp_exceptions(self, custom_path: Optional[str] = None) -> Dict[str, Dict]:
        """Load FP exceptions configuration.
        
        Args:
            custom_path: Custom path to exceptions file (overrides defaults)
            
        Returns:
            Dictionary of exceptions per analyzer with pre-compiled patterns
        """
        paths_to_try = []
        
        # If custom path provided, use only that
        if custom_path:
            paths_to_try = [custom_path]
        else:
            # Try default paths in order
            paths_to_try = DEFAULT_FP_EXCEPTIONS_PATHS
        
        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        exceptions = json.load(f)
                    
                    # Pre-compile patterns and paths for performance
                    compiled_exceptions = {}
                    for analyzer, rules in exceptions.items():
                        compiled_exceptions[analyzer] = {}
                        for evidence_type, config in rules.items():
                            compiled_config = config.copy()
                            
                            # Pre-compile pattern regexes
                            if 'patterns' in config:
                                compiled_config['compiled_patterns'] = []
                                for p in config['patterns']:
                                    try:
                                        compiled_config['compiled_patterns'].append(
                                            re.compile(p)
                                        )
                                    except re.error as e:
                                        self._logger.warning(
                                            f"Invalid pattern '{p}': {e}"
                                        )
                            
                            # Pre-compile path regexes
                            if 'paths' in config:
                                compiled_config['compiled_paths'] = []
                                for p in config['paths']:
                                    try:
                                        compiled_config['compiled_paths'].append(
                                            re.compile(p)
                                        )
                                    except re.error as e:
                                        self._logger.warning(
                                            f"Invalid path pattern '{p}': {e}"
                                        )
                            
                            compiled_exceptions[analyzer][evidence_type] = compiled_config
                    
                    self._logger.info(f"Loaded FP exceptions from {path}")
                    return compiled_exceptions
                except (json.JSONDecodeError, OSError) as e:
                    self._logger.warning(f"Failed to load FP exceptions from {path}: {e}")
        
        # Return empty dict if no config found
        self._logger.info("No FP exceptions config found, suppression disabled")
        return {}
    
    def is_false_positive(self, analyzer: str, evidence_type: str,
                          context: Optional[str] = None,
                          filepath: Optional[str] = None) -> bool:
        """Check if a detection should be suppressed as a false positive.
        
        Args:
            analyzer: Name of the analyzer
            evidence_type: Type of evidence (e.g., 'aws_key', 'mining_tool')
            context: Optional context string (e.g., process name, username)
            filepath: Optional file path being analyzed
            
        Returns:
            True if this should be suppressed as a false positive
        """
        if not self._enable_suppression:
            return False
        
        # Check if analyzer has exceptions configured
        if analyzer not in self._fp_exceptions:
            return False
        
        analyzer_exceptions = self._fp_exceptions[analyzer]
        
        # Check if evidence_type has exceptions
        if evidence_type not in analyzer_exceptions:
            return False
        
        evidence_config = analyzer_exceptions[evidence_type]
        
        # Check pattern matches using pre-compiled patterns
        if 'compiled_patterns' in evidence_config and context:
            for compiled_pattern in evidence_config['compiled_patterns']:
                if compiled_pattern.match(context):
                    self._logger.debug(
                        f"FP suppressed: {analyzer}/{evidence_type} "
                        f"matched pattern"
                    )
                    return True
        
        # Check path matches using pre-compiled paths
        if 'compiled_paths' in evidence_config and filepath:
            for compiled_path in evidence_config['compiled_paths']:
                if compiled_path.match(filepath):
                    self._logger.debug(
                        f"FP suppressed: {analyzer}/{evidence_type} "
                        f"matched path"
                    )
                    return True
        
        # Check process names (for process-based detections)
        if 'processes' in evidence_config and context:
            allowed_processes = evidence_config['processes']
            if context in allowed_processes:
                self._logger.debug(
                    f"FP suppressed: {analyzer}/{evidence_type} "
                    f"allowed process '{context}'"
                )
                return True
        
        return False
    
    def get_exception_context(self, analyzer: str, evidence_type: str) -> Optional[str]:
        """Get the context description for an FP exception.
        
        Args:
            analyzer: Analyzer name
            evidence_type: Evidence type
            
        Returns:
            Context description if configured, None otherwise
        """
        if analyzer in self._fp_exceptions:
            if evidence_type in self._fp_exceptions[analyzer]:
                return self._fp_exceptions[analyzer][evidence_type].get('context')
        return None
    
    def _save_records(self):
        """Save FP records to file."""
        log_file = os.path.join(self._log_dir, 'fp-records.json')
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'records': [r.to_dict() for r in self._fp_records],
                    'counts': dict(self._fp_counts),
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except OSError as e:
            self._logger.error(f"Failed to save FP records: {e}")
    
    def record_fp(self, analyzer: str, evidence_type: str, 
                  context: Optional[str] = None):
        """Record a false positive.
        
        Args:
            analyzer: Name of the analyzer that generated the FP
            evidence_type: Type of evidence that was a FP
            context: Optional context about why this is a FP
        """
        with self._lock:
            record = FPRecord(
                analyzer=analyzer,
                evidence_type=evidence_type,
                context=context
            )
            self._fp_records.append(record)
            self._fp_counts[analyzer] += 1
            
            self._logger.info(
                f"FP recorded: analyzer={analyzer}, type={evidence_type}"
            )
            
            # Auto-save every 100 records
            if len(self._fp_records) % 100 == 0:
                self._save_records()
    
    def record_detection(self, analyzer: str, count: int = 1):
        """Record total detections for an analyzer.
        
        Args:
            analyzer: Name of the analyzer
            count: Number of detections to add
        """
        with self._lock:
            self._total_detections[analyzer] += count
    
    def get_fp_count(self, analyzer: str) -> int:
        """Get FP count for an analyzer.
        
        Args:
            analyzer: Analyzer name
            
        Returns:
            Number of false positives
        """
        with self._lock:
            return self._fp_counts.get(analyzer, 0)
    
    def get_total_detections(self, analyzer: str) -> int:
        """Get total detections for an analyzer.
        
        Args:
            analyzer: Analyzer name
            
        Returns:
            Total number of detections
        """
        with self._lock:
            return self._total_detections.get(analyzer, 0)
    
    def _get_fp_rate_unlocked(self, analyzer: str) -> float:
        """Calculate FP rate without acquiring lock. Caller must hold self._lock."""
        total = self._total_detections.get(analyzer, 0)
        if total == 0:
            return 0.0
        fps = self._fp_counts.get(analyzer, 0)
        return fps / total

    def get_fp_rate(self, analyzer: str) -> float:
        """Calculate FP rate for an analyzer.

        FP Rate = False Positives / Total Detections

        Args:
            analyzer: Analyzer name

        Returns:
            FP rate (0.0 to 1.0), or 0.0 if no detections
        """
        with self._lock:
            return self._get_fp_rate_unlocked(analyzer)
    
    def get_all_fp_rates(self) -> Dict[str, float]:
        """Get FP rates for all analyzers.
        
        Returns:
            Dictionary mapping analyzer names to FP rates
        """
        with self._lock:
            rates = {}
            for analyzer in set(self._fp_counts.keys()) | set(self._total_detections.keys()):
                rates[analyzer] = self._get_fp_rate_unlocked(analyzer)
            return rates
    
    def check_threshold(self, analyzer: str) -> tuple:
        """Check if FP rate exceeds threshold.
        
        Args:
            analyzer: Analyzer name
            
        Returns:
            Tuple of (exceeds_threshold: bool, message: str)
        """
        rate = self.get_fp_rate(analyzer)
        if rate > self._fp_threshold:
            return True, f"Analyzer '{analyzer}' FP rate {rate:.2%} exceeds threshold {self._fp_threshold:.2%}"
        return False, ""
    
    def _get_weekly_fps_unlocked(self) -> List[FPRecord]:
        """Get weekly FPs without acquiring lock. Caller must hold self._lock."""
        cutoff = time.time() - (7 * 24 * 60 * 60)
        return [r for r in self._fp_records if r.timestamp >= cutoff]

    def get_weekly_fps(self) -> List[FPRecord]:
        """Get FPs recorded in the last 7 days.

        Returns:
            List of FP records from the last week
        """
        with self._lock:
            return self._get_weekly_fps_unlocked()
    
    def generate_report(self, output_path: str) -> str:
        """Generate a comprehensive FP report.
        
        Args:
            output_path: Path to save the Markdown report
            
        Returns:
            Path to the generated report
        """
        with self._lock:
            now = datetime.now()
            weekly_fps = self._get_weekly_fps_unlocked()
            
            # Build report content
            lines = [
                "# False Positive Tracking Report",
                "",
                f"**Generated**: {now.isoformat()}",
                f"**Log Directory**: {self._log_dir}",
                "",
                "## Summary",
                "",
                f"- **Total Analyzers Tracked**: {len(set(self._fp_counts.keys()))}",
                f"- **Total False Positives**: {sum(self._fp_counts.values())}",
                f"- **Total Detections**: {sum(self._total_detections.values())}",
                f"- **Overall FP Rate**: {self._calculate_overall_rate():.2%}",
                "",
                "## Per-Analyzer FP Rates",
                "",
                "| Analyzer | FP Count | Total Detections | FP Rate | Status |",
                "|----------|----------|------------------|---------|--------|",
            ]
            
            alerts = []
            for analyzer in sorted(set(self._fp_counts.keys()) | set(self._total_detections.keys())):
                fp_count = self._fp_counts.get(analyzer, 0)
                total = self._total_detections.get(analyzer, 0)
                rate = self._get_fp_rate_unlocked(analyzer)
                status = "OK" if rate <= self._fp_threshold else "ALERT"
                
                if rate > self._fp_threshold:
                    alerts.append(f"- {analyzer}: {rate:.2%} FP rate")
                
                lines.append(
                    f"| {analyzer} | {fp_count} | {total} | {rate:.2%} | {status} |"
                )
            
            if alerts:
                lines.extend([
                    "",
                    "## Alerts",
                    "",
                    "The following analyzers exceed FP rate threshold:",
                    "",
                ] + alerts)
            
            lines.extend([
                "",
                "## Weekly Trend (Last 7 Days)",
                "",
                f"- **Total FPs This Week**: {len(weekly_fps)}",
            ])
            
            if len(weekly_fps) > self._weekly_threshold:
                lines.append(f"- **WARNING**: Weekly FP count ({len(weekly_fps)}) exceeds threshold ({self._weekly_threshold})")
            
            # Group by analyzer
            weekly_by_analyzer = defaultdict(int)
            for record in weekly_fps:
                weekly_by_analyzer[record.analyzer] += 1
            
            if weekly_by_analyzer:
                lines.extend([
                    "",
                    "### Weekly Breakdown by Analyzer",
                    "",
                    "| Analyzer | Weekly FPs |",
                    "|----------|------------|",
                ])
                for analyzer, count in sorted(weekly_by_analyzer.items(), key=lambda x: -x[1]):
                    lines.append(f"| {analyzer} | {count} |")
            
            lines.extend([
                "",
                "## Configuration",
                "",
                f"- **FP Rate Threshold**: {self._fp_threshold:.2%}",
                f"- **Weekly Count Threshold**: {self._weekly_threshold}",
            ])
            
            # Top 10 Most Suppressed Detections
            if self._fp_records:
                lines.extend([
                    "",
                    "## Top 10 Most Suppressed Detections",
                    "",
                    "| Rank | Analyzer | Evidence Type | Count | Percentage |",
                    "|------|----------|---------------|-------|------------|",
                ])
                
                fp_aggregates: Dict[str, int] = defaultdict(int)
                for record in self._fp_records:
                    key = f"{record.analyzer}:{record.evidence_type}"
                    fp_aggregates[key] += 1
                
                top_10 = sorted(fp_aggregates.items(), key=lambda x: -x[1])[:10]
                total_fps = sum(self._fp_counts.values())
                
                for rank, (key, count) in enumerate(top_10, 1):
                    parts = key.split(':', 1)
                    analyzer_name = parts[0]
                    evidence_type = parts[1] if len(parts) > 1 else ""
                    percentage = (count / total_fps * 100) if total_fps > 0 else 0
                    lines.append(
                        f"| {rank} | {analyzer_name} | {evidence_type} | {count} | {percentage:.1f}% |"
                    )
            
            # Per-Analyzer FP Rate Benchmark Comparison
            benchmarks = {
                'credential_analyzer': 0.05,
                'malware_analyzer': 0.02,
                'network_analyzer': 0.08,
                'process_analyzer': 0.05,
                'rootkit_analyzer': 0.02,
                'container_analyzer': 0.05,
                'persistence_analyzer': 0.05,
            }
            
            all_analyzers = sorted(set(self._fp_counts.keys()) | set(self._total_detections.keys()))
            if all_analyzers:
                lines.extend([
                    "",
                    "## Per-Analyzer Benchmark Comparison",
                    "",
                    "| Analyzer | FP Rate | Benchmark | Status |",
                    "|----------|---------|-----------|--------|",
                ])
                
                for analyzer in all_analyzers:
                    rate = self._get_fp_rate_unlocked(analyzer)
                    benchmark = benchmarks.get(analyzer, 0.05)
                    status = "OK" if rate <= benchmark else "HIGH"
                    lines.append(
                        f"| {analyzer} | {rate:.2%} | {benchmark:.2%} | {status} |"
                    )
            
            # Weekly ASCII Trend Chart
            if weekly_fps:
                daily_counts: Dict[str, int] = defaultdict(int)
                for record in weekly_fps:
                    day = datetime.fromtimestamp(record.timestamp).strftime('%Y-%m-%d')
                    daily_counts[day] += 1
                
                if daily_counts:
                    lines.extend([
                        "",
                        "## Weekly FP Trend (ASCII)",
                        "",
                        "```",
                    ])
                    
                    max_count = max(daily_counts.values())
                    for day in sorted(daily_counts.keys()):
                        count = daily_counts[day]
                        bar_length = int((count / max_count) * 40) if max_count > 0 else 0
                        bar = '#' * bar_length
                        lines.append(f"{day}: {bar} ({count})")
                    
                    lines.append("```")
            
            lines.extend([
                "",
                "---",
                "",
                "*Report generated by sec-userspace FpTracker*",
            ])
            
            # Write to file
            content = "\n".join(lines)
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self._logger.info(f"FP report generated: {output_path}")
            except OSError as e:
                self._logger.error(f"Failed to write FP report: {e}")
                # Fallback to log directory
                fallback_path = os.path.join(self._log_dir, f"fp-report-{now.strftime('%Y-%m-%d')}.md")
                with open(fallback_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                output_path = fallback_path
            
            return output_path
    
    def _calculate_overall_rate(self) -> float:
        """Calculate overall FP rate across all analyzers."""
        total_fps = sum(self._fp_counts.values())
        total_detections = sum(self._total_detections.values())
        if total_detections == 0:
            return 0.0
        return total_fps / total_detections
    
    def enable_auto_fp_suggestions(self, enabled: bool = True, threshold: int = 10):
        """Enable or disable auto-FP suggestion generation.
        
        Args:
            enabled: Whether to enable auto-FP suggestions
            threshold: Number of occurrences before suggesting (default: 10)
        """
        self._enable_auto_fp = enabled
        self._auto_fp_threshold = threshold
    
    def record_detection_with_context(self, analyzer: str, evidence_type: str,
                                       context: str, filepath: Optional[str] = None):
        """Record detection for auto-FP analysis.
        
        Args:
            analyzer: Analyzer name
            evidence_type: Evidence type
            context: Detection context string
            filepath: Optional file path
        """
        if not self._enable_auto_fp:
            return
        
        key = f"{analyzer}:{evidence_type}:{context}"
        
        with self._lock:
            self._detection_frequency[key] += 1
            
            if self._detection_frequency[key] >= self._auto_fp_threshold:
                if key not in self._suggested_rules:
                    self._suggest_fp_exception(analyzer, evidence_type, context, filepath)
                    self._suggested_rules[key] = True
    
    def _suggest_fp_exception(self, analyzer: str, evidence_type: str,
                              context: str, filepath: Optional[str]):
        """Generate FP exception suggestion and save to file."""
        occurrence_count = self._detection_frequency[
            f"{analyzer}:{evidence_type}:{context}"
        ]
        
        suggestion = {
            'analyzer': analyzer,
            'evidence_type': evidence_type,
            'occurrences': occurrence_count,
            'timestamp': datetime.now().isoformat(),
            'suggested_rule': {
                'patterns': [re.escape(context)] if context else [],
                'paths': [re.escape(filepath)] if filepath else [],
                'context': f"Auto-suggested: detected {occurrence_count} times"
            }
        }
        
        self._logger.info(f"Auto-FP Suggestion: {analyzer}/{evidence_type} ({occurrence_count} occurrences)")
        
        suggestion_file = os.path.join(self._log_dir, 'fp-suggestions.json')
        suggestions = []
        if os.path.exists(suggestion_file):
            try:
                file_size = os.path.getsize(suggestion_file)
                if file_size <= 10 * 1024 * 1024:  # 10MB limit
                    with open(suggestion_file, 'r', encoding='utf-8') as f:
                        suggestions = json.load(f)
            except (json.JSONDecodeError, OSError):
                suggestions = []
        
        # Avoid duplicates
        if not any(s.get('analyzer') == analyzer and
                   s.get('evidence_type') == evidence_type and
                   s.get('suggested_rule', {}).get('patterns') == suggestion['suggested_rule']['patterns']
                   for s in suggestions):
            suggestions.append(suggestion)
            try:
                with open(suggestion_file, 'w', encoding='utf-8') as f:
                    json.dump(suggestions, f, indent=2, default=str)
            except OSError as e:
                self._logger.error(f"Failed to save FP suggestions: {e}")
    
    def get_suggestions(self) -> List[dict]:
        """Get current auto-FP suggestions.
        
        Returns:
            List of suggestion dictionaries
        """
        suggestion_file = os.path.join(self._log_dir, 'fp-suggestions.json')
        if os.path.exists(suggestion_file):
            try:
                with open(suggestion_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return []
    
    def reset(self):
        """Reset all counters and records."""
        with self._lock:
            self._fp_counts.clear()
            self._total_detections.clear()
            self._fp_records.clear()
            self._save_records()
            self._logger.info("FP tracker reset")


# Global singleton instance (lazy initialization)
_tracker_instance: Optional[FpTracker] = None
_tracker_lock = threading.Lock()


def get_tracker(log_dir: Optional[str] = None, enable_suppression: bool = True) -> FpTracker:
    """Get or create the global FP tracker instance.
    
    Args:
        log_dir: Optional custom log directory
        enable_suppression: Enable FP suppression based on exceptions (default: True)
        
    Returns:
        FpTracker instance
    """
    global _tracker_instance
    if _tracker_instance is None:
        with _tracker_lock:
            if _tracker_instance is None:
                _tracker_instance = FpTracker(log_dir=log_dir, enable_suppression=enable_suppression)
    return _tracker_instance


def record_fp(analyzer: str, evidence_type: str, context: Optional[str] = None):
    """Convenience function to record a false positive.
    
    Args:
        analyzer: Analyzer name
        evidence_type: Evidence type
        context: Optional context
    """
    get_tracker().record_fp(analyzer, evidence_type, context)


def record_detection(analyzer: str, count: int = 1):
    """Convenience function to record detections.
    
    Args:
        analyzer: Analyzer name
        count: Detection count
    """
    get_tracker().record_detection(analyzer, count)


def is_false_positive(analyzer: str, evidence_type: str,
                      context: Optional[str] = None,
                      filepath: Optional[str] = None) -> bool:
    """Check if a detection should be suppressed as false positive.
    
    Args:
        analyzer: Analyzer name
        evidence_type: Evidence type
        context: Optional context (process name, username, etc.)
        filepath: Optional file path
        
    Returns:
        True if should be suppressed
    """
    return get_tracker().is_false_positive(analyzer, evidence_type, context, filepath)


def get_exception_context(analyzer: str, evidence_type: str) -> Optional[str]:
    """Get context description for an FP exception.
    
    Args:
        analyzer: Analyzer name
        evidence_type: Evidence type
        
    Returns:
        Context description or None
    """
    return get_tracker().get_exception_context(analyzer, evidence_type)
