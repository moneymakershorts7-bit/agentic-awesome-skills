"""DGA (Domain Generation Algorithm) Detection Analyzer

Implements multi-algorithm DGA detection using statistical analysis,
temporal pattern recognition, dictionary-based filtering, and ML-based classification.

ATT&CK Technique: T1679 - Domain Generation Algorithms
Tactic: Command and Control
"""
import os
import math
import re
import json
import shutil
from typing import List, Dict, Tuple, Optional
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from ..reporter.evidence import Evidence, Severity
from ..utils.datetime_compat import fromisoformat
from ..utils.remediation_generator import generate_generic_remediation
from .base import BaseAnalyzer
from ..utils.fp_tracker import get_tracker, is_false_positive, record_fp
import threading
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

import statistics as _statistics

class DGADetectionAnalyzer(BaseAnalyzer):
    """DGA Detection Analyzer - Detects algorithmically generated domains
    
    Detection capabilities:
    1. Statistical analysis (entropy, n-gram, consonant ratio)
    3. Dictionary-based filtering (whitelist/blacklist)
    4. Temporal pattern analysis (burst detection, NXDOMAIN correlation)
    5. Multi-criteria scoring with severity grading
    
    ATT&CK: T1679 - Domain Generation Algorithms
    """
    name = 'dga_detection_analyzer'
    timeout = 30
    required_collectors = ['network', 'dns', 'process']

    def should_skip(self) -> tuple:
        """Run lightweight check in quick mode instead of skipping."""
        return (False, '')

    estimated_time = 5.0
    analyzer_type = BaseAnalyzer.CRITICAL
    ATTACK_ID = 'T1679'
    ATTACK_TACTIC = 'Command and Control'
    MODEL_VERSION = '1.0'
    ENTROPY_SUSPICIOUS = 3.8
    ENTROPY_HIGH = 4.2
    DOMAIN_LENGTH_THRESHOLD = 15
    CONSONANT_RATIO_THRESHOLD = 0.6
    DIGIT_RATIO_MIN = 0.2
    DIGIT_RATIO_MAX = 0.8
    NXDOMAIN_RATE_THRESHOLD = 0.6
    QUERY_BURST_THRESHOLD = 10
    TEMPORAL_SCALES = {'short_term': {'window_minutes': 5, 'threshold': 10, 'purpose': 'Detect active DGA bursts'}, 'medium_term': {'window_minutes': 60, 'threshold': 50, 'purpose': 'Detect sustained DGA activity'}, 'long_term': {'window_minutes': 1440, 'threshold': 200, 'purpose': 'Detect periodic DGA patterns'}}

    def __init__(self, workspace_dir: str=None):
        super().__init__(workspace_dir)
        self._dns_baseline = None
        self._periodicity_cache = None
        self._load_dns_baseline()
        self._periodicity_cache = self._load_periodicity_cache()

    def _load_dns_baseline(self):
        """Load DNS behavior baseline from workspace with validation
        
        Loads persisted baseline data and validates structure.
        If primary file is corrupted, attempts to restore from backup.
        Creates new baseline if neither exists or both are invalid.
        """
        if not self.workspace_dir:
            self._dns_baseline = self._create_empty_baseline()
            return
        try:
            baseline_file = os.path.join(self.workspace_dir, 'dns_baseline.json')
            if os.path.exists(baseline_file):
                with open(baseline_file, 'r', encoding='utf-8') as f:
                    loaded_baseline = json.load(f)
                required_keys = ['total_days', 'avg_daily_queries', 'avg_unique_domains', 'avg_nxdomain_rate', 'hourly_distribution', 'daily_query_history']
                if all((k in loaded_baseline for k in required_keys)):
                    self._dns_baseline = loaded_baseline
                    _get_logger().info(f"Loaded DNS baseline with {self._dns_baseline.get('total_days', 0)} days of data")
                else:
                    missing = [k for k in required_keys if k not in loaded_baseline]
                    _get_logger().warning(f'Invalid baseline structure (missing: {missing}), attempting backup restoration')
                    self._restore_baseline_from_backup()
            else:
                self._dns_baseline = self._create_empty_baseline()
                _get_logger().info('No existing baseline found, created new baseline')
        except (json.JSONDecodeError, KeyError) as e:
            _get_logger().warning(f'Baseline file corrupted: {e}, attempting backup restoration')
            self._restore_baseline_from_backup()
        except OSError as e:
            _get_logger().warning(f'Failed to load DNS baseline: {e}')
            self._dns_baseline = self._create_empty_baseline()

    def _restore_baseline_from_backup(self):
        """Restore baseline from backup file if available"""
        if not self.workspace_dir:
            self._dns_baseline = self._create_empty_baseline()
            return
        try:
            backup_file = os.path.join(self.workspace_dir, 'dns_baseline.json.bak')
            if os.path.exists(backup_file):
                with open(backup_file, 'r', encoding='utf-8') as f:
                    restored_baseline = json.load(f)
                required_keys = ['total_days', 'avg_daily_queries', 'hourly_distribution']
                if all((k in restored_baseline for k in required_keys)):
                    self._dns_baseline = restored_baseline
                    _get_logger().info(f"Successfully restored baseline from backup: {self._dns_baseline.get('total_days', 0)} days")
                    return
            _get_logger().warning('Backup not found or invalid, creating new baseline')
            self._dns_baseline = self._create_empty_baseline()
        except (json.JSONDecodeError, OSError) as e:
            _get_logger().warning(f'Backup restoration failed: {e}, creating new baseline')
            self._dns_baseline = self._create_empty_baseline()

    def _create_empty_baseline(self) -> Dict:
        """Create empty DNS baseline structure"""
        return {'total_days': 0, 'avg_daily_queries': 0.0, 'avg_unique_domains': 0.0, 'avg_nxdomain_rate': 0.0, 'hourly_distribution': {}, 'daily_query_history': []}

    def _save_dns_baseline(self):
        """Save DNS behavior baseline to workspace with atomic writes and backup
        
        Implements atomic write strategy:
        1. Create backup of existing file (.bak)
        2. Write to temporary file (.tmp)
        3. Atomic replace using os.replace()
        
        This ensures file integrity even if process is interrupted during write.
        """
        if not self.workspace_dir or not self._dns_baseline:
            return
        try:
            baseline_file = os.path.join(self.workspace_dir, 'dns_baseline.json')
            os.makedirs(os.path.dirname(baseline_file), exist_ok=True)
            backup_file = baseline_file + '.bak'
            if os.path.exists(baseline_file):
                shutil.copy2(baseline_file, backup_file)
                _get_logger().debug(f'Created baseline backup at {backup_file}')
            temp_file = baseline_file + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(self._dns_baseline, f, indent=2)
            os.replace(temp_file, baseline_file)
            _get_logger().debug(f'Saved DNS baseline to {baseline_file}')
        except OSError as e:
            _get_logger().warning(f'Failed to save DNS baseline: {e}')
            try:
                temp_file = os.path.join(self.workspace_dir, 'dns_baseline.json.tmp')
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except OSError:
                pass

    def _update_dns_baseline(self, daily_stats: Dict):
        """Update DNS baseline with daily statistics using exponential smoothing"""
        if not self._dns_baseline:
            self._dns_baseline = self._create_empty_baseline()
        self._dns_baseline['total_days'] += 1
        alpha = 0.1
        self._dns_baseline['avg_daily_queries'] = alpha * daily_stats.get('total_queries', 0) + (1 - alpha) * self._dns_baseline.get('avg_daily_queries', 0)
        self._dns_baseline['avg_unique_domains'] = alpha * daily_stats.get('unique_domains', 0) + (1 - alpha) * self._dns_baseline.get('avg_unique_domains', 0)
        self._dns_baseline['avg_nxdomain_rate'] = alpha * daily_stats.get('nxdomain_rate', 0) + (1 - alpha) * self._dns_baseline.get('avg_nxdomain_rate', 0)
        for hour_str, count in daily_stats.get('hourly_distribution', {}).items():
            hour = int(hour_str)
            if hour not in self._dns_baseline['hourly_distribution']:
                self._dns_baseline['hourly_distribution'][str(hour)] = []
            self._dns_baseline['hourly_distribution'][str(hour)].append(count)
            if len(self._dns_baseline['hourly_distribution'][str(hour)]) > 30:
                self._dns_baseline['hourly_distribution'][str(hour)] = self._dns_baseline['hourly_distribution'][str(hour)][-30:]
        self._dns_baseline['daily_query_history'].append(daily_stats.get('total_queries', 0))
        if len(self._dns_baseline['daily_query_history']) > 30:
            self._dns_baseline['daily_query_history'] = self._dns_baseline['daily_query_history'][-30:]
        self._save_dns_baseline()

    def _archive_daily_stats(self, daily_stats: Dict):
        """Archive daily DNS statistics to dns_history directory
        
        Saves a snapshot of daily statistics for historical analysis.
        Files are named by date (YYYY-MM-DD.json) for easy retrieval.
        
        Args:
            daily_stats: Dictionary containing daily DNS statistics
        """
        if not self.workspace_dir:
            return
        try:
            history_dir = os.path.join(self.workspace_dir, 'dns_history')
            os.makedirs(history_dir, exist_ok=True)
            today_str = datetime.now().strftime('%Y-%m-%d')
            history_file = os.path.join(history_dir, f'{today_str}.json')
            archive_data = {'date': today_str, 'total_queries': daily_stats.get('total_queries', 0), 'unique_domains': daily_stats.get('unique_domains', 0), 'nxdomain_count': int(daily_stats.get('total_queries', 0) * daily_stats.get('nxdomain_rate', 0)), 'nxdomain_rate': daily_stats.get('nxdomain_rate', 0), 'hourly_distribution': daily_stats.get('hourly_distribution', {}), 'archived_at': datetime.now().isoformat(), 'analyzer_version': self.MODEL_VERSION}
            temp_file = history_file + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(archive_data, f, indent=2)
            os.replace(temp_file, history_file)
            _get_logger().debug(f'Archived daily stats to {history_file}')
            self._cleanup_old_history(retention_days=90)
        except OSError as e:
            _get_logger().warning(f'Failed to archive daily stats: {e}')

    def _cleanup_old_history(self, retention_days: int=90):
        """Remove DNS history files older than retention period
        
        Implements rolling retention policy to prevent unbounded storage growth.
        Keeps last N days of history, removes older files.
        
        Args:
            retention_days: Number of days to retain (default: 90)
        """
        if not self.workspace_dir:
            return
        try:
            history_dir = os.path.join(self.workspace_dir, 'dns_history')
            if not os.path.exists(history_dir):
                return
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            removed_count = 0
            for history_file in Path(history_dir).glob('*.json'):
                try:
                    file_date_str = history_file.stem
                    file_date = datetime.strptime(file_date_str, '%Y-%m-%d')
                    if file_date < cutoff_date:
                        os.remove(history_file)
                        _get_logger().debug(f'Removed old history file: {history_file.name}')
                        removed_count += 1
                except (ValueError, OSError) as e:
                    _get_logger().warning(f'Failed to process history file {history_file.name}: {e}')
            if removed_count > 0:
                _get_logger().info(f'Cleaned up {removed_count} old history files')
        except OSError as e:
            _get_logger().warning(f'Failed to cleanup old history: {e}')

    def _load_periodicity_cache(self):
        """Load periodicity detection cache from workspace
        
        Checks if cached results are still valid based on reanalysis schedule.
        Returns None if cache is stale or unavailable.
        """
        if not self.workspace_dir:
            return None
        try:
            cache_file = os.path.join(self.workspace_dir, 'dns_periodicity', 'analysis_results.json')
            if not os.path.exists(cache_file):
                return None
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            required_keys = ['last_analysis_date', 'next_reanalysis_date', 'results']
            if not all((k in cache_data for k in required_keys)):
                _get_logger().warning('Invalid periodicity cache structure')
                return None
            today_str = datetime.now().strftime('%Y-%m-%d')
            if today_str < cache_data['next_reanalysis_date']:
                _get_logger().info(f"Using cached periodicity results (valid until {cache_data['next_reanalysis_date']})")
                return cache_data['results']
            else:
                _get_logger().info('Periodicity cache expired, will reanalyze')
                return None
        except (json.JSONDecodeError, OSError) as e:
            _get_logger().warning(f'Failed to load periodicity cache: {e}')
            return None

    def _save_periodicity_cache(self, results: Dict):
        """Save periodicity detection results to cache
        
        Implements smart reanalysis schedule based on data quality:
        - < 3 days data: reanalyze daily
        - 3-7 days data: reanalyze every 3 days
        - > 7 days data: reanalyze weekly
        
        Args:
            results: Periodicity detection results to cache
        """
        if not self.workspace_dir or not results:
            return
        try:
            cache_dir = os.path.join(self.workspace_dir, 'dns_periodicity')
            os.makedirs(cache_dir, exist_ok=True)
            cache_file = os.path.join(cache_dir, 'analysis_results.json')
            total_days = self._dns_baseline.get('total_days', 0) if self._dns_baseline else 0
            if total_days < 3:
                reanalyze_interval = 1
                data_quality = 'insufficient'
            elif total_days < 7:
                reanalyze_interval = 3
                data_quality = 'developing'
            else:
                reanalyze_interval = 7
                data_quality = 'good'
            next_date = (datetime.now() + timedelta(days=reanalyze_interval)).strftime('%Y-%m-%d')
            cache_data = {'last_analysis_date': datetime.now().strftime('%Y-%m-%d'), 'next_reanalysis_date': next_date, 'data_quality': data_quality, 'baseline_days': total_days, 'results': results}
            temp_file = cache_file + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2)
            os.replace(temp_file, cache_file)
            _get_logger().debug(f'Saved periodicity cache (quality: {data_quality}, next analysis: {next_date})')
        except OSError as e:
            _get_logger().warning(f'Failed to save periodicity cache: {e}')

    def _should_reanalyze_periodicity(self) -> bool:
        """Check if periodicity reanalysis is needed
        
        Returns:
            True if reanalysis should be performed, False if cached results are valid
        """
        cache = self._load_periodicity_cache()
        return cache is None

    def _check_baseline_deviation(self, current_stats: Dict) -> Tuple[bool, float]:
        """Check if current statistics deviate significantly from baseline
        
        Returns:
            Tuple of (is_anomalous, anomaly_score 0-1)
        """
        if not self._dns_baseline or self._dns_baseline['total_days'] < 7:
            return (False, 0.0)
        anomaly_scores = []
        avg_queries = self._dns_baseline['avg_daily_queries']
        query_history = self._dns_baseline.get('daily_query_history', [])
        if query_history and len(query_history) > 1:
            std_queries = _statistics.stdev(query_history) if len(query_history) >= 2 else avg_queries * 0.3
            if std_queries > 0:
                z_score = abs(current_stats.get('total_queries', 0) - avg_queries) / std_queries
                anomaly_scores.append(z_score)
        avg_nxdomain = self._dns_baseline['avg_nxdomain_rate']
        current_nxdomain = current_stats.get('nxdomain_rate', 0)
        if current_nxdomain > avg_nxdomain * 2:
            anomaly_scores.append(2.0)
        for hour_str, count in current_stats.get('hourly_distribution', {}).items():
            if hour_str in self._dns_baseline['hourly_distribution']:
                historical = self._dns_baseline['hourly_distribution'][hour_str]
                if historical and len(historical) > 1:
                    avg_hourly = _statistics.mean(historical)
                    std_hourly = _statistics.stdev(historical) if len(historical) >= 2 else avg_hourly * 0.3
                    if std_hourly > 0 and count > avg_hourly + 3 * std_hourly:
                        anomaly_scores.append(3.0)
        if not anomaly_scores:
            return (False, 0.0)
        max_score = max(anomaly_scores)
        return (max_score > 2.0, min(max_score / 5.0, 1.0))

    def _classify_with_ml(self, domain: str, stats: Dict) -> Tuple[bool, float]:
        """Classify domain using rule-based method (ML removed)
        
        Args:
            domain: Domain name to classify
            stats: Statistical features extracted from domain
            
        Returns:
            Tuple of (is_dga, confidence_score)
        """
        return self._rule_based_classify(domain, stats)

    def _rule_based_classify(self, domain: str, stats: Dict) -> Tuple[bool, float]:
        """Rule-based DGA classification (fallback method)
        
        Args:
            domain: Domain name to classify
            stats: Statistical features
            
        Returns:
            Tuple of (is_dga, confidence_score)
        """
        entropy = stats.get('entropy', 0.0)
        consonant_ratio = stats.get('consonant_ratio', 0.0)
        suspicion_score = stats.get('suspicion_score', 0)
        confidence = 0.0
        if entropy > self.ENTROPY_HIGH:
            confidence += 0.4
        elif entropy > self.ENTROPY_SUSPICIOUS:
            confidence += 0.25
        if consonant_ratio > self.CONSONANT_RATIO_THRESHOLD:
            confidence += 0.3
        if suspicion_score >= 6:
            confidence += 0.3
        elif suspicion_score >= 4:
            confidence += 0.2
        is_dga = confidence >= 0.5
        return (is_dga, min(confidence, 1.0))
    LEGITIMATE_DOMAINS_WHITELIST = {'cloudfront.net', 'akamai.net', 'fastly.net', 'cloudflare.com', 'amazonaws.com', 's3.amazonaws.com', 'ec2.amazonaws.com', 'lambda.amazonaws.com', 'execute-api.amazonaws.com', 'elasticbeanstalk.com', 'elb.amazonaws.com', 'blob.core.windows.net', 'queue.core.windows.net', 'table.core.windows.net', 'file.core.windows.net', 'azurewebsites.net', 'azureedge.net', 'trafficmanager.net', 'servicebus.windows.net', 'database.windows.net', 'visualstudio.com', 'dev.azure.com', 'appspot.com', 'cloudfunctions.net', 'run.app', 'storage.googleapis.com', 'cloud.google.com', 'firebaseio.com', 'firestore.googleapis.com', 'svc.cluster.local', 'pod.cluster.local', 'cluster.local', 'svc.kubernetes.io', 'vercel.app', 'netlify.app', 'herokuapp.com', 'fly.dev', 'railway.app', 'render.com', 'onrender.com', 'deno.dev', 'deno.land', 'github.io', 'gitlab.io', 'pages.dev', 'circleci.com', 'travis-ci.org', 'appveyor.com', 'surge.sh', 'now.sh', 'glitch.me', 'repl.co', 'repl.it', 'codepen.io', 'stackblitz.com', 'codesandbox.io', 'jsfiddle.net', 'gstatic.com', 'googleapis.com', 'unpkg.com', 'jsdelivr.net', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'sharepoint.com', 'live.com', 'outlook.com', 'windows.net', 'msidentity.com', 'google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'github.com', 'gitlab.com', 'bitbucket.org', 'npmjs.com', 'pypi.org', 'rubygems.org', 'slack.com', 'zoom.us', 'office365.com'}
    ENGLISH_WORDS = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'its', 'may', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'she', 'use', 'her', 'long', 'make', 'many', 'more', 'then', 'them', 'these', 'they', 'this', 'will', 'with', 'have', 'from', 'been', 'call', 'first', 'find', 'here', 'thing', 'point', 'look', 'small', 'number', 'always', 'work', 'life', 'where', 'after', 'back', 'good', 'name', 'very', 'when', 'come', 'would', 'there', 'each', 'about', 'which', 'their', 'write', 'would', 'like', 'other', 'said', 'much', 'some', 'into', 'than', 'only', 'could', 'state', 'year', 'people', 'part', 'know', 'against', 'your', 'city', 'made', 'between', 'just', 'national', 'most', 'such', 'being', 'those', 'before', 'great', 'world', 'near', 'build', 'self', 'earth', 'man'}
    DGA_PATTERNS = [re.compile('^[a-z]{15,}\\d{3,}$', re.IGNORECASE), re.compile('^\\d{3,}[a-z]{10,}$', re.IGNORECASE), re.compile('^[a-z\\d]{20,}$', re.IGNORECASE), re.compile('^[bcdfghjklmnpqrstvwxz]{8,}$', re.IGNORECASE), re.compile('^[a-z]+\\d+[a-z]+\\d+[a-z]+$', re.IGNORECASE)]

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute DGA detection analysis with enhanced temporal and process correlation
        
        Args:
            collected_data: Collected data from network, dns, and process collectors
            
        Returns:
            List of DGA evidence objects
        """
        evidences = []
        tracker = get_tracker()
        tracker.record_detection('dga_detection_analyzer', 1)
        try:
            network_data = self._get_data(collected_data, 'network')
            dns_data = self._get_data(collected_data, 'dns', strict=False, default={})
            process_data = self._get_data(collected_data, 'process')
            if not network_data and (not dns_data):
                return evidences
            dns_queries = self._extract_dns_queries(dns_data)
            tcp_connections = self._extract_connections(network_data)
            processes = self._extract_processes(process_data)
            domain_stats = self._statistical_analysis(dns_queries, tcp_connections)
            temporal_results = self._temporal_analysis(dns_queries)
            if processes and dns_queries:
                suspicious_procs = self._correlate_process_dns(processes, dns_queries)
                if suspicious_procs:
                    temporal_results['suspicious_processes'] = suspicious_procs
            if temporal_results.get('total_queries', 0) > 0:
                daily_stats = {'total_queries': temporal_results['total_queries'], 'unique_domains': temporal_results['unique_domains'], 'nxdomain_rate': temporal_results['nxdomain_rate'], 'hourly_distribution': temporal_results.get('hourly_distribution', {})}
                self._update_dns_baseline(daily_stats)
                self._archive_daily_stats(daily_stats)
                if self._should_reanalyze_periodicity():
                    _get_logger().info('Performing periodicity reanalysis...')
                    periodic_result = temporal_results.get('periodic_pattern', {})
                    if periodic_result:
                        self._save_periodicity_cache(periodic_result)
            evidences.extend(self._generate_evidence(domain_stats, temporal_results, dns_queries))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().error(f'DGA detection analysis failed: {e}')
        return evidences

    def _extract_processes(self, process_data) -> List[Dict]:
        """Extract process information from collector data"""
        if not process_data:
            return []
        return process_data.get('processes', [])

    def _extract_dns_queries(self, dns_data) -> List[Dict]:
        """Extract DNS queries from collector data"""
        if not dns_data:
            return []
        return dns_data.get('queries', dns_data.get('dns_queries', []))

    def _extract_connections(self, network_data) -> List[Dict]:
        """Extract TCP connections from collector data"""
        if not network_data:
            return []
        connections = []
        for key in ['tcp_connections', 'tcp6_connections']:
            connections.extend(network_data.get(key, []))
        return connections

    def _statistical_analysis(self, dns_queries: List[Dict], connections: List[Dict]) -> Dict[str, Dict]:
        """Perform statistical analysis on domains
        
        Returns:
            Dict mapping domain to its statistical features
        """
        domain_features = {}
        observed_domains = set()
        for query in dns_queries:
            domain = query.get('domain', '')
            if domain:
                observed_domains.add(domain.lower())
        for conn in connections:
            hostname = conn.get('hostname', conn.get('remote_hostname', ''))
            if hostname:
                observed_domains.add(hostname.lower())
        for domain in observed_domains:
            if self._is_whitelisted(domain):
                continue
            if self._is_internal_domain(domain):
                continue
            features = self._extract_features(domain)
            if features['is_suspicious']:
                domain_features[domain] = features
        return domain_features

    def _extract_features(self, domain: str) -> Dict:
        """Extract statistical features from a domain and classify with ML
        
        Returns:
            Dict with feature values, suspicion score, and ML classification
        """
        parts = domain.split('.')
        if len(parts) < 2:
            return {'is_suspicious': False}
        sld = parts[0]
        entropy = self._calculate_shannon_entropy(sld)
        length_score = len(sld) > self.DOMAIN_LENGTH_THRESHOLD
        consonant_ratio = self._calculate_consonant_ratio(sld)
        digit_ratio = self._calculate_digit_ratio(sld)
        ngram_score = self._ngram_analysis(sld)
        has_dictionary_word = self._contains_dictionary_word(sld)
        matches_dga_pattern = self._matches_dga_pattern(domain)
        suspicion_score = 0
        reasons = []
        if entropy > self.ENTROPY_HIGH:
            suspicion_score += 3
            reasons.append(f'Very high entropy: {entropy:.2f}')
        elif entropy > self.ENTROPY_SUSPICIOUS:
            suspicion_score += 2
            reasons.append(f'High entropy: {entropy:.2f}')
        if length_score:
            suspicion_score += 1
            reasons.append(f'Long subdomain: {len(sld)} chars')
        if consonant_ratio > self.CONSONANT_RATIO_THRESHOLD:
            suspicion_score += 2
            reasons.append(f'High consonant ratio: {consonant_ratio:.2f}')
        if self.DIGIT_RATIO_MIN < digit_ratio < self.DIGIT_RATIO_MAX:
            suspicion_score += 1
            reasons.append(f'Suspicious digit ratio: {digit_ratio:.2f}')
        if ngram_score > 0.7:
            suspicion_score += 2
            reasons.append(f'Unusual n-gram pattern: {ngram_score:.2f}')
        if not has_dictionary_word and len(sld) > 10:
            suspicion_score += 1
            reasons.append('No recognizable dictionary words')
        if matches_dga_pattern:
            suspicion_score += 2
            reasons.append('Matches known DGA pattern')
        stats = {'entropy': entropy, 'consonant_ratio': consonant_ratio, 'suspicion_score': suspicion_score}
        ml_is_dga, ml_confidence = self._classify_with_ml(domain, stats)
        is_suspicious = suspicion_score >= 4 or (ml_is_dga and ml_confidence > 0.7)
        if ml_is_dga:
            reasons.append(f'ML classified as DGA (confidence: {ml_confidence:.2f})')
        return {'domain': domain, 'sld': sld, 'entropy': entropy, 'length': len(sld), 'consonant_ratio': consonant_ratio, 'digit_ratio': digit_ratio, 'ngram_score': ngram_score, 'has_dictionary_word': has_dictionary_word, 'matches_dga_pattern': matches_dga_pattern, 'suspicion_score': suspicion_score, 'reasons': reasons, 'is_suspicious': is_suspicious, 'ml_is_dga': ml_is_dga, 'ml_confidence': ml_confidence}

    def _calculate_shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _calculate_consonant_ratio(self, text: str) -> float:
        """Calculate ratio of consonants to total alphabetic characters"""
        vowels = set('aeiouAEIOU')
        alpha_chars = [c for c in text if c.isalpha()]
        if not alpha_chars:
            return 0.0
        consonants = [c for c in alpha_chars if c not in vowels]
        return len(consonants) / len(alpha_chars)

    def _calculate_digit_ratio(self, text: str) -> float:
        """Calculate ratio of digits to total characters"""
        if not text:
            return 0.0
        digits = sum((1 for c in text if c.isdigit()))
        return digits / len(text)

    def _ngram_analysis(self, text: str) -> float:
        """Analyze n-gram frequency patterns
        
        Returns:
            Score from 0.0 (normal) to 1.0 (highly unusual)
        """
        if len(text) < 3:
            return 0.0
        common_bigrams = {'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd', 'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar', 'st', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le', 've', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne', 'ea'}
        bigrams = [text[i:i + 2].lower() for i in range(len(text) - 1)]
        if not bigrams:
            return 0.0
        common_count = sum((1 for b in bigrams if b in common_bigrams))
        common_ratio = common_count / len(bigrams)
        return 1.0 - common_ratio

    def _contains_dictionary_word(self, text: str) -> bool:
        """Check if text contains recognizable dictionary words"""
        text_lower = text.lower()
        if text_lower in self.ENGLISH_WORDS:
            return True
        for word in self.ENGLISH_WORDS:
            if len(word) >= 4 and word in text_lower:
                return True
        return False

    def _matches_dga_pattern(self, domain: str) -> bool:
        """Check if domain matches known DGA patterns"""
        for pattern in self.DGA_PATTERNS:
            if pattern.search(domain):
                return True
        return False

    def _is_whitelisted(self, domain: str) -> bool:
        """Check if domain is in whitelist"""
        for wl_domain in self.LEGITIMATE_DOMAINS_WHITELIST:
            if domain.endswith(wl_domain) or domain == wl_domain:
                return True
        return False

    def _is_internal_domain(self, domain: str) -> bool:
        """Check if domain is internal/local"""
        internal_tlds = {'local', 'localdomain', 'localhost', 'lan', 'internal', 'home', 'corp', 'private', 'example', 'test', 'dev'}
        parts = domain.split('.')
        if parts and parts[-1] in internal_tlds:
            return True
        cloud_patterns = ['^ip-\\d+-\\d+-\\d+-\\d+', '^ec2-\\d+-\\d+-\\d+-\\d+', '^vm-\\d+', '^host-\\d+', '^[a-z0-9][a-z0-9\\-]*\\d{4,}\\.s3\\.', '^[a-z0-9][a-z0-9\\-]*\\d{4,}\\.blob\\.core\\.windows\\.net', '^[a-z0-9][a-z0-9\\-]*\\d{4,}\\.storage\\.googleapis\\.com', '^d[a-z0-9]+\\.cloudfront\\.net$', '^\\d{1,3}-\\d{1,3}-\\d{1,3}-\\d{1,3}\\..*\\.pod\\.cluster\\.local$', '^[a-z0-9\\-]+-[a-z0-9]{5}\\.[a-z0-9\\-]+\\.svc\\.cluster\\.local$', '^[a-z0-9][a-z0-9\\-]*-[a-z0-9]{5,}\\.(vercel|netlify)\\.app$', '^[a-z0-9][a-z0-9\\-]*-\\d+\\.(herokuapp|fly\\.dev|railway\\.app)$']
        for pattern in cloud_patterns:
            if re.match(pattern, domain, re.IGNORECASE):
                return True
        return False

    def _sliding_window_analysis(self, dns_queries: List[Dict], window_minutes: int, step_minutes: int, threshold: int) -> List[Dict]:
        """Sliding window analysis for temporal pattern detection
        
        Args:
            dns_queries: List of DNS query events with timestamps
            window_minutes: Window duration in minutes
            step_minutes: Step between windows in minutes
            threshold: Threshold for unique domains to trigger anomaly
            
        Returns:
            List of anomalies detected in each window
        """
        anomalies = []
        if not dns_queries:
            return anomalies
        parsed_queries = []
        for q in dns_queries:
            ts = q.get('timestamp', '')
            dt = self._parse_timestamp(ts)
            if dt:
                parsed_queries.append((dt, q))
        if not parsed_queries:
            return anomalies
        parsed_queries.sort(key=lambda x: x[0])
        start_time = parsed_queries[0][0]
        end_time = parsed_queries[-1][0]
        window_delta = timedelta(minutes=window_minutes)
        step_delta = timedelta(minutes=step_minutes)
        current_start = start_time
        while current_start < end_time:
            current_end = current_start + window_delta
            window_queries = [(dt, q) for dt, q in parsed_queries if current_start <= dt < current_end]
            if not window_queries:
                current_start += step_delta
                continue
            unique_domains = set((q['domain'].lower() for _, q in window_queries if q.get('domain')))
            nxdomain_count = sum((1 for _, q in window_queries if q.get('response_code') in ('NXDOMAIN', '3', 3)))
            unique_count = len(unique_domains)
            nxdomain_rate = nxdomain_count / max(len(window_queries), 1)
            if unique_count > threshold:
                anomalies.append({'window_start': current_start.isoformat(), 'window_end': current_end.isoformat(), 'unique_domains': unique_count, 'nxdomain_rate': round(nxdomain_rate, 2), 'total_queries': len(window_queries), 'domains': list(unique_domains)[:50]})
            current_start += step_delta
        return anomalies

    def _detect_periodic_patterns(self, dns_history: List[Dict], period_hours: int=24) -> Dict:
        """Detect periodic DGA activity patterns using standard library
        
        Args:
            dns_history: Historical DNS query data (7+ days)
            period_hours: Expected period in hours (default: 24)
            
        Returns:
            Dict with periodicity analysis results
        """
        if not dns_history:
            return {'periodic': False, 'reason': 'No data'}
        hourly_counts = self._build_hourly_time_series(dns_history)
        if len(hourly_counts) < period_hours * 3:
            return {'periodic': False, 'reason': 'Insufficient data'}
        try:
            mean_val = _statistics.mean(hourly_counts)
            variance = _statistics.variance(hourly_counts) if len(hourly_counts) >= 2 else 0
            if variance < 1e-06:
                return {'periodic': False, 'reason': 'No variance in data'}
            # Simple periodicity detection: compare variance of period-aligned buckets
            n_periods = len(hourly_counts) // period_hours
            if n_periods < 2:
                return {'periodic': False, 'reason': 'Insufficient periods'}
            period_sums = []
            for p in range(n_periods):
                start = p * period_hours
                end = start + period_hours
                period_sums.append(sum(hourly_counts[start:end]))
            if len(period_sums) >= 2:
                cv = _statistics.stdev(period_sums) / _statistics.mean(period_sums) if _statistics.mean(period_sums) > 0 else 0
                # Low coefficient of variation across periods suggests periodicity
                is_periodic = cv < 0.5 and mean_val > 1.0
                score = max(0, 1.0 - cv)
                return {'periodic': is_periodic, 'period_hours': period_hours, 'score': float(score), 'confidence': min(float(score / 0.6), 1.0)}
        except (ValueError, TypeError, ZeroDivisionError) as e:
            _get_logger().warning(f'Periodicity detection failed: {e}')
        return {'periodic': False, 'reason': 'No significant periodicity detected'}

    def _build_hourly_time_series(self, dns_history: List[Dict]) -> List[float]:
        """Build hourly time series from DNS history
        
        Args:
            dns_history: List of DNS query records with timestamps
            
        Returns:
            List of query counts per hour
        """
        if not dns_history:
            return []
        timestamps = []
        for record in dns_history:
            dt = self._parse_timestamp(record.get('timestamp', ''))
            if dt:
                timestamps.append(dt)
        if not timestamps:
            return []
        min_time = min(timestamps)
        max_time = max(timestamps)
        total_hours = int((max_time - min_time).total_seconds() / 3600) + 1
        hourly_counts = [0.0] * total_hours
        for dt in timestamps:
            hour_idx = int((dt - min_time).total_seconds() / 3600)
            if 0 <= hour_idx < total_hours:
                hourly_counts[hour_idx] += 1
        return hourly_counts

    def _parse_timestamp(self, timestamp: str) -> Optional[datetime]:
        """Parse timestamp string to datetime object"""
        if not timestamp:
            return None
        try:
            if 'T' in timestamp:
                return fromisoformat(timestamp)
            else:
                return datetime.fromtimestamp(float(timestamp))
        except (ValueError, TypeError, OSError):
            return None

    def _correlate_process_dns(self, processes: List[Dict], dns_queries: List[Dict]) -> List[Dict]:
        """Correlate DNS queries with processes
        
        Identify processes making suspicious DNS queries
        
        Args:
            processes: List of process information dicts
            dns_queries: List of DNS query dicts with PID info
            
        Returns:
            List of suspicious process-DNS correlations
        """
        process_dns_map = defaultdict(list)
        for query in dns_queries:
            pid = query.get('pid')
            if pid:
                process_dns_map[pid].append(query)
        suspicious_processes = []
        for pid, queries in process_dns_map.items():
            dga_count = 0
            for q in queries:
                domain = q.get('domain', '')
                if domain:
                    features = self._extract_features(domain)
                    if features.get('is_suspicious'):
                        dga_count += 1
            nxdomain_rate = sum((1 for q in queries if q.get('response_code') in ('NXDOMAIN', '3', 3))) / max(len(queries), 1)
            if dga_count > 5 or nxdomain_rate > 0.6:
                proc_info = next((p for p in processes if str(p.get('pid')) == str(pid)), {})
                suspicious_processes.append({'pid': pid, 'process_name': proc_info.get('name', proc_info.get('process_name', '')), 'cmdline': proc_info.get('cmdline', ''), 'user': proc_info.get('user', ''), 'dga_domain_count': dga_count, 'nxdomain_rate': round(nxdomain_rate, 2), 'total_queries': len(queries), 'sample_domains': [q['domain'] for q in queries[:10]]})
        return suspicious_processes

    def _temporal_analysis(self, dns_queries: List[Dict]) -> Dict:
        """Analyze temporal patterns in DNS queries with multi-scale analysis
        
        Returns:
            Dict with comprehensive temporal analysis results
        """
        if not dns_queries:
            return {'has_burst': False, 'nxdomain_rate': 0.0, 'multi_scale_analysis': {}, 'periodic_pattern': None, 'baseline_deviation': 0.0}
        time_buckets = defaultdict(set)
        nxdomain_count = 0
        total_queries = len(dns_queries)
        hourly_distribution = defaultdict(int)
        for query in dns_queries:
            timestamp = query.get('timestamp', '')
            domain = query.get('domain', '')
            response_code = query.get('response_code', query.get('rcode', ''))
            if not domain:
                continue
            minute_bucket = self._get_minute_bucket(timestamp)
            if minute_bucket:
                time_buckets[minute_bucket].add(domain.lower())
            dt = self._parse_timestamp(timestamp)
            if dt:
                hourly_distribution[str(dt.hour)] += 1
            if response_code in ('NXDOMAIN', '3', 3):
                nxdomain_count += 1
        has_burst = False
        max_unique_per_minute = 0
        for minute, domains in time_buckets.items():
            unique_count = len(domains)
            max_unique_per_minute = max(max_unique_per_minute, unique_count)
            if unique_count >= self.QUERY_BURST_THRESHOLD:
                has_burst = True
                break
        nxdomain_rate = nxdomain_count / total_queries if total_queries > 0 else 0.0
        multi_scale_results = {}
        for scale_name, config in self.TEMPORAL_SCALES.items():
            window_minutes = config['window_minutes']
            threshold = config['threshold']
            step_minutes = max(1, window_minutes // 5)
            anomalies = self._sliding_window_analysis(dns_queries, window_minutes=window_minutes, step_minutes=step_minutes, threshold=threshold)
            multi_scale_results[scale_name] = {'anomalies_detected': len(anomalies) > 0, 'anomaly_count': len(anomalies), 'threshold': threshold, 'window_minutes': window_minutes, 'sample_anomalies': anomalies[:3]}
        periodic_result = self._detect_periodic_patterns(dns_queries, period_hours=24)
        daily_stats = {'total_queries': total_queries, 'unique_domains': sum((len(domains) for domains in time_buckets.values())), 'nxdomain_rate': nxdomain_rate, 'hourly_distribution': dict(hourly_distribution)}
        is_baseline_deviation, deviation_score = self._check_baseline_deviation(daily_stats)
        return {'has_burst': has_burst, 'max_unique_per_minute': max_unique_per_minute, 'nxdomain_rate': nxdomain_rate, 'total_queries': total_queries, 'unique_domains': daily_stats['unique_domains'], 'multi_scale_analysis': multi_scale_results, 'periodic_pattern': periodic_result, 'baseline_deviation': deviation_score, 'is_baseline_deviation': is_baseline_deviation, 'hourly_distribution': dict(hourly_distribution)}

    def _get_minute_bucket(self, timestamp: str) -> Optional[str]:
        """Convert timestamp to minute bucket string"""
        if not timestamp:
            return None
        try:
            if 'T' in timestamp:
                dt = fromisoformat(timestamp)
            else:
                dt = datetime.fromtimestamp(float(timestamp))
            return dt.strftime('%Y-%m-%d %H:%M')
        except (ValueError, TypeError, OSError):
            return None

    def _generate_evidence(self, domain_stats: Dict, temporal_results: Dict, dns_queries: List[Dict]) -> List[Evidence]:
        """Generate evidence from analysis results with enhanced temporal context"""
        evidences = []
        if not domain_stats and (not temporal_results.get('has_burst')):
            return evidences
        suspicious_domains = list(domain_stats.values())
        num_suspicious = len(suspicious_domains)
        has_burst = temporal_results.get('has_burst', False)
        nxdomain_rate = temporal_results.get('nxdomain_rate', 0.0)
        multi_scale = temporal_results.get('multi_scale_analysis', {})
        periodic_pattern = temporal_results.get('periodic_pattern', {})
        baseline_deviation = temporal_results.get('baseline_deviation', 0.0)
        is_baseline_deviation = temporal_results.get('is_baseline_deviation', False)
        burst_count = sum((scale.get('anomaly_count', 0) for scale in multi_scale.values()))
        temporal_confidence_boost = 0.0
        if periodic_pattern.get('periodic'):
            temporal_confidence_boost += 0.1 * periodic_pattern.get('confidence', 0)
        if is_baseline_deviation:
            temporal_confidence_boost += 0.05 * baseline_deviation
        if burst_count > 0:
            temporal_confidence_boost += 0.05 * min(burst_count / 3, 1.0)
        if num_suspicious > 50 or (has_burst and nxdomain_rate > 0.8):
            severity = Severity.CRITICAL
            confidence = min(0.85 + temporal_confidence_boost, 0.95)
        elif num_suspicious > 20 or (has_burst and nxdomain_rate > 0.6):
            severity = Severity.HIGH
            confidence = min(0.75 + temporal_confidence_boost, 0.9)
        elif num_suspicious > 5 or nxdomain_rate > 0.6:
            severity = Severity.MEDIUM
            confidence = min(0.65 + temporal_confidence_boost, 0.8)
        elif num_suspicious > 0:
            severity = Severity.LOW
            confidence = min(0.5 + temporal_confidence_boost, 0.7)
        else:
            severity = Severity.LOW
            confidence = min(0.4 + temporal_confidence_boost, 0.6)
        top_domains = sorted(suspicious_domains, key=lambda x: x['suspicion_score'], reverse=True)[:20]
        domain_list = [d['domain'] for d in top_domains]
        avg_entropy = sum((d['entropy'] for d in suspicious_domains)) / num_suspicious if num_suspicious > 0 else 0.0
        context = f'{num_suspicious}_domains'
        if is_false_positive('dga_detection_analyzer', 'dga_detected', context=context):
            record_fp('dga_detection_analyzer', 'dga_detected', context=f'Suppressed: {context}')
            return evidences
        temporal_desc_parts = []
        if periodic_pattern.get('periodic'):
            period_hours = periodic_pattern.get('period_hours', 24)
            temporal_desc_parts.append(f'Periodic pattern detected (~{period_hours}h intervals)')
        if is_baseline_deviation:
            temporal_desc_parts.append(f'Activity {baseline_deviation:.1f}x above normal baseline')
        if burst_count > 0:
            temporal_desc_parts.append(f'{burst_count} burst events detected')
        temporal_desc = '. '.join(temporal_desc_parts) if temporal_desc_parts else ''
        title = f'DGA Domain Activity Detected: {num_suspicious} suspicious domains'
        if periodic_pattern.get('periodic'):
            title += ' with Periodic Pattern'
        evidence = self._create_evidence(severity=severity, confidence=confidence, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, title=title, description=f"Detected {num_suspicious} domains with DGA characteristics. Average entropy: {avg_entropy:.2f}. DNS burst detected: {has_burst}. NXDOMAIN rate: {nxdomain_rate:.1%}. Top suspicious domains: {', '.join(domain_list[:5])}" + (f'. {temporal_desc}' if temporal_desc else ''), raw_data={'total_domains_analyzed': len(domain_list), 'suspicious_domains': num_suspicious, 'average_entropy': round(avg_entropy, 2), 'dns_burst_detected': has_burst, 'nxdomain_rate': round(nxdomain_rate, 4), 'periodic_pattern': periodic_pattern, 'top_suspicious_domains': [{'domain': d['domain'], 'entropy': round(d['entropy'], 2), 'suspicion_score': d['suspicion_score'], 'reasons': d['reasons']} for d in top_domains[:10]]}, remediation='Investigate processes making DNS queries to these domains. Block identified DGA domains at DNS resolver. Check for malware indicators on affected systems. Monitor for continued DGA activity.' + (' Analyze periodic patterns for C2 communication timing.' if periodic_pattern.get('periodic') else ''), evidence_details=self._create_evidence_details(service_type='domain_generation'), remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'dga_detection_analyzer'}))
        evidences.append(evidence)
        return evidences