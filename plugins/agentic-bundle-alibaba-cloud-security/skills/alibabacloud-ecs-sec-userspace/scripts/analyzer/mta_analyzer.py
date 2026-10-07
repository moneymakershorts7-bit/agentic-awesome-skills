"""MTA Abuse Detection Analyzer - T1505.002 Transport Agent"""
import os
import re
from datetime import datetime, timezone
from typing import List, Dict, Any

from ..reporter.evidence import Evidence
from ..reporter.severity import Severity
from .base import BaseAnalyzer
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

class MtaAnalyzer(BaseAnalyzer):
    """MTA (Mail Transfer Agent) Abuse Detection Analyzer
    
    Detects attacker behavior of using mail services for persistence or data exfiltration
    
    Detection capabilities:
    1. Exim/Postfix/Sendmail configuration audit
    2. Mail queue anomaly detection
    3. Anomalous mail sending patterns
    4. Unauthorized relay detection
    
    ATT&CK mapping: T1505.002 (Transport Agent)
    """
    
    name = "mta_analyzer"
    timeout = 60
    required_collectors = ["process", "filesystem", "log"]
    
    # MTA related processes
    MTA_PROCESSES = {'exim', 'postfix', 'sendmail', 'dovecot', 'courier', 'master'}
    
    # Common MTA configuration paths
    MTA_CONFIG_PATHS = {
        'exim': [
            '/etc/exim4/exim4.conf',
            '/etc/exim/exim.conf',
            '/etc/exim4/conf.d/main/01_exim4-config_listmacrosdefs',
        ],
        'postfix': [
            '/etc/postfix/main.cf',
            '/etc/postfix/master.cf',
        ],
        'sendmail': [
            '/etc/mail/sendmail.mc',
            '/etc/mail/sendmail.cf',
        ],
    }
    
    # Suspicious configuration patterns (pattern, description, severity)
    SUSPICIOUS_CONFIG_PATTERNS = [
        # Open relay detection
        (re.compile(r'relay_domains\s*=\s*\*?', re.IGNORECASE),
         "开放中继配置", Severity.HIGH, "T1505.002"),
        (re.compile(r'mynetworks\s*=.*0\.0\.0\.0/0', re.IGNORECASE),
         "允许所有网络中继", Severity.HIGH, "T1505.002"),
        (re.compile(r'mynetworks\s*=\s*"?\s*0\.0\.0\.0/0', re.IGNORECASE),
         "允许所有网络中继", Severity.HIGH, "T1505.002"),
        
        # Mail forwarding to external addresses
        (re.compile(r'virtual_alias_maps.*(?:curl|wget|http|https)', re.IGNORECASE),
         "远程虚拟别名映射", Severity.MEDIUM, "T1505.002"),
        (re.compile(r'transport_maps.*(?:curl|wget|http|https)', re.IGNORECASE),
         "远程传输映射", Severity.MEDIUM, "T1505.002"),
        
        # Suspicious pipe commands
        (re.compile(r'pipe\s*=\s*(?:/bin/(?:bash|sh)|/usr/bin/perl|/usr/bin/python)', re.IGNORECASE),
         "危险命令管道", Severity.CRITICAL, "T1505.002"),
        (re.compile(r'transport_filter\s*=\s*(?:/bin/(?:bash|sh)|nc |netcat)', re.IGNORECASE),
         "危险传输过滤器", Severity.CRITICAL, "T1505.002"),
        (re.compile(r'.*\|\s*(?:/bin/(?:bash|sh)|nc |netcat|curl|wget)', re.IGNORECASE),
         "可疑命令管道", Severity.HIGH, "T1505.002"),
        
        # Anomalous mail forwarding
        (re.compile(r'(?:forward|redirect)\s*:?\s*(?:/dev/null|/tmp/|\|.*sh)', re.IGNORECASE),
         "异常邮件转发规则", Severity.MEDIUM, "T1505.002"),
        
        # Authentication bypass
        (re.compile(r'smtpd_relay_restrictions\s*=.*permit', re.IGNORECASE),
         "宽松的中继限制", Severity.MEDIUM, "T1505.002"),
        (re.compile(r'smtpd_client_restrictions\s*=.*permit', re.IGNORECASE),
         "宽松的客户端限制", Severity.MEDIUM, "T1505.002"),
    ]
    
    # Mail log paths
    MAIL_LOG_PATHS = [
        '/var/log/mail.log',
        '/var/log/maillog',
        '/var/log/exim4/mainlog',
        '/var/log/exim_mainlog',
        '/var/log/exim4/rejectlog',
        '/var/log/exim_rejectlog',
        '/var/log/mail/mail.log',
    ]
    
    # Mail queue directories
    MAIL_QUEUE_DIRS = [
        '/var/spool/mqueue',
        '/var/spool/exim4',
        '/var/spool/exim',
        '/var/mail',
        '/var/spool/postfix',
    ]
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    @staticmethod
    def _get_timestamp() -> str:
        """Get current UTC timestamp string"""
        return datetime.now(timezone.utc).isoformat()
    
    def analyze(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Perform MTA abuse detection
        
        Args:
            collected_data: Collected data dictionary
            
        Returns:
            Evidence list
        """
        evidences = []
        
        try:
            # 1. Check if MTA process exists
            mta_processes = self._detect_mta_processes(collected_data)
            
            if not mta_processes:
                _get_logger().debug("[mta_analyzer] No MTA processes detected, skipping detection")
                return evidences
            
            _get_logger().info(f"[mta_analyzer] MTA processes detected: {mta_processes}")
            
            # 2. Configuration audit
            config_evidences = self._audit_mta_configs()
            evidences.extend(config_evidences)
            
            # 3. Mail queue detection
            queue_evidences = self._check_mail_queue()
            evidences.extend(queue_evidences)
            
            # 4. Log anomaly detection
            log_evidences = self._analyze_mail_logs(collected_data)
            evidences.extend(log_evidences)
            
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().error(f"[mta_analyzer] Detection error: {e}")
        
        _get_logger().info(f"[mta_analyzer] Detection complete, found {len(evidences)} evidences")
        return evidences
    
    def _detect_mta_processes(self, collected_data: Dict[str, Any]) -> List[str]:
        """Detect running MTA processes
        
        Args:
            collected_data: Collected process data
            
        Returns:
            MTA process name list
        """
        try:
            process_data = self._get_data(collected_data, "process")
            running_mta = set()
            
            for proc in process_data.get("processes", []):
                comm = proc.get("comm", "").lower()
                exe = proc.get("exe", "").lower()
                cmdline = proc.get("cmdline", "").lower()
                
                for mta in self.MTA_PROCESSES:
                    if mta in comm or mta in exe or mta in cmdline:
                        running_mta.add(mta)
            
            return list(running_mta)
        except KeyError:
            _get_logger().debug("[mta_analyzer] Unable to get process data")
            return []
    
    def _audit_mta_configs(self) -> List[Evidence]:
        """Audit MTA configuration files
        
        Returns:
            Evidence list
        """
        evidences = []
        
        for mta_type, config_paths in self.MTA_CONFIG_PATHS.items():
            for config_path in config_paths:
                if not os.path.exists(config_path):
                    continue
                
                try:
                    # Symlink safety check
                    os.lstat(config_path)
                    if os.path.islink(config_path):
                        _get_logger().debug(f"[mta_analyzer] Skipping symlink: {config_path}")
                        continue
                    
                    with open(config_path, 'r', errors='ignore', encoding='utf-8') as f:
                        content = f.read(512 * 1024)  # Limit 512KB
                    
                    for pattern, desc, severity, attack_id in self.SUSPICIOUS_CONFIG_PATTERNS:
                        if pattern.search(content):
                            evidence = Evidence(
                                id=f"mta-{mta_type}-config-{len(evidences)}",
                                module=self.name,
                                title=f"MTA 配置异常：{desc}",
                                description=f"{mta_type} 配置文件 {config_path} 包含可疑配置：{desc}",
                                severity=severity,
                                confidence=0.85,
                                attack_id=attack_id,
                                attack_tactic="Collection",
                                source_path=config_path,
                                timestamp=self._get_timestamp(),
                                remediation=f"check {config_path} 配置，移除恶意规则",
                                raw_data={
                                    "mta_type": mta_type,
                                    "config_file": config_path,
                                    "pattern_matched": pattern.pattern,
                                }
                            )
                            evidences.append(evidence)
                            
                except OSError as e:
                    _get_logger().debug(f"[mta_analyzer] Failed to read config {config_path}: {e}")
                except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
                    _get_logger().error(f"[mta_analyzer] Configuration audit error {config_path}: {e}")
        
        return evidences
    
    def _check_mail_queue(self) -> List[Evidence]:
        """Check mail queue anomalies
        
        Returns:
            Evidence list
        """
        evidences = []
        queue_threshold = 1000  # Threshold: 1000 emails
        
        for queue_dir in self.MAIL_QUEUE_DIRS:
            if not os.path.exists(queue_dir):
                continue
            
            try:
                files = os.listdir(queue_dir)
                file_count = len(files)
                
                if file_count > queue_threshold:
                    evidence = Evidence(
                        id=f"mta-queue-{len(evidences)}",
                        module=self.name,
                        title="邮件队列异常堆积",
                        description=f"邮件队列目录 {queue_dir} 包含 {file_count} 个文件 (阈值：{queue_threshold})",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        attack_id="T1505.002",
                        attack_tactic="Collection",
                        source_path=queue_dir,
                        timestamp=self._get_timestamp(),
                        remediation="check邮件队列，清理垃圾邮件，调查异常来源",
                        raw_data={
                            "queue_dir": queue_dir,
                            "file_count": file_count,
                            "threshold": queue_threshold,
                        }
                    )
                    evidences.append(evidence)
                    
            except OSError as e:
                _get_logger().debug(f"[mta_analyzer] Failed to check queue {queue_dir}: {e}")
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
                _get_logger().error(f"[mta_analyzer] Queue check error {queue_dir}: {e}")
        
        return evidences
    
    def _analyze_mail_logs(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Analyze mail log anomalies
        
        Args:
            collected_data: Collected log data
            
        Returns:
            Evidence list
        """
        evidences = []
        sender_threshold = 100  # Single user send threshold: 100 emails
        recipient_threshold = 50  # Single recipient threshold: 50 emails
        
        for log_path in self.MAIL_LOG_PATHS:
            if not os.path.exists(log_path):
                continue
            
            try:
                with open(log_path, 'r', errors='ignore', encoding='utf-8') as f:
                    # Read last 10MB of logs
                    content = f.read(10 * 1024 * 1024)
                    lines = content.splitlines()[-10000:]  # Last 10000 lines
                
                # Count sender distribution
                sender_counts: Dict[str, int] = {}
                recipient_counts: Dict[str, int] = {}
                
                for line in lines:
                    line_lower = line.lower()
                    
                    # Extract sender from=<...>
                    if 'from=' in line_lower:
                        match = re.search(r'from=<([^>]*)>', line, re.IGNORECASE)
                        if match:
                            sender = match.group(1)
                            sender_counts[sender] = sender_counts.get(sender, 0) + 1
                    
                    # Extract recipient to=<...>
                    if 'to=' in line_lower:
                        match = re.search(r'to=<([^>]*)>', line, re.IGNORECASE)
                        if match:
                            recipient = match.group(1)
                            recipient_counts[recipient] = recipient_counts.get(recipient, 0) + 1
                
                # Detect anomalous senders (single user sends > threshold)
                for sender, count in sender_counts.items():
                    if count > sender_threshold:
                        evidence = Evidence(
                            id=f"mta-log-sender-{len(evidences)}",
                            module=self.name,
                            title="异常邮件发送pattern",
                            description=f"发件人 '{sender or 'unknown'}' 在短时间内发送 {count} 封邮件 (阈值：{sender_threshold})",
                            severity=Severity.MEDIUM,
                            confidence=0.75,
                            attack_id="T1505.002",
                            attack_tactic="Collection",
                            source_path=log_path,
                            timestamp=self._get_timestamp(),
                            remediation="调查该发件人是否为正常业务行为，check是否被用于垃圾邮件",
                            raw_data={
                                "sender": sender or "unknown",
                                "count": count,
                                "threshold": sender_threshold,
                            }
                        )
                        evidences.append(evidence)
                
                # Detect anomalous recipients (single recipient receives > threshold)
                for recipient, count in recipient_counts.items():
                    if count > recipient_threshold:
                        evidence = Evidence(
                            id=f"mta-log-recipient-{len(evidences)}",
                            module=self.name,
                            title="异常邮件接收pattern",
                            description=f"收件人 '{recipient or 'unknown'}' 在短时间内接收 {count} 封邮件 (阈值：{recipient_threshold})",
                            severity=Severity.LOW,
                            confidence=0.65,
                            attack_id="T1505.002",
                            attack_tactic="Collection",
                            source_path=log_path,
                            timestamp=self._get_timestamp(),
                            remediation="调查该收件人是否为正常业务行为",
                            raw_data={
                                "recipient": recipient or "unknown",
                                "count": count,
                                "threshold": recipient_threshold,
                            }
                        )
                        evidences.append(evidence)
                        
            except OSError as e:
                _get_logger().debug(f"[mta_analyzer] Failed to read log {log_path}: {e}")
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
                _get_logger().error(f"[mta_analyzer] Log analysis error {log_path}: {e}")
        
        return evidences
