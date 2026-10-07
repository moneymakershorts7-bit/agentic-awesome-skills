"""Systemd Timer and D-Bus Persistence Analyzer"""
import re
from typing import List, Dict, Any
from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
from .base import BaseAnalyzer
from ..utils.remediation_generator import generate_generic_remediation

class SystemdTimerAnalyzer(BaseAnalyzer):
    """Systemd Timer and D-Bus Activation Persistence Analyzer
    
    Detects persistence via:
    - T1053.006: Scheduled Task/Job: Systemd Timers
    - T1543.002: Create or Modify System Process: Systemd Service
    - T1546.008: Event Triggered Execution: Accessibility Features (D-Bus)
    """
    name = 'systemd_timer_analyzer'
    timeout = 30
    required_collectors = ['service']
    estimated_time = 5.0
    analyzer_type = BaseAnalyzer.CRITICAL
    SUSPICIOUS_COMMAND_PATTERNS = [re.compile('/dev/tcp/'), re.compile('curl\\s.*\\|\\s*bash', re.IGNORECASE), re.compile('wget\\s.*\\|\\s*bash', re.IGNORECASE), re.compile('/tmp/\\.'), re.compile('/dev/shm/'), re.compile('base64\\s+-d', re.IGNORECASE), re.compile('python.*-c\\s+[\'\\"]import', re.IGNORECASE), re.compile('nc\\s+.*-e', re.IGNORECASE), re.compile('mkfifo|named pipe', re.IGNORECASE)]
    SUSPICIOUS_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/']
    HIGH_FREQUENCY_CALENDAR = [re.compile('^\\*:\\d{1,2}/\\d+$'), re.compile('^\\*/\\d+$'), re.compile('^minutely$')]
    OFF_HOURS_PATTERN = re.compile('\\b(00|01|02|03|04|05):\\d{2}:\\d{2}\\b')
    TRUSTED_DBUS_NAMESPACES = {'org.freedesktop', 'org.bluez', 'org.NetworkManager', 'org.fedoraproject'}
    LEGITIMATE_SYSTEM_TIMERS = {'sysstat-collect.timer', 'sysstat-summary.timer', 'logrotate.timer', 'man-db.timer', 'apt-daily.timer', 'apt-daily-upgrade.timer', 'dnf-makecache.timer', 'systemd-tmpfiles-clean.timer', 'fstrim.timer', 'certbot-renew.timer', 'fwupd-refresh.timer', 'unattended-upgrades.timer', 'e2scrub_all.timer', 'mlocate.timer', 'shadow-utils.timer'}

    def should_skip(self) -> tuple:
        """Run lightweight check in quick mode instead of skipping."""
        return (False, '')
    def _is_legitimate_system_timer(self, timer_name: str) -> bool:
        """Check if timer is from a known legitimate system package."""
        return timer_name in self.LEGITIMATE_SYSTEM_TIMERS

    def analyze(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Analyze systemd timers and D-Bus services for persistence"""
        evidences = []
        service_data = self._get_data(collected_data, 'service')
        if not service_data:
            return evidences
        evidences.extend(self._detect_suspicious_timers(service_data))
        evidences.extend(self._detect_orphaned_timers(service_data))
        evidences.extend(self._detect_calendar_anomalies(service_data))
        evidences.extend(self._detect_dbus_activation(service_data))
        evidences.extend(self._detect_transient_units(service_data))
        return evidences

    def _detect_suspicious_timers(self, service_data: Dict) -> List[Evidence]:
        """Detect suspicious systemd timer configurations"""
        evidences = []
        timers = service_data.get('systemd_timers', [])
        if not timers:
            return evidences
        services_by_name = {}
        for svc in service_data.get('systemd_services', []):
            svc_name = svc.get('name', '')
            services_by_name[svc_name] = svc
        for timer in timers:
            timer_name = timer.get('name', '')
            unit_file = timer.get('unit_file', '')
            if not timer_name:
                continue
            if self._is_legitimate_system_timer(timer_name):
                continue
            associated_svc_name = timer.get('unit', '').replace('.timer', '.service')
            if not associated_svc_name:
                base_name = timer_name.replace('.timer', '.service')
                associated_svc_name = base_name
            associated_svc = services_by_name.get(associated_svc_name)
            exec_start = ''
            if associated_svc:
                exec_start = associated_svc.get('exec_start', '')
            if not exec_start:
                continue
            for pattern in self.SUSPICIOUS_COMMAND_PATTERNS:
                if pattern.search(exec_start):
                    evidences.append(self._create_evidence(title=f'Suspicious Systemd Timer: {timer_name}', description=f'Timer {timer_name} triggers service {associated_svc_name} with suspicious command pattern: {pattern.pattern}. ExecStart: {exec_start[:150]}', severity=Severity.HIGH, confidence=0.85, attack_id='T1053.006', source_path=unit_file, raw_data={'timer': timer_name, 'service': associated_svc_name, 'exec_start': exec_start, 'on_calendar': timer.get('on_calendar', [])}, remediation=f'Audit timer {timer_name} and service {associated_svc_name}. Verify ExecStart command legitimacy. Disable if unauthorized: systemctl disable --now {timer_name}', evidence_details=self._create_evidence_details(service_type='systemd_service'), remediation_commands=generate_generic_remediation(attack_id='1053.006', context={'analyzer': 'systemd_timer_analyzer'})))
                    break
            for susp_path in self.SUSPICIOUS_PATHS:
                if susp_path in exec_start:
                    evidences.append(self._create_evidence(title=f'Timer with Suspicious Path: {timer_name}', description=f'Timer {timer_name} service executes from suspicious path: {exec_start[:150]}', severity=Severity.HIGH, confidence=0.8, attack_id='T1053.006', source_path=unit_file, raw_data={'timer': timer_name, 'service': associated_svc_name, 'exec_start': exec_start, 'suspicious_path': susp_path}, remediation=f'Verify execution path legitimacy. Remove if unauthorized.', evidence_details=self._create_evidence_details(service_type='systemd_service'), remediation_commands=generate_generic_remediation(attack_id='1053.006', context={'analyzer': 'systemd_timer_analyzer'})))
                    break
            on_boot = timer.get('on_boot_sec', '')
            delay = timer.get('randomized_delay_sec', '')
            if on_boot and delay:
                try:
                    boot_sec = int(on_boot.rstrip('s'))
                    delay_sec = int(delay.rstrip('s'))
                    if boot_sec < 60 and delay_sec < 30:
                        evidences.append(self._create_evidence(title=f'Rapid Boot Timer: {timer_name}', description=f'Timer {timer_name} activates quickly after boot (OnBootSec={on_boot}, RandomizedDelaySec={delay}). May indicate early-stage persistence mechanism.', severity=Severity.MEDIUM, confidence=0.7, attack_id='T1053.006', source_path=unit_file, raw_data={'timer': timer_name, 'on_boot_sec': on_boot, 'randomized_delay_sec': delay}, remediation='Review boot-time activation necessity.', evidence_details=self._create_evidence_details(service_type='systemd_service'), remediation_commands=generate_generic_remediation(attack_id='1053.006', context={'analyzer': 'systemd_timer_analyzer'})))
                except (ValueError, AttributeError):
                    pass
        return evidences

    def _detect_orphaned_timers(self, service_data: Dict) -> List[Evidence]:
        """Detect orphaned timers without corresponding service files"""
        evidences = []
        timers = service_data.get('systemd_timers', [])
        if not timers:
            return evidences
        services_by_name = {}
        for svc in service_data.get('systemd_services', []):
            svc_name = svc.get('name', '')
            services_by_name[svc_name] = svc
        for timer in timers:
            timer_name = timer.get('name', '')
            unit_file = timer.get('unit_file', '')
            if not timer_name:
                continue
            if self._is_legitimate_system_timer(timer_name):
                continue
            declared_unit = timer.get('unit', '')
            if not declared_unit:
                declared_unit = timer_name.replace('.timer', '.service')
            has_service = declared_unit in services_by_name
            if not has_service:
                service_exists = False
                service_dirs = ['/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system']
                import os
                for svc_dir in service_dirs:
                    svc_path = os.path.join(svc_dir, declared_unit)
                    if os.path.exists(svc_path):
                        service_exists = True
                        break
                if not service_exists:
                    evidences.append(self._create_evidence(title=f'Orphaned Timer: {timer_name}', description=f'Timer {timer_name} references service {declared_unit} but no corresponding service file found. This may indicate incomplete cleanup or stealth persistence.', severity=Severity.MEDIUM, confidence=0.75, attack_id='T1053.006', source_path=unit_file, raw_data={'timer': timer_name, 'missing_service': declared_unit, 'on_calendar': timer.get('on_calendar', [])}, remediation=f'Investigate timer purpose. Disable if orphaned: systemctl disable --now {timer_name}', evidence_details=self._create_evidence_details(service_type='systemd_service'), remediation_commands=generate_generic_remediation(attack_id='1053.006', context={'analyzer': 'systemd_timer_analyzer'})))
        return evidences

    def _detect_calendar_anomalies(self, service_data: Dict) -> List[Evidence]:
        """Detect anomalous calendar expressions in timers"""
        evidences = []
        timers = service_data.get('systemd_timers', [])
        if not timers:
            return evidences
        for timer in timers:
            timer_name = timer.get('name', '')
            unit_file = timer.get('unit_file', '')
            calendars = timer.get('on_calendar', [])
            if not calendars:
                continue
            is_system_timer = unit_file and any((unit_file.startswith(path) for path in ['/usr/lib/systemd', '/lib/systemd']))
            if self._is_legitimate_system_timer(timer_name):
                continue
            for calendar_expr in calendars:
                if not calendar_expr:
                    continue
                for pattern in self.HIGH_FREQUENCY_CALENDAR:
                    if pattern.match(calendar_expr):
                        confidence = 0.5 if is_system_timer else 0.7
                        evidences.append(self._create_evidence(title=f'High-Frequency Timer: {timer_name}', description=f"Timer {timer_name} uses high-frequency schedule: '{calendar_expr}'. May indicate C2 communication or rapid data exfiltration.", severity=Severity.MEDIUM, confidence=confidence, attack_id='T1053.006', source_path=unit_file, raw_data={'timer': timer_name, 'calendar_expression': calendar_expr}, remediation='Review execution frequency necessity.', evidence_details=EvidenceDetail(file_path=unit_file, service_type='systemd_timer'), remediation_commands=['Stop and disable suspicious service', 'Review service configuration and logs', 'Check service dependencies', 'Investigate service origin and remove if malicious']))
                        break
                if self.OFF_HOURS_PATTERN.search(calendar_expr):
                    confidence = 0.4 if is_system_timer else 0.6
                    evidences.append(self._create_evidence(title=f'Off-Hours Timer: {timer_name}', description=f"Timer {timer_name} scheduled during off-hours: '{calendar_expr}'. Attackers often use nighttime schedules to avoid detection.", severity=Severity.LOW, confidence=confidence, attack_id='T1053.006', source_path=unit_file, raw_data={'timer': timer_name, 'calendar_expression': calendar_expr}, remediation='Verify scheduling aligns with business requirements.', evidence_details=EvidenceDetail(file_path=unit_file, service_type='systemd_timer'), remediation_commands=['Stop and disable suspicious service', 'Review service configuration and logs', 'Check service dependencies', 'Investigate service origin and remove if malicious']))
        return evidences

    def _detect_dbus_activation(self, service_data: Dict) -> List[Evidence]:
        """Detect suspicious D-Bus activated services"""
        evidences = []
        dbus_services = service_data.get('dbus_services', [])
        if not dbus_services:
            return evidences
        for svc in dbus_services:
            dbus_name = svc.get('dbus_name', '')
            exec_cmd = svc.get('exec', '')
            filepath = svc.get('file', '')
            if not exec_cmd:
                continue
            is_trusted = any((dbus_name.startswith(ns) for ns in self.TRUSTED_DBUS_NAMESPACES))
            if not is_trusted:
                for pattern in self.SUSPICIOUS_COMMAND_PATTERNS:
                    if pattern.search(exec_cmd):
                        evidences.append(self._create_evidence(title=f'Suspicious D-Bus Activation: {dbus_name}', description=f'D-Bus service {dbus_name} executes suspicious command: {exec_cmd[:150]}', severity=Severity.HIGH, confidence=0.8, attack_id='T1546.008', source_path=filepath, raw_data={'dbus_name': dbus_name, 'exec': exec_cmd, 'user': svc.get('user', '')}, remediation=f'Audit D-Bus service configuration. Remove unauthorized activations.', evidence_details=self._create_evidence_details(service_type='systemd_service'), remediation_commands=generate_generic_remediation(attack_id='1546.008', context={'analyzer': 'systemd_timer_analyzer'})))
                        break
                for susp_path in self.SUSPICIOUS_PATHS:
                    if susp_path in exec_cmd:
                        evidences.append(self._create_evidence(title=f'D-Bus Service Suspicious Path: {dbus_name}', description=f'D-Bus service {dbus_name} executes from suspicious path: {exec_cmd[:150]}', severity=Severity.HIGH, confidence=0.75, attack_id='T1546.008', source_path=filepath, raw_data={'dbus_name': dbus_name, 'exec': exec_cmd}, remediation='Verify execution path legitimacy.', evidence_details=EvidenceDetail(file_path=filepath, service_type='systemd_timer'), remediation_commands=['Stop and disable suspicious service', 'Review service configuration and logs', 'Check service dependencies', 'Investigate service origin and remove if malicious']))
                        break
        return evidences

    def _detect_transient_units(self, service_data: Dict) -> List[Evidence]:
        """Detect transient units created at runtime"""
        evidences = []
        import os
        transient_dir = '/run/systemd/transient'
        if not os.path.isdir(transient_dir):
            return evidences
        try:
            transient_files = os.listdir(transient_dir)
        except OSError:
            return evidences
        service_names = {svc.get('name', '') for svc in service_data.get('systemd_services', [])}
        for filename in transient_files:
            if not filename.endswith('.service'):
                continue
            if filename not in service_names:
                evidences.append(self._create_evidence(title=f'Transient Unit Detected: {filename}', description=f'Transient service unit {filename} found in {transient_dir}. Transient units are often created by systemd-run and may indicate ephemeral attack infrastructure.', severity=Severity.LOW, confidence=0.6, attack_id='T1543.002', source_path=os.path.join(transient_dir, filename), raw_data={'unit_file': filename, 'location': transient_dir}, remediation='Investigate transient unit creation source.', evidence_details=EvidenceDetail(file_path=os.path.join(transient_dir, filename), service_type='transient_unit'), remediation_commands=['Review systemd timer configurations for anomalies', 'Audit timer units for malicious service execution', 'Verify timer authenticity and remove unauthorized entries', 'Monitor for continued suspicious timer activity']))
        return evidences