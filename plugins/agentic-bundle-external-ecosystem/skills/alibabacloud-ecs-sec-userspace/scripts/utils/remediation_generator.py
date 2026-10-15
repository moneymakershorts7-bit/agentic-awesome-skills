"""Remediation command generator utility

Provides type-specific, actionable remediation commands for different
evidence types (process, file, network, credential, etc.)

This module replaces generic remediation messages like
"Investigate T{attack_id} indicator" with specific, actionable commands.
"""
from typing import List, Optional, Dict, Any


def generate_process_remediation(
    pid: Optional[int] = None,
    cmdline: Optional[str] = None,
    attack_id: str = "",
    severity: str = "HIGH",
    context: Optional[Dict[str, Any]] = None
) -> List[str]:
    """Generate remediation commands for process-related findings.
    
    Args:
        pid: Process ID
        cmdline: Process command line
        attack_id: MITRE ATT&CK technique ID
        severity: Severity level
        context: Additional context (parent_pid, user, executable, etc.)
    
    Returns:
        List of remediation commands
    """
    commands = []
    commands.append("# 1. Investigate process details")
    
    if pid:
        commands.append(f"ps aux | grep {pid}")
        commands.append(f"cat /proc/{pid}/status 2>/dev/null | head -20")
        commands.append(f"ls -la /proc/{pid}/exe 2>/dev/null")
        
        if cmdline:
            commands.append(f"# Process command: {cmdline[:100]}")
        
        if context and context.get('parent_pid'):
            commands.append(f"# Parent PID: {context['parent_pid']}")
            commands.append(f"ps -p {context['parent_pid']} -o pid,ppid,cmd 2>/dev/null")
        
        commands.append("# 2. Check process network connections")
        commands.append(f"ss -tunap | grep {pid} 2>/dev/null || netstat -tunap | grep {pid} 2>/dev/null")
        
        commands.append("# 3. Review process file details")
        if context and context.get('executable'):
            commands.append(f"file {context['executable']} 2>/dev/null")
            commands.append(f"ls -la {context['executable']} 2>/dev/null")
            commands.append(f"stat {context['executable']} 2>/dev/null")
        
        commands.append("# 4. Terminate if malicious")
        commands.append(f"kill -TERM {pid}  # Graceful termination")
        commands.append(f"kill -9 {pid}     # Force kill if needed")
        
        if context and context.get('cwd'):
            commands.append(f"# 5. Check working directory for artifacts")
            commands.append(f"ls -la {context['cwd']} 2>/dev/null")
    else:
        commands.append(f"ps aux | grep -i '{attack_id}'  # Search for related processes")
    
    commands.append("# 6. Review system logs")
    commands.append("journalctl -u suspicious-service --since '1 hour ago' 2>/dev/null")
    commands.append("grep -i 'error\\|warning\\|suspicious' /var/log/syslog | tail -50")
    
    if attack_id:
        commands.append(f"# 7. Research ATT&CK technique")
        commands.append(f"# https://attack.mitre.org/techniques/{attack_id}/")
    
    return commands


def generate_file_remediation(
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    attack_id: str = "",
    severity: str = "HIGH",
    context: Optional[Dict[str, Any]] = None
) -> List[str]:
    """Generate remediation commands for file-related findings.
    
    Args:
        file_path: Suspicious file path
        line_number: Line number in file
        attack_id: MITRE ATT&CK technique ID
        severity: Severity level
        context: Additional context (file_hash, owner, permissions, etc.)
    
    Returns:
        List of remediation commands
    """
    commands = []
    
    if file_path:
        commands.append("# 1. Examine file details")
        commands.append(f"ls -la {file_path} 2>/dev/null")
        commands.append(f"file {file_path} 2>/dev/null")
        commands.append(f"stat {file_path} 2>/dev/null")
        
        if context and context.get('file_hash'):
            commands.append(f"# Expected hash: {context['file_hash']}")
            commands.append(f"sha256sum {file_path} 2>/dev/null")
        
        commands.append("# 2. View file contents")
        if line_number:
            commands.append(f"sed -n '{max(1, line_number-5)},{line_number+5}p' {file_path} 2>/dev/null")
            commands.append(f"# Issue at line {line_number}")
        else:
            commands.append(f"cat {file_path} 2>/dev/null | head -50")
        
        commands.append("# 3. Check file ownership and permissions")
        commands.append(f"stat -c '%U:%G %a' {file_path} 2>/dev/null")
        
        if context and context.get('suid'):
            commands.append("# WARNING: File has SUID bit set")
            commands.append(f"chmod u-s {file_path}  # Remove SUID bit if not needed")
        
        commands.append("# 4. Quarantine file (optional)")
        commands.append(f"cp {file_path} /tmp/{file_path.split('/')[-1]}.quarantine 2>/dev/null")
        
        commands.append("# 5. Remove or fix file")
        commands.append(f"# rm {file_path}  # Uncomment to delete")
    else:
        commands.append("# Investigate file indicator")
        commands.append("find / -name 'suspicious_file' -type f 2>/dev/null")
    
    commands.append("# 6. Search for related files")
    if context and context.get('file_pattern'):
        commands.append(f"find / -name '{context['file_pattern']}' -type f 2>/dev/null")
    
    if attack_id:
        commands.append(f"# 7. Research ATT&CK technique")
        commands.append(f"# https://attack.mitre.org/techniques/{attack_id}/")
    
    return commands


def generate_network_remediation(
    local_addr: Optional[str] = None,
    remote_addr: Optional[str] = None,
    port: Optional[int] = None,
    protocol: str = "tcp",
    attack_id: str = "",
    context: Optional[Dict[str, Any]] = None
) -> List[str]:
    """Generate remediation commands for network-related findings.
    
    Args:
        local_addr: Local address
        remote_addr: Remote address (e.g., C2 server)
        port: Port number
        protocol: Protocol (tcp/udp)
        attack_id: MITRE ATT&CK technique ID
        context: Additional context (process, pid, etc.)
    
    Returns:
        List of remediation commands
    """
    commands = []
    commands.append("# 1. Check active network connections")
    
    if remote_addr:
        commands.append(f"ss -tunap | grep {remote_addr} 2>/dev/null || netstat -tunap | grep {remote_addr} 2>/dev/null")
        commands.append(f"# 2. Block suspicious remote address")
        commands.append(f"iptables -A OUTPUT -d {remote_addr} -j DROP  # Block outbound")
        commands.append(f"iptables -A INPUT -s {remote_addr} -j DROP   # Block inbound")
    elif port:
        commands.append(f"ss -tunap | grep :{port} 2>/dev/null || netstat -tunap | grep :{port} 2>/dev/null")
        commands.append(f"# 2. Check what is listening on port {port}")
        commands.append(f"lsof -i :{port} 2>/dev/null")
    elif local_addr:
        commands.append(f"ss -tunap | grep {local_addr} 2>/dev/null")
    else:
        commands.append("ss -tunap 2>/dev/null | head -50")
    
    if context and context.get('pid'):
        commands.append(f"# 3. Check process using this connection")
        commands.append(f"ps aux | grep {context['pid']}")
    
    commands.append("# 4. Review firewall rules")
    commands.append("iptables -L -n -v 2>/dev/null | head -50")
    
    commands.append("# 5. Check DNS resolution")
    if remote_addr:
        commands.append(f"nslookup {remote_addr} 2>/dev/null || dig {remote_addr} 2>/dev/null")
        commands.append(f"whois {remote_addr} 2>/dev/null | head -30")
    
    commands.append("# 6. Monitor for continued communication")
    commands.append(f"tcpdump -i any host {remote_addr or 'suspicious_host'} -w /tmp/capture.pcap 2>/dev/null &")
    
    if attack_id:
        commands.append(f"# 7. Research ATT&CK technique")
        commands.append(f"# https://attack.mitre.org/techniques/{attack_id}/")
    
    return commands


def generate_credential_remediation(
    credential_type: Optional[str] = None,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    pid: Optional[int] = None,
    location_type: str = "file",
    context: Optional[Dict[str, Any]] = None
) -> List[str]:
    """Generate remediation commands for credential leak findings.
    
    Args:
        credential_type: Type of credential (AWS, OpenAI, etc.)
        file_path: File containing credential
        line_number: Line number in file
        pid: Process ID exposing credential
        location_type: Location type (file, process, history, log)
        context: Additional context
    
    Returns:
        List of remediation commands
    """
    commands = []
    
    provider = "Unknown"
    rotation_url = None
    rotation_command = None
    
    if credential_type:
        cred_lower = credential_type.lower()
        if 'openai' in cred_lower or (context and context.get('value', '').lower().startswith('sk-')):
            provider = "OpenAI"
            rotation_url = "https://platform.openai.com/api-keys"
            rotation_command = "# Create new API Key in OpenAI Console and delete old one"
        elif 'aws' in cred_lower or (context and context.get('value', '').lower().startswith(('akia', 'asia'))):
            provider = "AWS"
            rotation_url = "https://console.aws.amazon.com/iam/home#/security_credentials"
            rotation_command = "aws iam create-access-key --user-name <user> && aws iam delete-access-key --access-key-id <old-key>"
        elif 'azure' in cred_lower:
            provider = "Azure"
            rotation_url = "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"
            rotation_command = "az ad app credential reset --id <app-id>"
        elif 'alibaba' in cred_lower or (context and context.get('value', '').lower().startswith('ltai')):
            provider = "Alibaba Cloud"
            rotation_url = "https://ram.console.aliyun.com/users"
            rotation_command = "# Create new AccessKey in RAM Console and delete old one"
        elif 'gcp' in cred_lower or 'google' in cred_lower:
            provider = "Google Cloud"
            rotation_url = "https://console.cloud.google.com/apis/credentials"
            rotation_command = "# Create new service account key in GCP Console"
    
    if location_type == "file" and file_path:
        commands.append("# 1. Remove credential from file")
        if line_number:
            commands.append(f"sed -i '{line_number}d' {file_path}")
        commands.append("# 2. Verify removal")
        if provider != "Unknown":
            commands.append(f"grep -n '{provider}' {file_path}")
        else:
            commands.append(f"grep -n 'KEY\\|SECRET\\|TOKEN' {file_path}")
        commands.append("# 3. Rotate credentials immediately")
        if rotation_command:
            commands.append(rotation_command)
        if rotation_url:
            commands.append(f"# URL: {rotation_url}")
        commands.append("# 4. Check file permissions")
        commands.append(f"chmod 600 {file_path}  # Restrict access")
        
    elif location_type == "process" and pid:
        commands.append(f"# 1. Terminate process (if not needed)")
        commands.append(f"kill -TERM {pid}")
        commands.append("# 2. Use environment variables instead of command-line arguments")
        if credential_type:
            commands.append(f"export {credential_type}='<rotated-value>'")
        commands.append("# 3. Rotate credentials")
        if rotation_command:
            commands.append(rotation_command)
        if rotation_url:
            commands.append(f"# URL: {rotation_url}")
            
    elif location_type == "history" and file_path:
        commands.append("# 1. Remove credential from history file")
        if line_number:
            commands.append(f"sed -i '{line_number}d' {file_path}")
        commands.append("# 2. Clear history cache")
        commands.append(f"history -d {line_number} 2>/dev/null || true")
        commands.append("history -w")
        commands.append("# 3. Verify removal")
        commands.append(f"grep -n 'KEY\\|SECRET\\|TOKEN' {file_path}")
        commands.append("# 4. Prevent future leaks (add to ~/.bashrc)")
        commands.append('echo \'export HISTIGNORE="*KEY*:*SECRET*:*PASSWORD*"\' >> ~/.bashrc')
        
    elif location_type == "log" and file_path:
        commands.append("# 1. Rotate log file")
        commands.append(f"mv {file_path} {file_path}.old")
        commands.append(f"touch {file_path}")
        commands.append("# 2. Secure old log")
        commands.append(f"chmod 600 {file_path}.old")
        commands.append(f"chown root:root {file_path}.old 2>/dev/null")
        commands.append("# 3. Rotate credentials")
        if rotation_command:
            commands.append(rotation_command)
    else:
        commands.append("# 1. Identify credential location")
        commands.append("grep -rn 'KEY\\|SECRET\\|TOKEN\\|PASSWORD' /etc/ /home/ 2>/dev/null | head -20")
        commands.append("# 2. Rotate exposed credentials")
        if rotation_command:
            commands.append(rotation_command)
        if rotation_url:
            commands.append(f"# URL: {rotation_url}")
    
    commands.append("# 3. Audit access logs for unauthorized usage")
    commands.append("# 4. Update credential management practices")
    
    return commands


def generate_persistence_remediation(
    file_path: Optional[str] = None,
    service_name: Optional[str] = None,
    cron_job: Optional[str] = None,
    attack_id: str = "",
    context: Optional[Dict[str, Any]] = None
) -> List[str]:
    """Generate remediation commands for persistence mechanism findings.
    
    Args:
        file_path: Persistence file path
        service_name: Service name
        cron_job: Cron job entry
        attack_id: MITRE ATT&CK technique ID
        context: Additional context
    
    Returns:
        List of remediation commands
    """
    commands = []
    commands.append("# 1. Identify persistence mechanism")
    
    if service_name:
        commands.append(f"systemctl status {service_name} 2>/dev/null")
        commands.append(f"systemctl disable {service_name} 2>/dev/null")
        commands.append(f"systemctl stop {service_name} 2>/dev/null")
        commands.append(f"rm /etc/systemd/system/{service_name}.service 2>/dev/null")
        commands.append("systemctl daemon-reload")
    elif cron_job and file_path:
        commands.append(f"# Cron job: {cron_job[:100]}")
        commands.append(f"crontab -l | grep -v '{cron_job[:50]}' | crontab -")
        commands.append(f"rm {file_path} 2>/dev/null")
    elif file_path:
        commands.append(f"ls -la {file_path} 2>/dev/null")
        commands.append(f"cat {file_path} 2>/dev/null")
        commands.append(f"rm {file_path} 2>/dev/null")
    else:
        commands.append("crontab -l 2>/dev/null")
        commands.append("ls -la /etc/cron.* 2>/dev/null")
        commands.append("systemctl list-units --type=service --state=running 2>/dev/null")
    
    commands.append("# 2. Check for related processes")
    commands.append("ps aux | grep -i suspicious 2>/dev/null")
    
    commands.append("# 3. Scan for additional persistence mechanisms")
    commands.append("find /etc/init.d /etc/systemd /var/spool/cron -type f -mtime -7 2>/dev/null")
    commands.append("ls -la ~/.config/autostart/ 2>/dev/null")
    
    commands.append("# 4. Monitor for reinstallation")
    commands.append(f"inotifywait -m /etc/cron.d /etc/systemd/system -e create -e modify 2>/dev/null &")
    
    if attack_id:
        commands.append(f"# 5. Research ATT&CK technique")
        commands.append(f"# https://attack.mitre.org/techniques/{attack_id}/")
    
    return commands


def generate_user_auth_remediation(
    username: Optional[str] = None,
    file_path: Optional[str] = None,
    attack_id: str = "",
    context: Optional[Dict[str, Any]] = None
) -> List[str]:
    """Generate remediation commands for user/authentication findings.
    
    Args:
        username: Suspicious username
        file_path: File path (e.g., authorized_keys)
        attack_id: MITRE ATT&CK technique ID
        context: Additional context
    
    Returns:
        List of remediation commands
    """
    commands = []
    
    if username:
        commands.append(f"# 1. Check user account details")
        commands.append(f"id {username} 2>/dev/null")
        commands.append(f"grep {username} /etc/passwd 2>/dev/null")
        commands.append(f"grep {username} /etc/shadow 2>/dev/null")
        commands.append(f"lastlog -u {username} 2>/dev/null")
        
        commands.append(f"# 2. Check user login history")
        commands.append(f"last | grep {username} 2>/dev/null")
        commands.append(f"journalctl _SYSTEMD_UNIT=sshd.service | grep {username} 2>/dev/null | tail -20")
        
        commands.append(f"# 3. Lock account if suspicious")
        commands.append(f"passwd -l {username} 2>/dev/null")
        
        commands.append(f"# 4. Remove user if unauthorized")
        commands.append(f"# userdel -r {username}  # Uncomment to delete")
    elif file_path:
        commands.append(f"# 1. Examine authentication file")
        commands.append(f"ls -la {file_path} 2>/dev/null")
        commands.append(f"cat {file_path} 2>/dev/null")
        
        if 'authorized_keys' in file_path:
            commands.append("# 2. Remove unauthorized SSH keys")
            commands.append(f"# Edit {file_path} and remove suspicious entries")
            commands.append(f"chmod 600 {file_path}")
        elif 'passwd' in file_path or 'shadow' in file_path:
            commands.append("# 2. Check for UID 0 accounts")
            commands.append("awk -F: '$3 == 0 {print}' /etc/passwd")
            commands.append("# 3. Remove unauthorized UID 0 accounts")
        else:
            commands.append(f"rm {file_path} 2>/dev/null")
    else:
        commands.append("# 1. Audit user accounts")
        commands.append("awk -F: '$3 == 0 {print}' /etc/passwd")
        commands.append("cat /etc/passwd | grep -v nologin | grep -v false")
        commands.append("# 2. Check SSH configuration")
        commands.append("grep -i 'permitrootlogin\\|passwordauthentication' /etc/ssh/sshd_config")
    
    commands.append("# 3. Review authentication logs")
    commands.append("grep -i 'failed password\\|invalid user' /var/log/auth.log 2>/dev/null | tail -20")
    commands.append("grep -i 'accepted publickey' /var/log/auth.log 2>/dev/null | tail -20")
    
    commands.append("# 4. Harden SSH configuration")
    commands.append("# PermitRootLogin no")
    commands.append("# PasswordAuthentication no")
    commands.append("# MaxAuthTries 3")
    
    if attack_id:
        commands.append(f"# 5. Research ATT&CK technique")
        commands.append(f"# https://attack.mitre.org/techniques/{attack_id}/")
    
    return commands


def generate_generic_remediation(
    attack_id: str = "",
    severity: str = "HIGH",
    context: Optional[Dict[str, Any]] = None
) -> List[str]:
    """Generate generic but still actionable remediation commands.
    
    Use this as fallback when specific type is unknown.
    
    Args:
        attack_id: MITRE ATT&CK technique ID
        severity: Severity level
        context: Additional context
    
    Returns:
        List of remediation commands
    """
    commands = []
    commands.append("# 1. Investigate the suspicious activity")
    commands.append("# Review evidence details in the security report")
    
    if context:
        if context.get('file_path'):
            commands.append(f"# File: {context['file_path']}")
            commands.append(f"ls -la {context['file_path']} 2>/dev/null")
        if context.get('pid'):
            commands.append(f"# PID: {context['pid']}")
            commands.append(f"ps aux | grep {context['pid']}")
        if context.get('remote_addr'):
            commands.append(f"# Remote: {context['remote_addr']}")
            commands.append(f"ss -tunap | grep {context['remote_addr']}")
    
    commands.append("# 2. Review related system logs")
    commands.append("journalctl --since '1 hour ago' 2>/dev/null | grep -i 'error\\|warning' | tail -30")
    commands.append("dmesg | tail -30 2>/dev/null")
    
    commands.append("# 3. Check for additional indicators of compromise")
    commands.append("find /tmp /var/tmp -type f -mtime -1 2>/dev/null | head -20")
    commands.append("ps aux | grep -i 'suspicious\\|unknown' 2>/dev/null")
    
    commands.append("# 4. Apply appropriate remediation")
    commands.append("# Isolate affected system if critical")
    commands.append("# Rotate credentials if exposed")
    commands.append("# Block malicious IPs/domains")
    
    commands.append("# 5. Monitor for recurrence")
    commands.append("# Enable enhanced logging")
    commands.append("# Set up alerts for similar activity")
    
    if attack_id:
        commands.append(f"# 6. Research ATT&CK technique")
        commands.append(f"# https://attack.mitre.org/techniques/{attack_id}/")
    
    return commands


def generate_remediation_for_evidence(
    evidence_data: Dict[str, Any]
) -> List[str]:
    """Main entry point - generate remediation based on evidence context.
    
    Analyzes evidence data and selects the appropriate remediation generator.
    
    Args:
        evidence_data: Dictionary containing evidence context with keys like:
            - type: Evidence type (process, file, network, credential, persistence, auth)
            - pid, cmdline, file_path, line_number, remote_addr, port
            - credential_type, location_type, service_name, cron_job, username
            - attack_id, severity
    
    Returns:
        List of remediation commands
    """
    evidence_type = evidence_data.get('type', 'generic')
    attack_id = evidence_data.get('attack_id', '')
    severity = evidence_data.get('severity', 'HIGH')
    
    if evidence_type == 'process':
        return generate_process_remediation(
            pid=evidence_data.get('pid'),
            cmdline=evidence_data.get('cmdline'),
            attack_id=attack_id,
            severity=severity,
            context=evidence_data
        )
    elif evidence_type == 'file':
        return generate_file_remediation(
            file_path=evidence_data.get('file_path'),
            line_number=evidence_data.get('line_number'),
            attack_id=attack_id,
            severity=severity,
            context=evidence_data
        )
    elif evidence_type == 'network':
        return generate_network_remediation(
            local_addr=evidence_data.get('local_addr'),
            remote_addr=evidence_data.get('remote_addr'),
            port=evidence_data.get('port'),
            protocol=evidence_data.get('protocol', 'tcp'),
            attack_id=attack_id,
            context=evidence_data
        )
    elif evidence_type == 'credential':
        return generate_credential_remediation(
            credential_type=evidence_data.get('credential_type'),
            file_path=evidence_data.get('file_path'),
            line_number=evidence_data.get('line_number'),
            pid=evidence_data.get('pid'),
            location_type=evidence_data.get('location_type', 'file'),
            context=evidence_data
        )
    elif evidence_type == 'persistence':
        return generate_persistence_remediation(
            file_path=evidence_data.get('file_path'),
            service_name=evidence_data.get('service_name'),
            cron_job=evidence_data.get('cron_job'),
            attack_id=attack_id,
            context=evidence_data
        )
    elif evidence_type == 'auth':
        return generate_user_auth_remediation(
            username=evidence_data.get('username'),
            file_path=evidence_data.get('file_path'),
            attack_id=attack_id,
            context=evidence_data
        )
    else:
        return generate_generic_remediation(
            attack_id=attack_id,
            severity=severity,
            context=evidence_data
        )
