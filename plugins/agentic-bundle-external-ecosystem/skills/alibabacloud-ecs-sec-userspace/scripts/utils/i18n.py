"""Internationalization (i18n) module for sec-userspace.

This module provides localization mappings for generating Chinese reports
from English internal data. All internal logs, JSON reports, and code use
standard English for AI model efficiency.
"""

# Conclusion mappings (English -> Chinese)
CONCLUSION_MAP = {
    "COMPROMISED": "已被入侵",
    "SUSPICIOUS": "高度可疑",
    "RISKY": "存在风险",
    "SAFE": "未发现入侵",
    "BENIGN": "正常",
    "CLEAN": "安全"
}

# Severity mappings (English -> Chinese)
SEVERITY_MAP = {
    "CRITICAL": "严重",
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
    "INFO": "信息"
}

# Module name mappings (English -> Chinese)
MODULE_MAP = {
    "process_analyzer": "进程异常检测",
    "network_analyzer": "网络异常检测",
    "credential_analyzer": "凭据泄漏检测",
    "persistence_analyzer": "持久化机制检测",
    "rootkit_analyzer": "Rootkit 检测",
    "webshell_analyzer": "Webshell 检测",
    "malware_analyzer": "恶意软件检测",
    "ransomware_analyzer": "勒索软件检测",
    "rat_analyzer": "远程访问工具检测",
    "mining_analyzer": "挖矿程序检测",
    "auth_analyzer": "认证安全检测",
    "log_analyzer": "日志异常检测",  # DISABLED (confidence < 0.95)
    "file_analyzer": "文件完整性检测",
    "ebpf_analyzer": "eBPF 安全检测",
    "container_analyzer": "容器安全检测",
    "remote_service_analyzer": "远程服务检测",
    "mcp_security_analyzer": "MCP 安全检测",
    "skill_analyzer": "AI Skill 安全检测",
    "history_analyzer": "历史命令检测",
    "ai_security_analyzer": "AI 系统安全检测",
    "ai_tool_misuse_analyzer": "AI 工具滥用检测",
    "ai_content_analyzer": "AI 内容安全检测",
    "mta_analyzer": "邮件传输安全检测",
    "web_exploit_analyzer": "Web 攻击检测",
    "supply_chain_analyzer": "供应链安全检测",
    "threat_intel_analyzer": "威胁情报检测"
}

# ATT&CK tactic mappings (English -> Chinese)
TACTIC_MAP = {
    "Initial Access": "初始访问",
    "Execution": "执行",
    "Persistence": "持久化",
    "Privilege Escalation": "权限提升",
    "Defense Evasion": "防御绕过",
    "Credential Access": "凭据访问",
    "Discovery": "发现",
    "Lateral Movement": "横向移动",
    "Collection": "收集",
    "Command and Control": "命令与控制",
    "Exfiltration": "数据渗出",
    "Impact": "影响"
}

# ATT&CK technique ID to tactic name mappings
ATTACK_ID_TO_TACTIC = {
    # Initial Access
    'T1190': 'Exploit Public-Facing Application',
    'T1133': 'External Remote Services',
    'T1566': 'Phishing',
    
    # Execution
    'T1059': 'Command and Scripting Interpreter',
    'T1059.001': 'PowerShell',
    'T1059.004': 'Unix Shell',
    'T1059.007': 'Containerized Application',
    
    # Persistence
    'T1547': 'Boot or Logon Autostart Execution',
    'T1547.006': 'Kernel Modules and Extensions',
    'T1548': 'Abuse Elevation Control Mechanism',
    'T1548.001': 'Setuid and Setgid',
    'T1548.003': 'Sudo and Sudo Caching',
    'T1556': 'Modify Authentication Process',
    'T1556.004': 'NTLM',
    
    # Privilege Escalation
    'T1068': 'Exploitation for Privilege Escalation',
    
    # Defense Evasion
    'T1070': 'Indicator Removal',
    'T1070.001': 'Clear Windows Event Logs',
    'T1070.003': 'Clear Command History',
    'T1070.004': 'File Deletion',
    'T1070.006': 'Timestomping',
    'T1564': 'Hide Artifacts',
    'T1564.001': 'Hidden Files and Directories',
    
    # Credential Access
    'T1110': 'Brute Force',
    'T1552': 'Unsecured Credentials',
    'T1552.001': 'Credentials In Files',
    'T1552.004': 'Private Keys',
    
    # Discovery
    'T1078': 'Valid Accounts',
    'T1082': 'System Information Discovery',
    'T1083': 'File and Directory Discovery',
    
    # Lateral Movement
    'T1021': 'Remote Services',
    'T1021.004': 'SSH',
    'T1021.007': 'Cloud Services',
    'T1098': 'Account Manipulation',
    'T1098.004': 'SSH Authorized Keys',
    'T1570': 'Lateral Tool Transfer',
    
    # Collection
    'T1005': 'Data from Local System',
    'T1039': 'Data from Network Shared Drive',
    
    # Command and Control
    'T1048': 'Exfiltration Over Alternative Mechanism',
    'T1071': 'Application Layer Protocol',
    'T1095': 'Non-Application Layer Protocol',
    'T1105': 'Ingress Tool Transfer',
    'T1571': 'Non-Standard Port',
    'T1572': 'Protocol Tunneling',
    
    # Exfiltration
    'T1041': 'Exfiltration Over C2 Channel',
    
    # Impact
    'T1486': 'Data Encrypted for Impact',
    'T1496': 'Resource Hijacking',
    
    # Container/Kubernetes specific
    'T1610': 'Deploy Container',
    'T1611': 'Escape to Host',
    
    # Supply Chain
    'T1195': 'Supply Chain Compromise',
    'T1195.001': 'Compromise Software Dependencies and Development Tools',
    
    # Email
    'T1505': 'Server Software Component',
    'T1505.002': 'Transport Agent',
    'T1505.003': 'Web Shell',
    
    # Rootkit
    'T1014': 'Rootkit',
    
    # Defense Evasion - Additional
    'T1027': 'Obfuscated Files or Information',
    'T1055.009': 'Process Injection: Embedded Portlet',
    'T1620': 'Reflective Code Loading',
    
    # Execution - Additional
    'T1059.006': 'Command and Scripting Interpreter: Python',
    
    # Command and Control - Additional
    'T1071.001': 'Application Layer Protocol: Web Protocols',
    'T1679': 'Web Service API',
    
    # Supply Chain - Additional
    'T1195.002': 'Supply Chain Compromise: Compromise Software Supply Chain',
    
    # User Execution - Additional
    'T1204.005': 'User Execution: Malicious Image',
    
    # Defense Evasion - Cloud
    'T1562.008': 'Impair Defenses: Disable or Modify Cloud Logs',
    
    # Impact - Data Manipulation
    'T1565.001': 'Data Manipulation: Stored Data Manipulation',
    
    # Discovery - Additional
    'T1592': 'Gather Victim Host Information',
    'T1619': 'Cloud Storage Object Discovery',
    
    # Initial Access - Additional
    'T1608': 'Install Tooling',
    
    # Container - Additional
    'T1610.002': 'Deploy Container: Local Execution',
    
    # Impact - Additional
    'T1650': 'Acquire Infrastructure',
    'T1659': 'Content Injection',
    
    # AI Security Standards (Custom)
    'ASI06:2026': 'AI Agent Memory Integrity',
    'ASI09:2026': 'AI Agent Trust Boundary'
}


def get_attack_tactic_name(attack_id: str) -> str:
    """Get the full tactic name from ATT&CK ID.
    
    Args:
        attack_id: MITRE ATT&CK technique ID (e.g., 'T1105')
        
    Returns:
        Full tactic/technique name in English, or empty string if not found
    """
    return ATTACK_ID_TO_TACTIC.get(attack_id, '')

# Common log message mappings (Chinese -> English for internal logs)
LOG_MESSAGE_MAP = {
    # Analyzer status messages
    "开始分析...": "Starting analysis...",
    "分析完成": "Analysis completed",
    "发现 {} 个证据": "Found {} evidence items",
    "检测完成": "Detection completed",
    
    # Collector status messages
    "开始采集...": "Starting collection...",
    "采集完成": "Collection completed",
    "采集 {} 项": "Collected {} items",
    
    # System status messages
    "CPU 负载正常": "CPU load normal",
    "可用内存充足": "Sufficient memory available",
    "启动": "starting",
    "执行完成": "execution completed",
    
    # Conclusion messages
    "已被入侵": "COMPROMISED",
    "高度可疑": "SUSPICIOUS",
    "存在风险": "AT_RISK",
    "未发现入侵": "CLEAN",
    
    # Error messages
    "权限不足": "Permission denied",
    "超时": "Timeout",
    "文件不存在": "File not found",
    "分析跳过": "Analysis skipped"
}


def translate_conclusion(en_conclusion: str) -> str:
    """Translate conclusion from English to Chinese.
    
    Args:
        en_conclusion: English conclusion string
        
    Returns:
        Chinese translation or original if not found
    """
    return CONCLUSION_MAP.get(en_conclusion, en_conclusion)


def translate_severity(en_severity: str) -> str:
    """Translate severity level from English to Chinese.
    
    Args:
        en_severity: English severity string (CRITICAL/HIGH/MEDIUM/LOW/INFO)
        
    Returns:
        Chinese translation or original if not found
    """
    return SEVERITY_MAP.get(en_severity, en_severity)


def translate_module(en_module: str) -> str:
    """Translate module name from English to Chinese.
    
    Args:
        en_module: English module name
        
    Returns:
        Chinese translation or original if not found
    """
    return MODULE_MAP.get(en_module, en_module)


def translate_tactic(en_tactic: str) -> str:
    """Translate ATT&CK tactic from English to Chinese.
    
    Args:
        en_tactic: English tactic name
        
    Returns:
        Chinese translation or original if not found
    """
    return TACTIC_MAP.get(en_tactic, en_tactic)


def localize_log_message(zh_message: str) -> str:
    """Convert Chinese log message to English for internal logging.
    
    Args:
        zh_message: Chinese log message
        
    Returns:
        English translation or original if not found
    """
    # Try exact match first
    if zh_message in LOG_MESSAGE_MAP:
        return LOG_MESSAGE_MAP[zh_message]
    
    # Try pattern matching for messages with variables
    result = zh_message
    for zh_pattern, en_pattern in LOG_MESSAGE_MAP.items():
        if zh_pattern in result:
            result = result.replace(zh_pattern, en_pattern)
    
    return result
