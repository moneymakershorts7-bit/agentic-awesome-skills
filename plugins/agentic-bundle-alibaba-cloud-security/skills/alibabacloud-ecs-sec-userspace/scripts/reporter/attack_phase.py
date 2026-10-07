"""Attack Phase Classifier - Maps evidence to MITRE ATT&CK phases"""
from typing import List, Dict
from .evidence import Evidence


ATTACK_PHASES = {
    "initial_access": {
        "tactics": ["TA0001"],
        "name": "Initial Access",
        "name_cn": "初始入侵",
        "description": "Attack entry point",
        "indicators": ["web_exploit", "phishing", "supply_chain", "valid_account"]
    },
    "execution": {
        "tactics": ["TA0002"],
        "name": "Execution",
        "name_cn": "代码执行",
        "description": "Malicious code execution",
        "indicators": ["command_execution", "script_execution", "user_execution"]
    },
    "persistence": {
        "tactics": ["TA0003"],
        "name": "Persistence",
        "name_cn": "持久化",
        "description": "Maintaining access",
        "indicators": ["cron_job", "systemd_service", "ssh_key", "backdoor"]
    },
    "privilege_escalation": {
        "tactics": ["TA0004"],
        "name": "Privilege Escalation",
        "name_cn": "权限提升",
        "description": "Gaining higher privileges",
        "indicators": ["sudo_abuse", "suid_binary", "kernel_exploit"]
    },
    "defense_evasion": {
        "tactics": ["TA0005"],
        "name": "Defense Evasion",
        "name_cn": "防御规避",
        "description": "Avoiding detection",
        "indicators": ["log_clearing", "rootkit", "process_injection"]
    },
    "credential_access": {
        "tactics": ["TA0006"],
        "name": "Credential Access",
        "name_cn": "凭据窃取",
        "description": "Stealing credentials",
        "indicators": ["credential_dumping", "keylogging", "hash_capture"]
    },
    "discovery": {
        "tactics": ["TA0007"],
        "name": "Discovery",
        "name_cn": "环境探测",
        "description": "System reconnaissance",
        "indicators": ["system_info", "network_scan", "file_search"]
    },
    "lateral_movement": {
        "tactics": ["TA0008"],
        "name": "Lateral Movement",
        "name_cn": "横向移动",
        "description": "Moving through the network",
        "indicators": ["ssh_lateral", "remote_service", "file_share"]
    },
    "collection": {
        "tactics": ["TA0009"],
        "name": "Collection",
        "name_cn": "数据收集",
        "description": "Gathering target data",
        "indicators": ["data_staging", "screen_capture", "keylogging"]
    },
    "command_and_control": {
        "tactics": ["TA0011"],
        "name": "Command & Control",
        "name_cn": "命令控制",
        "description": "C2 communication",
        "indicators": ["c2_beacon", "dns_tunnel", "reverse_shell"]
    },
    "exfiltration": {
        "tactics": ["TA0010"],
        "name": "Exfiltration",
        "name_cn": "数据外泄",
        "description": "Data theft",
        "indicators": ["data_upload", "cloud_exfil", "alternate_protocol"]
    },
    "impact": {
        "tactics": ["TA0040"],
        "name": "Impact",
        "name_cn": "破坏影响",
        "description": "Damage and destruction",
        "indicators": ["ransomware", "data_destruction", "service_stop"]
    }
}

TECHNIQUE_TO_PHASE = {
    "T1190": "initial_access",
    "T1133": "initial_access",
    "T1078": "initial_access",
    "T1189": "initial_access",
    "T1059": "execution",
    "T1053": "execution",
    "T1204": "execution",
    "T1053.003": "persistence",
    "T1053.002": "persistence",
    "T1098": "persistence",
    "T1021": "lateral_movement",
    "T1078": "persistence",
    "T1548": "privilege_escalation",
    "T1068": "privilege_escalation",
    "T1055": "defense_evasion",
    "T1070": "defense_evasion",
    "T1014": "defense_evasion",
    "T1003": "credential_access",
    "T1110": "credential_access",
    "T1056": "credential_access",
    "T1082": "discovery",
    "T1083": "discovery",
    "T1087": "discovery",
    "T1046": "discovery",
    "T1021": "lateral_movement",
    "T1076": "lateral_movement",
    "T1005": "collection",
    "T1074": "collection",
    "T1113": "collection",
    "T1071": "command_and_control",
    "T1132": "command_and_control",
    "T1573": "command_and_control",
    "T1048": "exfiltration",
    "T1041": "exfiltration",
    "T1567": "exfiltration",
    "T1486": "impact",
    "T1485": "impact",
    "T1489": "impact",
}

KEYWORD_PHASE_MAP = {
    "sql injection": "initial_access",
    "xss": "initial_access",
    "web exploit": "initial_access",
    "phishing": "initial_access",
    "command execution": "execution",
    "shell": "execution",
    "bash": "execution",
    "powershell": "execution",
    "cron": "persistence",
    "systemd": "persistence",
    "startup": "persistence",
    "backdoor": "persistence",
    "rootkit": "defense_evasion",
    "log clear": "defense_evasion",
    "hiding": "defense_evasion",
    "password": "credential_access",
    "credential": "credential_access",
    "shadow": "credential_access",
    "hash": "credential_access",
    "keylog": "credential_access",
    "scan": "discovery",
    "enumerate": "discovery",
    "reconnaissance": "discovery",
    "system info": "discovery",
    "lateral": "lateral_movement",
    "ssh": "lateral_movement",
    "rdp": "lateral_movement",
    "collect": "collection",
    "exfil": "exfiltration",
    "upload": "exfiltration",
    "transfer": "exfiltration",
    "c2": "command_and_control",
    "beacon": "command_and_control",
    "reverse shell": "command_and_control",
    "ransomware": "impact",
    "encrypt": "impact",
    "delete": "impact",
    "destroy": "impact",
}


class AttackPhaseClassifier:
    """攻击阶段分类器
    
    Maps evidence to MITRE ATT&CK phases based on:
    1. attack_tactic field (priority)
    2. attack_id (MITRE ATT&CK technique ID)
    3. Keyword matching in title/description
    """

    def __init__(self):
        self.phase_map = self._build_phase_map()

    def _build_phase_map(self) -> Dict[str, str]:
        """Build tactic to phase mapping"""
        result = {}
        for phase_key, phase_data in ATTACK_PHASES.items():
            for tactic in phase_data["tactics"]:
                result[tactic] = phase_key
        return result

    def classify(self, evidence: Evidence) -> str:
        """Classify evidence into attack phase
        
        Args:
            evidence: Evidence object
            
        Returns:
            Phase key: initial_access, execution, persistence, etc.
        """
        if not evidence:
            return "unknown"
        
        # 1. Priority: use attack_tactic
        tactic = getattr(evidence, 'attack_tactic', '')
        if tactic:
            tactic_upper = tactic.upper()
            if tactic_upper in self.phase_map:
                return self.phase_map[tactic_upper]
        
        # 2. Use attack_id (MITRE ATT&CK technique ID)
        attack_id = getattr(evidence, 'attack_id', '')
        if attack_id:
            attack_id_upper = attack_id.upper()
            if attack_id_upper in TECHNIQUE_TO_PHASE:
                return TECHNIQUE_TO_PHASE[attack_id_upper]
        
        # 3. Keyword matching in title and description
        return self._keyword_match(
            getattr(evidence, 'title', ''),
            getattr(evidence, 'description', '')
        )

    def _keyword_match(self, title: str, description: str) -> str:
        """Match keywords in title and description to phases"""
        text = f"{title} {description}".lower()
        
        best_match = None
        best_score = 0
        
        for keywords, phase in KEYWORD_PHASE_MAP.items():
            if keywords in text:
                score = len(keywords)
                if score > best_score:
                    best_score = score
                    best_match = phase
        
        return best_match if best_match else "unknown"

    def classify_all(self, evidences: List[Evidence]) -> Dict[str, List[Evidence]]:
        """Classify all evidences into attack phases
        
        Args:
            evidences: List of Evidence objects
            
        Returns:
            Dict mapping phase keys to lists of evidences
        """
        result = {phase: [] for phase in ATTACK_PHASES.keys()}
        result["unknown"] = []
        
        for evidence in evidences:
            phase = self.classify(evidence)
            if phase in result:
                result[phase].append(evidence)
            else:
                result["unknown"].append(evidence)
        
        return result

    def get_phase_info(self, phase_key: str) -> dict:
        """Get phase information
        
        Args:
            phase_key: Phase key (e.g., 'initial_access')
            
        Returns:
            Phase information dict
        """
        return ATTACK_PHASES.get(phase_key, {
            "name": "Unknown",
            "name_cn": "未知",
            "description": "Unknown phase"
        })
