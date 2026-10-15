# MITRE ATT&CK Technique Mappings | 技术映射表

> sec-userspace 检测能力与 MITRE ATT&CK Framework v18 的完整映射关系。
> 共覆盖 **80+ 技术编号**，跨越 **14 个战术阶段**。

---

## 映射统计

| ATT&CK 战术 | 覆盖技术数 | 对应分析器数 |
|-------------|-----------|-------------|
| Initial Access (TA0001) | 3 | 3 |
| Execution (TA0002) | 5 | 6 |
| Persistence (TA0003) | 8 | 5 |
| Privilege Escalation (TA0004) | 4 | 4 |
| Defense Evasion (TA0005) | 8 | 10 |
| Credential Access (TA0006) | 5 | 4 |
| Discovery (TA0007) | 1 | 3 |
| Lateral Movement (TA0008) | 6 | 3 |
| Collection (TA0009) | 3 | 3 |
| Command and Control (TA0011) | 8 | 5 |
| Exfiltration (TA0010) | 4 | 3 |
| Impact (TA0040) | 4 | 4 |
| Resource Development (TA0042) | 1 | 1 |

---

## 按战术阶段详表

### Initial Access | 初始访问 (TA0001)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1133 | External Remote Services | RemoteServiceAnalyzer |
| T1190 | Exploit Public-Facing Application | WebExploitAnalyzer |
| T1195.001 | Compromise Software Supply Chain | VulnerabilityDBAnalyzer, VersionUpdateAnalyzer |
| T1195.002 | Compromise Software Dependencies | VulnerabilityDBAnalyzer |

### Execution | 执行 (TA0002)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1059 | Command and Scripting Interpreter | ProcessAnalyzer, FilelessMalwareAnalyzer |
| T1059.001 | PowerShell | ProcessAnalyzer |
| T1059.004 | Unix Shell | ProcessAnalyzer |
| T1059.006 | Python | ProcessAnalyzer |
| T1203 | Exploitation for Client Execution | VulnerabilityDBAnalyzer |
| T1204.002 | Malicious File | MalwareAnalyzer |

### Persistence | 持久化 (TA0003)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1037.004 | RC Scripts | PersistenceAnalyzer |
| T1053.003 | Cron | PersistenceAnalyzer |
| T1053.005 | Scheduled Task | SystemdTimerAnalyzer |
| T1053.006 | Systemd Timers | SystemdTimerAnalyzer |
| T1505.002 | Transport Agent | MTAAnalyzer |
| T1505.003 | Web Shell | WebshellAnalyzer, WebExploitAnalyzer |
| T1543.002 | Systemd Service | SystemdTimerAnalyzer |
| T1546.004 | Unix Shell Configuration Modification | PersistenceAnalyzer |
| T1547.001 | Registry Run Keys / Startup Folder | PersistenceAnalyzer |
| T1547.006 | Kernel Modules and Extensions | RootkitAnalyzer, KernelTaintAnalyzer |

### Privilege Escalation | 权限提升 (TA0004)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1548 | Abuse Elevation Control Mechanism | FileAnalyzer |
| T1548.001 | Setuid and Setgid | AuthAnalyzer, FileAnalyzer |
| T1548.003 | Sudo and Sudo Caching | AuthAnalyzer |
| T1611 | Escape to Host | ContainerSyscallMonitor, CiliumEvasionDetector |

### Defense Evasion | 防御规避 (TA0005)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1014 | Rootkit | RootkitAnalyzer, IoUringRootkitAnalyzer, KernelIntegrityChecker, MemfdFilelessRootkitAnalyzer |
| T1027 | Obfuscated Files or Information | FilelessMalwareAnalyzer |
| T1027.002 | Software Packing | MalwareAnalyzer |
| T1036.004 | Masquerade Task or Service | ProcessTreeAnalyzer |
| T1036.005 | Match Legitimate Name or Location | ProcessAnalyzer |
| T1070.002 | Clear Linux or Mac System Logs | LogAnalyzer |
| T1070.004 | File Deletion | LogAnalyzer |
| T1070.006 | Timestomp | FileAnalyzer |
| T1562.001 | Disable or Modify Tools | KernelIntegrityChecker |
| T1562.008 | Disable or Modify Cloud Logs | CiliumEvasionDetector, KernelIntegrityChecker |
| T1564.001 | Hidden Files and Directories | FileAnalyzer |
| T1620 | Reflective Code Loading | FilelessMalwareAnalyzer, MemoryThreatAnalyzer, MemfdFilelessAnalyzer |

### Credential Access | 凭据访问 (TA0006)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1003 | OS Credential Dumping | MemoryForensicsAnalyzer |
| T1110 | Brute Force | AuthAnalyzer |
| T1552.001 | Credentials In Files | DataEncryptionAnalyzer |
| T1556.003 | Pluggable Authentication Modules | PAMBackdoorAnalyzer |
| T1556.004 | Network Device Authentication | AuthAnalyzer, PAMBackdoorAnalyzer |

### Discovery | 发现 (TA0007)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1046 | Network Service Discovery | LateralMovementCorrelator, K8sLateralMovementAnalyzer |

### Lateral Movement | 横向移动 (TA0008)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1021 | Remote Services | LateralMovementAnalyzer, LateralMovementCorrelator |
| T1021.004 | SSH | LateralMovementAnalyzer |
| T1021.007 | Cloud Services | LateralMovementAnalyzer |
| T1563.001 | SSH Hijacking | LateralMovementCorrelator |
| T1570 | Lateral Tool Transfer | LateralMovementAnalyzer, LateralMovementCorrelator |
| T1072 | Software Deployment Tools | LateralMovementCorrelator |

### Collection | 数据收集 (TA0009)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1005 | Data from Local System | MemoryForensicsAnalyzer, FileBehaviorAnalyzer |
| T1530 | Data from Cloud Storage | MemoryInspectionAnalyzer |
| T1560 | Archive Collected Data | FileBehaviorAnalyzer |

### Command and Control | 命令与控制 (TA0011)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1071 | Application Layer Protocol | NetworkAnalyzer, ThreatIntelAnalyzer |
| T1071.001 | Web Protocols | NetworkBehaviorAnalyzer |
| T1071.004 | DNS | NetworkBehaviorAnalyzer |
| T1095 | Non-Application Layer Protocol | NetworkAnalyzer |
| T1105 | Ingress Tool Transfer | ThreatIntelAnalyzer, RATAnalyzer |
| T1205 | Traffic Signaling | NetworkAnalyzer |
| T1568.002 | Domain Generation Algorithms | DGADetectionAnalyzer |
| T1571 | Non-Standard Port | NetworkAnalyzer |
| T1572 | Protocol Tunneling | LateralMovementAnalyzer |

### Exfiltration | 数据外泄 (TA0010)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1048 | Exfiltration Over Alternative Protocol | CloudExfiltrationAnalyzer, PubSubAbuseAnalyzer |
| T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 | CloudExfiltrationAnalyzer |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 | CloudExfiltrationAnalyzer |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 | CloudExfiltrationAnalyzer |

### Impact | 影响 (TA0040)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1486 | Data Encrypted for Impact | RansomwareAnalyzer |
| T1496 | Resource Hijacking | MiningAnalyzer |
| T1498 | Network Denial of Service | NetworkAnalyzer |
| T1499 | Endpoint Denial of Service | NetworkAnalyzer |
| T1565.001 | Stored Data Manipulation | MemoryPoisonAnalyzer, MemoryVersionControlAnalyzer |

### Resource Development | 资源开发 (TA0042)

| 技术 ID | 技术名称 | 检测分析器 |
|---------|---------|-----------|
| T1584.002 | DNS Server | ThreatIntelAnalyzer |

---

## 补充说明

- 技术编号基于 MITRE ATT&CK for Enterprise v18 (Linux 平台)
- 单个分析器可能映射多个技术编号（多维度检测）
- 单个技术编号可能被多个分析器覆盖（纵深防御）
- 完整分析器详情参见 [detection-capabilities.md](detection-capabilities.md)
