# Detection Capabilities | 检测能力详表

> sec-userspace 完整检测能力清单，按检测类别分组，标注关联的 MITRE ATT&CK 技术编号。

---

## 检测能力总览

| 维度 | 数量 |
|------|------|
| 安全分析器 | 51 |
| 数据采集器 | 10 |
| ATT&CK 技术映射 | 103+ |
| 检测类别 | 12 |

---

## 1. 进程异常检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| ProcessAnalyzer | 进程异常检测：隐藏进程、已删除二进制运行、异常路径进程、反弹 Shell | T1059, T1036.005 |
| ProcessTreeAnalyzer | 进程树异常检测：异常父子关系、孤儿进程、进程链分析 | T1036.004, T1055 |
| RuntimeCodeInjectionAnalyzer | 运行时代码注入检测：ptrace 注入、/proc/pid/mem 写入 | T1055.001, T1055.002, T1055.003 |

## 2. 网络异常检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| NetworkAnalyzer | 网络异常检测：可疑监听端口、隐藏连接、C2 通信、非标准端口 | T1071, T1095, T1571 |
| NetworkBehaviorAnalyzer | 网络行为画像：连接模式分析、流量基线偏移 | T1071.001, T1071.004 |
| DGADetectionAnalyzer | DGA 域名检测：域名生成算法识别、高熵域名告警 | T1568.002 |
| ThreatIntelAnalyzer | 威胁情报匹配：恶意 IP/域名/哈希 IoC 比对 | T1071, T1105 |

## 3. 认证与凭据检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| AuthAnalyzer | 认证异常检测：暴力破解、异常登录、SSH 后门密钥、UID 0 账户 | T1110, T1078, T1098.004, T1136.001 |
| PAMBackdoorAnalyzer | PAM 后门检测：PAM 模块篡改、认证绕过 | T1556.003, T1556.004 |
| DataEncryptionAnalyzer | 凭据泄露检测：明文密码、SSH 私钥暴露、API Key 硬编码 | T1552.001, T1552.004 |

## 4. 持久化机制检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| PersistenceAnalyzer | 持久化检测：Crontab 后门、Shell 配置注入、rc.local 后门 | T1053.003, T1546.004, T1547.001 |
| SystemdTimerAnalyzer | Systemd 持久化：恶意 Service/Timer、D-Bus 后门 | T1053.005, T1053.006, T1543.002 |
| MTAAnalyzer | MTA 传输代理后门检测 | T1505.002 |

## 5. Rootkit 检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| RootkitAnalyzer | Rootkit 综合检测：内核模块异常、系统调用劫持 | T1014, T1547.006 |
| LibraryInjectionAnalyzer | LD_PRELOAD 劫持检测：/etc/ld.so.preload、环境变量注入 | T1574.006, T1574.007 |
| IoUringRootkitAnalyzer | io_uring Rootkit 检测：io_uring 接口滥用 | T1014, T1055 |
| KernelIntegrityChecker | 内核完整性检测：内核模块签名验证、taint 标志 | T1014, T1562.008 |
| KernelTaintAnalyzer | 内核 taint 分析：异常内核标志、模块加载异常 | T1014, T1547.006 |

## 6. Webshell 检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| WebshellAnalyzer | Webshell 检测：信息熵分析、危险函数匹配、多层混淆检测 | T1505.003 |
| WebExploitAnalyzer | Web 漏洞利用检测：已知 CVE 利用、Web 后门 | T1190, T1505.003 |

## 7. 恶意软件检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| MalwareAnalyzer | 恶意软件扫描：ELF 静态分析、已知恶意特征匹配 | T1204.002 |
| MiningAnalyzer | 挖矿程序检测：矿池连接、CPU 异常占用、已知矿工特征 | T1496 |
| RansomwareAnalyzer | 勒索软件检测：文件加密行为、勒索信特征 | T1486 |
| RATAnalyzer | 远控木马检测：已知 RAT 特征、隐蔽通信 | T1059, T1105 |
| FilelessMalwareAnalyzer | 无文件恶意软件检测：内存驻留、脚本注入 | T1620, T1055, T1059, T1027 |

## 8. 内存取证检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| MemoryForensicsAnalyzer | 内存取证分析：进程内存注入、代码注入检测 | T1055, T1055.001, T1003, T1005 |
| MemoryThreatAnalyzer | 内存驻留威胁检测：RWX 内存区域异常 | T1055, T1620 |
| MemoryInspectionAnalyzer | 内存检查：敏感数据内存暴露 | T1530 |
| MemoryPoisonAnalyzer | 内存投毒检测 | T1565.001, T1071 |
| MemoryVersionControlAnalyzer | 内存版本控制异常检测 | T1565, T1565.001 |
| MemfdFilelessAnalyzer | memfd 无文件攻击检测：共享内存 Rootkit | T1620, T1014 |
| MemfdFilelessRootkitAnalyzer | memfd 无文件 Rootkit 深度检测 | T1014, T1055 |

## 9. 文件系统检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| FileAnalyzer | 文件异常检测：SUID/SGID 异常、敏感目录可写、隐藏文件 | T1548.001, T1564.001 |
| FileBehaviorAnalyzer | 文件行为分析：访问模式异常、批量文件操作 | T1005, T1560 |

## 10. 横向移动检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| LateralMovementAnalyzer | 横向移动检测：SSH 横向、端口转发、隧道代理 | T1021, T1021.004, T1572, T1570 |
| LateralMovementCorrelator | 横向移动时序关联：多源告警关联分析 | T1021, T1046, T1563.001 |
| RemoteServiceAnalyzer | 远程服务异常检测 | T1133 |

## 11. 容器 / K8s 检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| KubernetesAnalyzer | K8s 安全检测：RBAC 风险、特权容器、敏感挂载 | T1610, T1611 |
| K8sRuntimeBehaviorAnalyzer | K8s 运行时行为异常检测 | T1610 |
| K8sLateralMovementAnalyzer | K8s 横向移动检测：服务间异常通信 | T1046 |
| ContainerSyscallMonitor | 容器系统调用监控：逃逸行为检测 | T1611, T1609, T1610 |
| CiliumEvasionDetector | Cilium eBPF 安全策略绕过检测 | T1611, T1562.008 |
| CiliumRuntimeSecurityAnalyzer | Cilium/Tetragon eBPF 运行时安全分析 | T1014 |

## 12. 其他检测

| 分析器 | 说明 | ATT&CK 技术 |
|--------|------|-------------|
| LogAnalyzer | 日志异常检测：日志清除、日志篡改、时间空白 | T1070.002, T1070.004 |
| CloudExfiltrationAnalyzer | 云数据外泄检测 | T1537, T1048 |
| CloudStorageExecutionAnalyzer | 云存储执行检测 | T1204.005 |
| PubSubAbuseAnalyzer | Pub/Sub CLI 工具滥用检测 | T1048 |
| CICDDetector | CI/CD 环境检测 | — |
| VulnerabilityDBAnalyzer | 漏洞数据库匹配：已知 CVE 与系统组件比对 | T1195.001, T1195.002, T1203 |
| VersionUpdateAnalyzer | Agent 版本更新检测 | T1195.001 |

---

## 数据采集器

| 采集器 | 说明 | 数据源 |
|--------|------|--------|
| SystemCollector | 系统信息采集 | /proc/version, /etc/os-release, uname |
| ProcessCollector | 进程信息采集 | /proc/*/status, /proc/*/cmdline |
| NetworkCollector | 网络信息采集 | /proc/net/tcp, ss, netstat |
| UserCollector | 用户信息采集 | /etc/passwd, /etc/shadow, /etc/group |
| FileSystemCollector | 文件系统采集 | SUID/SGID 文件, 可写目录, 隐藏文件 |
| LogCollector | 日志采集 | /var/log/auth.log, /var/log/syslog, wtmp |
| CronCollector | 定时任务采集 | crontab, /etc/cron.d/, /etc/cron.daily/ |
| ServiceCollector | 服务采集 | systemctl, /etc/systemd/system/ |
| DNSCollector | DNS 信息采集 | /etc/resolv.conf, DNS 查询记录 |
| PackageHistoryCollector | 软件包历史采集 | rpm/dpkg 安装记录 |
