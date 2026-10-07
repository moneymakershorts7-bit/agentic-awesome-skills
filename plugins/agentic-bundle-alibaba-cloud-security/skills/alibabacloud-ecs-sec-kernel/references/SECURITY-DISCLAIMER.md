# ⚠️ 安全声明 / Security Disclaimer

---

## 使用条款 / Terms of Use

### 中文

本工具（sec-kernel）是一款 Linux 内核 CVE 漏洞检测与 PoC 漏洞验证工具。使用本工具前，您必须仔细阅读并完全理解以下安全声明。使用本工具即表示您同意受以下条款的约束。

### English

This tool (sec-kernel) is a Linux kernel CVE vulnerability detection and PoC vulnerability verification tool. Before using this tool, you must carefully read and fully understand the following security disclaimer. By using this tool, you agree to be bound by the following terms.

---

## 授权要求 / Authorization Requirements

### 中文

1. **所有权确认** — 您仅可对自己拥有完全所有权或已获得书面合法授权的系统进行安全检测
2. **授权范围** — 您必须确保检测行为在授权范围之内，不得超越授权边界
3. **严禁未授权测试** — 严禁对任何未经授权的系统、网络、设备进行安全测试
4. **第三方系统** — 对第三方系统进行检测前，必须获得系统所有者的明确书面授权

### English

1. **Ownership Confirmation** — You may only perform security detection on systems that you fully own or have obtained written legal authorization to test
2. **Authorization Scope** — You must ensure that detection activities are within the authorized scope and do not exceed authorization boundaries
3. **Unauthorized Testing Prohibited** — Security testing on any unauthorized systems, networks, or devices is strictly prohibited
4. **Third-Party Systems** — Explicit written authorization from the system owner must be obtained before testing any third-party systems

---

## Kernel Crash 风险声明 / Kernel Crash Risk Statement

### 中文

本工具在执行 PoC 漏洞验证时，会触发真实的内核漏洞利用路径。这些操作**可能导致以下后果**：

1. **Kernel Panic** — 内核崩溃，系统立即停止运行
2. **Kernel Hang** — 内核死锁，系统无响应需要硬重启
3. **Kernel Deadlock** — 内核资源死锁，相关子系统不可用
4. **系统不稳定** — 内存损坏或状态异常导致后续行为不可预测

**使用本工具即表示您已知晓并接受上述风险。**

### English

This tool triggers real kernel vulnerability exploitation paths during PoC verification. These operations **may result in the following consequences**:

1. **Kernel Panic** — Kernel crash, system immediately halts
2. **Kernel Hang** — Kernel deadlock, system unresponsive requiring hard reboot
3. **Kernel Deadlock** — Kernel resource deadlock, related subsystems become unavailable
4. **System Instability** — Memory corruption or state anomalies leading to unpredictable behavior

**By using this tool, you acknowledge and accept the above risks.**

---

## 安全底线 / Security Baseline

### 中文

尽管 PoC 验证可能影响系统稳定性，本工具承诺以下安全底线：

1. **不永久改写系统关键文件** — PoC 不会修改 `/etc`、`/boot`、`/usr`、`/lib` 等系统关键目录下的文件
2. **不进行持久化提权** — PoC 不会使用 `su`/`sudo` 进行持久化提权，不会创建后门用户或修改认证配置
3. **完整的恢复机制** — 所有临时文件修改（如 CTF 验证文件）均在 Post 阶段完整清理和恢复
4. **临时文件隔离** — 所有 PoC 操作限制在 `/tmp/sec-kernel-poc-*` 临时目录中
5. **执行超时保护** — 所有 PoC 执行均有超时限制（默认 10 秒），防止无限阻塞

### English

Although PoC verification may affect system stability, this tool guarantees the following security baseline:

1. **No Permanent Modification of Critical System Files** — PoC will not modify files under critical system directories such as `/etc`, `/boot`, `/usr`, `/lib`
2. **No Persistent Privilege Escalation** — PoC will not use `su`/`sudo` for persistent privilege escalation, will not create backdoor users or modify authentication configurations
3. **Complete Recovery Mechanism** — All temporary file modifications (e.g., CTF verification files) are fully cleaned and restored during the Post phase
4. **Temporary File Isolation** — All PoC operations are confined to `/tmp/sec-kernel-poc-*` temporary directories
5. **Execution Timeout Protection** — All PoC executions have timeout limits (default 10 seconds) to prevent indefinite blocking

---

## 建议运行环境 / Recommended Runtime Environment

### 中文

鉴于 PoC 验证可能导致 kernel crash，**强烈建议**在以下环境中运行本工具：

1. **虚拟机（VM）** — 使用 KVM/QEMU/VMware/VirtualBox 等虚拟化平台
2. **可快照环境** — 运行前创建快照，crash 后可快速恢复
3. **一次性实例** — 使用云平台（AWS/GCP/Azure）的临时实例
4. **专用测试机** — 与生产网络完全隔离的物理测试机

**禁止在以下环境中运行**：
- 承载生产业务的服务器
- 无法快速恢复的环境
- 共享的开发/CI 服务器

### English

Given that PoC verification may cause kernel crash, it is **strongly recommended** to run this tool in the following environments:

1. **Virtual Machines (VM)** — Use virtualization platforms such as KVM/QEMU/VMware/VirtualBox
2. **Snapshotable Environments** — Create snapshots before execution for quick recovery after crash
3. **Disposable Instances** — Use temporary instances on cloud platforms (AWS/GCP/Azure)
4. **Dedicated Test Machines** — Physical test machines completely isolated from production networks

**Running in the following environments is prohibited**:
- Servers carrying production workloads
- Environments that cannot be quickly recovered
- Shared development/CI servers

---

## 环境限制 / Environment Restrictions

### 中文

1. **仅限测试环境** — 本工具仅允许在隔离的测试环境中使用
2. **严禁生产环境** — 严禁在任何生产环境中运行本工具，包括但不限于：
   - 承载业务流量的服务器
   - 存储用户数据的系统
   - 提供在线服务的基础设施
   - 任何可能影响业务连续性的环境
3. **隔离要求** — 测试环境必须与生产网络完全隔离
4. **数据保护** — 测试环境中不得包含真实的敏感数据或个人信息

### English

1. **Test Environment Only** — This tool is only permitted for use in isolated test environments
2. **Production Environment Prohibited** — Running this tool in any production environment is strictly prohibited, including but not limited to:
   - Servers carrying business traffic
   - Systems storing user data
   - Infrastructure providing online services
   - Any environment that may affect business continuity
3. **Isolation Requirement** — The test environment must be completely isolated from production networks
4. **Data Protection** — Test environments must not contain real sensitive data or personal information

---

## 法律责任 / Legal Liability

### 中文

1. **用户全责** — 用户对使用本工具产生的一切后果承担全部法律责任
2. **合规义务** — 用户有义务确保使用本工具的行为符合所在国家/地区的法律法规
3. **违规后果** — 未经授权对他人系统进行安全测试可能构成违法行为，包括但不限于：
   - 非法侵入计算机信息系统罪
   - 破坏计算机信息系统罪
   - 违反《网络安全法》相关条款
   - 违反 Computer Fraud and Abuse Act (CFAA)
   - 违反 Computer Misuse Act
4. **损害赔偿** — 因违规使用导致的任何损失，由用户自行承担全部赔偿责任

### English

1. **Full User Responsibility** — Users bear full legal responsibility for all consequences arising from the use of this tool
2. **Compliance Obligation** — Users are obligated to ensure that the use of this tool complies with the laws and regulations of their jurisdiction
3. **Consequences of Violation** — Unauthorized security testing on others' systems may constitute illegal activities, including but not limited to:
   - Unauthorized access to computer information systems
   - Destruction of computer information systems
   - Violations of Cybersecurity Law
   - Violations of the Computer Fraud and Abuse Act (CFAA)
   - Violations of the Computer Misuse Act
4. **Damages** — Users shall bear full liability for any losses caused by unauthorized or improper use

---

## 免责条款 / Disclaimer

### 中文

1. **工具本身中立** — 本工具仅为安全研究和防御目的而设计，工具本身不承担任何因滥用产生的责任
2. **无担保** — 本工具按"现状"提供，不提供任何明示或暗示的担保，包括但不限于适销性、特定用途适用性的担保
3. **风险自担** — 使用本工具进行检测的风险完全由用户自行承担
4. **间接损害免责** — 开发者不对任何间接的、附带的、特殊的、惩罚性的或后果性的损害承担责任
5. **Kernel Crash 风险** — PoC 验证过程可能导致 kernel panic/hang/deadlock，导致系统需要重启。用户必须在可快照/可恢复的环境中运行

### English

1. **Tool Neutrality** — This tool is designed solely for security research and defensive purposes; the tool itself bears no responsibility for any misuse
2. **No Warranty** — This tool is provided "as-is" without any express or implied warranties, including but not limited to warranties of merchantability or fitness for a particular purpose
3. **Risk Assumption** — All risks associated with using this tool for detection are solely borne by the user
4. **Indirect Damages Disclaimer** — Developers shall not be liable for any indirect, incidental, special, punitive, or consequential damages
5. **Kernel Crash Risk** — The PoC verification process may cause kernel panic/hang/deadlock, requiring system reboot. Users must run in snapshotable/recoverable environments

> **最后更新 / Last Updated**: 2026-05-09
>
> **适用版本 / Applicable Version**: sec-kernel v1.2.0+
