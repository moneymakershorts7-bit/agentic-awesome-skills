# Lessons Learned - 误报案例库 & AI Agent 经验教训

## 概述

本文档记录 sec-userspace 运行过程中**已确认的误报案例**和**AI Agent 操作经验教训**，供后续扫描时快速判定参考。

每次扫描验证告警后，如果发现新的误报模式，**必须追加记录到本文档**。

---

## AI Agent 经验教训 (2026-04-28 起)

### [2026-04-28] pyz 运行失败时未下载 Python 3.11

- **问题**: AI Agent 在遇到 pyz 字节码兼容问题时，没有自动下载 Python 3.11 运行时
- **错误行为**: 
  - 尝试用系统 Python 3.12 运行 pyz
  - 失败后放弃使用 sec-userspace
  - 没有下载 Python 3.11 standalone
- **正确行为**: 
  - 检测到 "bad magic number" 错误后，立即下载 Python 3.11 standalone
  - 从 GitHub 下载 `cpython-3.11.11+20241206-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz` 到 `workspace/python311/`
  - 使用 `workspace/python311/bin/python3` 重新运行扫描
- **根本原因**: SKILL.md 缺少明确的 Python 运行时使用指南
- **处置方式**: 已在 SKILL.md 中添加 "CRITICAL: Python Runtime Usage Guide" 章节，强化 AI Agent 必须遵守的流程
- **预防措施**: 
  - SKILL.md 中新增强制性检查清单
  - Troubleshooting 部分明确标注常见错误
  - For AI Agents 部分增加第 6 条原则

---

## 误报案例格式

```
### [日期] 告警名称
- **模块**: analyzer 名称
- **环境**: WSL2 / K8s / 容器 / 云主机 / 开发机
- **告警内容**: 原始告警描述
- **验证命令**: 实际执行的验证命令
- **验证结果**: 命令输出摘要
- **误报原因**: 为什么是误报
- **处置方式**: 已加白名单 / 已修复源码 / 仅记录
```

---

## 误报案例

### [2026-04-28] 进程隐藏检测

- **模块**: process_hiding_analyzer
- **环境**: Cloud K8s node
- **告警内容**: 发现 283 个隐藏进程：在 /proc 中持续存在但不在进程列表中
- **验证命令**: 
  ```bash
  ls -d /proc/[0-9]* 2>/dev/null | wc -l
  ps -e --no-headers | wc -l
  ```
- **验证结果**: 两者都返回 285，进程数一致
- **误报原因**: 检测逻辑在 K8s 环境中存在问题，/proc 和 ps 的进程数实际一致
- **处置方式**: 仅记录，待后续版本修复

### [2026-04-28] Dangerous Mount: /

- **模块**: container_escape_analyzer
- **环境**: 物理机/虚拟机（非容器）
- **告警内容**: Mount point / detected. Risk: Root filesystem mount - full host access
- **验证命令**: 
  ```bash
  mount | grep "on / "
  ```
- **验证结果**: `/dev/nvme0n1p3 on / type ext4 (rw,relatime)` - 正常的根文件系统挂载
- **误报原因**: 该检测器主要用于容器环境检测容器逃逸，在物理机上不应触发
- **处置方式**: 仅记录，待后续版本修复环境检测逻辑

### [2026-05-29] Unsigned Kernel Modules Detected (WSL2)

- **模块**: kernel_integrity_checker
- **环境**: WSL2 (AlmaLinux 10.1)
- **告警内容**: Found 29 suspicious unsigned kernel modules
- **验证命令**: 
  ```bash
  uname -r | grep microsoft && ls /lib/modules/$(uname -r)/
  ```
- **验证结果**: 内核版本含 `microsoft-standard-WSL2`，模块目录正常存在
- **误报原因**: WSL2 内核由 Windows 宿主管控，内核模块签名机制与标准 Linux 不同，无签名属正常行为
- **处置方式**: 仅记录，WSL2 环境建议跳过此检测

### [2026-05-29] Kernel Symbol Table Inconsistencies (WSL2)

- **模块**: kernel_integrity_checker
- **环境**: WSL2 (AlmaLinux 10.1)
- **告警内容**: Found 122529 kernel symbols that cannot be associated with known kernel modules
- **验证命令**: 
  ```bash
  uname -r | grep microsoft
  ```
- **验证结果**: 内核版本含 `microsoft-standard-WSL2`
- **误报原因**: WSL2 使用 Microsoft 定制内核，符号表与标准 Linux 内核模块关联关系不同，大量符号无法关联属正常
- **处置方式**: 仅记录，WSL2 环境建议跳过此检测

### [2026-05-29] Unknown PAM Modules (System RPM)

- **模块**: pam_backdoor_analyzer
- **环境**: AlmaLinux 10.1（WSL2 / 标准服务器）
- **告警内容**: Unknown PAM module 误报以下三个模块：
  - `/lib64/security/pam_canonicalize_user.so`
  - `/lib64/security/pam_setquota.so`
  - `/lib64/security/pam_systemd_loadkey.so`
- **验证命令**: 
  ```bash
  rpm -qf /lib64/security/pam_canonicalize_user.so
  rpm -qf /lib64/security/pam_setquota.so
  rpm -qf /lib64/security/pam_systemd_loadkey.so
  ```
- **验证结果**: `pam-1.6.1-8.el10.x86_64` 和 `systemd-pam-257-13.el10.alma.1.x86_64`
- **误报原因**: 以上三个 PAM 模块均为系统 RPM 包提供的标准模块（pam + systemd-pam），不在 pam_backdoor_analyzer 已知模块列表中
- **处置方式**: 应将这些标准系统 PAM 模块加入 pam_backdoor_analyzer 的已知模块白名单

### [2026-05-29] sudo NOPASSWD Rule (Development Environment)

- **模块**: auth_analyzer
- **环境**: 开发机/WSL2
- **告警内容**: Found NOPASSWD sudo rule: ecs-user ALL=(ALL) NOPASSWD: ALL
- **验证命令**: 
  ```bash
  sudo grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/
  ```
- **验证结果**: `/etc/sudoers.d/ecs-user:ecs-user ALL=(ALL) NOPASSWD: ALL`
- **误报原因**: 开发环境为方便使用配置 NOPASSWD 属常见实践，非安全威胁
- **处置方式**: 仅记录，生产环境建议移除此配置

---

## 维护规则

1. **每次扫描验证后**，如果发现新的误报模式，必须追加到本文档对应的环境分类下
2. **格式要求**：必须包含模块名、环境、验证命令、验证结果、误报原因、处置方式
3. **累积优化**：当同一模块的误报案例累积超过 3 条时，应考虑在源码或白名单中修复
4. **定期回顾**：每次 Release 前回顾本文档，将高频误报转化为白名单规则或源码优化
5. **AI Agent 经验教训**：记录 AI Agent 在使用过程中的常见错误和改进措施，帮助后续 AI Agent 更好地使用工具
