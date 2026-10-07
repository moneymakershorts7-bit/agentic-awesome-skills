# 白名单管理

## 概述

确认的误报应添加到白名单中，以防止重复告警。

数据泄露拦截器提供运行时保护，具备全面的白名单机制，支持：
- 多层白名单（PID、IP、域名、路径、环境）
- 环境感知拦截（开发、预发布、生产）
- Dry-run 模式用于安全测试
- YAML 和 JSON 配置格式
- 自动回滚能力

## 配置文件

| 文件 | 用途 |
|------|------|
| `assets/whitelist.yaml.example` | 完整的示例配置 |
| `assets/whitelist-default.json` | 内置默认白名单 |
| `assets/runtime-whitelist.json` | AI Agent 保护的运行时防护规则 |
| `/etc/sec-userspace/whitelist.yaml` | 生产环境配置（推荐） |
| `/data/sec-userspace/workspace/whitelist.json` | 旧版工作区白名单 |

## 快速开始

### 开发环境

```bash
# Use defaults (dry-run enabled)
python3 -m scripts.main --mode quick
```

### 生产环境

```bash
# 1. Copy example configuration
sudo cp assets/whitelist.yaml.example /etc/sec-userspace/whitelist.yaml

# 2. Customize for your environment
sudo vim /etc/sec-userspace/whitelist.yaml

# 3. Run with custom config
sudo python3 -m scripts.main \
  --whitelist-config /etc/sec-userspace/whitelist.yaml \
  --no-dry-run
```

## 白名单文件位置

`/data/sec-userspace/workspace/whitelist.json`

## 白名单格式

```json
{
  "version": "1.0",
  "entries": [
    {
      "id": "whitelist-001",
      "module": "credential_analyzer",
      "pattern": "AKIAIOSFODNN7EXAMPLE",
      "reason": "AWS example key for documentation",
      "added_by": "agent",
      "added_at": "2026-03-29T10:30:00Z",
      "expires": null
    },
    {
      "id": "whitelist-002",
      "module": "process_analyzer",
      "pattern": "/usr/bin/dockerd",
      "reason": "Docker daemon, normal system service",
      "added_by": "agent",
      "added_at": "2026-03-29T10:35:00Z",
      "expires": "2026-06-29T00:00:00Z"
    }
  ]
}
```

## 字段说明

| 字段 | 必填 | 说明 |
|------|------|------|
| `id` | 是 | 唯一标识符，格式 `whitelist-NNN` |
| `module` | 是 | 来源检测模块名称 |
| `pattern` | 是 | 匹配模式（文件路径、进程名、凭据模式） |
| `reason` | 是 | 误报说明 |
| `added_by` | 是 | 来源：`agent` 或 `user` |
| `added_at` | 是 | 时间戳（ISO 8601） |
| `expires` | 否 | 过期时间，null = 永不过期 |

## 匹配规则

- `module` + `pattern` 精确匹配时跳过告警
- 支持 Glob 模式：`*` 匹配任意字符
- 已过期的条目自动跳过

## 命令

```bash
# View current whitelist
cat /data/sec-userspace/workspace/whitelist.json 2>/dev/null || echo "Whitelist not found"

# Create whitelist file
sudo mkdir -p /data/sec-userspace/workspace
sudo tee /data/sec-userspace/workspace/whitelist.json > /dev/null << 'EOF'
{
  "version": "1.0",
  "entries": []
}
EOF
```

## 管理原则

- **最小权限**：仅添加确认的误报
- **可追溯**：每条记录必须有清晰的 `reason`
- **定期审计**：每季度审查白名单
- **安全优先**：对 CRITICAL 级别告警保持谨慎

---

## 生产环境部署指南

### 前置条件

部署到生产环境前，请确保：

1. **先在预发布环境测试**
   ```bash
   # Run in staging with dry-run mode
   python3 -m scripts.main \
     --whitelist-config /etc/sec-userspace/whitelist.yaml \
     --dry-run
   ```

2. **审查默认白名单**
   ```bash
   # Check what's whitelisted by default
   cat assets/whitelist-default.json
   ```

3. **识别关键业务进程**
   - 列出所有不应被拦截的关键服务
   - 记录预期的网络连接
   - 梳理正常的数据流模式

### 第一阶段：审计模式（第 1-2 周）

以仅审计模式运行，收集基线数据：

```bash
# Configuration for audit mode
config:
  dry_run: true
  environment: "production"
  
audit_logging:
  enabled: true
  log_level: "DEBUG"  # Capture all events
```

**目标**：
- 了解正常行为模式
- 识别潜在误报
- 调优白名单配置
- 不进行实际拦截

### 第二阶段：告警模式（第 3-4 周）

启用告警但不拦截：

```bash
# Update configuration
production:
  strict_mode: true
  require_approval: true  # Manual review before blocking
  
auto_block:
  enabled: false  # Don't auto-block yet
  
notifications:
  slack:
    enabled: true
    channel: "#security-alerts"
```

**目标**：
- 验证告警准确性
- 培训安全团队的响应流程
- 优化严重性阈值
- 建立检测信心

### 第三阶段：有限拦截（第 5-6 周）

仅对 CRITICAL 级别威胁启用拦截：

```bash
auto_block:
  enabled: true
  severity_levels:
    - "CRITICAL"
  exclude_processes:
    - "systemd"
    - "dockerd"
    - "containerd"
    - "kubelet"
    - "nginx"
    - "postgres"
```

**目标**：
- 测试拦截机制
- 验证回滚流程
- 评估对运维的影响
- 记录发现的问题

### 第四阶段：完整保护（第 7 周起）

启用完整保护并持续监控：

```bash
auto_block:
  enabled: true
  severity_levels:
    - "CRITICAL"
    - "HIGH"
  exclude_processes: []  # Remove exclusions after validation
  
rollback:
  auto_rollback: false
  notify_on_rollback: true
```

**目标**：
- 完整运营能力
- 持续监控
- 定期更新白名单
- 集成事件响应

## 监控与维护

### 每日检查

```bash
# Monitor disk usage
du -sh /var/log/sec-userspace/
```

### 每周任务

1. **分析误报**
   - 调查所有报告的问题
   - 将合法流量添加到白名单
   - 记录根因

3. **更新威胁情报**
   ```bash
   # Refresh threat intel database
   python3 -m scripts.threat_intel.update
   ```

### 每月任务

1. **白名单审计**
   - 审查所有白名单条目
   - 清除过期条目
   - 验证仍然需要的例外项

2. **性能评估**
   - 检查 CPU/内存开销
   - 审查日志轮转
   - 按需优化配置

3. **事件响应演练**
   - 测试回滚流程
   - 验证通知渠道
   - 更新运维手册

## 故障排除

### 问题：合法流量被拦截

**症状**：启用拦截后业务应用出现故障

**解决方案**：
```bash
# 1. 检查告警日志
sudo tail -100 /var/log/sec-userspace/sec-userspace.log

# 2. 将合法域名添加到白名单
# Edit /etc/sec-userspace/whitelist.yaml and add:
trusted_domains:
  - "api.your-business.com"

# 4. Reload configuration
sudo systemctl restart sec-userspace
```

### 问题：误报率过高

**症状**：告警过多，影响运维

**解决方案**：
```bash
# 1. Temporarily increase threshold
production:
  alert_thresholds:
    medium: false  # Reduce noise
    
# 2. Run in audit mode to retrain
config:
  dry_run: true
  
# 3. Analyze patterns and update whitelist
```

### 问题：回滚失败

**症状**：被拦截的连接无法恢复

**解决方案**：
```bash
# Manual iptables rollback
iptables -L -n -v  # List current rules
iptables -D OUTPUT -d <IP> -j DROP  # Remove specific rule

# Manual process resume
kill -SIGCONT <PID>  # Resume stopped process

# Manual file unlock
chattr -i /path/to/file  # Remove immutable flag
```

## 集成示例

### SIEM 集成（Splunk）

```yaml
integrations:
  siem:
    enabled: true
    endpoint: "https://splunk.company.com:8088/services/collector"
    api_key: "${SPLUNK_HEC_TOKEN}"
    sourcetype: "sec:inspect:block"
    index: "security"
```

### Slack 通知

```yaml
integrations:
  notifications:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK_URL}"
      channel: "#security-alerts"
      username: "SecInspect Bot"
      icon_emoji: ":shield:"
      
      # Custom message format
      message_template: |
        :rotating_light: *Data Exfiltration Attempt Blocked*
        Severity: {{severity}}
        Process: {{process_name}} (PID: {{pid}})
        Destination: {{dst_ip}}:{{dst_port}}
        Action: {{action}}
        Time: {{timestamp}}
```

### PagerDuty 集成

```yaml
integrations:
  paging:
    pagerduty:
      enabled: true
      routing_key: "${PAGERDUTY_ROUTING_KEY}"
      severity_mapping:
        CRITICAL: "critical"
        HIGH: "error"
        MEDIUM: "warning"
        LOW: "info"
```

## 安全注意事项

### 白名单安全

- 永远不要将 `0.0.0.0/0` 或 `*` 域名加入白名单
- 尽可能使用具体的 IP/域名
- 为临时例外设置过期时间
- 生产环境白名单变更需要审批

### 日志保护

```bash
# Secure log directory
sudo mkdir -p /var/log/sec-userspace
sudo chmod 750 /var/log/sec-userspace
sudo chown root:security-team /var/log/sec-userspace

# Enable log rotation
sudo tee /etc/logrotate.d/sec-userspace > /dev/null << 'EOF'
/var/log/sec-userspace/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 640 root security-team
}
EOF
```

### 配置保护

```bash
# Secure configuration file
sudo chmod 600 /etc/sec-userspace/whitelist.yaml
sudo chown root:root /etc/sec-userspace/whitelist.yaml

# Use environment variables for secrets
export SLACK_WEBHOOK_URL="xxx"
export PAGERDUTY_ROUTING_KEY="yyy"
```

## 性能调优

### 资源限制

```yaml
# Limit resource consumption
performance:
  max_cpu_percent: 10
  max_memory_mb: 512
  scan_interval_seconds: 60
  batch_size: 100
```

### 日志轮转

```bash
# Rotate logs daily, keep 90 days
sudo vim /etc/logrotate.d/sec-userspace
```

### 数据库优化

```bash
# Vacuum SQLite databases monthly
sqlite3 /var/lib/sec-userspace/threat-intel.db "VACUUM;"
```
