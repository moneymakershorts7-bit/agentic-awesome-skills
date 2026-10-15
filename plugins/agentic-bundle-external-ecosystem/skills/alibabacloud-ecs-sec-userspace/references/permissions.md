# AI 工具权限配置

## 安全模型

sec-userspace 采用**只读采集 + 最小写入**的安全模型：

| 操作类型 | 范围 | 说明 |
|---|---|---|
| **root (sudo)** | 系统级 | 需要 root 权限读取 /proc、/sys、系统日志等内核/系统信息 |
| **只读采集** | 全系统 | 所有系统信息均为只读收集，**零系统修改**，不写入/删除/修改任何系统文件 |
| **写入** | 仅 workspace/ | 只需要 workspace 目录的写权限，用于保存扫描日志和报告 |

---

## 最小权限集

```json
{
  "permissions": {
    "allow": [
      "Bash(sudo:*)",
      "Bash(python3:*)",
      "Read(**)",
      "Write(/data/sec-userspace/workspace/**)",
      "Write(workspace/**)"
    ]
  }
}
```

### 权限逐项说明

| 权限 | 用途 | 安全说明 |
|---|---|---|
| `Bash(sudo:*)` | 以 root 权限执行安全扫描 | 必需：读取 /proc/*/maps、/sys/module、auth.log 等需要 root |
| `Bash(python3:*)` | 运行 sec-userspace Python 脚本 | 必需：执行扫描入口 |
| `Read(**)` | 读取系统文件、日志和配置 | 只读：不会修改任何系统文件 |
| `Write(/data/sec-userspace/workspace/**)` | 保存报告和日志到默认工作区 | 主路径，优先使用 |
| `Write(workspace/**)` | 保存报告和日志到相对工作区 | 降级路径，主路径写入失败时使用 |

---

## 权限预配置

### 自动配置（推荐）

sec-userspace 提供 `setup_permissions.py` 脚本，自动检测系统中已安装的 AI 工具并预配置权限：

```bash
# 自动检测所有已安装的 AI 工具并配置权限（推荐）
cd {SKILL_BASE_DIR} && python3 scripts/setup_permissions.py --auto

# 指定某个工具
python3 scripts/setup_permissions.py --tool claude
python3 scripts/setup_permissions.py --tool qoder

# 配置所有支持的工具
python3 scripts/setup_permissions.py --all

# 预览（不实际修改）
python3 scripts/setup_permissions.py --auto --dry-run

# 查看当前权限
python3 scripts/setup_permissions.py --show

# 列出支持的工具
python3 scripts/setup_permissions.py --list
```

脚本会自动：
1. 扫描系统中已安装的 AI 工具（检测 `~/.claude`、`~/.qoder` 等目录）
2. 备份已有配置文件
3. 合并最小权限到配置文件（不覆盖已有权限）
4. 报告配置结果

### 手动配置

将以下 JSON 写入对应工具的配置文件：

```json
{
  "permissions": {
    "allow": [
      "Bash(sudo:*)",
      "Bash(python3:*)",
      "Read(**)",
      "Write(/data/sec-userspace/workspace/**)",
      "Write(workspace/**)"
    ]
  }
}
```

---

## 支持的 AI 工具

### 主要支持（完全兼容）

| 工具 | 配置文件路径 | 检测标记 |
|---|---|---|
| **Claude Code** | `~/.claude/settings.local.json` | `~/.claude/` |
| **QoderCLI** | `~/.qoder/settings.json` | `~/.qoder/` |
| **OpenCode** | `~/.opencode/settings.json` | `~/.opencode/` |

### 次要支持

| 工具 | 配置文件路径 | 检测标记 |
|---|---|---|
| Windsurf | `~/.codeium/windsurf/settings.json` | `~/.codeium/` |
| Cursor | `~/.cursor/settings.json` | `~/.cursor/` |
| Gemini CLI | `~/.gemini/settings.json` | `~/.gemini/` |
| Trae | `~/.trae/settings.json` | `~/.trae/` |

---

## 验证权限

配置完成后验证：

```bash
# 验证 sudo 权限
sudo id > /dev/null && echo "Sudo OK"

# 验证读取权限
sudo cat /proc/1/status > /dev/null 2>&1 && echo "Read OK"

# 验证写入权限
mkdir -p /data/sec-userspace/workspace && touch /data/sec-userspace/workspace/.test && rm /data/sec-userspace/workspace/.test && echo "Write OK"
```

---

## FAQ

**Q: 为什么需要 root 权限？**
A: 安全扫描需要读取 `/proc/*/maps`（内存映射）、`/proc/*/exe`（进程二进制）、`/sys/module`（内核模块）、`/var/log/auth.log`（认证日志）等系统级信息，这些都需要 root 权限。

**Q: sec-userspace 会修改系统文件吗？**
A: 不会。sec-userspace 所有系统信息均为只读采集，唯一的写入操作是将报告和日志保存到 workspace 目录。

**Q: 写入路径的优先级是什么？**
A: 优先写入 `/data/sec-userspace/workspace/`，若该路径不可写则降级到相对路径 `./workspace/`。可通过 `--output-dir` 参数自定义。
