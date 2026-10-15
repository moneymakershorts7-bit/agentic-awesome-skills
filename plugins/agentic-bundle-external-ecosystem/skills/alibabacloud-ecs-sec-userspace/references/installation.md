# 安装指南

## 快速安装

```bash
# 安装到 Claude Code 技能目录（推荐）
ln -s {SKILL_BASE_DIR} ~/.claude/skills/sec-userspace

# 安装到通用 AI 工具技能目录（agentskills.io 标准）
ln -s {SKILL_BASE_DIR} ~/.agents/skills/sec-userspace
```

## 支持的安装路径

| 工具 | 路径 | 优先级 |
|------|------|--------|
| Claude Code | `~/.claude/skills/sec-userspace` | 主要 |
| OpenCode | `~/.opencode/skills/sec-userspace` | 主要 |
| QoderCLI | `~/.qoder/skills/sec-userspace` | 主要 |
| Windsurf | `~/.codeium/windsurf/skills/sec-userspace` | 次要 |
| Cursor | `~/.cursor/skills/sec-userspace` | 次要 |
| Gemini CLI | `~/.gemini/skills/sec-userspace` | 次要 |
| Trae | `~/.trae/skills/sec-userspace` | 次要 |
| 通用 | `~/.agents/skills/sec-userspace` | 通用 |

## 环境配置

### 前置条件

- **Python**：>= 3.11
- **操作系统**：Linux（主流发行版）
- **权限**：root (sudo)

### 首次安装

```bash
# 创建工作目录
sudo mkdir -p /data/sec-userspace/workspace
sudo mkdir -p /var/log/sec-userspace

# 运行环境配置脚本
cd {SKILL_BASE_DIR}
sudo bash scripts/setup.sh
```

### 配置脚本功能

1. **Python 检测**：自动检测 Python >= 3.11
2. **Python 安装**：缺失时自动安装（支持 Debian/Ubuntu/RHEL/Alpine/SUSE/Arch）
3. **venv 创建**：创建隔离的 Python 环境
4. **技能安装**：自动创建符号链接到已检测的 AI 工具
5. **定时任务配置**：可选的每日安全扫描

```bash
# 配置并启用定时任务
sudo bash scripts/setup.sh --init-cron

# 移除定时任务
sudo bash scripts/setup.sh --remove-cron
```

## 运行时自动安装

sec-userspace 在每次运行时自动扫描已安装的 AI 工具并创建符号链接，无需手动安装。

特性：
- 幂等性：已存在的符号链接自动跳过
- 非阻塞：安装失败不影响扫描功能
- Sudo 感知：使用 `SUDO_USER` 查找真实用户主目录

## 验证安装

```bash
# 检查技能是否已安装
ls -la ~/.claude/skills/sec-userspace/SKILL.md

# 检查版本
head -5 ~/.claude/skills/sec-userspace/SKILL.md

# 测试运行
cd {SKILL_BASE_DIR} && sudo python3 -m scripts.main --help
```

## 更新技能

由于安装使用符号链接，源码更新会自动反映：

```bash
# 强制重新创建符号链接
ln -sf {SKILL_BASE_DIR} ~/.claude/skills/sec-userspace
```

## 卸载

```bash
rm -f ~/.claude/skills/sec-userspace
rm -f ~/.agents/skills/sec-userspace
rm -f ~/.qoder/skills/sec-userspace
```
