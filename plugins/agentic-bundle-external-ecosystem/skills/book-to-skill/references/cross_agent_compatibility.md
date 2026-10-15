# Cross-Agent Compatibility and Discovery

## Skill Roots by Host

| Host | Personal Root | Project Root |
|---|---|---|
| **GitHub Copilot CLI** | `~/.copilot/skills` or `~/.agents/skills` | `.github/skills` |
| **Claude Code** | `~/.claude/skills` | `.claude/skills` |
| **Amp** | `~/.config/agents/skills` or `~/.agents/skills` | `.agents/skills` |
| **Hermes Agent** | `$HERMES_HOME/skills/<category>` | `.hermes/skills` |
| **OpenCode** | `~/.agents/skills` | `.opencode/skills` |
| **OpenClaw** | `~/.openclaw/skills` or `~/.agents/skills` | `.agents/skills` |

## Symlink Strategy for Claude Code
For cross-agent installs in `~/.agents/skills`, link into Claude Code:
```bash
mkdir -p "$HOME/.claude/skills"
ln -sfn "$HOME/.agents/skills/<skill_name>" "$HOME/.claude/skills/<skill_name>"
```

## Publishing Generated Skills
To publish a generated skill:
1. Initialize git in the skill directory:
   ```bash
   cd "$SKILLS_HOME/<skill_name>"
   git init -b main
   git add -A
   git commit -m "feat(<skill_name>): initial skill generation"
   gh repo create "<skill_name>" --private --source . --push
   ```
2. Verify visibility and respect copyright boundaries.
