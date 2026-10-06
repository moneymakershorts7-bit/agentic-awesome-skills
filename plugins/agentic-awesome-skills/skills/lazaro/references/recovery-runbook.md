# Lázaro Recovery Runbook

## Emergency Restoration Steps

If migrating to a brand-new OS or restoring after a machine wipe:

```bash
# Step 1: Install prerequisite packages (git, python3, tar)
sudo apt update && sudo apt install -y git python3 tar curl

# Step 2: Authenticate GitHub CLI or clone via SSH
gh auth login
# OR
git clone https://github.com/moneymakershorts7-bit/lazaro-personalization-backup.git ~/lazaro-backup

# Step 3: Run the 1-Click Restoration Script
bash ~/lazaro-backup/restore.sh

# Step 4: Supply local environment credentials (optional for external MCP servers)
export GITHUB_PERSONAL_ACCESS_TOKEN="your_token_here"
```

## Health Verification

Check that the restored symlinks point to the expected targets:
- `ls -la ~/.agents/skills` -> `~/.gemini/config/skills`
- `ls -la ~/.agents/memory` -> `~/.gemini/config/memory`
- `ls -la ~/AGENTS.md` -> `~/.gemini/config/AGENTS.md`
