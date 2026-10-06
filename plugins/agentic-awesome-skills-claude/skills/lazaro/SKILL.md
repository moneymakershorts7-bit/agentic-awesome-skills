---
name: lazaro
description: Automated agent personalization backup, 0-secret sanitizer, and 1-click disaster recovery system with private GitHub syncing and local archive generation.
category: agentic
risk: safe
source: community
source_repo: moneymakershorts7-bit/lazaro-personalization-backup
source_type: community
date_added: "2026-10-06"
author: npirela
tags: [lazaro, backup, disaster-recovery, state-snapshot, personalization, secrets-free, memory, resurrection]
tools: [Bash, Read, Write]
---

# Lázaro: Agent Personalization Backup & 1-Click Resurrection

## Overview

`lazaro` executes the automated backup and disaster recovery pipeline for the agent's personalized environment. It sanitizes all configs (stripping secrets, keys, and tokens), synchronizes the 4-layer cognitive memory (`~/.agents/memory/`), backs up custom skills (`~/.agents/skills/`), creates local compressed `.tar.gz` / `.zip` archives in `~/backups/`, and pushes the state to the user's private GitHub repository (`moneymakershorts7-bit/lazaro-personalization-backup`).

## When to Use

- Triggered whenever the user inputs `/lazaro` in chat.
- When asked to "backup our personalization", "create backup", "take disaster recovery snapshot", or "resurrect environment".
- Before major system re-installations, migrations to new machines, or destructive operations.
- Periodic milestone backups of cognitive memory and newly distilled skills.

---

## Execution Workflow

When invoked via `/lazaro` or backup request:

1. **Execute Backup Script**:
   ```bash
   bash /home/npirela/lazaro-personalization-backup/backup.sh
   ```

2. **Verify Security Gate**:
   - The script runs `verify-secrets.py` to assert zero secrets, API tokens, passwords, or private keys are in the archive or commit.
   - MCP credentials in `mcp_config.json` are automatically replaced with `${ENV_VAR}` variables.

3. **Verify Local Archives & Remote Sync**:
   - Confirms creation of `~/backups/lazaro-personalization-latest.tar.gz` and `.zip`.
   - Reads SHA-256 hash from `~/backups/lazaro-personalization-latest.tar.gz.sha256`.
   - Confirms push to `https://github.com/moneymakershorts7-bit/lazaro-personalization-backup`.

4. **Return Status Summary**:
   - Report the backup timestamp, total skills saved, memory files saved, archive path, and GitHub sync status.

---

## 1-Click Restoration Reference

To restore this backup on any new machine:
```bash
git clone https://github.com/moneymakershorts7-bit/lazaro-personalization-backup.git ~/lazaro-backup
bash ~/lazaro-backup/restore.sh
```

For complete recovery runbook, see [recovery-runbook.md](references/recovery-runbook.md).
