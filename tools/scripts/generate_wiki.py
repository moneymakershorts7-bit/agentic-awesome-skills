#!/usr/bin/env python3
"""
generate_wiki.py: Autonomous GitHub Wiki Generator and Synchronizer
Generates rich, fully cross-linked GitHub Wiki pages for Agentic Awesome Skills:
- Home.md (Hero overview, ecosystem stats, quickstart for all agents)
- _Sidebar.md & _Footer.md (Structured navigation & metadata)
- Skills-Catalog.md (2,764+ skills grouped with risks, tools, and repo links)
- Editorial-Bundles.md (59+ curated domain bundles with install instructions)
- Daily-Discovery.md (Daily scout logs & staged candidate tracking)
- Free-For-Dev-Directory.md (Curated developer tools with free tiers)
- Agent-Integrations.md (Setup for Claude Code, Jules, Gemini CLI, Cursor, etc.)
- Google-Jules-Sentinel.md (Autonomous cloud maintenance, REST API, CLI, workflows)
- Security-and-Auditing.md (Security scanner, malware checks, Skillspector)
- Contributing-and-Maintainer-Guide.md (Contribution guidelines, schemas, testing)

Supports local generation or direct git synchronization to the .wiki.git repository.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from _project_paths import find_repo_root
    REPO_ROOT = find_repo_root(__file__)
except Exception:
    REPO_ROOT = Path(__file__).resolve().parents[2]

GITHUB_REPO_DEFAULT = "moneymakershorts7-bit/agentic-awesome-skills"
GITHUB_REPO_UPSTREAM = "sickn33/agentic-awesome-skills"


def load_json_file(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️  Warning: failed to load {path}: {e}", file=sys.stderr)
        return default


def get_current_date() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def get_current_timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class WikiGenerator:
    def __init__(self, repo_root: Path, target_repo: str = GITHUB_REPO_DEFAULT):
        self.repo_root = repo_root
        self.target_repo = target_repo
        self.catalog_data = load_json_file(repo_root / "data" / "catalog.json", {})
        self.skills_index = load_json_file(repo_root / "skills_index.json", [])
        self.bundles_data = load_json_file(repo_root / "data" / "editorial-bundles.json", {}).get("bundles", [])
        self.free_for_dev = load_json_file(repo_root / "data" / "free_for_dev_index.json", [])
        self.package_json = load_json_file(repo_root / "package.json", {})
        
        # Build lookup table for skills
        self.skills = self.catalog_data.get("skills", [])
        if not self.skills and isinstance(self.skills_index, list):
            self.skills = self.skills_index
        
        self.total_skills = len(self.skills)
        self.version = self.package_json.get("version", "18.12.0")

    def generate_home(self) -> str:
        date_str = get_current_date()
        return f"""# 🇨🇭 Agentic Awesome Skills Wiki (Swiss Army Knife Edition)

Welcome to the official **Agentic Awesome Skills — Swiss Army Knife Edition** Knowledge Base and Developer Wiki!

The all-in-one **Swiss Army Knife for AI Coding Agents**: 2,764+ verified agent skills, 59 curated domain bundles, 1,321 free developer tools, Model Context Protocol (MCP) integrations, AST malware protection, and autonomous Google Jules maintenance.

*An autonomous, hardened distribution modified and maintained by **The Machine** (`moneymakershorts7-bit`), continuously synced with upstream `sickn33/agentic-awesome-skills`.*

[![Skills Total](https://img.shields.io/badge/Verified_Skills-{self.total_skills}+-blue.svg)](Skills-Catalog)
[![Curated Bundles](https://img.shields.io/badge/Curated_Bundles-{len(self.bundles_data)}+-green.svg)](Editorial-Bundles)
[![Free Dev Tools](https://img.shields.io/badge/Free_Dev_Tools-{len(self.free_for_dev)}+-orange.svg)](Free-For-Dev-Directory)
[![Version](https://img.shields.io/badge/Edition-Swiss_Army_Knife_V{self.version}-purple.svg)](https://github.com/{self.target_repo}/releases)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/{self.target_repo}/blob/main/LICENSE)

---

## 🚀 Quick Navigation

| Section | Description |
| :--- | :--- |
| 📚 **[Skills Catalog](Skills-Catalog)** | Complete browsable directory of all **{self.total_skills:,}** indexed skills grouped by category. |
| 📦 **[Editorial Bundles](Editorial-Bundles)** | **{len(self.bundles_data)}** curated domain stacks (DevOps, Security, Mobile, AI/ML, Fullstack). |
| 🔭 **[Daily Discovery Log](Daily-Discovery)** | Daily automated scouting reports of newly released skills & MCP servers. |
| 🆓 **[Free-For-Dev Directory](Free-For-Dev-Directory)** | Indexed knowledge base of **{len(self.free_for_dev):,}** developer tools with free tiers. |
| 🤖 **[Agent Integrations](Agent-Integrations)** | Setup instructions for Claude Code, Google Jules, Gemini CLI, Cursor, Windsurf, Devin, Kiro. |
| 🛡️ **[Google Jules Sentinel](Google-Jules-Sentinel)** | Documentation of Google Jules autonomous cloud maintenance agent and workflows. |
| 🔒 **[Security & Auditing](Security-and-Auditing)** | Security scanning, AST-based malware detection, Skillspector integration. |
| 🤝 **[Contributing Guide](Contributing-and-Maintainer-Guide)** | How to build skills, frontmatter standards, local testing, and Conventional Commits. |

---

## ⚡ Instant Setup for AI Coding Agents

Agentic Awesome Skills works out-of-the-box with all leading AI developer tools:

### 1. Claude Code
Install skills directly into your global or project agent directory:
```bash
# Clone or link skills to ~/.agents/skills/ or project .agents/skills/
git clone https://github.com/{self.target_repo}.git
cp -r agentic-awesome-skills/skills/* ~/.agents/skills/
```

### 2. Google Jules (Autonomous Cloud VM)
Configure your repository with an `AGENTS.md` file referencing the Jules maintainer directives:
```bash
# Dispatch autonomous background coding tasks to Jules
curl -s -X POST https://jules.googleapis.com/v1alpha/sessions \\
  -H "x-goog-api-key: $JULES_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "prompt": "Review and update repository dependencies",
    "sourceContext": {{"source": "sources/github/{self.target_repo}"}},
    "automationMode": "AUTO_CREATE_PR"
  }}'
```

### 3. Google Gemini CLI & Antigravity
Mount skills dynamically in Antigravity or Gemini CLI workspaces:
```bash
# Symlink skills into active workspace
ln -s /path/to/agentic-awesome-skills/skills ~/.gemini/skills
```

### 4. Cursor / Windsurf / Devin / Roo Code / Goose
Point your custom rule/skills directory to the `skills/` folder or import specific bundles using AAS CLI:
```bash
npx agentic-awesome-skills bundle install aas-security-operations
```

---

## 🏗️ Architecture & Security Principles

1. **Progressive Disclosure**: Keep skill files concise (< 300 lines) and link detailed references to `references/`.
2. **Deterministic Tool-First Gate**: Mechanical operations (formatting, conversions, OCR) use industry CLI tools instead of wasteful LLM tokens.
3. **Strict Grounding & Veracity**: Zero hallucination, absolute factual verification, and honest error reporting.
4. **Autonomous Sentinel**: Daily discovery scouts GitHub and Google Jules continuously heals, verifies, and updates documentation.

> ℹ️ *Wiki synchronized automatically on {date_str} by **The Machine** & Google Jules Maintainer Sentinel.*
"""

    def generate_sidebar(self) -> str:
        return f"""### 🇨🇭 AAS Swiss Army Knife
* **[🏠 Home](Home)**
* **[🏗️ Architecture & Principles](Home#%EF%B8%8F-architecture--security-principles)**

---

### 📚 Catalog & Ecosystem
* **[📖 Skills Catalog ({self.total_skills:,})](Skills-Catalog)**
* **[📦 Editorial Bundles ({len(self.bundles_data)})](Editorial-Bundles)**
* **[🆓 Free-For-Dev Directory ({len(self.free_for_dev):,})](Free-For-Dev-Directory)**
* **[🔭 Daily Discovery Log](Daily-Discovery)**

---

### 🤖 Agent Integrations
* **[⚡ All Agent Integrations](Agent-Integrations)**
* **[🤖 Google Jules Sentinel](Google-Jules-Sentinel)**
* **[🟣 Claude Code Guide](Agent-Integrations#1-claude-code)**
* **[🔵 Gemini & Antigravity](Agent-Integrations#3-google-gemini-cli--antigravity)**
* **[🟢 Cursor & Windsurf](Agent-Integrations#4-cursor--windsurf)**
* **[🟠 Kiro & OpenCode](Agent-Integrations#5-kiro--opencode--goose)**

---

### 🛡️ Governance & Quality
* **[🔒 Security & Auditing](Security-and-Auditing)**
* **[🤝 Contributing Guide](Contributing-and-Maintainer-Guide)**
* **[📦 GitHub Repository](https://github.com/{self.target_repo})**
"""

    def generate_footer(self) -> str:
        timestamp = get_current_timestamp()
        return f"""---
<div align="center">
  <sub>Maintained and modified autonomously by <b>The Machine</b>, <b>Google Jules</b> & <b>Agentic Awesome Skills</b> Maintainers. Last updated: <code>{timestamp}</code></sub>
</div>
"""

    def generate_skills_catalog(self) -> str:
        # Group skills by category
        categories: Dict[str, List[Dict[str, Any]]] = {}
        for s in self.skills:
            cat = s.get("category", "uncategorized") or "uncategorized"
            categories.setdefault(cat, []).append(s)
        
        # Sort categories by item count descending
        sorted_cats = sorted(categories.items(), key=lambda x: len(x[1]), reverse=True)
        
        md = []
        md.append(f"# 📖 Agentic Skills Catalog\n")
        md.append(f"This page indexes all **{self.total_skills:,}** verified agent skills available in the repository.\n")
        md.append("Skills are formatted following the Agent Skill Specification with valid YAML frontmatter, deterministic triggers, risk ratings, and progressive disclosure references.\n\n")
        
        md.append("## 📊 Categories Overview\n\n")
        md.append("| Category | Skills Count | Primary Domain |\n")
        md.append("| :--- | :---: | :--- |\n")
        for cat_name, cat_skills in sorted_cats:
            cat_anchor = cat_name.lower().replace(" ", "-").replace("/", "-")
            md.append(f"| [**{cat_name.title()}**](#{cat_anchor}) | `{len(cat_skills)}` | Domain skills for {cat_name} |\n")
        md.append("\n---\n\n")

        for cat_name, cat_skills in sorted_cats:
            cat_anchor = cat_name.lower().replace(" ", "-").replace("/", "-")
            sorted_cat_skills = sorted(cat_skills, key=lambda x: x.get("id", ""))
            md.append(f"## <a id=\"{cat_anchor}\"></a>📂 {cat_name.title()} ({len(cat_skills)})\n\n")
            md.append("| Skill Name | Risk | Description | Repo Source |\n")
            md.append("| :--- | :---: | :--- | :---: |\n")
            
            for skill in sorted_cat_skills:
                skill_id = skill.get("id", "")
                name = skill.get("name", skill_id)
                desc = (skill.get("description", "") or "").replace("\n", " ").strip()
                if len(desc) > 140:
                    desc = desc[:137] + "..."
                risk = skill.get("risk", "safe")
                risk_badge = f"`{risk.upper()}`" if risk != "safe" else "`SAFE`"
                path = skill.get("path", f"skills/{skill_id}/SKILL.md")
                repo_link = f"[{name}](https://github.com/{self.target_repo}/tree/main/{path})"
                
                md.append(f"| **`{name}`** | {risk_badge} | {desc} | {repo_link} |\n")
            
            md.append("\n[🔼 Back to Top](#-agentic-skills-catalog)\n\n---\n\n")

        return "".join(md)

    def generate_editorial_bundles(self) -> str:
        md = []
        md.append(f"# 📦 Curated Editorial Bundles\n\n")
        md.append(f"Agentic Awesome Skills provides **{len(self.bundles_data)}** pre-configured, production-tested skill bundles designed for specific agent roles and project domains.\n\n")
        
        md.append("## 🚀 Bundle Directory\n\n")
        md.append("| Bundle | Group | Skills | Target Audience | Description |\n")
        md.append("| :--- | :--- | :---: | :--- | :--- |\n")
        
        for bundle in self.bundles_data:
            b_id = bundle.get("id", "")
            b_name = bundle.get("name", b_id)
            b_group = bundle.get("group", "General")
            b_skills = bundle.get("skills", [])
            b_audience = bundle.get("audience", "Developers")
            b_desc = bundle.get("description", "")
            if len(b_desc) > 100:
                b_desc = b_desc[:97] + "..."
            b_anchor = b_id.lower().replace(" ", "-")
            md.append(f"| [**{b_name}**](#{b_anchor}) | `{b_group}` | `{len(b_skills)}` | {b_audience} | {b_desc} |\n")
        
        md.append("\n---\n\n")

        for bundle in self.bundles_data:
            b_id = bundle.get("id", "")
            b_name = bundle.get("name", b_id)
            b_group = bundle.get("group", "General")
            b_skills = bundle.get("skills", [])
            b_audience = bundle.get("audience", "Developers")
            b_tagline = bundle.get("tagline", "")
            b_desc = bundle.get("description", "")
            b_emoji = bundle.get("emoji", "📦")
            b_anchor = b_id.lower().replace(" ", "-")

            md.append(f"## <a id=\"{b_anchor}\"></a>{b_emoji} {b_name} (`{b_id}`)\n\n")
            if b_tagline:
                md.append(f"> **{b_tagline}**\n\n")
            md.append(f"- **Domain Group**: `{b_group}`\n")
            md.append(f"- **Target Audience**: {b_audience}\n")
            md.append(f"- **Skills Count**: `{len(b_skills)}` skills\n")
            md.append(f"- **Description**: {b_desc}\n\n")

            md.append("### Included Skills:\n\n")
            md.append("| Skill ID | Category | Repository Link |\n")
            md.append("| :--- | :--- | :--- |\n")
            for skill_id in b_skills:
                skill_path = f"skills/{skill_id}/SKILL.md"
                md.append(f"| **`{skill_id}`** | Recommended | [`{skill_id}`](https://github.com/{self.target_repo}/tree/main/{skill_path}) |\n")
            
            md.append(f"\n```bash\n# Install this bundle via AAS CLI\nnpx agentic-awesome-skills bundle install {b_id}\n```\n\n")
            md.append("[🔼 Back to Top](#-curated-editorial-bundles)\n\n---\n\n")

        return "".join(md)

    def generate_daily_discovery(self) -> str:
        md = []
        md.append("# 🔭 Daily Discovery & Scout Log\n\n")
        md.append("Every day at `06:00 UTC`, Google Jules and the Daily Discovery Scout autonomously scan GitHub for newly published Agent Skills, Model Context Protocol (MCP) servers, and AI coding utilities.\n\n")
        
        discovery_dir = self.repo_root / "docs" / "discovery"
        ledger_path = discovery_dir / "LEDGER.md"
        
        if ledger_path.exists():
            try:
                with open(ledger_path, "r", encoding="utf-8") as f:
                    ledger_content = f.read()
                md.append("## 📜 Discovery Ledger History\n\n")
                md.append(ledger_content.strip())
                md.append("\n\n---\n\n")
            except Exception as e:
                md.append(f"*(Could not read ledger: {e})*\n\n")

        # Check for recent discovery report files
        if discovery_dir.exists():
            report_files = sorted(discovery_dir.glob("*.md"), reverse=True)
            report_files = [f for f in report_files if f.name != "LEDGER.md"]
            if report_files:
                latest_report = report_files[0]
                try:
                    with open(latest_report, "r", encoding="utf-8") as f:
                        latest_content = f.read()
                    md.append(f"## 🌟 Latest Scouting Report (`{latest_report.stem}`)\n\n")
                    md.append(latest_content.strip())
                    md.append("\n\n---\n\n")
                except Exception as e:
                    md.append(f"*(Could not read latest report: {e})*\n\n")

        return "".join(md)

    def generate_free_for_dev(self) -> str:
        md = []
        md.append(f"# 🆓 Free-For-Dev Developer Tools Directory\n\n")
        md.append(f"An indexed, curated directory of **{len(self.free_for_dev):,}** SaaS, PaaS, IaaS, APIs, AI platforms, and development tools offering free tiers. Maintained autonomously in collaboration with the open-source community.\n\n")

        # Group by category
        categories: Dict[str, List[Dict[str, Any]]] = {}
        for item in self.free_for_dev:
            cat = item.get("category", "General") or "General"
            categories.setdefault(cat, []).append(item)

        sorted_cats = sorted(categories.items(), key=lambda x: len(x[1]), reverse=True)

        md.append("## 📊 Tool Categories\n\n")
        md.append("| Category | Free Services Count |\n")
        md.append("| :--- | :---: |\n")
        for cat_name, cat_items in sorted_cats:
            cat_anchor = cat_name.lower().replace(" ", "-").replace("/", "-")
            md.append(f"| [**{cat_name}**](#{cat_anchor}) | `{len(cat_items)}` |\n")
        md.append("\n---\n\n")

        for cat_name, cat_items in sorted_cats:
            cat_anchor = cat_name.lower().replace(" ", "-").replace("/", "-")
            sorted_items = sorted(cat_items, key=lambda x: x.get("name", ""))
            md.append(f"## <a id=\"{cat_anchor}\"></a>🛠️ {cat_name} ({len(cat_items)})\n\n")
            md.append("| Service | Free Tier Description | Tags | Link |\n")
            md.append("| :--- | :--- | :--- | :---: |\n")

            for item in sorted_items:
                name = item.get("name", "")
                url = item.get("url", "")
                desc = (item.get("description", "") or "").replace("\n", " ").strip()
                if len(desc) > 130:
                    desc = desc[:127] + "..."
                tags = ", ".join([f"`{t}`" for t in item.get("tags", [])[:3]]) or "`dev`"
                link_btn = f"[{name}]({url})" if url else name
                md.append(f"| **{name}** | {desc} | {tags} | {link_btn} |\n")

            md.append("\n[🔼 Back to Top](#-free-for-dev-developer-tools-directory)\n\n---\n\n")

        return "".join(md)

    def generate_agent_integrations(self) -> str:
        return f"""# ⚡ Agent Integrations & Setup Guide

Agentic Awesome Skills is designed for instant interoperability across the entire AI engineering landscape.

---

## 1. Claude Code
Claude Code natively discovers skills placed inside `~/.agents/skills/` or `.agents/skills/`.

```bash
# Option A: Symlink all skills globally
mkdir -p ~/.agents/skills
git clone https://github.com/{self.target_repo}.git ~/agentic-awesome-skills
ln -s ~/agentic-awesome-skills/skills/* ~/.agents/skills/

# Option B: Add per-project
cp -r ~/agentic-awesome-skills/skills/tdd-workflow ./agents/skills/
```

Claude Code commands:
- `/skill <name>`: Explicitly loads instructions into context.
- Automatic routing: Claude Code selects relevant skills based on intent and task keywords.

---

## 2. Google Jules (Autonomous Cloud Agent)
Google Jules is Google's cloud-based autonomous coding agent. Jules reads `AGENTS.md` at repository root to discover project commands, test suites, and standards.

### Running Jules via REST API
```bash
curl -s -X POST https://jules.googleapis.com/v1alpha/sessions \\
  -H "x-goog-api-key: $JULES_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "prompt": "Implement comprehensive security tests for auth middleware",
    "sourceContext": {{"source": "sources/github/{self.target_repo}"}},
    "automationMode": "AUTO_CREATE_PR"
  }}'
```

### Running Jules via Official CLI (`@google/jules`)
```bash
npm install -g @google/jules
jules login --no-launch-browser
jules remote new --session "Optimize caching layer"
```

---

## 3. Google Gemini CLI & Antigravity
Mount skills into Antigravity or Gemini CLI agent profiles:

```bash
# Antigravity skill directory
mkdir -p ~/.gemini/antigravity-cli/skills
cp -r skills/* ~/.gemini/antigravity-cli/skills/
```

Antigravity auto-loads skills matching your current coding goals, enforces security boundaries, and isolates risky executions.

---

## 4. Cursor & Windsurf
For Cursor IDE (`.cursorrules` or `.cursor/rules/`) and Windsurf (`.windsurfrules`):

```bash
# Export skills directly to Cursor Rules
python3 tools/scripts/export_cursor_rules.py --output .cursor/rules/
```

---

## 5. Kiro, OpenCode & Goose
All tools conforming to the open Agent Skill specification can directly mount the `skills/` directory. Each skill contains a standardized `SKILL.md` with YAML frontmatter:

```yaml
---
name: skill-name
description: Clear, action-oriented trigger description
allowed-tools:
  - Bash
  - Read
  - Write
---
```

---

[🔼 Back to Top](#-agent-integrations--setup-guide)
"""

    def generate_google_jules_sentinel(self) -> str:
        return f"""# 🤖 Google Jules Autonomous Sentinel

Google Jules (`https://jules.google`) serves as the primary autonomous cloud maintainer for the **Agentic Awesome Skills** repository.

---

## 🌟 Autonomous Roles

Jules runs on scheduled cron triggers and cloud dispatch webhooks to execute:
1. **Daily GitHub Discovery Scout (`06:00 UTC`)**: Discovers newly published Agent Skills and MCP servers on GitHub, staging candidates in `staging/discovery/`.
2. **Daily GitHub Wiki Synchronizer (`06:30 UTC`)**: Builds, validates, and synchronizes this complete GitHub Wiki from catalog ground truth.
3. **Continuous Security Auditing**: Runs multi-engine vulnerability scanning, AST-based malware checks, and Skillspector policy validation.
4. **CI/CD Auto-Healing & PR Triage**: Inspects failed Actions runs, addresses Dependabot security advisories, and generates atomic fix PRs.

---

## 🛠️ Jules REST API Integration

The repository uses Google Jules REST API `v1alpha` for headless continuous automation:

```bash
# Dispatch autonomous documentation sync
curl -s -X POST https://jules.googleapis.com/v1alpha/sessions \\
  -H "x-goog-api-key: $JULES_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "prompt": "Act as Jules Documentation Maintainer. Execute python3 tools/scripts/generate_wiki.py --sync. Verify all 2,764+ skills and 59 bundles are properly indexed and formatted.",
    "title": "Daily Wiki & Documentation Sync",
    "sourceContext": {{
      "source": "sources/github/{self.target_repo}",
      "githubRepoContext": {{"startingBranch": "main"}}
    }},
    "automationMode": "AUTO_CREATE_PR"
  }}'
```

---

## ⚙️ Maintenance CLI Integration (`skills-maintainer`)

Maintainers can interact with Jules directly from the repository terminal:

```bash
# Check Jules status
skills-maintainer jules version
skills-maintainer jules list --session

# Dispatch specialized sentinels
skills-maintainer jules discovery   # Daily GitHub Scout
skills-maintainer jules docs        # Wiki & Docs sync
skills-maintainer jules security    # Vulnerability & Malware audit
skills-maintainer jules ci-fix      # CI/CD heal
```

---

[🔼 Back to Top](#-google-jules-autonomous-sentinel)
"""

    def generate_security_and_auditing(self) -> str:
        return f"""# 🔒 Security, Safety & Auditing Policies

Security is a first-class requirement across all **{self.total_skills:,}** skills in this repository.

---

## 🛡️ Three-Tier Security Architecture

Every skill in Agentic Awesome Skills is audited and assigned a security classification:

| Risk Rating | Definition | Policy & Enforcement |
| :---: | :--- | :--- |
| `SAFE` | Safe, deterministic local operations (reading files, code analysis, pure computation). | Permitted without restrictions. |
| `AUDIT_REQUIRED` | Requires external network access, package installations, or cloud credentials. | Must declare `allowed-domains`, `allowed-tools`, and pass Skillspector baseline checks. |
| `BLOCKED` | Malicious patterns, data exfiltration, obfuscation, or unauthorized remote access. | Immediately quarantined and barred from the catalog. |

---

## 🔍 Continuous Auditing Engines

1. **Malware & Supply-Chain Scanner (`tools/scripts/malware_scanner.py`)**:
   - Analyzes Python, JavaScript, and shell scripts using AST parsing.
   - Detects reverse shells, socket exfiltration, unquoted command injections, and suspicious obfuscation.
   
2. **Skillspector Baseline Validation**:
   - Evaluates data flows against declared permissions.
   - Enforces strict Least-Privilege boundaries.

3. **Validation Test Suite**:
   ```bash
   # Run full security and integrity audit
   npm run validate:strict
   npm run security:malware
   npm run security:scan:strict
   ```

---

[🔼 Back to Top](#-security-safety--auditing-policies)
"""

    def generate_contributing_guide(self) -> str:
        return f"""# 🤝 Contributing & Maintainer Guide

We welcome contributions of new Agent Skills, MCP server definitions, curated bundles, and documentation improvements!

---

## 📝 Skill Specification Standards

Every skill folder must contain a `SKILL.md` conforming to the specification:

```markdown
---
name: your-skill-name
description: Concise, action-oriented explanation of what this skill does and when to invoke it.
license: MIT
risk: safe
source: community
date_added: '{get_current_date()}'
allowed-tools:
  - Read
  - Write
  - Bash
---

# Your Skill Title

## When to Use
- Detailed triggers and use cases...

## Instructions & Workflows
- Concrete operational steps...

## Limitations
- Explicit boundaries...
```

---

## 🧪 Local Testing & Verification Workflow

Before submitting a Pull Request:

```bash
# 1. Validate skill frontmatter and directory structure
npm run validate

# 2. Run security and malware scans
npm run security:malware
npm run security:scan

# 3. Update index and catalog
npm run chain

# 4. Verify GitHub Actions workflow integrity
npm run lint:workflows
```

---

## 🏷️ Conventional Commits Standard

All commits must follow Conventional Commits:
- `feat(skill-name): add new skill for X`
- `fix(skill-name): correct parameter parsing`
- `security(skill-name): restrict allowed network domains`
- `docs(wiki): update catalog and discovery logs`

---

[🔼 Back to Top](#-contributing--maintainer-guide)
"""

    def generate_all(self, output_dir: Path) -> Dict[str, str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        pages = {
            "Home.md": self.generate_home(),
            "_Sidebar.md": self.generate_sidebar(),
            "_Footer.md": self.generate_footer(),
            "Skills-Catalog.md": self.generate_skills_catalog(),
            "Editorial-Bundles.md": self.generate_editorial_bundles(),
            "Daily-Discovery.md": self.generate_daily_discovery(),
            "Free-For-Dev-Directory.md": self.generate_free_for_dev(),
            "Agent-Integrations.md": self.generate_agent_integrations(),
            "Google-Jules-Sentinel.md": self.generate_google_jules_sentinel(),
            "Security-and-Auditing.md": self.generate_security_and_auditing(),
            "Contributing-and-Maintainer-Guide.md": self.generate_contributing_guide(),
        }

        for filename, content in pages.items():
            file_path = output_dir / filename
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  ✅ Generated {filename} ({len(content):,} bytes)")

        return pages


def sync_to_wiki_git(wiki_dir: Path, target_repo: str, token: Optional[str] = None) -> bool:
    """Sync generated pages to the GitHub wiki git repository."""
    print(f"\n🔄 Synchronizing Wiki to GitHub remote for {target_repo}...")
    
    if token:
        remote_url = f"https://x-access-token:{token}@github.com/{target_repo}.wiki.git"
    else:
        # Use existing git credentials or SSH
        remote_url = f"https://github.com/{target_repo}.wiki.git"
    
    # Check if wiki_dir is already a git repo
    is_git = (wiki_dir / ".git").is_dir()
    
    try:
        if not is_git:
            print("  📥 Cloning wiki repository...")
            clone_cmd = ["git", "clone", remote_url, str(wiki_dir)]
            subprocess.run(clone_cmd, check=True, capture_output=True, text=True)
        else:
            print("  🔄 Pulling latest wiki changes...")
            subprocess.run(["git", "-C", str(wiki_dir), "pull", "--rebase"], check=False, capture_output=True, text=True)

        # Re-generate pages into the git directory
        generator = WikiGenerator(REPO_ROOT, target_repo=target_repo)
        generator.generate_all(wiki_dir)

        # Check status
        status = subprocess.run(["git", "-C", str(wiki_dir), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout.strip()
        if not status:
            print("  ✨ Wiki is already up-to-date. No changes to commit.")
            return True

        # Commit and push
        date_str = get_current_date()
        print("  💾 Staging and committing wiki updates...")
        subprocess.run(["git", "-C", str(wiki_dir), "config", "user.name", "Google Jules [bot]"], check=True)
        subprocess.run(["git", "-C", str(wiki_dir), "config", "user.email", "jules[bot]@users.noreply.github.com"], check=True)
        subprocess.run(["git", "-C", str(wiki_dir), "add", "."], check=True)
        commit_msg = f"docs(wiki): synchronize daily skills catalog and ecosystem [{date_str}]"
        subprocess.run(["git", "-C", str(wiki_dir), "commit", "-m", commit_msg], check=True)
        
        print("  🚀 Pushing wiki updates to GitHub...")
        subprocess.run(["git", "-C", str(wiki_dir), "push", "origin", "HEAD"], check=True)
        print("  🎉 Wiki synchronized successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Wiki Git synchronization failed: {e}", file=sys.stderr)
        if e.stderr:
            print(f"Error output: {e.stderr}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Autonomous GitHub Wiki Generator for Agentic Awesome Skills")
    parser.add_argument("--output-dir", type=str, default="wiki", help="Target output directory for markdown files")
    parser.add_argument("--repo", type=str, default=GITHUB_REPO_DEFAULT, help="GitHub target repository (owner/repo)")
    parser.add_argument("--sync", action="store_true", help="Sync directly to the GitHub wiki git remote")
    parser.add_argument("--token", type=str, default=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"), help="GitHub access token for push")
    
    args = parser.parse_args()
    output_path = Path(args.output_dir)
    if not output_path.is_absolute():
        output_path = REPO_ROOT / output_path

    print(f"🧠 Starting Agentic Awesome Skills Wiki Generator for {args.repo}...")
    generator = WikiGenerator(REPO_ROOT, target_repo=args.repo)

    if args.sync:
        success = sync_to_wiki_git(output_path, args.repo, token=args.token)
        sys.exit(0 if success else 1)
    else:
        pages = generator.generate_all(output_path)
        print(f"\n🎉 Successfully generated {len(pages)} wiki pages in {output_path}")


if __name__ == "__main__":
    main()
