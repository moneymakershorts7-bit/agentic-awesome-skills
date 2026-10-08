---
name: better-icons
description: Universal agent-agnostic icon search and retrieval for 200,000+ vector icons across 150+ libraries with CLI and MCP server support.
category: frontend
risk: safe
source: community
source_repo: better-auth/better-icons
source_type: community
date_added: "2026-10-07"
author: Better Auth / Fatih A
license: MIT
tags: [frontend, icons, svg, ui, design-systems, mcp, cli, multi-framework]
tools: [claude, cursor, codex, antigravity, opencode, windsurf, jules, vscode]
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Grep
permissions:
  - shell
  - file_read
  - file_write
  - network
metadata:
  allowed-domains:
    - api.iconify.design
---

# Better Icons (Universal Agent-Agnostic Icon Engine)

Search, recommend, batch-retrieve, and synchronize vector SVGs across 150+ icon collections (Lucide, Heroicons, Material Design, Tabler, Phosphor, Remix, Font Awesome, Simple Icons) with over 200,000 icons.

Operates seamlessly in any agent harness (Claude Code, Cursor, Google Antigravity, OpenCode, Windsurf, VS Code, Google Jules) via direct **CLI commands** or standard **Model Context Protocol (MCP)** tools.

---

## When to Use

- Use when adding icons to UI components (buttons, navbars, cards, status badges, dropdowns).
- Use when the user requests a specific icon (e.g. "add a github logo", "find a settings gear icon in Lucide").
- Use to prevent token waste: sync SVGs directly to files (`.tsx`, `.vue`, `.svelte`, `.svg`) rather than dumping massive raw SVG markup in conversational context.
- Use when exploring matching icons across multiple design systems to maintain optical stroke consistency.

---

## Quick Reference & Guides

| Guide | Description |
| :--- | :--- |
| [references/cli-reference.md](references/cli-reference.md) | Full CLI commands, batch flags, JSON pipes, and stdout redirection. |
| [references/mcp-reference.md](references/mcp-reference.md) | Universal agent MCP server configuration schemas and tool specifications. |
| [references/collections.md](references/collections.md) | Catalog of 150+ icon collections with prefixes, styles, and counts. |
| [references/framework-sync.md](references/framework-sync.md) | Export patterns for React/Next.js, Vue 3, Svelte 5, Solid.js, and raw SVG. |

---

## Dual-Mode Operation

### Mode A: Direct CLI Execution (Universal Fallback)

Works in any shell, terminal subagent, or container without prior MCP setup.

```bash
# 1. Search for icons across all libraries
better-icons search <query> [--prefix <name>] [--limit <n>] [--json]

# Examples:
better-icons search arrow --limit 5
better-icons search home --prefix lucide
better-icons search github --prefix simple-icons

# 2. Get raw SVG code
better-icons get <prefix:name> [--color <color>] [--size <px>]

# Examples:
better-icons get lucide:check > ./src/assets/check.svg
better-icons get mdi:account --color '#3b82f6' --size 24

# 3. Batch download all search results to directory
better-icons search check -d ./src/assets/icons/ --color currentColor
```

### Mode B: MCP Tool Invocation (AI Agent Integration)

When configured as an MCP server, agents can call tools directly:

| MCP Tool | Functionality | Key Parameters |
| :--- | :--- | :--- |
| `search_icons` | Search across collections | `query`, `prefix`, `limit`, `category` |
| `get_icon` | Get single icon SVG / React code | `icon_id` (`prefix:name`), `color`, `size`, `format` |
| `get_icons` | Batch retrieve up to 20 icons | `icon_ids` (`["lucide:home", "mdi:user"]`) |
| `list_collections` | Explore available libraries | `category`, `search` |
| `recommend_icons` | AI icon recommendation | `use_case`, `style` (`solid`/`outline`), `limit` |
| `find_similar_icons`| Find alternative styles | `icon_id`, `limit` |
| `sync_icon` | Append icon component directly to file | `icons_file`, `framework`, `icon_id`, `component_name` |
| `scan_project_icons`| List icons already in project | `icons_file` |

---

## Token Efficiency & Best Practices

1. **Direct File Syncing:** Always write retrieved icons to disk (`icons.tsx` or `./public/icons/`) using `better-icons get <id> > file.svg` or `sync_icon` rather than pasting hundreds of lines of raw SVG path coordinates into chat.
2. **Collection Consistency:** Stick to a single icon set per surface (e.g. `lucide:*` for clean 2px outline interfaces, `solar:*` for fintech).
3. **Stroke & Weight Alignment:**
   - 400 (Regular) text $\to$ 1.5px stroke icons (`lucide`, `tabler`).
   - 600 (Semibold) text $\to$ 2px stroke icons (`lucide` default, `heroicons` outline).
4. **Dynamic States:** Use `currentColor` so icons adapt automatically to parent CSS `hover`, `active`, and `dark:` color tokens.

---

## Limitations

- **Network Access:** Requires internet connectivity to `api.iconify.design` to query libraries and fetch fresh SVGs.
- **Icon Namespace:** Queries must conform to `prefix:name` standard syntax when addressing specific icon glyphs.
