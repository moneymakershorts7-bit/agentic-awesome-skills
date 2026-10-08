# Better Icons: Model Context Protocol (MCP) Reference

The `better-icons` MCP server allows any AI coding assistant to search, recommend, batch retrieve, and sync icons directly to codebase files without polluting the conversational context with massive inline SVGs.

---

## 1. Universal Agent Harness Configurations

Add the following configuration block to your agent's MCP configuration:

### Cursor (`~/.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "better-icons": {
      "command": "npx",
      "args": ["-y", "better-icons"]
    }
  }
}
```

### Claude Code (`~/.claude/settings.json` or `claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "better-icons": {
      "command": "npx",
      "args": ["-y", "better-icons"]
    }
  }
}
```

### Google Antigravity (`~/.gemini/antigravity/mcp_config.json`)
```json
{
  "mcpServers": {
    "better-icons": {
      "command": "npx",
      "args": ["-y", "better-icons"]
    }
  }
}
```

### OpenCode & Windsurf
```json
{
  "mcpServers": {
    "better-icons": {
      "command": "bunx",
      "args": ["better-icons"]
    }
  }
}
```

---

## 2. MCP Tool Specifications

### `search_icons`
- `query` (*string, required*): Search keyword (e.g., `arrow`, `home`, `user`).
- `limit` (*number, optional*): Maximum results (1–999, default 32).
- `prefix` (*string, optional*): Filter by collection (`mdi`, `lucide`, `heroicons`, `tabler`).
- `category` (*string, optional*): Filter by domain category.

### `get_icon`
- `icon_id` (*string, required*): Formatted as `prefix:name` (e.g. `lucide:home`, `mdi:cog`).
- `color` (*string, optional*): Icon color (`#000`, `currentColor`).
- `size` (*number, optional*): Size in pixels.
- `format` (*string, optional*): `svg` (default) or `url`.

### `get_icons`
- `icon_ids` (*array of strings, required*): Up to 20 icon IDs for batch resolution.
- `color` (*string, optional*): Global color override.
- `size` (*number, optional*): Global size in pixels.

### `recommend_icons`
- `use_case` (*string, required*): Description of UI component or intent (e.g., `danger delete confirmation button`).
- `style` (*string, optional*): `solid`, `outline`, or `any`.
- `limit` (*number, optional*): Number of recommendations (1–20).

### `sync_icon`
- `icons_file` (*string, required*): Absolute path to project's icons file (e.g., `/home/user/app/src/components/icons.tsx`).
- `framework` (*string, required*): `react`, `vue`, `svelte`, `solid`, or `svg`.
- `icon_id` (*string, required*): Target icon identifier (`lucide:trash-2`).
- `component_name` (*string, optional*): Custom export name (e.g. `TrashIcon`).
