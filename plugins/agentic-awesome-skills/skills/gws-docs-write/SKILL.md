---
name: gws-docs-write
description: "Google Docs: Append text to a document."
metadata:
  version: 0.22.5
  openclaw:
    category: "productivity"
    requires:
      bins:
        - gws
    cliHelp: "gws docs +write --help"
risk: safe
source: community
date_added: "2026-10-03"
---

# docs +write

## When to Use
Use this skill whenever the task matches the workflows and capabilities described above.


> **PREREQUISITE:** Read `../gws-shared/SKILL.md` for auth, global flags, and security rules. If missing, run `gws generate-skills` to create it.

Append text to a document

## Usage

```bash
gws docs +write --document <ID> --text <TEXT>
```

## Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--document` | ✓ | — | Document ID |
| `--text` | ✓ | — | Text to append (plain text) |

## Examples

```bash
gws docs +write --document DOC_ID --text 'Hello, world!'
```

## Tips

- Text is inserted at the end of the document body.
- For rich formatting, use the raw batchUpdate API instead.

> [!CAUTION]
> This is a **write** command — confirm with the user before executing.

## See Also

- [gws-shared](https://github.com/googleworkspace/cli) — Global flags and auth
- [gws-docs](https://github.com/googleworkspace/cli) — All read and write google docs commands


## Limitations

- Standard usage limits and external API rate boundaries apply to gws-docs-write.
- Requires compatible execution environment with necessary CLI or runtime tools.
