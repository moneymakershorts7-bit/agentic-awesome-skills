# Better Icons: CLI Command Reference

The `better-icons` CLI provides instant, agent-agnostic access to 200,000+ vector icons across 150+ open-source libraries via Iconify.

---

## 1. Quick Search

```bash
# Basic keyword search
better-icons search <query>

# Search with limit (default: 32)
better-icons search arrow --limit 10

# Filter by icon collection prefix
better-icons search user --prefix lucide
better-icons search home --prefix mdi
better-icons search settings --prefix heroicons

# Output clean JSON for scripts / agent parsers
better-icons search check --json
```

---

## 2. Retrieving & Exporting SVGs

```bash
# Output raw SVG to stdout
better-icons get lucide:home

# Redirect to SVG file
better-icons get lucide:home > ./public/icons/home.svg

# Customize color and pixel dimensions
better-icons get mdi:account --color '#3b82f6' --size 24 > ./public/icons/user.svg
better-icons get heroicons:check --color 'currentColor' --size 16

# Retrieve JSON with dimensions, body SVG, and collection metadata
better-icons get tabler:bell --json
```

---

## 3. Batch Search & Download

```bash
# Search and automatically download matching icons to a directory
better-icons search arrow -d                 # saves to ./icons/
better-icons search check -d ./src/assets/   # custom output directory

# Filter batch downloads with styling attributes
better-icons search star -d ./icons -c '#f59e0b' -s 24 --limit 20
```

---

## 4. Non-Interactive Agent / Script Execution

When executing in CI/CD or background scripts without global installation, use `npx` or `bunx`:

```bash
# Bunx (ultra-fast)
bunx better-icons search search --limit 5

# Npx
npx -y better-icons get simple-icons:github > ./github.svg
```
