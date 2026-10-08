# Repository Guidelines

## Project Structure & Module Organization

This repository publishes an installable library of agent skills and plugin bundles. Canonical skill sources live in `skills/<skill-id>/SKILL.md`; use lowercase, hyphenated skill IDs. Mirrored plugin distributions live under `plugins/`. Contributor and user docs live in `docs/`; localized docs live in `docs_zh-CN/` and `docs/vietnamese/`. Maintenance scripts and tests are in `tools/scripts/` and `tools/scripts/tests/`. The hosted catalog app is in `apps/web-app/`. Registry outputs such as `CATALOG.md`, `skills_index.json`, and `data/catalog.json` are generated artifacts. Editorial inputs in `data/` remain source files; use `tools/scripts/generated_files.js` for the exact generated-file classification.

## Build, Test, and Development Commands

- `npm ci`: install root dependencies for scripts and validation.
- `npm run validate`: validate skill frontmatter, required sections, and schema rules.
- `npm run security:docs`: run safety checks for command, install, credential, and network guidance.
- `npm run test`: run the repository script test suite.
- `npm run build`: regenerate core indexes and build the catalog data.
- `npm run app:install`: install `apps/web-app` dependencies.
- `npm run app:dev`: start the local Vite catalog app.
- `npm run app:build`: build and prerender the catalog app.

Before PRs, run `npm run validate && npm run test && npm run security:docs`.

## Coding Style & Naming Conventions

Use Markdown for skills and docs, JavaScript/Node for most tooling, and Python for audits and sync helpers. Keep skill directories lowercase with hyphens, for example `skills/my-awesome-skill/SKILL.md`. Start new skills from `docs/contributors/skill-template.md`; include frontmatter, `## When to Use`, examples, and limitations. Keep generated-file edits out of community PRs unless doing maintainer release or sync work.

## Testing Guidelines

Tests live mainly in `tools/scripts/tests/` and use Node assertions or Python `unittest`. Name new tests after the behavior under test, for example `installer_filters.test.js` or `test_validate_skills_strict.py`. Run targeted tests during development, then run the relevant npm scripts above. Web app changes should also run `npm run app:test` or `npm run app:test:coverage`.

## Commit & Pull Request Guidelines

History uses conventional-style subjects such as `feat: add ...`, `fix: refresh ...`, `docs: add ...`, and `chore: release ...`. Keep commits focused. PRs must use the default template, include the Quality Bar Checklist, link an issue when applicable, and allow maintainer edits. Source PRs should avoid generated registry artifacts; CI enforces this source-only contract.

## Agent-Specific Instructions

Respect deeper `AGENTS.md` files inside skill subtrees. When changing canonical skill content that is mirrored under `plugins/agentic-awesome-skills/` or `plugins/agentic-awesome-skills-claude/`, check whether mirrors must be synchronized. For release work, follow the scripted `release:prepare` and `release:publish` flow rather than hand-editing version surfaces.

### Current-Base Instruction Guard

Repository instructions must match the exact Git base used for the task. After creating a clean clone, worktree, or topic branch, re-read that base's `AGENTS.md`, `.github/MAINTENANCE.md`, canonical maintainer skill, and `package.json`; those files supersede instructions inherited from the checkout that launched the task.

Every command, script, reviewer, or gate described as mandatory must exist on the current task base. If it is absent, do not recover or execute it from another branch, worktree, stash, installed copy, or historical commit. Treat the mismatch as evidence that the procedure may have been retired, inspect `origin/main` and the relevant removal history, then follow the current-base contract or report the unresolved conflict.

### Mandatory Maintainer Workflow

For every repository maintenance sweep, PR merge batch, maintainer-side PR repair, canonical synchronization, combined Security/Quality cleanup and merge, or tag/release request, **always invoke and follow the `antigravity-maintainer-batch-release` skill before triage or mutation**. If the client has not installed or discovered that skill, read and follow the repository-canonical copy at `skills/antigravity-maintainer-batch-release/SKILL.md`. This is a hard gate, including when the user asks for direct merges or a direct update to `main`; do not substitute a generic Git or GitHub workflow.

Treat `main` as pull-request-only. Perform maintainer edits on a topic branch or in a clean temporary clone, merge accepted source PRs with `npm run merge:batch`, and let the protected canonical-sync PR own generated state and contributor-credit drift. Never retry a rejected direct push to `main` and never use a generic push helper for releases.

Use the skill's end-to-end sequence: complete triage, repair mergeable source PRs, run checks in parallel, merge source PRs in conflict-aware order, perform one canonical synchronization after the source batch, use the scripted protected-release flow when requested, and verify final `main`, tag, GitHub Release, npm package, CI, and live public surfaces. For changed `SKILL.md` files, distinguish a real Tessl `review` from `manual-review-required`; the latter means Tessl was unavailable or did not produce a passing result and requires a maintainer review attested to the exact full head SHA. If neither an installed skill nor the repository-canonical copy is available and readable, stop before making repository changes and report that blocker explicitly.

Every stable or prerelease version must finish with the full-release-alignment gate in the maintainer skill. Do not declare a release complete until clean local `main` equals `origin/main`; canonical generated state is drift-free; every Codex and Claude plugin mirror, editorial bundle, manifest, compatibility report, and marketplace is regenerated and version-aligned; the tag, GitHub Release, npm version and intended dist-tag agree; CI, CodeQL, and the release-tag Pages deployment for the exact released commit are green; live catalog and legacy-bridge surfaces match; and every already-configured local AAS MCP host is pinned to and actually running the released version. A release request authorizes updating existing AAS host entries only, never creating an absent host configuration.

#### Skill Content Review Gate

For every canonical `SKILL.md` change or tracked bundle-file change, run `npm run validate`, `npm run validate:references`, `npm run security:docs`, and the relevant tests. Inspect semantics, safety, provenance, declared risk, limitations, and every bundled file. The official merge gate remains a truthful Tessl `review` or a maintainer review attested to the exact full head SHA; heuristic local scores and inferred risk labels are not merge authority.

Reviewed fork bundle exceptions are restricted to the protected-base ledger in
`tools/config/reviewed-fork-skills.json` and the current maintainer skill. They
bind a complete previously reviewed skill tree and still require exact-current-head
attestation, all required checks and strict protection; no general script allowlist
or PR-controlled ledger is authorized.

## Google Jules Autonomous Agent Directives

When Google Jules (`https://jules.google`) runs autonomously on this repository (via scheduled tasks, suggested tasks, or remote sessions):

1. **Strict Restrictive Governance — Zero Direct Merges:**
   - **Jules NEVER decides whether to merge code or push to `main` directly.**
   - All work by Jules MUST be submitted as a pull request on a branch prefixed with `jules/` (e.g., `jules/daily-docs-wiki-sync`, `jules/security-hardening`, `jules/weekly-optimization`).
   - The decision to merge, request changes, or reject/close the PR is exclusively reserved for the human assistant maintainer during the monthly sweep (`skills-maintainer prs` / `skills-maintainer all`).
   - Keep pull requests small, self-contained, and atomic (< 150 lines changed when possible). Include a detailed security and audit rationale in the PR body.

2. **Environment & Initial Setup:**
   - Execute `npm ci` to install project dependencies.
   - Standard runtimes (Node 22, Bun, Python 3.12, Go 1.24, Rust 1.87) are preinstalled in the Jules Ubuntu VM.
   - For security tooling: ensure `uv tool install skill-scanner` and `npx skill-inspector` are accessible.

3. **Specialized Autonomous Sentinel Agents:**

   ### A. Daily Documentation & GitHub Wiki Synchronizer (Daily)
   - **Branch:** `jules/daily-docs-wiki-sync`
   - **Scope:**
     1. Synchronize repository metrics, badge counts, and table of contents in `README.md`.
     2. Update web catalog assets: `npm run update:skills` and `npm run audit:consistency`.
     3. Synchronize the GitHub Wiki repository (`https://github.com/moneymakershorts7-bit/agentic-awesome-skills.wiki.git`):
        - Keep `Home.md` aligned with latest release catalog.
        - Ensure `_Sidebar.md` indexes all skill categories and bundles.
        - Verify zero dead links in Wiki navigation.

   ### B. Daily Multi-Engine Security & Hardening Auditor (Daily)
   - **Branch:** `jules/security-hardening-patch`
   - **Engines & Protocols:**
     1. **Cisco AI Defense (`skill-scanner`):** Execute `skill-scanner scan --scan-all` to detect AST-level exfiltration, tainted source-to-sink flows, and undeclared network destinations.
     2. **Skill-Inspector (`inspect-skills`):** Run `npx skill-inspector` across modified skills to verify spec compliance and provider safety boundaries.
     3. **Cloudflare Security Audit (`cloudflare-security-audit`):** Apply Cloudflare's 6-phase discovery harness to audit trust boundaries, evaluate authentication token handoffs, and eliminate command injection risks in bundled scripts.
     4. Enforce Principle of Minimum Privilege: restrict `allowed-tools` and declare `allowed-domains` in metadata for any external API interaction.
     5. **Zero Secrets Rule:** Never commit or echo tokens, credentials, or private keys.

   ### C. Weekly Quality & Performance Optimization Agent (Weekly)
   - **Branch:** `jules/weekly-optimization-audit`
   - **Scope:**
     1. Enforce Progressive Disclosure: ensure `SKILL.md` files stay concise (< 300 lines), moving detailed reference implementations to `references/` and helpers to `scripts/`.
     2. Deduplicate skill implementations and unify schemas across `skills/` and `plugins/`.
     3. Run `npm run bundles:sync` and `npm run plugin-compat:sync` to eliminate bundle drift.
     4. Check warning budget with `npm run check:warning-budget`.

   ### D. CI/CD Workflow & Build Auto-Fixer Agent (On-Demand / Continuous)
   - **Branch:** `jules/ci-fix-patches`
   - **Scope:**
     1. Ingest failing GitHub Actions logs from CI, linting, or security workflows.
     2. Auto-fix action pinning: ensure all GitHub Actions in `.github/workflows/*.yml` use immutable 40-character commit SHAs.
     3. Auto-fix test and specification contract discrepancies (e.g., missing `## Limitations` sections in `SKILL.md`, broken links in `references/`, or frontmatter schema errors).
     4. Auto-resolve Dependabot peer dependency lockfile conflicts (such as major TypeScript vs. typescript-eslint mismatches).
     5. Apply linter/formatter fixes (`ruff check --fix`, `actionlint`).

   ### E. Malware & Supply-Chain Defense Sentinel (Daily)
   - **Branch:** `jules/malware-defense-patch`
   - **Scope:**
     1. Execute deep malware & backdoor detection: `npm run scan:malware` (`python3 tools/scripts/malware_scanner.py --strict .`).
     2. Audit scripts and workflows for reverse shells (`/dev/tcp`, `nc -e`, `pty.spawn`), base64 decode-and-execute chains, LD_PRELOAD hijacking, and credential dumping sinks.
     3. Verify absence of disguised binary payloads (ELF, PE, Mach-O magic headers) inside text files.
     4. Propose atomic defensive patches isolating untrusted inputs on branch `jules/malware-defense-patch`.

   ### F. Daily Agent Skills & MCP Discovery Scout Sentinel (Daily)
   - **Branch:** `jules/daily-discovery-YYYYMMDD`
   - **Scope (Multi-Agent & Multi-Model Adaptable):**
     1. Programmatically scout GitHub for newly published or trending Agent Skills (`topic:agent-skills`, `topic:claude-skills`, `topic:agentic-skills`, `topic:antigravity-skills`) and Model Context Protocol (MCP) servers (`topic:mcp-server`, `topic:modelcontextprotocol`).
     2. Universal model & harness adaptation: format discovered skills with cross-agent compatibility (Google Antigravity, Anthropic Claude Code, OpenAI Codex, Cursor, Gemini CLI, Windsurf, OpenCode, and open local models via Ollama/vLLM).
     3. De-duplicate against existing repository catalog (`skills_index.json`, `skills/`, `data/discovered_mcps.json`).
     4. Stage candidate skills in `staging/discovery/YYYY-MM-DD/skills/<id>/SKILL.md` and MCP server configurations in `staging/discovery/YYYY-MM-DD/mcps/<id>.json`.
     5. Compile daily scouting digest at `docs/discovery/YYYY-MM-DD.md` and append to master ledger `docs/discovery/LEDGER.md`.
     6. Run `npm run validate` to ensure strict schema compliance before opening the pull request.
     7. Propose additions on branch `jules/daily-discovery-YYYYMMDD` via Pull Request titled `feat(discovery): daily new skills and MCP servers scout [YYYY-MM-DD]`.
     8. Monthly Maintenance Decision Gate: During the monthly sweep (`skills-maintainer all` / `skills-maintainer review-discovery`), the maintainer or any agent model evaluates candidates, audits security, and decides whether to accept into the active catalog or reject.

   ### G. Issue Auto-Triage & Solution Sentinel (Event-Driven)
   - **Trigger:** GitHub Issue created or labeled with `jules`, `auto-fix`, or `bug` (via `.github/workflows/jules-issue-resolver.yml`).
   - **Branch:** `jules/issue-<issue-number>-<issue-slug>`
   - **Scope:**
     1. Fetch issue metadata, reproduce reported discrepancies or test failures, and trace root cause.
     2. Implement minimal targeted fix adhering strictly to Swiss Army Knife repository standards and Conventional Commits (`fix(<scope>): ...`).
     3. Verify complete pass of verification suite (`npm run validate`, `npm run lint:workflows`, `npm run test`).
     4. Submit clean Pull Request linking directly to the issue (`Closes #<id>`) in `AUTO_CREATE_PR` mode.

4. **Required Verification Pipeline Before PR Submission:**
   Before finalizing any plan, committing changes, or submitting a Pull Request, Jules MUST execute and pass:
   ```bash
   # 1. Validate skill frontmatter, schemas, and required sections:
   npm run validate

   # 2. Check for security guidelines, credentials, and network declarations:
   npm run security:docs

   # 3. Verify repository consistency and bundle alignment:
   npm run audit:consistency

   # 4. Run test suites:
   npm run test
   ```
   If any check fails, Jules must fix the issue before opening the PR.

## Learned User Preferences

- For maintainer sweeps, PR merges, issue closure, and releases, follow the canonical `antigravity-maintainer-batch-release` skill together with `.github/MAINTENANCE.md`; do not substitute a generic Git or GitHub workflow.
- When executing an attached plan, implement the plan without editing the plan file; use existing todos instead of recreating them.
- Optional TypeSafe Jev tooling must accelerate triage and quality; never add mandatory steps to `merge:batch`, CI, or branch protection.
- Keep Jev usage within a small monthly TypeSafe budget by capping skills per run and treating output as advisory only.
- Store TypeSafe API keys only in gitignored `.env.local`; rotate any key exposed in chat, logs, or commits.
- Before committing new maintainer tooling, run a full validation round on a real open skill PR (worktree, deterministic checks, and Jev smoke when applicable).
- Release changelog and GitHub release notes must match the actual tag diff (skill counts, catalog totals, contributor thanks); emphasize catalog skills in user-facing notes, not maintainer-only tooling.
- Respond in Italian when the user writes maintainer or release requests in Italian.

## Learned Workspace Facts

- `npm run maintainer:jev-hints` evaluates skill content from the `--head` git ref via `git show`; pass `--repo` with a PR worktree when changed skills are not present on the current checkout.
- Jev hints default to five skills per run, exit 0 with a skip message when `TYPESAFE_API_KEY` is unset, and never satisfy Tessl or `--reviewed-head` skill review.
- Maintainer documentation for Jev lives in `docs/maintainers/jev-hints.md`; the upstream TypeSafe agent skill is installed under `.agents/skills/typesafe-ai/` via `npx skills add typesafe-ai/skills --skill typesafe-ai`.
