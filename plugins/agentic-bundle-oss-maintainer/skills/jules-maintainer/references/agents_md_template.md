# AGENTS.md Template for Google Jules Compatibility

Google Jules automatically detects and parses `AGENTS.md` located at the root of any connected repository. Jules uses this file to:
1. Determine test commands and execution pipelines.
2. Identify code conventions, architectural boundaries, and linting rules.
3. Understand preinstalled tools and custom environment setup scripts.

---

## Jules VM Preinstalled Environment Reference

Every Jules task executes in an Ubuntu VM with:
- **Node.js**: v22.16 (nvm available with v18, v20), npm, yarn, pnpm
- **Python**: 3.12 (pyenv available with 3.10), pip, poetry, uv, black, ruff, mypy, pytest
- **Go**: 1.24+
- **Rust**: 1.87+ (cargo)
- **Java**: OpenJDK 21 (Maven, Gradle)
- **C/C++**: Clang 18, GCC 13, CMake, Ninja, Conan
- **Docker**: Docker Engine & Docker Compose

---

## Recommended `AGENTS.md` Structure for Repositories

Place this file as `AGENTS.md` in the root of your repository:

```markdown
# Project Guidelines for AI Agents (Jules & Antigravity)

## 1. Project Overview & Architecture
- Framework: [e.g., Next.js 15 App Router / FastAPI / Go Gin]
- Language: [e.g., TypeScript strict / Python 3.12 / Go 1.24]
- Package Manager: [e.g., pnpm / bun / uv / poetry]

## 2. Environment Setup & Dependency Installation
\`\`\`bash
# Command to install dependencies:
pnpm install --frozen-lockfile
# or:
uv sync
\`\`\`

## 3. Testing & Verification Gate
Agents must run and pass these tests before creating a PR or marking tasks complete:
\`\`\`bash
# 1. Typecheck:
pnpm tsc --noEmit

# 2. Linter:
pnpm lint

# 3. Unit & Integration Tests:
pnpm test
\`\`\`

## 4. Code & Git Conventions
- Follow Conventional Commits: \`feat:\`, \`fix:\`, \`docs:\`, \`refactor:\`, \`test:\`.
- Keep modifications minimal and focused on the requested prompt.
- Do not modify configuration files or add unapproved third-party dependencies unless explicitly requested.
- Maintain existing comments and architectural patterns.

## 5. Jules Proactivity Directives
- When processing **Suggested Tasks**, locate relevant \`#TODO\` comments, implement the required logic, add corresponding unit tests, and remove the resolved \`#TODO\` marker.
- For **Scheduled Tasks (Security)**, run dependency audit tools (\`pnpm audit\` or \`pip audit\`) and apply minor/patch security updates.
- For **Scheduled Tasks (Performance)**, focus on algorithmic efficiency, cache utilization, and avoiding redundant database/network calls without altering public API contracts.
```
