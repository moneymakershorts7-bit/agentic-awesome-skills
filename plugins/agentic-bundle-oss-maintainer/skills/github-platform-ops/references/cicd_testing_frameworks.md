# CI/CD Testing Frameworks, Automated Verification & Pipeline Linters

Comprehensive technical reference manual for modern CI/CD testing strategies, local pipeline emulation (`act`), programmable pipelines (`dagger`), matrix sharding, and security linters (`zizmor`, `actionlint`, `shellcheck`).

---

## 1. Local CI/CD Pipeline Emulation & Tooling

Testing pipelines directly on cloud runners wastes billable minutes, pollutes commit logs, and slows the feedback loop. Industry standard local testing tools provide rapid, deterministic verification:

### A. Local Execution with `act` (nektos/act)
`act` executes GitHub Actions locally within Docker containers using the GitHub Actions runner container images:

```bash
# 1. Run default push event workflows locally
act push

# 2. Run specific job with dry-run / list
act -l
act -j unit-and-integration

# 3. Simulate pull_request event with custom event payload
act pull_request -e event.json

# 4. Pass mock secrets and environment variables
act push -s GITHUB_TOKEN="mock_token" -s DB_PASSWORD="local_test_pass"

# 5. Use medium runner image for full architecture parity
act -P ubuntu-latest=catthehacker/ubuntu:act-latest
```

### B. Programmable CI/CD with Dagger & Earthly
- **Dagger (dagger.io):** Encapsulates CI/CD steps in strongly-typed code (Go, TypeScript, Python) executing against an isolated BuildKit engine with content-addressable layer caching. Eliminates vendor lock-in between GitHub Actions, GitLab CI, and local workstations.
- **Earthly (earthly.dev):** Combines syntax of Makefiles and Dockerfiles into `Earthfile` targets. Ensures that `earthly +test` yields 100% byte-for-byte identical outcomes locally and inside CI.

---

## 2. Static Analysis & Pipeline Security Linters

Before executing pipelines, validate YAML syntax, shell scripts, and security posture using static linters:

### A. Multi-Linter Audit Command Suite
```bash
# 1. Syntax, Expression Type & Schema Validation (actionlint)
actionlint .github/workflows/*.yml

# 2. Shell Script Security & POSIX Pitfall Detection (shellcheck)
shellcheck -s bash .github/scripts/*.sh

# 3. GitHub Actions Security Linter (zizmor)
# Audits for unpinned actions, template injections, and token over-privilege
zizmor .github/workflows/
```

### B. Pipeline Security Checklist (zizmor & Scorecard Compliance)
1. **Never interpolate expressions inside run blocks:**
   - ❌ **Dangerous (Template Injection):** `run: echo "PR Title: ${{ github.event.pull_request.title }}"`
   - ✅ **Hardened (Environment Variable):**
     ```yaml
     env:
       PR_TITLE: ${{ github.event.pull_request.title }}
     run: echo "PR Title: $PR_TITLE"
     ```
2. **Immutable Commit SHA Pinning:**
   - ❌ **Mutable Tag:** `uses: actions/checkout@v4`
   - ✅ **Pinned SHA:** `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`
3. **Explicit Least Privilege:**
   - Workflows must declare `permissions: read-all` or `permissions: contents: read` at top level.

---

## 3. High-Performance Test Matrices & Sharding Patterns

### A. Matrix Pruning Strategy
To prevent runner exhaustion across combinatorial matrices ($OS \times Node \times Shard$), test full runtime ranges only on Linux, pruning redundant matrix leaves on macOS and Windows:

```yaml
strategy:
  fail-fast: false
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
    node-version: ['20.x', '22.x']
    shard: [1, 2, 3, 4]
    exclude:
      - os: windows-latest
        node-version: '20.x'
      - os: macos-latest
        node-version: '20.x'
```

### B. Native Test Sharding & Artifact Reporting
Use native test runner sharding (Vitest, Jest, Playwright) combined with JUnit XML generation for deterministic test splits:

```yaml
steps:
  - name: Execute Sharded Test Suite
    env:
      SHARD_INDEX: ${{ matrix.shard }}
      TOTAL_SHARDS: 4
    run: |
      npx vitest run --shard="${SHARD_INDEX}/${TOTAL_SHARDS}" --reporter=default --reporter=junit --outputFile="test-results-${SHARD_INDEX}.xml"

  - name: Upload Test Report Artifact
    if: always()
    uses: actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1 # v4.6.1
    with:
      name: test-results-${{ matrix.os }}-shard${{ matrix.shard }}
      path: test-results-${{ matrix.shard }}.xml
      retention-days: 7
```

---

## 4. GitHub Actions Caching Architecture & Cache Management API

### A. Cache Invalidation Best Practices
- **Package Managers:** Use `actions/setup-node` (`cache: 'npm'`), `actions/setup-python` (`cache: 'pip'`), or `actions/setup-go` (`cache: 'go'`) rather than manual `actions/cache`.
- **Compiler Outputs:** Formulate cache keys using deterministic checksums of lockfiles:
  ```yaml
  - uses: actions/cache@d4323d4df104b026a6aa633fdb11d772115f6fc1 # v4.2.2
    with:
      path: |
        ~/.cargo/bin/
        ~/.cargo/registry/index/
        target/
      key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
      restore-keys: |
        ${{ runner.os }}-cargo-
  ```

### B. Cache Inspection & Purge via REST API (`gh api`)
```bash
# 1. List active repository caches
gh api /repos/:owner/:repo/actions/caches --jq '.actions_caches[] | {id: .id, key: .key, size_mb: (.size_in_bytes / 1048576 | floor), last_accessed: .last_accessed_at}'

# 2. Delete cache entries by key prefix via gh cache CLI
gh cache delete --key Linux-cargo-

# 3. Purge all caches for a branch
gh cache delete --all
```
