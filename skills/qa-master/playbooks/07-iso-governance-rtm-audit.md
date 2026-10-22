# Playbook 07: ISO Governance & Requirements Traceability (RTM) Audit

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                       PLAYBOOK 07: ISO GOVERNANCE & RTM AUDIT                           │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ Standards: ISO 9001 (8.3.4, 8.5.2) | ISO 27001 (8.25, 8.32) | SOC 2 CC8.1 | CMMI PR/VV  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

## Objective
Verify bi-directional requirements traceability (100% coverage), enforce the Two-Person Rule on pull requests, and validate configuration management integrity.

---

## Step 1: Pre-Flight Verification
Verify that the repository working tree is clean and that the latest commit is signed:
```bash
# Check working tree
if [[ -n $(git status --porcelain) ]]; then
  echo "[FAIL] Uncommitted changes present. Cannot certify dirty working tree."
  exit 1
fi

# Verify commit signature
LATEST_COMMIT=$(git rev-parse HEAD)
git verify-commit "$LATEST_COMMIT" || echo "[WARN] Commit $LATEST_COMMIT is not GPG/SSH signed."
```

---

## Step 2: Build & Validate the Requirements Traceability Matrix
Run the governance auditor to parse specification files in `docs/requirements/` and map them to tests and source code AST symbols:
```bash
python3 ~/.agents/skills/qa-master/scripts/governance_auditor.py --audit-rtm . --output .audit/rtm_manifest.json
```

### Acceptance Criteria:
- `traceability_coverage_pct == 100.0`
- Zero unmapped requirements
- Zero orphaned test cases

---

## Step 3: Verify the Two-Person Rule (Segregation of Duties)
Verify that the pull request was reviewed and approved by an independent engineer (author $\neq$ reviewer):
```bash
python3 ~/.agents/skills/qa-master/scripts/governance_auditor.py --verify-peer-review .audit/peer_review_manifest.json
```

### Diagnostic & Self-Healing:
If `author == reviewer`, the commit is blocked. Re-route the pull request to an authorized peer reviewer or tech lead before proceeding.
