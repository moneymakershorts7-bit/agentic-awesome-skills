# Playbook 05: Incident Feedback Loop Closure

This playbook details how to close the loop on every security incident, penetration testing report, or bug bounty finding, guaranteeing the vulnerability class can never recur.

---

## 1. The Three-Fold Feedback Invariant
Every security flaw that escapes into production requires three mandatory deliverables before the post-mortem can be marked "Closed":

```
┌────────────────────────────────────────────────────────┐
│              ESCAPED VULNERABILITY INCIDENT            │
└───────────────────────────┬────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
1. Pipeline Regression  2. Semantic SAST /   3. Threat Model &
   Integration Test        Linter Rule          Policy-as-Code
   (Deterministic pass/    (AST pattern check   (Architectural
    fail automated test)    in CI gate)          update in docs)
```

---

## 2. Step-by-Step Implementation

### Step 1: Write an Automated Regression Test
1. Create a unit or integration test that reproduces the exact attack payload:
   - Example: In an IDOR flaw where user A accesses user B's account:
   ```python
   def test_tenant_isolation_cross_tenant_access_blocked():
       token_tenant_a = create_auth_token(tenant_id="tenant-a")
       response = client.get("/api/v1/data/tenant-b/records", headers={"Authorization": token_tenant_a})
       assert response.status_code == 403
       assert "forbidden" in response.text.lower()
   ```
2. Run test to verify it fails on unpatched code and passes with the patch.

### Step 2: Author a Custom Semgrep Rule
1. In `rules/custom-security-rules.yml`, author a semantic AST check detecting similar patterns across the repository:
   ```yaml
   rules:
     - id: require-tenant-scope-filter
       patterns:
         - pattern: $DB.query(..., tenant_id=...)
       message: "Database query missing explicit tenant isolation scope"
       languages: [python]
       severity: ERROR
   ```
2. Add rule to the CI `semgrep` scan step.

### Step 3: Update the Threat Model & Backlog Guidelines
1. Update `docs/security/threat-models/` reflecting the new threat vector and mitigation.
2. Share the lesson in the engineering blameless post-mortem retrospective.
