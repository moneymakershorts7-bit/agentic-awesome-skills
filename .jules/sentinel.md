# Sentinel Audit Ledger: agentic-awesome-skills

This file tracks periodic automated security audits, vulnerability scans, and hygiene checks conducted by Google Jules.

## Guidelines for Sentinel
1. **Focus on Skills Security:**
   - Check for undeclared external network calls in `SKILL.md` or bundled scripts.
   - Ensure all skills specify appropriate `allowed-tools` and minimum necessary permissions.
   - Never commit or log secrets, tokens, or credentials.
2. **Verification Commands:**
   - `npm run validate`
   - `npm run security:docs`
   - `npm run test`
3. **Remediation Protocol:**
   - If remediation is needed, propose an atomic, focused PR (< 100 lines) with Conventional Commits.

## Audit History
- **2026-10-04**: Initial Sentinel ledger established. All active skills verified against Cisco AI Defense and AAS specifications.
