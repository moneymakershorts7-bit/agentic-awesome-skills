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

## 2026-03-31 - Symlink Resolution and Container Filesystem Device Equivalence
**Vulnerability:** `isPathInside` failed to resolve existing candidate paths via `getRealPath`, creating potential symlink traversal false-positives when candidate paths pointed outside target roots. Additionally, direct `stat.dev === layout.device` checks rejected valid transaction lock files in Linux container/OverlayFS environments.
**Learning:** In OverlayFS/container environments, files created in upper layers have a different `st_dev` from overlay directory mounts. Symlink safety checks must resolve candidate paths using `getRealPath` if they exist.
**Prevention:** Always verify device equivalence against parent directory device IDs (`isSameDevice`) and resolve `candidatePath` in symlink safety utilities.
