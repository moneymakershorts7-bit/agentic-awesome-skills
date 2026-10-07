---
name: github-dependabot-security
description: Automate software composition analysis (SCA), prioritize CVE alerts via CVSS/EPSS scores, and configure dependency review workflows in CI/CD.
license: Apache-2.0
risk: safe
source: official
allowed-tools:
  - bash
  - read
  - write
  - glob
  - grep
  - run_command
  - view_file
  - write_to_file
---

# github-dependabot-security

**Vendor**: GitHub  
**Category**: Software Composition Analysis (SCA) & Supply Chain

## Overview
Automate software composition analysis (SCA), prioritize CVE alerts via CVSS/EPSS scores, and configure dependency review workflows in CI/CD.

## Workflow & Capabilities

1. **Dependabot Configuration & Hardening**:
   - Configure `.github/dependabot.yml` with scoped ecosystem rules, schedule frequencies, and dependency groups.
   - Enforce automated security updates while separating security patches from minor/major version upgrades.
2. **Vulnerability Prioritization & Triage**:
   - Triage Dependabot alerts based on reachable call paths, CVSS v3/v4 metrics, and EPSS exploit probability scores.
3. **Dependency Review Action**:
   - Enforce `actions/dependency-review-action` in PR gating to block newly introduced high/critical vulnerable packages or non-compliant licenses.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
