---
name: github-secret-scanning
description: Configure GitHub Secret Scanning, author custom regex pattern definitions, enforce Push Protection, and automate token revocation workflows.
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

# github-secret-scanning

**Vendor**: GitHub  
**Category**: Secret Scanning & Credential Protection

## Overview
Configure GitHub Secret Scanning, author custom regex pattern definitions, enforce Push Protection, and automate token revocation workflows.

## Workflow & Capabilities

1. **Push Protection Enforcement**:
   - Configure repository and organization level Push Protection to block commits containing sensitive tokens before pushing.
   - Define bypass approval policies and audit bypass reasons.
2. **Custom Secret Pattern Authoring**:
   - Author high-fidelity regex patterns for proprietary internal tokens, API keys, and private certificates.
   - Include regex boundaries, prefix indicators, and entropy checks to minimize false positives.
3. **Leak Remediation & Revocation**:
   - Automate post-leak incident response: token invalidation, commit history rewriting (git-filter-repo/BFG), and audit log verification.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
