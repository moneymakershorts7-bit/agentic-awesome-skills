---
name: github-security-advisories
description: Coordinate vulnerability disclosure workflows, author GitHub Security Advisories (GHSA), request CVE IDs, and collaborate in temporary private forks.
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

# github-security-advisories

**Vendor**: GitHub  
**Category**: Vulnerability Management & Coordinated Disclosure

## Overview
Coordinate vulnerability disclosure workflows, author GitHub Security Advisories (GHSA), request CVE IDs, and collaborate in temporary private forks.

## Workflow & Capabilities

1. **Private Vulnerability Reporting**:
   - Enable and configure private vulnerability reporting channels for open-source repositories.
2. **GHSA Creation & CVE Reservation**:
   - Author clear, structured advisory drafts with CVSS v3.1/v4.0 scoring, affected versions, patched versions, and workarounds.
   - Request CVE identifiers directly through the GitHub CNA interface.
3. **Collaborative Remediation**:
   - Open a Temporary Private Fork to collaborate on fixes, run CI tests secretly, and merge once the advisory is published.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
