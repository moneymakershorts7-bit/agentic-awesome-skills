---
name: github-codeql-analysis
description: Author custom CodeQL queries, triage static analysis results (SARIF), configure taint-tracking data flows, and automate CI/CD code scanning pipelines.
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

# github-codeql-analysis

**Vendor**: GitHub  
**Category**: Static Application Security Testing (SAST)

## Overview
Author custom CodeQL queries, triage static analysis results (SARIF), configure taint-tracking data flows, and automate CI/CD code scanning pipelines.

## Workflow & Capabilities

1. **Custom CodeQL Query Engineering**:
   - Author `.ql` queries targeting SQL injection (CWE-89), Command injection (CWE-78), Cross-Site Scripting (CWE-79), and Path traversal (CWE-22).
   - Define custom Sources, Sinks, Sanitizers, and Additional Taint Steps in CodeQL DataFlow modules.
2. **SARIF Triage & Baseline Management**:
   - Parse SARIF outputs from CodeQL CLI, filter out false positives, and verify remediation completeness.
3. **Workflow Integration**:
   - Hardened `github/codeql-action` workflow definitions with language matrix builds and autobuild overrides.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
