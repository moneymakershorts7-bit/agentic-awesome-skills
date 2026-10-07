---
name: github-actions-security-hardening
description: Harden GitHub Actions CI/CD workflows, enforce SHA pinning, least-privilege GITHUB_TOKEN permissions, OpenID Connect (OIDC), and runner isolation.
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

# github-actions-security-hardening

**Vendor**: GitHub  
**Category**: CI/CD Pipeline & Supply Chain Security

## Overview
Harden GitHub Actions CI/CD workflows, enforce SHA pinning, least-privilege GITHUB_TOKEN permissions, OpenID Connect (OIDC), and runner isolation.

## Workflow & Capabilities

1. **Action Version Pinning & Supply Chain Defenses**:
   - Enforce immutable full 40-character commit SHA pinning for third-party actions instead of floating tags.
   - Audit action dependencies using `step-security/harden-runner` or `zizmor`.
2. **Least Privilege GITHUB_TOKEN Permissions**:
   - Set top-level `permissions: {}` (or `permissions: read-all`) and grant explicit minimal permissions per job (`contents: read`, `pull-requests: write`).
3. **OIDC Federation**:
   - Replace long-lived cloud credentials (AWS Access Keys, Azure Service Principal secrets) with short-lived OIDC tokens via `aws-actions/configure-aws-credentials` and `azure/login`.
4. **Prevent Script Injection**:
   - Never directly interpolate untrusted context variables (e.g. `${{ github.event.issue.title }}`) into bash scripts; pass them via environment variables.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
