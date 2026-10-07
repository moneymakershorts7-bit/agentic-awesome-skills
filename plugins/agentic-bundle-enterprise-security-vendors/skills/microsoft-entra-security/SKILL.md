---
name: microsoft-entra-security
description: Implement Zero Trust identity protection, Conditional Access policies, Privileged Identity Management (PIM), workload identity security, and app consent governance.
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

# microsoft-entra-security

**Vendor**: Microsoft  
**Category**: Identity & Access Management (IAM / Zero Trust)

## Overview
Implement Zero Trust identity protection, Conditional Access policies, Privileged Identity Management (PIM), workload identity security, and app consent governance.

## Workflow & Capabilities

1. **Conditional Access Policy Hardening**:
   - Design and audit Conditional Access (CA) policies enforcing phishing-resistant MFA (FIDO2, Windows Hello for Business).
   - Implement continuous access evaluation (CAE), device compliance checks (Intune), and session controls (sign-in frequency, app-enforced restrictions).
2. **Privileged Identity Management (PIM)**:
   - Configure just-in-time (JIT) role activation with approval workflows and maximum role duration limits.
   - Enforce access reviews for highly privileged roles (Global Administrator, Security Administrator, Cloud Application Administrator).
3. **Identity Protection & Risk Investigation**:
   - Monitor and remediate User Risk and Sign-in Risk events (anomalous token, unfamiliar sign-in properties, password spray).
4. **App Registration & Consent Governance**:
   - Audit enterprise applications with high-privilege MS Graph application permissions (e.g. `Directory.ReadWrite.All`, `Mail.ReadWrite`).
   - Restrict user consent for unverified multitenant applications.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
