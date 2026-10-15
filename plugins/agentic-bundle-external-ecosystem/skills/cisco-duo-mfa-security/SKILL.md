---
name: cisco-duo-mfa-security
description: Automate Cisco Duo Zero Trust identity security, Trusted Endpoints policies, continuous trusted access (CTA), and risk-based adaptive MFA.
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

# cisco-duo-mfa-security

**Vendor**: Cisco  
**Category**: Identity Security & Multi-Factor Authentication

## Overview
Automate Cisco Duo Zero Trust identity security, Trusted Endpoints policies, continuous trusted access (CTA), and risk-based adaptive MFA.

## Workflow & Capabilities

1. **Policy & Rule Architecture**:
   - Design Global, Application, and Group policies enforcing phishing-resistant authentication (Duo Mobile Passkeys, FIDO2 WebAuthn).
   - Configure Device Health Application checks (minimum OS version, disk encryption, firewall enabled).
2. **Continuous Trusted Access (CTA)**:
   - Enforce step-up authentication upon detected risk signals (impossible travel, Wi-Fi security change, malware alert).
3. **Duo Admin API Automation**:
   - Automate user provisioning, bypass code generation, authentication log auditing, and lockout recovery.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
