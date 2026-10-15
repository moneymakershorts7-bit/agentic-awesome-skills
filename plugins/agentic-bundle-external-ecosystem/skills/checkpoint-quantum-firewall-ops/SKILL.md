---
name: checkpoint-quantum-firewall-ops
description: Automate Check Point Gaia OS & R81.x SmartConsole Web Services API, optimize Access Control layers, review NAT policies, and remove shadow rules.
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

# checkpoint-quantum-firewall-ops

**Vendor**: Check Point  
**Category**: Enterprise Firewall & Network Security

## Overview
Automate Check Point Gaia OS & R81.x SmartConsole Web Services API, optimize Access Control layers, review NAT policies, and remove shadow rules.

## Workflow & Capabilities

1. **Access Control Rule Base Optimization**:
   - Structure ordered Security Layers (Network Layer, Application Control & URL Filtering Layer, Content Awareness Layer).
   - Identify obsolete and shadowed rules using session logs and rule hit counters.
2. **NAT Policy Hardening**:
   - Audit Automatic and Manual NAT rules to prevent address exhaustion and unintentional direct routing.
3. **Management API (mgmt_cli) Automation**:
   - Automate host object creation, policy verification, and batch publishing using Check Point Management API (`mgmt_cli`).

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
