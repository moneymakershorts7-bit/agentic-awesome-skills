---
name: fortinet-fortigate-policy-audit
description: Analyze FortiOS firewall policies, audit interface bindings, review VIP/NAT configurations, and eliminate shadow or redundant rules.
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

# fortinet-fortigate-policy-audit

**Vendor**: Fortinet  
**Category**: Firewall Policy & Network Security

## Overview
Analyze FortiOS firewall policies, audit interface bindings, review VIP/NAT configurations, and eliminate shadow or redundant rules.

## Workflow & Capabilities

1. **FortiOS Policy Base Review**:
   - Audit firewall policies (`config firewall policy`) for proper source/destination interfaces, addresses, services, and action settings.
   - Identify unused policies based on hit counts and session logs.
2. **VIP & NAT Security**:
   - Inspect Virtual IPs (`config firewall vip`) and port forwarding mappings to prevent accidental public exposure of management interfaces.
3. **Security Profile Attachment**:
   - Ensure AV, IPS, Web Filter, Application Control, and SSL Inspection profiles are active on all outbound and inbound policies.
4. **FortiOS CLI & REST API Automation**:
   - Query policy status and test routing lookup via FortiOS API and SSH CLI.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
