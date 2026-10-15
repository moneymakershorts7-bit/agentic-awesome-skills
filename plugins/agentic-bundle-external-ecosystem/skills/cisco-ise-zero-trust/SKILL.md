---
name: cisco-ise-zero-trust
description: Configure Cisco Identity Services Engine (ISE 3.x), 802.1X Network Access Control (NAC), TrustSec Security Group Tagging (SGT), and endpoint posture.
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

# cisco-ise-zero-trust

**Vendor**: Cisco  
**Category**: Network Access Control (NAC) & Micro-segmentation

## Overview
Configure Cisco Identity Services Engine (ISE 3.x), 802.1X Network Access Control (NAC), TrustSec Security Group Tagging (SGT), and endpoint posture.

## Workflow & Capabilities

1. **Policy Sets & Authentication/Authorization**:
   - Construct modular ISE Policy Sets combining Authentication rules (EAP-TLS, PEAP) and Authorization rules based on AD group, device type, and location.
2. **Profiling & Anomaly Detection**:
   - Profile endpoints using DHCP, RADIUS, SNMP, and HTTP User-Agent probes to prevent MAC spoofing.
3. **TrustSec & Software-Defined Micro-segmentation**:
   - Design Security Group Tagging (SGT) matrices and enforce Security Group ACLs (SGACLs) across switches and firewalls.
4. **Endpoint Posture Assessment**:
   - Enforce AnyConnect/Secure Client posture validation (antivirus definitions, patch level) before granting full network admission.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
