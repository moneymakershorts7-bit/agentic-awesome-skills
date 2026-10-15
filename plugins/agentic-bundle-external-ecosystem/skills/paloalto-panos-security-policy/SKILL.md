---
name: paloalto-panos-security-policy
description: Audit PAN-OS Next-Generation Firewall (NGFW) policies, migrate port-based rules to App-ID, configure security zones, and optimize security rule bases.
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

# paloalto-panos-security-policy

**Vendor**: Palo Alto Networks  
**Category**: Next-Generation Firewall (NGFW) & Network Security

## Overview
Audit PAN-OS Next-Generation Firewall (NGFW) policies, migrate port-based rules to App-ID, configure security zones, and optimize security rule bases.

## Workflow & Capabilities

1. **App-ID Migration & Policy Optimization**:
   - Analyze port-based legacy rules and migrate them to application-specific App-ID rules.
   - Detect shadow rules, unused rules, and overly permissive any-any rules.
2. **Security Zone & Interface Configuration**:
   - Enforce zone-based security boundaries (Trust, DMZ, Untrust) with strict inter-zone inspection.
3. **Decryption Policy Architecture**:
   - Configure SSL Inbound Inspection and SSL Forward Proxy decryption policies with category exclusion lists (e.g. financial-services, health-and-medicine).
4. **PAN-OS XML / REST API Automation**:
   - Query rule hit counts, validate commit operations, and export configuration baselines.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
