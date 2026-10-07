---
name: paloalto-cortex-xdr-hunting
description: Triage Cortex XDR incidents, execute XQL threat hunting queries, analyze causality chains, and configure Behavioral Indicators of Compromise (BIOC) rules.
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

# paloalto-cortex-xdr-hunting

**Vendor**: Palo Alto Networks  
**Category**: Extended Detection & Response (XDR / SOC)

## Overview
Triage Cortex XDR incidents, execute XQL threat hunting queries, analyze causality chains, and configure Behavioral Indicators of Compromise (BIOC) rules.

## Workflow & Capabilities

1. **Incident Triage & Causality Analysis**:
   - Reconstruct endpoint execution trees using the Causality Group Owner (CGO) graph.
   - Distinguish benign administrative activity from living-off-the-land (LotL) attacks.
2. **XQL Threat Hunting**:
   - Query raw telemetry across endpoint, network, and cloud identity datasets.
3. **BIOC & IOC Rule Authoring**:
   - Create custom Behavioral IOC rules targeting unauthorized persistence, privilege escalation, and credential dumping.
4. **Automated Response Dispatch**:
   - Isolate compromised endpoints, terminate malicious process trees, and quarantine suspect binaries via API.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
