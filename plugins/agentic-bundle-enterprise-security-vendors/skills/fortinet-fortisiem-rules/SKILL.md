---
name: fortinet-fortisiem-rules
description: Develop multi-vendor SIEM correlation rules, custom parser templates, real-time analytics engine (RTAE) tuning, and threat mitigation workflows.
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

# fortinet-fortisiem-rules

**Vendor**: Fortinet  
**Category**: SIEM Engineering & Multi-Vendor Analytics

## Overview
Develop multi-vendor SIEM correlation rules, custom parser templates, real-time analytics engine (RTAE) tuning, and threat mitigation workflows.

## Workflow & Capabilities

1. **Real-Time Analytics Engine (RTAE) Rules**:
   - Build stateful multi-event correlation rules (e.g. multiple failed logins followed by successful login and sensitive file export).
2. **Parser Definition & Attribute Mapping**:
   - Author XML/regex parsers mapping syslog streams to standard FortiSIEM event attributes (`srcIp`, `destIp`, `user`, `procName`).
3. **Baseline Anomaly Detection**:
   - Configure statistical baseline rules detecting deviations in user traffic volume, login hours, and outbound data transfer.
4. **Automated Remediation Scripts**:
   - Configure FortiSIEM notification and mitigation scripts to ban IPs on FortiGate firewalls automatically.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
