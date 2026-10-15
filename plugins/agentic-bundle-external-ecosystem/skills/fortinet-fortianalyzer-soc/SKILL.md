---
name: fortinet-fortianalyzer-soc
description: Configure FortiAnalyzer event correlation, SOC dashboards, forensic log querying, automated incident handlers, and IOC matching.
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

# fortinet-fortianalyzer-soc

**Vendor**: Fortinet  
**Category**: SOC Operations & Log Analytics

## Overview
Configure FortiAnalyzer event correlation, SOC dashboards, forensic log querying, automated incident handlers, and IOC matching.

## Workflow & Capabilities

1. **SOC Dashboard & Event Management**:
   - Configure threat monitoring dashboards tracking top compromised hosts, high-risk applications, and VPN anomalies.
2. **Automated Incident Handlers**:
   - Create event handlers triggered by critical IPS, AV, or Botnet C&C events with automated email/webhook dispatch.
3. **SQL Query Engineering**:
   - Write custom SQL dataset queries to extract threat trends across FortiGate traffic, UTM, and event logs.
4. **IOC Engine & Outbreak Alerts**:
   - Enable automated IOC database matching to detect historical compromise indicators.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
