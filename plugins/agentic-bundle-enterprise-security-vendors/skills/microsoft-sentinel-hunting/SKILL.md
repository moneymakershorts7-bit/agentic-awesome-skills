---
name: microsoft-sentinel-hunting
description: Design Kusto Query Language (KQL) hunting queries, detection analytic rules, ASIM normalization, incident investigation, and SOAR automation playbooks for Microsoft Sentinel.
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

# microsoft-sentinel-hunting

**Vendor**: Microsoft  
**Category**: SIEM & Security Orchestration (SOAR)

## Overview
Design Kusto Query Language (KQL) hunting queries, detection analytic rules, ASIM normalization, incident investigation, and SOAR automation playbooks for Microsoft Sentinel.

## Workflow & Capabilities

1. **KQL Hunting & Detection Rule Engineering**:
   - Author scheduled query rules and Near-Real-Time (NRT) alerts adhering to the Advanced Security Information Model (ASIM).
   - Map detection rules to MITRE ATT&CK tactics, techniques, and sub-techniques.
2. **Incident Triage & Entity Investigation**:
   - Investigate entity timelines (Account, Host, IP, Cloud Resource) across correlated alert graphs.
   - Pivot through `SecurityAlert`, `SecurityEvent`, `SigninLogs`, `AuditLogs`, and `DeviceEvents` tables.
3. **Data Connector & Log Ingestion Health**:
   - Monitor data connector status, workspace ingestion volume, and billable table growth.
   - Optimize ingestion costs using auxiliary logs, basic logs, and log data transformation rules (DCR).
4. **SOAR Automation Playbooks**:
   - Build and test Logic App playbooks for automated host isolation, IP blocking on firewalls, and Entra ID password reset.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
