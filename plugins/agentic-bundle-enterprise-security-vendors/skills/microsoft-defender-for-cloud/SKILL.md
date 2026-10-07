---
name: microsoft-defender-for-cloud
description: Evaluate Cloud Security Posture Management (CSPM), Secure Score, regulatory compliance baselines, and workload protection (CWPP) across Azure, AWS, and GCP.
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

# microsoft-defender-for-cloud

**Vendor**: Microsoft  
**Category**: Cloud Security Posture & Workload Protection

## Overview
Evaluate Cloud Security Posture Management (CSPM), Secure Score, regulatory compliance baselines, and workload protection (CWPP) across Azure, AWS, and GCP.

## Workflow & Capabilities

1. **Secure Score Assessment**:
   - Query Microsoft Defender for Cloud Secure Score APIs across subscriptions and multi-cloud connectors.
   - Prioritize recommendations with the highest security impact and lowest operational blast radius.
2. **Cloud Security Posture Management (CSPM)**:
   - Audit attack path analysis graphs and identify toxic combinations (e.g. exposed VM + high privileges + unpatched CVE).
   - Evaluate regulatory compliance baselines (NIST SP 800-53, ISO 27001, CIS Azure Foundations, PCI-DSS 4.0).
3. **Cloud Workload Protection (CWPP)**:
   - Configure Defender plans for Servers, Containers (AKS), Storage (malware scanning & sensitive data threat detection), and Azure SQL / Cosmos DB.
   - Audit agentless scanning coverage and vulnerability assessment configurations.
4. **Governance & Remediation Automation**:
   - Enforce automated remediation workflows using Azure Logic Apps and Azure Policy remediation tasks.
   - Establish governance rules to assign resource owners and remediation SLAs for high-severity findings.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
