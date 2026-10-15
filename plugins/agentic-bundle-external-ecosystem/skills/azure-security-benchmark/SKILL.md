---
name: azure-security-benchmark
description: Audit and enforce the Microsoft Cloud Security Benchmark (MCSB v1/v2), CIS Azure Foundations, and Azure Policy initiatives across subscriptions.
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

# azure-security-benchmark

**Vendor**: Microsoft  
**Category**: Cloud Compliance & Security Baselines

## Overview
Audit and enforce the Microsoft Cloud Security Benchmark (MCSB v1/v2), CIS Azure Foundations, and Azure Policy initiatives across subscriptions.

## Workflow & Capabilities

1. **Microsoft Cloud Security Benchmark (MCSB) Assessment**:
   - Map cloud resource controls across the 12 domains: Network Security, Identity Management, Privileged Access, Data Protection, Asset Management, Logging, Threat Defense, Incident Response, Posture, Backup, DevSecOps, and Governance.
2. **Azure Policy Baseline Deployment**:
   - Assign built-in and custom Azure Policy definitions in `AuditIfNotExists` or `Deny` modes.
   - Remediate non-compliant resources using Managed Identity automated remediation tasks.
3. **Network Security Group (NSG) & Firewall Hardening**:
   - Audit NSGs for open inbound management ports (SSH 22, RDP 3389, WinRM 5985/5986).
   - Implement Application Security Groups (ASGs) and Azure Bastion zero-public-IP access.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
