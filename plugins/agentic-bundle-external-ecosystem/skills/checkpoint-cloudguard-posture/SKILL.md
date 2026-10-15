---
name: checkpoint-cloudguard-posture
description: Enforce multi-cloud posture management (CSPM) using Governance Specification Language (GSL), automate shift-left IaC scanning, and manage CloudGuard Network Security.
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

# checkpoint-cloudguard-posture

**Vendor**: Check Point  
**Category**: Cloud Security Posture & Network Protection

## Overview
Enforce multi-cloud posture management (CSPM) using Governance Specification Language (GSL), automate shift-left IaC scanning, and manage CloudGuard Network Security.

## Workflow & Capabilities

1. **GSL Rule Engineering**:
   - Author Governance Specification Language (GSL) rules to evaluate security configurations in AWS, Azure, and GCP.
2. **Shift-Left IaC Security**:
   - Scan Terraform, CloudFormation, and Kubernetes manifests in CI/CD pipelines to block drift and insecure defaults.
3. **CloudGuard Network Security (CGNS)**:
   - Deploy and manage auto-scaling CloudGuard Security Gateways in cloud transit VPCs/VNets with cloud-native load balancing.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
