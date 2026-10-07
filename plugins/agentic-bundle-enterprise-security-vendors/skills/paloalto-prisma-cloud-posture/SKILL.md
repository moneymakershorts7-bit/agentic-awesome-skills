---
name: paloalto-prisma-cloud-posture
description: Manage Cloud Security Posture (CSPM), Cloud Workload Protection (CWPP), IaC security scanning, and Code-to-Cloud security drift with Prisma Cloud.
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

# paloalto-prisma-cloud-posture

**Vendor**: Palo Alto Networks  
**Category**: Cloud Native Application Protection (CNAPP)

## Overview
Manage Cloud Security Posture (CSPM), Cloud Workload Protection (CWPP), IaC security scanning, and Code-to-Cloud security drift with Prisma Cloud.

## Workflow & Capabilities

1. **CSPM Policy & Compliance Auditing**:
   - Evaluate multi-cloud resources against CIS benchmarks, GDPR, and PCI-DSS using RQL (Resource Query Language).
2. **CWPP Container & Serverless Protection**:
   - Audit vulnerability and compliance scans across container registries (ECR, ACR, GCR) and Kubernetes clusters.
3. **IaC Security (Checkov Integration)**:
   - Scan Terraform, CloudFormation, Kubernetes YAML, and Helm charts in CI/CD pipelines to detect misconfigurations before deployment.
4. **Code-to-Cloud Traceability**:
   - Correlate runtime alerts back to the original source code repository, developer commit, and pull request.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
