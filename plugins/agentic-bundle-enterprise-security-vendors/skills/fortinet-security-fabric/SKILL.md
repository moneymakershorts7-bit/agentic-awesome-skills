---
name: fortinet-security-fabric
description: Audit Security Fabric continuous compliance, configure automated Fabric Connectors, and orchestrate synchronized threat response.
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

# fortinet-security-fabric

**Vendor**: Fortinet  
**Category**: Zero Trust Architecture & Security Fabric

## Overview
Audit Security Fabric continuous compliance, configure automated Fabric Connectors, and orchestrate synchronized threat response.

## Workflow & Capabilities

1. **Security Fabric Continuous Compliance Rating**:
   - Audit the Fabric Security Rating checks across Security Posture, Fabric Coverage, and Optimization.
2. **Fabric Connectors Configuration**:
   - Establish dynamic fabric connectors to AWS, Azure, GCP, VMware ESXi, and Kubernetes to pull dynamic address objects.
3. **Synchronized Threat Response**:
   - Configure automated FortiGate-FortiClient EMS-FortiSandbox quarantine workflows when an endpoint is infected.
4. **Topology & Asset Discovery**:
   - Audit the physical and logical Security Fabric topology for unmanaged or rogue network segments.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
