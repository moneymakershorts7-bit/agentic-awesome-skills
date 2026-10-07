---
name: cisco-secure-firewall-ops
description: Manage Cisco Secure Firewall Management Center (FMC) and Threat Defense (FTD), Access Control Policies (ACP), Snort 3 inspection, and prefilter rules.
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

# cisco-secure-firewall-ops

**Vendor**: Cisco  
**Category**: Next-Generation Firewall & Intrusion Prevention

## Overview
Manage Cisco Secure Firewall Management Center (FMC) and Threat Defense (FTD), Access Control Policies (ACP), Snort 3 inspection, and prefilter rules.

## Workflow & Capabilities

1. **Access Control Policy (ACP) Management**:
   - Build and optimize ACP rule hierarchies with proper Security Intelligence (SI) feeds, Network, Port, URL, and Application criteria.
2. **Snort 3 IPS Engine Tuning**:
   - Deploy Snort 3 inspection policies with Network Analysis Policies (NAP) and custom Snort rule overrides.
3. **Prefilter Policy Optimization**:
   - Offload high-volume non-inspected traffic (e.g. backup replication, known BGP peers) to prefilter policies to reduce CPU load.
4. **FMC REST API Automation**:
   - Automate object creation, policy deployment, and hit count analysis via FMC REST API.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
