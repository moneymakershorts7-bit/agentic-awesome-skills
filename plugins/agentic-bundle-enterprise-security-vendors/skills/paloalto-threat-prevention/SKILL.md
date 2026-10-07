---
name: paloalto-threat-prevention
description: Configure and tune Palo Alto Threat Prevention profiles (Antivirus, Anti-Spyware, Vulnerability Protection, URL Filtering, WildFire), and manage signature exceptions.
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

# paloalto-threat-prevention

**Vendor**: Palo Alto Networks  
**Category**: Threat Prevention & Malware Defense

## Overview
Configure and tune Palo Alto Threat Prevention profiles (Antivirus, Anti-Spyware, Vulnerability Protection, URL Filtering, WildFire), and manage signature exceptions.

## Workflow & Capabilities

1. **Security Profile Tuning**:
   - Configure Antivirus, Anti-Spyware (DNS Sinkholing), and Vulnerability Protection profiles with appropriate action thresholds (default, reset-both, block).
2. **WildFire Zero-Day Analysis**:
   - Configure real-time WildFire forwarding rules for PE, PDF, Office, and script file types.
3. **URL Filtering & Advanced Threat Defense**:
   - Enforce category blocks for Command-and-Control, Malware, Phishing, and Dynamic DNS.
4. **Signature Exception Management**:
   - Manage Threat ID exceptions with scoped source/destination IP filtering to resolve false positives safely.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
