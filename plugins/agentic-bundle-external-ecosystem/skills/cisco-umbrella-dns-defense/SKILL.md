---
name: cisco-umbrella-dns-defense
description: Implement Cisco Umbrella DNS-layer security, intelligent proxy inspection, Shadow IT discovery, and cloud access security broker (CASB) controls.
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

# cisco-umbrella-dns-defense

**Vendor**: Cisco  
**Category**: Secure Access Service Edge (SASE) & DNS Security

## Overview
Implement Cisco Umbrella DNS-layer security, intelligent proxy inspection, Shadow IT discovery, and cloud access security broker (CASB) controls.

## Workflow & Capabilities

1. **DNS-Layer Security Policies**:
   - Configure DNS security policies blocking Malware, Command and Control, Phishing, Newly Seen Domains, and Dynamic DNS.
2. **Intelligent Proxy & SSL Decryption**:
   - Enable selective proxy inspection for gray-reputation domains with file inspection via Cisco Secure Malware Analytics.
3. **App Discovery & Shadow IT Control**:
   - Audit unapproved cloud applications and enforce block/warn policies for high-risk SaaS categories.
4. **Umbrella Reporting & API Integration**:
   - Export activity logs to Amazon S3 / Azure Blob and query Umbrella Investigate API for domain enrichment.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
