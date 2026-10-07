---
name: cisco-talos-threat-intel
description: Integrate Cisco Talos threat intelligence feeds, enrich IP/Domain/File IOCs, map Snort SIDs, and evaluate Talos vulnerability advisories.
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

# cisco-talos-threat-intel

**Vendor**: Cisco  
**Category**: Threat Intelligence & Vulnerability Research

## Overview
Integrate Cisco Talos threat intelligence feeds, enrich IP/Domain/File IOCs, map Snort SIDs, and evaluate Talos vulnerability advisories.

## Workflow & Capabilities

1. **IOC Reputation Enrichment**:
   - Query Talos IP and Domain reputation categories (Spam, Malware, Botnet, Exploit).
   - Check file hash SHA-256 dispositions via Cisco Secure Malware Analytics (Threat Grid).
2. **Snort Rule & SID Mapping**:
   - Map Talos vulnerability advisories (TALOS-YYYY-XXXX) to Snort 2 and Snort 3 Signature IDs (SIDs).
3. **Threat Intelligence Feed Automation**:
   - Ingest Talos intelligence into SIEM, firewall, and endpoint security platforms via STIX/TAXII.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
