---
name: checkpoint-harmony-endpoint
description: Perform Harmony Endpoint threat hunting, EDR/XDR forensic investigation, behavioral guard monitoring, automated ransomware rollback, and web protection.
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

# checkpoint-harmony-endpoint

**Vendor**: Check Point  
**Category**: Endpoint Detection & Response (EDR / XDR)

## Overview
Perform Harmony Endpoint threat hunting, EDR/XDR forensic investigation, behavioral guard monitoring, automated ransomware rollback, and web protection.

## Workflow & Capabilities

1. **Threat Hunting & Forensic Investigation**:
   - Investigate automated forensic reports detailing root cause, process tree, modified registry keys, and network connections.
2. **Behavioral Guard & Anti-Ransomware**:
   - Monitor Behavioral Guard detections and verify automated volume shadow copy ransomware file restoration.
3. **Zero-Phishing & Web Protection**:
   - Enforce real-time credential theft prevention on corporate and personal web pages.
4. **Endpoint Remediation Actions**:
   - Isolate endpoints from network, terminate malicious processes, quarantine infected files, and push policy updates via Infinity Portal API.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
