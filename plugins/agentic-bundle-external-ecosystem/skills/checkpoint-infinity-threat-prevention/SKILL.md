---
name: checkpoint-infinity-threat-prevention
description: Configure Check Point Autonomous Threat Prevention, ThreatCloud AI intelligence, SandBlast zero-day emulation, and Threat Extraction (CDR).
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

# checkpoint-infinity-threat-prevention

**Vendor**: Check Point  
**Category**: Threat Prevention & Zero-Day Sandboxing

## Overview
Configure Check Point Autonomous Threat Prevention, ThreatCloud AI intelligence, SandBlast zero-day emulation, and Threat Extraction (CDR).

## Workflow & Capabilities

1. **Autonomous Threat Prevention Profile Management**:
   - Implement autonomous profiles (Strict, Recommended, Custom) auto-tuned by ThreatCloud AI.
2. **SandBlast Threat Emulation (Sandboxing)**:
   - Configure CPU-level threat emulation to detect evasion-resistant zero-day malware before execution.
3. **Threat Extraction (Content Disarm & Reconstruction - CDR)**:
   - Clean incoming documents (PDF, Office) in real time by removing active content, macros, and embedded objects while preserving readability.
4. **ThreatCloud AI Intelligence Queries**:
   - Pivot on IOC indicators across the global ThreatCloud AI network.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
