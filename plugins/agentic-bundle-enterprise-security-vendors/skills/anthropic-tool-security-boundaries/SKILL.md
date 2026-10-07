---
name: anthropic-tool-security-boundaries
description: Implement principle of least privilege for Claude tool use, strict schema validation, human-in-the-loop gates, and tainted parameter sanitization.
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

# anthropic-tool-security-boundaries

**Vendor**: Anthropic  
**Category**: Agent Tool Security & Execution Sandboxing

## Overview
Implement principle of least privilege for Claude tool use, strict schema validation, human-in-the-loop gates, and tainted parameter sanitization.

## Workflow & Capabilities

1. **Least-Privilege Tool Schema Design**:
   - Specify tight JSON schema types, regex patterns, and enum constraints for all tool parameters.
2. **Human-in-the-Loop (HITL) Policy**:
   - Define deterministic triggers requiring human confirmation before irreversible actions (e.g. deleting files, sending external emails, modifying production DBs).
3. **Tainted Flow Defense**:
   - Prevent untrusted inputs retrieved via tools (e.g. web scraping, file reading) from propagating directly into privileged tool invocations.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
