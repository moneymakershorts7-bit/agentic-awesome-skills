---
name: anthropic-constitutional-ai-safety
description: Implement Constitutional AI safety principles, critique-and-revision alignment prompts, harmlessness boundaries, and safe dialogue state machines.
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

# anthropic-constitutional-ai-safety

**Vendor**: Anthropic  
**Category**: AI Alignment & Constitutional Safety

## Overview
Implement Constitutional AI safety principles, critique-and-revision alignment prompts, harmlessness boundaries, and safe dialogue state machines.

## Workflow & Capabilities

1. **Constitutional Principle Specification**:
   - Author explicit, hierarchical safety constitutions governing model behavior under pressure.
2. **Critique-and-Revision Safety Loops**:
   - Implement automated self-critique steps where the model evaluates its draft response against the constitutional principles before final delivery.
3. **Calibrated Refusal Architecture**:
   - Design nuanced refusals that clearly state boundaries without sounding preachy or condescending.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
