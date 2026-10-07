---
name: nvidia-nemo-guardrails
description: Develop Colang guardrail policies, topical rails, moderation rails, fact-checking rails, and self-check input/output validation with NeMo Guardrails.
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

# nvidia-nemo-guardrails

**Vendor**: NVIDIA  
**Category**: AI Guardrails & LLM Safety

## Overview
Develop Colang guardrail policies, topical rails, moderation rails, fact-checking rails, and self-check input/output validation with NeMo Guardrails.

## Workflow & Capabilities

1. **Colang Flow & Policy Definition**:
   - Author `.co` flows specifying deterministic conversation trajectories and off-topic redirection.
2. **Multi-Rail Guardrail Architecture**:
   - Configure Input Rails (jailbreak check, toxic language filter).
   - Configure Dialog Rails (prescribed business flows, compliance guardrails).
   - Configure Output Rails (hallucination detection, fact-checking, PII masking).
3. **Embedding-Based Semantic Guardrails**:
   - Use vector similarity to detect adversarial intent variations without brittle regex matching.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
