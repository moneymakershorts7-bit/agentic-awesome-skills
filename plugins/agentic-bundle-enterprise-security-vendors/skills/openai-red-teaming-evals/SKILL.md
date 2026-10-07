---
name: openai-red-teaming-evals
description: Construct automated adversarial red-teaming test benches, prompt injection evaluation datasets, and jailbreak resilience benchmarks using OpenAI Evals.
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

# openai-red-teaming-evals

**Vendor**: OpenAI  
**Category**: AI Red Teaming & Adversarial Robustness

## Overview
Construct automated adversarial red-teaming test benches, prompt injection evaluation datasets, and jailbreak resilience benchmarks using OpenAI Evals.

## Workflow & Capabilities

1. **Adversarial Benchmark Construction**:
   - Build evaluation suites testing Direct Prompt Injection, Indirect Prompt Injection, Jailbreaking (prefix injection, persona adoption), and Data Leakage.
2. **OpenAI Evals Framework Integration**:
   - Define custom eval templates with model-graded eval prompts and deterministic match criteria.
3. **Automated Red Teaming Loops**:
   - Deploy automated attacker-defender LLM loops to discover latent alignment and safety failure modes.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
