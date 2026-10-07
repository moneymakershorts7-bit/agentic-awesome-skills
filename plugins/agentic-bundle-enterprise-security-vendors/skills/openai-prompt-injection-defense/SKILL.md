---
name: openai-prompt-injection-defense
description: Design structural defenses, dual-LLM verification architectures, input isolation delimiters, and tool argument validation for OpenAI models.
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

# openai-prompt-injection-defense

**Vendor**: OpenAI  
**Category**: AI Security & Prompt Injection Defense

## Overview
Design structural defenses, dual-LLM verification architectures, input isolation delimiters, and tool argument validation for OpenAI models.

## Workflow & Capabilities

1. **Structural Delimiters & Context Isolation**:
   - Enforce strict separation between trusted system instructions and untrusted data payloads using schema boundaries and delimiters.
2. **Dual-LLM Arbiter Pattern**:
   - Employ a secondary lightweight validator LLM to inspect user input and extracted web payloads for coercive or goal-diverting language.
3. **Tool Call Schema Validation**:
   - Validate and sanitize all function calling arguments against strict Pydantic/JSON Schemas before executing tools.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
