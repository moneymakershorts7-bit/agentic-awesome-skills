---
name: openai-moderation-guardrails
description: Integrate OpenAI Moderation API endpoints, normalize category scores, tune multi-modal thresholds, and enforce real-time content filtering.
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

# openai-moderation-guardrails

**Vendor**: OpenAI  
**Category**: AI Safety & Content Moderation

## Overview
Integrate OpenAI Moderation API endpoints, normalize category scores, tune multi-modal thresholds, and enforce real-time content filtering.

## Workflow & Capabilities

1. **Moderation API Integration**:
   - Implement calls to the latest OpenAI Moderation endpoint (`omni-moderation-latest`).
   - Process text and image inputs to identify policy violations across categories: hate, harassment, self-harm, sexual, violence.
2. **Dynamic Threshold Tuning**:
   - Normalize category probability scores and define granular enterprise thresholds.
   - Separate hard blocks (immediate rejection) from soft blocks (human review queue).
3. **Streaming & Async Guardrails**:
   - Implement chunk-based moderation and speculative completion cancellation upon detected violations.

## Verification & Safe Execution Rules
- Always operate under the Principle of Least Privilege.
- Validate configurations in a staging or sandbox environment before applying changes to production firewalls, clouds, or endpoints.
- Refer to `references/` for detailed API schemas, command syntaxes, and policy rule definitions.
