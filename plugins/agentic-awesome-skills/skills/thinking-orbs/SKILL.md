---
name: thinking-orbs
description: Dotted thought-orb loading indicators for AI & agent UIs with 9 animated cognitive states rendered on 2D canvas for React, React Native, and Vanilla JS.
category: ui-ux
risk: safe
source: community
source_repo: Jakubantalik/thinking-orbs
source_type: community
date_added: "2026-10-06"
author: Jakubantalik
tags: [thinking-orbs, agent-ui, loading-indicator, react, canvas, animation, motion, design, ui-ux]
tools: [Bash, Read, Write]
---

# Thinking Orbs: Animated Agent State & Thought Indicators

## Overview

`thinking-orbs` provides lightweight, mathematical 2D canvas thought-orb indicators for AI agent user interfaces. It offers 9 distinct animated states representing cognitive agent actions (`working`, `searching`, `solving`, `listening`, `connecting`, `weaving`, `composing`, `breathing`, `shaping`) with zero WebGL overhead and automatic dark/light theme switching.

## When to Use
- Visualizing agent thought processes, tool executions, reasoning loops, or network fetching in frontend apps.
- Replacing generic spinners or skeletons in AI chat interfaces with semantic cognitive animations.
- Building reactive AI status badges at chat-avatar scale (size 64) or inline-text scale (size 20).
- Implementing responsive agent UI state transitions in React, Next.js, or React Native.

---

## 9 Semantic Cognitive States

| State | Visual Behavior | Agent Action Context |
| :--- | :--- | :--- |
| `working` | Particles traveling on tilted orbits | General execution, running shell commands |
| `searching` | Meridian sweep scanning dotted globe | Web search, codebase grep, file lookup |
| `solving` | Scrambled rings clicking into solved phase | Reasoning, planning, algorithm execution |
| `listening` | Waveform rolling through spherical rings | Voice input, stream ingestion, audio |
| `connecting` | Constellation graph dynamically wiring | MCP tool call, API request, DB query |
| `weaving` | Three strands plaiting around sphere | Subagent synthesis, code generation |
| `composing` | Undulating multi-band sash ribbon | Long-form drafting, artifact generation |
| `breathing` | Softly expanding and contracting sphere | Idle standby, awaiting user prompt |
| `shaping` | Dotted morphing circle → triangle → square | UI component generation, styling |

---

## React Usage Example

```tsx
import { ThinkingOrb } from 'thinking-orbs'

export function AgentStatusBar({ agentState }: { agentState: 'searching' | 'working' | 'solving' }) {
  return (
    <div className="flex items-center gap-3 p-3 bg-zinc-900 border border-zinc-800 rounded-lg text-sm text-zinc-300">
      <ThinkingOrb state={agentState} size={20} theme="auto" />
      <span className="capitalize">Agent is {agentState}...</span>
    </div>
  )
}
```

---

For React Native setup, vanilla Canvas loop implementation, and CSS theme tokens, see [states-and-modes.md](references/states-and-modes.md).

## Limitations
- Use this skill only when the task clearly matches the scope described above.
- Do not treat the output as a substitute for environment-specific validation, testing, or expert review.
- Stop and ask for clarification if required inputs, permissions, safety boundaries, or success criteria are missing.
