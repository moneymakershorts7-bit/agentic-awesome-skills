---
name: make-interfaces-feel-better
description: Design engineering principles for making interfaces feel polished with animation, typography, shadows, border-radius, and micro-interaction details.
category: frontend
risk: safe
source: community
source_repo: jakubkrehel/make-interfaces-feel-better
source_type: community
date_added: "2026-10-07"
author: Jakub Krehel
license: MIT
tags: [frontend, design, ui, animation, typography, surfaces, polish, micro-interactions]
tools: [claude, cursor, codex, antigravity]
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Grep
---

# Details That Make Interfaces Feel Better

Great interfaces rarely come from a single thing. It is usually a collection of small design engineering details that compound into a refined user experience. Apply these principles when building UI components or reviewing frontend code across Tailwind CSS, vanilla CSS, CSS-in-JS, and Framer Motion / Motion.

Before suggesting or writing a fix, identify the project's existing styling system and express the change in that system. Never introduce a second styling system just to apply a polish fix.

When reviewing, slow the interface down: replay motion at 10% speed in the browser's Animations panel and inspect every state: `hover`, `focus`, `active`, `loading`, `empty`. What feels off at 10% speed is what is subtly wrong at full speed.

---

## When to Use
- Use when building or refining UI components, design systems, buttons, modal dialogs, and navigation bars.
- Use when the user requests interface polish, design detail fixes, tactile press feedback, or asks why a layout "feels off".
- Use when reviewing frontend code for motion restraint, optical alignment, concentric border radii, tabular numerals, or font smoothing.
- Supports both `quick` (high-traffic paths) and `full` (comprehensive 5-category inspection) review modes.

---

## Quick Reference & Deep Guides

| Category | Reference Guide | Focus Areas |
| :--- | :--- | :--- |
| **Typography** | [references/typography.md](references/typography.md) | Text wrapping (`balance`/`pretty`), font smoothing, tabular numbers (`tabular-nums`). |
| **Surfaces** | [references/surfaces.md](references/surfaces.md) | Concentric border radius, optical alignment, layered shadows, image outlines, hit areas. |
| **Animations** | [references/animations.md](references/animations.md) | Interruptible transitions, enter/exit stagger, icon animations, scale on press (`0.96`), motion restraint. |
| **Icons** | [references/icons.md](references/icons.md) | Stroke weight matching, single SVG states via `currentColor`, outline vs fill, RTL flipping. |
| **Performance** | [references/performance.md](references/performance.md) | Transition property specificity (never `all`), composited `will-change` usage. |

---

## Core Principles

### 1. Concentric Border Radius
$$\text{Outer Radius} = \text{Inner Radius} + \text{Padding}$$
Mismatched radii on nested elements is the most common flaw making nested cards and buttons look pinched.

### 2. Optical Over Geometric Alignment
When mathematical centering looks unbalanced, align optically. Buttons with asymmetric icons, play triangles, and badges require optical nudging.

### 3. Shadows for Elevation, Borders for Structure
For buttons, cards, and containers whose border exists only to fake depth, prefer layered transparent `box-shadow` tokens. Retain physical borders only for structural separators and selection/focus states.

### 4. Interruptible Animations
Use CSS transitions for interactive state changes so they can be smoothly interrupted mid-flight. Reserve CSS `@keyframes` for single-run staged entrances.

### 5. Split and Stagger Enter Animations
For infrequent staged entrances where sequence communicates visual hierarchy, break content into semantic chunks and stagger by ~100ms. Do not stagger routine, high-frequency interactions.

### 6. Subtle Exit Animations
Use a small fixed `translateY` instead of full height collapse. Exits should always be softer and faster than enters (`ease-out`).

### 7. Contextual Icon Animations
Animate icon swaps with `opacity` ($0 \to 1$), `scale` ($0.25 \to 1$), and `blur` ($4\text{px} \to 0\text{px}$). For Framer Motion, use `transition: { type: "spring", duration: 0.3, bounce: 0 }`. In pure CSS, cross-fade with `cubic-bezier(0.2, 0, 0, 1)`.

### 8. Font Smoothing & Typography
Apply `-webkit-font-smoothing: antialiased` to the root layout on macOS. Apply `font-variant-numeric: tabular-nums` to timers, metrics, and animated counters to prevent layout shift. Use `text-wrap: balance` for headings and `text-wrap: pretty` for body text.

### 9. Image Outlines & Scale on Press
Add a subtle `1px` outline (`oklch(0 0 0 / 0.1)` in light mode, `oklch(1 0 0 / 0.1)` in dark mode) to images to prevent border wash-out. Apply `active:scale-[0.96]` on buttons for tactile click feedback (never below `0.95`).

### 10. Minimum Hit Area & Specific Transitions
Interactive touch elements require at least a 44×44px hit area (40×40px on dense desktop). Never use `transition: all`; always specify target composite properties (`transform`, `opacity`, `filter`).

---

## Common Mistakes & Solutions

| Mistake | Correction |
| :--- | :--- |
| Same border radius on parent and child | Apply concentric formula: `outerRadius = innerRadius + padding` |
| Icons look off-center inside circular buttons | Adjust optical padding or center SVG path bounding box |
| Numbers jitter and jump during counts | Apply `tabular-nums` / `font-variant-numeric: tabular-nums` |
| Heavy text rendering on macOS | Apply `-webkit-font-smoothing: antialiased` on root |
| Staged animation replays on every keystroke | Use instant feedback or $\le 150\text{ms}$ opacity transition |
| `transition: all` causing layout jank | Declare exact properties: `transition-property: transform, opacity` |
| Tiny click targets on close buttons | Expand clickable pseudo-element hit area to at least 44×44px |

---

## Review Output Format

When conducting an interface review:
1. **Scope and Coverage:** State review mode (`quick` or `full`), files inspected, and framework/styling conventions.
2. **Findings Table:** Group by principle with columns: `Severity` (`HIGH`, `MEDIUM`, `LOW`), `Location` (`file:line`), `Before`, `After`, and `Why`.
3. **Considered but Rejected:** Document 1–3 alternative styling suggestions that were evaluated and rejected with rationale.
4. **Verification & Verdict:** State verification commands, browser 10% speed animation observations, and final verdict (`Approve`, `Needs changes`, or `Block`).

---

## Limitations

- **CSS Engine Bound:** Principles assume a modern browser environment supporting modern CSS properties (`oklch`, `text-wrap`, CSS container queries, subgrid).
- **Styling Parity:** Does not replace project-specific design system tokens; principles must be applied within existing design tokens.
