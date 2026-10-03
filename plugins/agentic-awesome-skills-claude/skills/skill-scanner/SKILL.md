---
name: skill-scanner
description: Security scanner for AI Agent Skills packages. Detects prompt injection, data exfiltration, and malicious code patterns with AST, YARA-X, and CEL policies.
allowed-tools:
  - bash
  - read_file
risk: safe
source: community
date_added: "2026-10-03"
---

# Skill Scanner

Cisco AI Defense Skill Scanner is a security analysis framework for Agent Skills following the open Agent Skills specification. It combines pattern-based detection (YAML + YARA-X), abstract syntax tree (AST) and dataflow analysis, and bounded Common Expression Language (CEL) policy enforcement.

## When to Use This Skill

Use this skill when:
- Auditing a newly downloaded or third-party skill package before installation.
- Running CI/CD security gating on skill directories or repositories.
- Detecting prompt injection, sensitive data leakage, credential theft, or unauthorized subprocess spawning.
- Validating custom security policies and suppressions across skill sets.

## CLI Usage Patterns

### 1. Scan a Single Skill Package
Scan a target skill directory containing `SKILL.md`:
```bash
skill-scanner scan /path/to/skill --policy ~/.config/skill-scanner/policy.yaml
```

### 2. Scan All Skills Recursively
Audit an entire skill repository or library:
```bash
skill-scanner scan-all ~/.agents/skills --recursive --policy ~/.config/skill-scanner/policy.yaml
```

### 3. Generate Output Formats
Output structured results for automated reporting:
```bash
# JSON output
skill-scanner scan /path/to/skill --format json

# SARIF output for GitHub Code Scanning
skill-scanner scan /path/to/skill --format sarif --output-sarif report.sarif
```

### 4. Policy Configuration
Generate or customize scan policies:
```bash
# Generate a balanced baseline policy
skill-scanner generate-policy --preset balanced -o ~/.config/skill-scanner/policy.yaml

# Available presets: balanced | low-noise | quiet | strict | permissive
```

## Security Findings Categories

- **Prompt Injection (PI):** Hidden system prompts, role hijacking, instruction override payloads.
- **Data Exfiltration (DE):** Unauthorized outbound webhooks, telemetry tunneling, secret leakage.
- **Rogue Execution (RE):** Arbitrary code execution via untrusted shell scripts or python evals.
- **Tool Misuse (TM):** Disproportionate tool permissions (`allowed-tools`) violating least privilege.

## Limitations

- Best-effort static and AST detection; cannot guarantee 100% absence of novel zero-day prompt obfuscations.
- Scanning non-standard skill layouts (without `SKILL.md`) requires `--lenient` mode.
- Behavioral analysis and LLM-judge verification require external API credentials (OpenAI / Anthropic) if enabled.
