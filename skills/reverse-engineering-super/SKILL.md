---
name: reverse-engineering-super
description: "Unified master reverse engineering framework for compiled binaries (ELF/PE/Mach-O), .NET, DEX, WASM, stripped Go/Rust, and protocols with automated triage."
category: "security-defensive"
risk: "safe"
source: "official"
date_added: "2026-10-09"
tools:
  - run_command
  - view_file
  - write_to_file
---

# Reverse Engineering Super-Skill (`reverse-engineering-super`)

A unified, multi-platform reverse engineering framework consolidating binary analysis, decompilation, protocol recovery, and dynamic instrumentation into a deterministic 4-phase workflow.

---

## 1. Strict Dual-Use Safety Invariants

This skill operates strictly under defensive software engineering, interoperability, legacy codebase reconstruction, and malware forensic triage mandates:

* **Invariant S-1 (Exploit Weaponization Proscription):** The agent is strictly prohibited from generating executable exploit payloads, shellcode, weaponized ROP chains, or heap grooming scripts. Analysis stops at root-cause analysis and defensive patching.
* **Invariant S-2 (DRM & Piracy Proscription):** The agent is strictly forbidden from creating keygens, cracking licensing routines, or bypassing copy protection schemes.
* **Invariant S-3 (Isolated Execution Invariant):** Target binaries must never be executed raw on the host OS. Dynamic tracing must run inside disposable, unprivileged containers or CPU emulators (QEMU/Qiling). Original samples are marked read-only; operations execute on verified workspace copies.
* **Invariant S-4 (Defensive Pivot Protocol):** Any prompt inquiring about offensive weaponization is automatically pivoted to:
  1. Vulnerability Root Cause Analysis (offsets, boundary flaws).
  2. Remediation Patch Design (source-level fix, bounds checking).
  3. Defensive Detection Signatures (YARA / Snort rules).

---

## 2. The 4-Phase Reversing Lifecycle

```
[Phase 1: Intake & Triage] ──► [Phase 2: Static Analysis] ──► [Phase 3: Dynamic Tracing] ──► [Phase 4: Logic Recovery]
   re_triage.py (0 tokens)      Decompilation & Xrefs         Sandboxed Frida / GDB          SMT Solving & Patching
```

### Phase 1: Automated Intake & Zero-Token Triage
Run the local triage engine before reading code into context:
```bash
python3 scripts/re_triage.py /path/to/target_binary
```
* Identifies magic bytes (ELF, PE, Mach-O, DEX, WASM, PCAP, JS).
* Measures Shannon entropy ($H > 7.15$ indicates packing/encryption).
* Detects compiler signatures (Go `pclntab`, Rust panic strings, .NET CLR, MSVC).
* Scans for cryptographic constants (AES S-Boxes, SHA-256, MD5, RC4).
* Outputs tailored CLI recipe and decompilation recommendations.

### Phase 2: Static Analysis & Multi-Target Lifting
Lifts the binary to intermediate representation or high-level source:
* **Native Binaries (ELF/PE/Mach-O):** Ghidra Headless / radare2 / r2ghidra.
* **Managed .NET:** `ilspycmd -p -o <output_dir> <target.dll>`
* **Android / DEX:** `jadx --deobf --show-bad-code -d <output_dir> <target.apk>`
* **WebAssembly (WASM):** `wasm2c <target.wasm> -o <target.c>`
* **Go / Rust:** Extract function names from `pclntab` or demangle with `rustfilt`.
* See [Target Architecture Matrix](references/target_matrix.md) for detailed calling conventions and schemas.

### Phase 3: Dynamic Instrumentation & Tracing
For runtime observation without manual host execution:
* **System Call Tracing:** `strace -f -s 512 -e trace=file,network <target_binary>`
* **Dynamic Binary Instrumentation:** `frida -f <target_binary> --no-pause -l <hook_script.js>`
* **Cycle-Accurate Emulation:** Qiling framework for emulating foreign architectures (ARM, MIPS) while evading anti-debugging traps.
* See [Anti-Analysis Countermeasures](references/anti_analysis.md) for defeating UPX packing, OLLVM flattening, and timing checks.

### Phase 4: Logic Recovery & AST Slicing
Reconstructing algorithms and state machines:
* Enforces the [Context-Bounded Slicing Protocol](references/slicing_protocol.md) ($\le 4,000$ tokens per sub-routine step).
* Trace backward cross-references (xrefs) originating from sensitive sink APIs (Crypto, Network, Exec).
* Use Z3 SMT solver for automated constraint evaluation and algorithm inversion.

---

## 3. POSIX Degradation Ladder (Graceful Fallback)

When high-level or proprietary tools (IDA, Ghidra, Frida) are unavailable, this skill degrades gracefully:

| Phase | Tier 1: Commercial | Tier 2: Open Source CLI | Tier 3: Standard POSIX / GNU Binutils | Tier 4: Pure Python |
| :--- | :--- | :--- | :--- | :--- |
| **Header Triage** | IDA / Ghidra GUI | `rabin2 -I <bin>` | `file <bin>`, `readelf -h <bin>` | `re_triage.py` |
| **Symbols / Imports** | IDA Exports | `rabin2 -s -i <bin>` | `nm -D <bin>`, `objdump -T <bin>` | Python struct ELF/PE parser |
| **String Extraction** | IDA Strings | `rabin2 -z <bin>` | `strings -a -t x -n 6 <bin>` | Python regex scan |
| **Disassembly** | Ghidra Decompiler | `r2 -qc 'pdf @ main'` | `objdump -d -M intel -C <bin>` | Capstone Python |
| **API Tracing** | Frida Interceptor | Qiling Emulation | `strace -f -e trace=all <bin>` | GDB batch logging |

---

## 4. Supporting References

* [Target Classification & Calling Conventions](references/target_matrix.md)
* [Anti-Analysis, Packing & Obfuscation Countermeasures](references/anti_analysis.md)
* [LLM Context-Bounded Slicing Protocol](references/slicing_protocol.md)
