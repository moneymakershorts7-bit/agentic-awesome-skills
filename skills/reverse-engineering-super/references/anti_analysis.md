# Anti-Analysis, Packing & Obfuscation Countermeasures

This reference provides technical methodologies for defeating binary protections, packing, obfuscation, and anti-analysis mechanisms during defensive analysis.

---

## 1. Packing & Compression Triage

### Shannon Entropy Triage
Entropy values reflect section randomness:
- $H < 6.0$: Unpacked executable code and structured data.
- $6.0 \le H \le 7.0$: Moderately dense code or compressed resource data.
- $H > 7.15$: Packed code, high-density encrypted payload, or compressed binary sections.

### Unpacking Methodologies
1. **Static UPX Unpacking:**
   ```bash
   upx -d -o unpacked_bin packed_bin
   ```
   *Header Repair:* If custom UPX packers zero out headers (`UPX0`, `UPX1`, `UPX!`), inspect section headers and restore standard 4-byte magic markers.
2. **Dynamic Original Entry Point (OEP) Recovery:**
   - Run sample inside sandboxed Qiling emulator or GDB with memory breakpoints (`watchpoint`) on `.text` segment.
   - When the unpacking stub executes the final tail-jump (`jmp <OEP>` or `push <OEP>; ret`), pause execution.
   - Dump process virtual memory to disk.
   - Reconstruct the Import Address Table (IAT) using Scylla or `r2` reconstruction scripts.

---

## 2. Control Flow De-Flattening (OLLVM)

Control Flow Flattening collapses hierarchical logic into a central switch-dispatcher inside an infinite loop.

```
          ┌───────────────────┐
          │  State Dispatcher │◄─────────────┐
          └─────────┬─────────┘              │
                    │                        │
       ┌────────────┼────────────┐           │
       ▼            ▼            ▼           │
   [Block A]    [Block B]    [Block C]       │
  (state = 2)  (state = 3)  (state = 1)──────┘
```

### De-Flattening Algorithm
1. **Identify the Dispatcher:** Locate the basic block with the highest in-degree (most incoming edges).
2. **Isolate the State Variable:** Identify the register or stack offset updated at the end of each functional block.
3. **Symbolic Execution Slicing (Angr / Triton):**
   - For each basic block, symbolically evaluate the execution path from that block through the dispatcher until the next state update is resolved.
4. **CFG Reconstruction:**
   - Replace the indirect jump back to the dispatcher with a direct conditional or unconditional jump to the calculated target block.
   - Eliminate dead blocks and unreachable dispatcher branches.

---

## 3. Opaque Predicates Elimination

An opaque predicate is a condition whose outcome is known at design time but evaluated at runtime via complex operations (e.g., $x^2 + x \equiv 0 \pmod 2$).

### Elimination Process
1. Locate conditional branches with high mathematical complexity.
2. Formulate the path condition into SMT constraints.
3. Solve using Z3:
   ```python
   from z3 import *
   x = BitVec('x', 32)
   s = Solver()
   s.add((x * x + x) % 2 != 0)
   if s.check() == unsat:
       print("Branch is invariant / opaque: patch with NOP or JMP")
   ```
4. Patch unreachable branch target with NOPs (`0x90`) or force unconditional jump.

---

## 4. Anti-Debugging & Anti-Tracing Evasion

### Linux Platform Countermeasures
- **`ptrace(PTRACE_TRACEME)` Check:**
  - *Mechanism:* Binaries call `ptrace` on themselves. If already attached by a debugger, `ptrace` returns -1 and the binary terminates.
  - *Countermeasure:* Intercept via `LD_PRELOAD`:
    ```c
    long ptrace(int request, int pid, void *addr, void *data) {
        return 0; // Always report success
    }
    ```
- **`/proc/self/status` TracerPid Scan:**
  - *Mechanism:* Reads `TracerPid` line from procfs.
  - *Countermeasure:* Hook `open` / `fopen` / `read` via preload shim to return `TracerPid:\t0`.
- **Timing Checks (`rdtsc`):**
  - *Mechanism:* Measures delta between instructions. If delta > 10,000 cycles, debugger single-stepping is detected.
  - *Countermeasure:* Run in Qiling / Unicorn CPU emulator with fixed cycle advancement per instruction.

### Windows Platform Countermeasures
- **PEB Checks (`BeingDebugged`, `NtGlobalFlag`):**
  - Patch PEB byte at `fs:[0x30] + 0x02` (32-bit) or `gs:[0x60] + 0x02` (64-bit) to 0.
- **TLS Callbacks:**
  - Enumerate AddressOfCallBacks in the PE Data Directory[9] (TLS Table). Set breakpoints on callback functions to analyze setup routines before `main` executes.
