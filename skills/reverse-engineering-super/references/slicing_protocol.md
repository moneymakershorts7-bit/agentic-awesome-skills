# LLM Context-Bounded Semantic Slicing Protocol

This protocol enforces strict token conservation when analyzing decompiled code or disassembly within LLM contexts.

---

## 1. The Context Explosion Problem

- A standard 2MB compiled native binary yields over **400,000 lines of disassembly**.
- Ingesting raw assembly or thousands of decompiled functions into an LLM context causes:
  1. Instantaneous context budget exhaustion.
  2. Loss of reasoning accuracy over long-range dependencies.
  3. Hallucinated registers, reversed jump conditions, and phantom instructions.

---

## 2. The 4-Tier Progressive Slicing Architecture

The agent strictly bounds context consumption to **$\le$ 4,000 tokens per sub-routine inspection cycle**:

```
[Layer 0: Binary Fingerprint]     ──►  ~150 tokens  (Format, Arch, Compiler, Security flags)
[Layer 1: High-Signal Sinks]     ──►  ~800 tokens  (Sensitive API Clusters: Crypto, Net, Exec)
[Layer 2: CFG Topological Map]   ──►  ~1,200 tokens (Call-graph depth k=2, Adjacency, Branch keys)
[Layer 3: Program Dependence PDG] ──►  ~2,500 tokens (Data-flow slice from input source to sink)
```

---

## 3. Detailed Slicing Rules

### Rule A: Bounded Call-Graph Traversal ($k=2$)
- Never dump an entire binary's function list.
- Generate call trees bounded to depth $k=2$ originating from the entrypoint or identified target exported function.
- Summarize leaf nodes with 1-line metadata: address, estimated instruction count, McCabe complexity.

### Rule B: Backward Cross-Reference (Xref) Slicing
Start slicing strictly from sensitive sink functions and trace backwards:
1. **Cryptographic Sinks:** `EVP_DecryptUpdate`, `CryptDecrypt`, `AES_*`, `MD5_Update`, `BCryptDecrypt`.
2. **Network I/O Sinks:** `connect`, `send`, `recv`, `HttpSendRequest`, `SSL_write`, `socket`.
3. **Process & Memory Sinks:** `system`, `execve`, `VirtualAlloc`, `mprotect`, `CreateProcess`.
4. **Validation Branches:** Conditional jumps comparing buffers against computed hash or key digests.

### Rule C: McCabe Cyclomatic Pruning
McCabe Complexity:
$$M = E - N + 2P$$
- Functions with $M=1$ (trivial getters, setters, trampoline jumps) are collapsed into one-line pseudo-signatures.
- Prune standard compiler scaffolding before presenting code to LLM:
  - Stack canary initialization (`fs:0x28`) and verification (`__stack_chk_fail`).
  - Standard frame pointer setup (`push rbp; mov rbp, rsp`).
  - Assertion checks and panic handler jumps.

### Rule D: Variable SSA Compaction
Convert messy compiler register spill/reload sequences into normalized, typed C variables:
- **Raw Decompiler Output:**
  ```c
  uVar1 = *(int *)(param_1 + 8);
  uVar2 = uVar1 ^ 0x5a;
  *(int *)(param_1 + 8) = uVar2;
  ```
- **Compacted Slice:**
  ```c
  param_1->key ^= 0x5A;
  ```
