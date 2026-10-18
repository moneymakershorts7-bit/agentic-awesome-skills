# Assembly Troubleshooting & Diagnostic Playbook

This runbook catalogs the standard low-level failure modes encountered during multi-architecture assembly engineering, along with exact diagnostic recipes and remediation steps.

---

## 1. General Protection Fault (`#GP(0)`) on Vector Load/Store (`vmovdqa`, `vmovaps`)

### Failure Pattern
- Runtime error: `Segmentation fault (core dumped)` or `#GP` trap on instruction `vmovdqa xmm, [ptr]` or `vmovaps ymm, [ptr]`.

### Root Cause
- Aligned vector instructions (`vmovdqa`, `vmovdqa64`, `vmovaps`) mandate that the memory address operand be strictly aligned to the vector size:
  - 16-byte alignment for XMM (SSE)
  - 32-byte alignment for YMM (AVX2)
  - 64-byte alignment for ZMM (AVX-512)
- If `(ptr % vector_bytes) != 0`, the hardware raises `#GP(0)`.

### Diagnostic Recipe
1. Inspect pointer alignment in GDB:
   ```gdb
   (gdb) print/x $rdi
   (gdb) print (uintptr_t)$rdi % 32
   ```
2. Remediation:
   - If the contract guarantees aligned memory, enforce buffer allocation via `aligned_alloc(32, size)` or `alignas(32)`.
   - If unaligned buffers must be supported, switch instruction to unaligned counterpart:
     - `vmovdqu` instead of `vmovdqa`
     - `vmovups` instead of `vmovaps`

---

## 2. Stack Misalignment Exception on `CALL` (`RSP % 16 != 0`)

### Failure Pattern
- Crash or corruption inside standard library routines (e.g. `printf`, `malloc`, `puts`) called from an assembly function, often crashing on an internal `movaps` instruction.

### Root Cause
- Per the System V AMD64 and AAPCS64 ABI, the stack pointer (`rsp` / `sp`) MUST be 16-byte aligned immediately prior to executing any `call` instruction.
- The `call` instruction pushes the 8-byte return address. Upon entry to the subroutine, `(rsp % 16) == 8`.
- If an odd number of 8-byte registers are pushed without compensating stack adjustment, `rsp` becomes misaligned before a nested call.

### Diagnostic Recipe
1. Add alignment assertion before the call:
   ```nasm
   ASSERT_RSP_ALIGNED_16
   ```
2. Ensure prologue balances pushes:
   ```nasm
   ; If pushing RBP (1 push = 8 bytes):
   push rbp
   mov  rbp, rsp
   sub  rsp, 8    ; Re-align to 16 bytes before any internal call
   ```
3. Or calculate exact frame padding: `sub rsp, (((local_bytes) + 15) & ~15) + 8`.

---

## 3. Control Protection Fault (`#CP`) on Function Entry (Intel CET)

### Failure Pattern
- Program terminates immediately upon indirect call (`call rax` or `call [vtable + offset]`) with signal `SIGSEGV` or `#CP`.

### Root Cause
- Hardware with Intel CET (Indirect Branch Tracking - IBT) enabled requires the first instruction executed at any indirect call/jump target to be `endbr64`.
- If the first opcode is not `0xF3 0x0F 0x1E 0xFA` (`endbr64`), the CPU aborts execution.

### Diagnostic Recipe
1. Disassemble the target symbol:
   ```bash
   objdump -d build/libasmmaster.a | grep -A2 "<asm_symbol>:"
   ```
2. Verify the first instruction:
   ```nasm
   global asm_my_routine
   asm_my_routine:
       endbr64       ; Mandatory Intel CET landing pad
       push rbp
       ...
   ```

---

## 4. Callee-Saved Register Corruption

### Failure Pattern
- Caller experiences corrupted local variables, invalid loop indices, or crashes after returning from an assembly routine.

### Root Cause
- Under System V AMD64, `rbx`, `rsp`, `rbp`, `r12`, `r13`, `r14`, `r15` are callee-saved (non-volatile).
- Under AAPCS64, `x19` through `x28`, `x29` (FP), and `d8` through `d15` are callee-saved.
- If an assembly subroutine overwrites any of these registers without preserving and restoring them, caller state is silently corrupted.

### Diagnostic Recipe
1. Audit clobber list in function header.
2. In prologue:
   ```nasm
   push rbx
   push r12
   push r13
   push r14
   push r15
   ```
3. In epilogue (in exact reverse order):
   ```nasm
   pop  r15
   pop  r14
   pop  r13
   pop  r12
   pop  rbx
   ```

---

## 5. Timing Leakage in Constant-Time Cryptographic Kernels

### Failure Pattern
- Dudect test fails with $|t| \ge 4.5$ on secret-dependent data.

### Root Cause
- A conditional jump (`jz`, `jnz`, `cbnz`) was executed whose condition depends on secret data.
- A table lookup indexed memory with secret data, introducing cache-timing latency variance.
- A variable-cycle instruction (`div`, `idiv`) was executed.

### Diagnostic Recipe
1. Scan assembly for conditional branches:
   ```bash
   objdump -d build/crypto_ct.o | grep -E "(je|jne|jz|jnz|js|jns|jg|jl|ja|jb)"
   ```
2. Replace conditional branches with constant-time bitwise masks:
   ```nasm
   ; Constant-time selection: cond ? a : b
   neg rdx
   xor rax, rsi
   and rax, rdx
   xor rax, rsi
   ```
