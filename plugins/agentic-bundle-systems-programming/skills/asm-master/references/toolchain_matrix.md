# 38+ FOSS Assembly Enterprise Toolchain Matrix Guide

This guide catalogs the 38+ canonical FOSS tools across the 6 operational categories supported and integrated into `asm-master`.

---

## 1. Assemblers, Macro Processors & Assembler Frontends

| Tool | Binary | Target Arch | Primary Invocation Recipe | Description |
| :--- | :--- | :--- | :--- | :--- |
| **NASM** | `nasm` | x86, x86_64 | `nasm -f elf64 -Werror -Iinclude/ src.asm -o out.o` | Netwide Assembler: Industry standard Intel-syntax assembler |
| **YASM** | `yasm` | x86, x86_64 | `yasm -f elf64 -g dwarf2 src.asm -o out.o` | Modular assembler supporting NASM and GAS syntaxes |
| **GNU AS** | `as` | Multi-Arch | `as -march=armv8.5-a src.s -o out.o` | Canonical GNU assembler from GNU Binutils |
| **FASM** | `fasm` | x86, x86_64 | `fasm src.asm out.o` | Flat Assembler: Ultra-fast self-hosting macro assembler |
| **LLVM-MC** | `llvm-mc` | Multi-Arch | `llvm-mc -arch=x86-64 -filetype=obj src.s -o out.o` | LLVM machine code assembler and instruction explorer |
| **FASMG** | `fasmg` | Multi-Arch | `fasmg src.asm out.bin` | Flat Assembler G: Multi-architecture macro engine |

---

## 2. Disassemblers, Object Inspectors & Binary Utilities

| Tool | Binary | Invocation Recipe | Description |
| :--- | :--- | :--- | :--- |
| **objdump** | `objdump` | `objdump -d -M intel binary` | GNU disassembler with Intel/AT&T switch |
| **readelf** | `readelf` | `readelf -l -S -s binary` | ELF header, program segments, and symbol inspector |
| **nm** | `nm` | `nm -C -g binary` | Extracts symbol tables with demangling support |
| **size** | `size` | `size --format=SysV binary` | Analyzes section memory allocations (.text, .data, .bss) |
| **strip** | `strip` | `strip --strip-unneeded binary` | Discards debug symbols for production release binaries |
| **c++filt** | `c++filt` | `c++filt <mangled_symbol>` | Demangles low-level linker symbols |

---

## 3. Emulators, Virtualizers & Architectural Simulators

| Tool | Binary | Invocation Recipe | Description |
| :--- | :--- | :--- | :--- |
| **QEMU x86_64** | `qemu-x86_64` | `qemu-x86_64 ./binary` | User-mode emulation for x86_64 binaries |
| **QEMU AArch64** | `qemu-aarch64` | `qemu-aarch64 ./binary_arm64` | User-mode emulation for ARM64 binaries |
| **QEMU RISC-V 64** | `qemu-riscv64` | `qemu-riscv64 ./binary_rv64` | User-mode emulation for 64-bit RISC-V |
| **QEMU System** | `qemu-system-x86_64` | `qemu-system-x86_64 -kernel os.bin` | Full-system bare-metal virtualization |
| **Bochs** | `bochs` | `bochs -f bochsrc.txt` | Cycle-accurate x86 PC emulator with internal debugger |
| **Unicorn** | `unicorn` | `python3 -c "import unicorn"` | Lightweight multi-arch CPU emulator framework |

---

## 4. Debuggers, Tracers & Dynamic Binary Instrumentation

| Tool | Binary | Invocation Recipe | Description |
| :--- | :--- | :--- | :--- |
| **GDB** | `gdb` | `gdb -q -ex "layout asm" ./binary` | GNU Project Debugger with GEF / pwndbg |
| **LLDB** | `lldb` | `lldb ./binary` | LLVM multi-architecture debugger |
| **strace** | `strace` | `strace -f -e trace=all ./binary` | Traces system calls, arguments, and signal delivery |
| **ltrace** | `ltrace` | `ltrace -C ./binary` | Intercepts dynamic shared library calls |
| **Valgrind** | `valgrind` | `valgrind --tool=memcheck ./binary` | Memory error detector & instruction translation |
| **Radare2** | `radare2` | `r2 -d ./binary` | Advanced reverse engineering and disassembly framework |

---

## 5. Microarchitectural Profiling & Latency Analyzers

| Tool | Binary | Invocation Recipe | Description |
| :--- | :--- | :--- | :--- |
| **perf** | `perf` | `perf stat -e cycles,instructions,cache-misses ./bin` | Linux performance counters (IPC, stalls, branch miss) |
| **LLVM-MCA** | `llvm-mca` | `llvm-mca -mcpu=skylake src.s` | Static microarchitectural pipeline port simulator |
| **uops.info** | `uops` | Parse XML/JSON tables | Latency, throughput, and port breakdown database |
| **LIKWID** | `likwid-perfctr` | `likwid-perfctr -C 0 -g BRANCH ./binary` | Hardware performance counter monitoring tools |
| **Hyperfine** | `hyperfine` | `hyperfine --warmup 3 './asm_bin' './c_bin'` | Statistical comparative benchmarking tool |
| **Cachegrind** | `valgrind` | `valgrind --tool=cachegrind ./binary` | Cache and branch prediction simulator |

---

## 6. Binary Hardening, Linkers & Verification Tooling

| Tool | Binary | Invocation Recipe | Description |
| :--- | :--- | :--- | :--- |
| **ld** | `ld` | `ld -z noexecstack -z relro -z now` | GNU Linker with mandatory security flags |
| **ld.lld** | `ld.lld` | `ld.lld -O2 --as-needed` | High-performance LLVM linker |
| **mold** | `mold` | `mold -run gcc ...` | Modern high-speed multi-threaded linker |
| **checksec** | `checksec` | `checksec --file=./binary` | Checks NX, PIE, RELRO, Canary, and ASLR |
| **dudect** | `dudect` | Welch's t-test ($|t| < 4.5$) | Statistical timing leakage detector |
| **angr** | `angr` | Python symbolic execution engine | Formal state reachability and vulnerability analysis |
| **CBMC** | `cbmc` | `cbmc --bounds-check src.c` | Bounded model checker for formal verification |
| **flawfinder** | `flawfinder` | `flawfinder src/` | Static analysis for low-level memory handling flaws |
| **cve-bin-tool**| `cve-bin-tool` | `cve-bin-tool bin/` | Binary scanner identifying known CVEs in libraries |
