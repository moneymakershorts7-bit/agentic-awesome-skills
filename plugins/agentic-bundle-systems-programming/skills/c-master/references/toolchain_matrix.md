# 38+ FOSS C Enterprise Toolchain Matrix

This document provides a guide to the 38+ canonical FOSS tools across 6 operational categories, including their purpose, typical installation method on Debian/Ubuntu, and recommended invocation flags.

---

## 1. Compilers, Static Analyzers & Linters

| Tool | Purpose | Install Command | Canonical Invocation |
| :--- | :--- | :--- | :--- |
| **`gcc`** | GNU Compiler Collection with ISO C23 | `apt-get install gcc-14` | `gcc -std=c23 -Wall -Wextra -Wpedantic -Werror` |
| **`clang`** | LLVM C Compiler with C23 | `apt-get install clang-18` | `clang -std=c23 -Wall -Wextra -Wpedantic -Werror` |
| **`clang-tidy`** | AST-based C linter and analyzer | `apt-get install clang-tidy` | `clang-tidy src/*.c -- -Iinclude` |
| **`clang-format`** | Style formatter (LLVM/Google) | `apt-get install clang-format` | `clang-format -i include/*.h src/*.c` |
| **`cppcheck`** | Deep C bug and UB static analyzer | `apt-get install cppcheck` | `cppcheck --enable=all --error-exitcode=1 src/` |
| **`frama-c`** | Formal verification platform | `opam install frama-c` | `frama-c -eva src/*.c` |
| **`splint`** | Secure programming static checker | `apt-get install splint` | `splint -Iinclude src/*.c` |
| **`scan-build`** | Clang static analyzer wrapper | `apt-get install clang-tools` | `scan-build make` |

---

## 2. Dynamic Analyzers & Sanitizers

| Tool | Purpose | Compiler / Flag | Invocation Recipe |
| :--- | :--- | :--- | :--- |
| **`AddressSanitizer`** | Out-of-bounds & UAF detection | `-fsanitize=address` | `gcc -fsanitize=address -g -o test test.c` |
| **`UBSan`** | Undefined behavior detection | `-fsanitize=undefined` | `gcc -fsanitize=undefined -g -o test test.c` |
| **`MemorySanitizer`** | Uninitialized read detection | `-fsanitize=memory` | `clang -fsanitize=memory -g -o test test.c` |
| **`ThreadSanitizer`** | Data race detection | `-fsanitize=thread` | `gcc -fsanitize=thread -g -o test test.c` |
| **`LeakSanitizer`** | Heap memory leak detection | `-fsanitize=leak` | `gcc -fsanitize=leak -g -o test test.c` |
| **`valgrind`** | Memcheck userspace memory debugger | `apt-get install valgrind` | `valgrind --leak-check=full --error-exitcode=1 ./bin` |
| **`massif`** | Heap profiler via Valgrind | `apt-get install valgrind` | `valgrind --tool=massif ./bin` |
| **`bpftrace`** | High-speed eBPF system tracing | `apt-get install bpftrace` | `bpftrace -e 'tracepoint:syscalls:sys_enter_openat { ... }'` |

---

## 3. Fuzzing & Formal Verification

| Tool | Purpose | Install Command | Invocation Recipe |
| :--- | :--- | :--- | :--- |
| **`afl-fuzz`** | AFL++ coverage-guided fuzzer | `apt-get install afl++` | `afl-fuzz -i in -o out -- ./target @@` |
| **`libFuzzer`** | In-process evolutionary fuzzer | Built into Clang | `clang -fsanitize=fuzzer,address target.c` |
| **`honggfuzz`** | HW-counter coverage fuzzer | `apt-get install honggfuzz` | `honggfuzz -i in -- ./target` |
| **`cbmc`** | Bounded model checker | `apt-get install cbmc` | `cbmc --bounds-check --pointer-check src/*.c` |
| **`klee`** | Symbolic execution engine | Docker / source build | `klee target.bc` |
| **`mull`** | LLVM mutation testing framework | GitHub release | `mull-runner ./test_suite` |

---

## 4. Unit Testing, Mocking & Test Harnesses

| Tool | Purpose | Key Attributes |
| :--- | :--- | :--- |
| **`unity`** | Lightweight embedded C test framework | Zero heap allocation, pure macro assertions |
| **`cmocka`** | Enterprise C test framework with mocks | Mock functions, exception handling simulation |
| **`criterion`** | Modern cross-platform test framework | Subtests, parameterized tests, test suites |
| **`check`** | Isolated process-based C test runner | Forking architecture isolates test crashes |
| **`fff`** | Fake Function Framework | Pure C header-only mock generator |

---

## 5. Performance Profiling, Tracing & Microbenchmarking

| Tool | Purpose | Invocation Recipe |
| :--- | :--- | :--- |
| **`perf`** | Linux hardware PMU profiler | `perf record -g ./bin && perf report` |
| **`gprof`** | GNU call graph execution profiler | Compile with `-pg`, run `./bin`, analyze `gmon.out` |
| **`cachegrind`** | Cache miss & branch prediction profiler | `valgrind --tool=cachegrind ./bin` |
| **`callgrind`** | Function call graph generator | `valgrind --tool=callgrind ./bin` |
| **`hyperfine`** | High-precision statistical CLI benchmarking | `hyperfine --warmup 3 './bin'` |
| **`hotspot`** | Linux perf visualization GUI | `hotspot perf.data` |

---

## 6. Build Systems, Dependency & Workspace Hygiene

| Tool | Purpose | Invocation Recipe |
| :--- | :--- | :--- |
| **`cmake`** | Meta-build system (3.28+) | `cmake -B build -G Ninja -DCMAKE_C_STANDARD=23` |
| **`ninja`** | Ultra-fast execution engine | `ninja -C build` |
| **`make`** | Standard GNU Make build tool | `make -j$(nproc)` |
| **`bear`** | Generates compile_commands.json | `bear -- make` |
| **`include-what-you-use`** | Header dependency pruning | `iwyu -Iinclude src/*.c` |
| **`flawfinder`** | Lexical vulnerability scanner | `flawfinder --minlevel=1 src/` |
| **`pkg-config`** | Library flag resolution | `pkg-config --cflags --libs libssl` |
