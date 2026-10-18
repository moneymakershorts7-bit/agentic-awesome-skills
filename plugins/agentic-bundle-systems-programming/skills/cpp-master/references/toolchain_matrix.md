# `cpp-master` 40+ Canonical FOSS C++ Toolchain Matrix

The `cpp-master` platform integrates and auto-detects 45 industry-standard FOSS tools across 6 operational categories:

## 1. Compilers, Build Systems & Package Managers

| Tool Name | Canonical Binary | Version Target | Primary Purpose | Execution Recipe |
| :--- | :--- | :--- | :--- | :--- |
| **GCC** | `gcc` / `g++` | GCC 14+ | GNU Compiler Collection C/C++ frontend | `g++ -std=c++23 -Wall -Wextra -Wpedantic -Werror main.cpp` |
| **Clang** | `clang` / `clang++` | Clang 18+ | LLVM Clang C/C++ frontend | `clang++ -std=c++23 -stdlib=libc++ main.cpp` |
| **CMake** | `cmake` | 3.28+ | Modern target-based meta-build system | `cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release` |
| **Ninja** | `ninja` | 1.11+ | Ultra-fast low-level build executor | `ninja -C build` |
| **Conan** | `conan` | 2.0+ | Enterprise multi-platform package manager | `conan install . --build=missing` |
| **vcpkg** | `vcpkg` | Latest | Microsoft cross-platform C/C++ package manager | `vcpkg install` |
| **Meson** | `meson` | 1.3+ | Fast, user-friendly Python-based build system | `meson setup builddir` |
| **ccache** | `ccache` | 4.8+ | Compiler cache for fast recompilation | `cmake -DCMAKE_CXX_COMPILER_LAUNCHER=ccache` |

---

## 2. Static Analysis, Linters & Architecture

| Tool Name | Canonical Binary | Primary Purpose | Execution Recipe |
| :--- | :--- | :--- | :--- |
| **Clang-Tidy** | `clang-tidy` | AST-based linter & static analyzer | `clang-tidy src/*.cpp -p build/ --warnings-as-errors=*` |
| **Cppcheck** | `cppcheck` | Zero false-positive bug & leak detector | `cppcheck --enable=all --error-exitcode=1 src/` |
| **IWYU** | `include-what-you-use` | Include hygiene optimizer | `include-what-you-use -p build/ src/main.cpp` |
| **SonarLint** | `sonarlint` | CLI & IDE code quality scanner | `sonarlint-cli` |
| **SonarQube** | `sonar-scanner` | Enterprise SecSDLC security scanner | `sonar-scanner` |
| **Flawfinder** | `flawfinder` | C/C++ security vulnerability detector | `flawfinder --minlevel=3 src/` |
| **Infer** | `infer` | Meta static analyzer for null derefs & race bugs | `infer run -- cmake --build build` |
| **Lizard** | `lizard` | Cyclomatic complexity analyzer (CC <= 10) | `lizard -C 10 include/ src/ tests/` |

---

## 3. Sanitizers & Dynamic Runtime Analysis

| Tool Name | Compiler Flag / Binary | Target Vulnerabilities | Invocation Recipe |
| :--- | :--- | :--- | :--- |
| **ASan** | `-fsanitize=address` | Buffer overflows, use-after-free, double-free | `cmake -B build -DCMAKE_CXX_FLAGS="-fsanitize=address"` |
| **UBSan** | `-fsanitize=undefined` | Integer overflow, null dereference, alignment | `cmake -B build -DCMAKE_CXX_FLAGS="-fsanitize=undefined"` |
| **TSan** | `-fsanitize=thread` | Data races, lock order inversion, deadlocks | `cmake -B build -DCMAKE_CXX_FLAGS="-fsanitize=thread"` |
| **MSan** | `-fsanitize=memory` | Uninitialized memory reads (Clang required) | `clang++ -fsanitize=memory -fsanitize-memory-track-origins` |
| **LSan** | `-fsanitize=leak` | Memory leaks at program termination | `cmake -B build -DCMAKE_CXX_FLAGS="-fsanitize=leak"` |
| **Valgrind** | `valgrind` | Deep heap diagnostics and cache simulation | `valgrind --leak-check=full --track-origins=yes ./bin` |

---

## 4. Testing, Mutation & Fuzzing

| Tool Name | Canonical Binary / Library | Primary Purpose | Execution Recipe |
| :--- | :--- | :--- | :--- |
| **Catch2** | Header/Library | Modern BDD unit testing for C++20 | `./build/bin/test_suite` |
| **GTest** | Google Test | Industry standard unit testing framework | `ctest --output-on-failure` |
| **GMock** | Google Mock | C++ mocking framework | Integrated in GTest targets |
| **doctest** | Header | Ultra-fast compile-time testing | `#include <doctest/doctest.h>` |
| **LibFuzzer** | `-fsanitize=fuzzer` | In-process, coverage-guided LLVM fuzzer | `clang++ -fsanitize=fuzzer,address fuzz_target.cpp` |
| **AFL++** | `afl-fuzz` | Evolutionary genetic fuzzer | `afl-fuzz -i corpus -o findings ./fuzz_target` |
| **Mull** | `mull-runner` | LLVM-based mutation testing (MSI >= 80%) | `mull-runner-18 ./build/bin/test_suite` |
| **Dextool Mutate** | `dextool` | C/C++ mutation testing tool | `dextool mutate --target test_suite` |
| **RapidCheck** | QuickCheck C++ | Generative property-based testing | `rc::check([](int a, int b) { ... });` |
| **FuzzTest** | Google FuzzTest | First-class C++ property fuzzing | `FUZZ_TEST(Suite, Target)` |

---

## 5. Profiling, Benchmarking & Performance

| Tool Name | Canonical Binary | Primary Purpose | Execution Recipe |
| :--- | :--- | :--- | :--- |
| **Google Benchmark** | `benchmark` | Microbenchmark library with nanosecond timer | `./benchmarks/run_benchmarks --benchmark_format=json` |
| **Linux Perf** | `perf` | CPU hardware performance counters | `perf record -F 99 -g -- ./build/bin/target` |
| **Hotspot** | `hotspot` | GUI for Linux perf flame graphs | `hotspot perf.data` |
| **Tracy** | `tracy` | Real-time nanosecond CPU/GPU profiler | `#include <tracy/Tracy.hpp>; ZoneScoped;` |
| **Heaptrack** | `heaptrack` | Fast lightweight heap allocation tracer | `heaptrack ./build/bin/target` |
| **Hyperfine** | `hyperfine` | CLI statistical benchmarking tool | `hyperfine --warmup 3 './bin1' './bin2'` |

---

## 6. Formatting, Documentation & Security

| Tool Name | Canonical Binary | Primary Purpose | Execution Recipe |
| :--- | :--- | :--- | :--- |
| **Clang-Format** | `clang-format` | AST deterministic code formatting | `clang-format -i src/*.cpp include/**/*.hpp` |
| **Doxygen** | `doxygen` | Source code documentation generator | `doxygen Doxyfile` |
| **Gitleaks** | `gitleaks` | Secret & private key credential scanner | `gitleaks detect --source . -v` |
| **CycloneDX Conan** | `cyclonedx-conan` | CycloneDX SBOM generator | `cyclonedx-conan . > sbom.json` |
| **Trivy** | `trivy` | Container image & filesystem vulnerability scanner | `trivy fs --severity HIGH,CRITICAL .` |
