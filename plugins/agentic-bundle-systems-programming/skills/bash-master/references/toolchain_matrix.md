# Exhaustive 38+ FOSS Shell Toolchain Matrix

The `bash-master` platform integrates and orchestrates 38+ battle-tested Free and Open Source (FOSS) tools across 6 distinct systems engineering categories.

---

## 1. Static Analysis, Linters & AST Analyzers
| Tool | Version / Purpose | Installation Recipe | Verification Pattern |
| :--- | :--- | :--- | :--- |
| **ShellCheck** | 0.10.0+ AST static analyzer | `apt install shellcheck` / `cabal install shellcheck` | `shellcheck --severity=style --enable=all script.sh` |
| **checkbashisms** | POSIX compliance checker | `apt install devscripts` | `checkbashisms -f -x script.sh` |
| **bashate** | OpenStack bash style linter | `pip install bashate` | `bashate -i E006,E040 script.sh` |
| **tree-sitter-bash** | AST grammar parser | `npm install tree-sitter-bash` / `cargo` | Parse AST trees deterministically |
| **devskim** | Microsoft IDE security scanner | `dotnet tool install -g Microsoft.DevSkim.CLI` | `devskim analyze script.sh` |
| **semgrep** | Semantic AST pattern matcher | `pip install semgrep` | `semgrep --config=p/bash script.sh` |
| **bear** | Compilation DB generator | `apt install bear` | Command-line tracing |
| **lizard** | Cyclomatic complexity analyzer | `pip install lizard` | `lizard -C 10 script.sh` |

---

## 2. Test Frameworks, Mocking & Assertions
| Tool | Version / Purpose | Installation Recipe | Verification Pattern |
| :--- | :--- | :--- | :--- |
| **Bats-Core** | 1.11.1+ TAP test runner | `git clone https://github.com/bats-core/bats-core.git && ./install.sh /usr/local` | `bats tests/` |
| **bats-assert** | Assertion primitives | `npm install -g bats-assert` or git submodule | `assert_success`, `assert_output` |
| **bats-support** | Test helper library | Git submodule in `test_helper/` | Test logging formatting |
| **bats-file** | Filesystem test assertions | Git submodule in `test_helper/` | `assert_file_exist` |
| **shunit2** | xUnit unit testing for shell | `apt install shunit2` | `shunit2 test_suite.sh` |
| **shellspec** | BDD test framework | `git clone https://github.com/shellspec/shellspec.git && make install` | `shellspec` |
| **kcov** | Code coverage analyzer | `apt install kcov` | `kcov coverage/ bats tests/` |
| **roundup** | Markdown-driven runner | `git clone https://github.com/bmizerany/roundup.git` | `roundup *.roundup` |

---

## 3. Formatters, Beautifiers & Minifiers
| Tool | Version / Purpose | Installation Recipe | Verification Pattern |
| :--- | :--- | :--- | :--- |
| **shfmt** | v3.14.1 Canonical formatter | `go install mvdan.cc/sh/v3/cmd/shfmt@latest` | `shfmt -d -i 2 -ci -bn script.sh` |
| **beautysh** | Python bash beautifier | `pip install beautysh` | `beautysh --indent-size 2 script.sh` |
| **shellman** | Snippet generator & formatter| `pip install shellman` | Generate templates |
| **bash-minifier** | Token minifier | `npm install -g bash-minifier` | Output minified distribution |

---

## 4. Security, Hardening & Secret Scanners
| Tool | Version / Purpose | Installation Recipe | Verification Pattern |
| :--- | :--- | :--- | :--- |
| **Gitleaks** | Secret & API key detector | `go install github.com/zricethezav/gitleaks/v8@latest` | `gitleaks detect --source=.` |
| **TruffleHog** | Git history secret scanner | `go install github.com/trufflesecurity/trufflehog/v3@latest` | `trufflehog filesystem .` |
| **Trivy** | Vulnerability / misconfig scan| `apt install trivy` | `trivy fs --severity HIGH,CRITICAL .` |
| **Grype** | SBOM vulnerability scanner | `apt install grype` | `grype dir:.` |
| **Syft** | SBOM generator | `apt install syft` | `syft dir:. -o spdx-json` |
| **apparmor_parser** | Mandatory access control | `apt install apparmor` | Profile compilation |
| **firejail** | SUID security sandbox | `apt install firejail` | `firejail --noprofile script.sh` |
| **bubblewrap** | Unprivileged container sandbox| `apt install bubblewrap` | `bwrap --ro-bind / / bash script.sh` |

---

## 5. Execution Engines, Profilers & Concurrency
| Tool | Version / Purpose | Installation Recipe | Verification Pattern |
| :--- | :--- | :--- | :--- |
| **Bash** | 5.2.21+ Primary shell | Default on modern Linux / Homebrew on macOS | `bash --version` |
| **dash** | POSIX /bin/sh standard | `apt install dash` | `dash script.sh` |
| **strace** | Syscall tracer & profiler | `apt install strace` | `strace -c -f bash script.sh` |
| **ltrace** | Dynamic library call tracer | `apt install ltrace` | `ltrace -c bash script.sh` |
| **flock** | util-linux atomic file locker| Default on Linux (`util-linux`) | `flock -x -w 10 200` |
| **timeout** | Coreutils process execution timer | Coreutils | `timeout --kill-after=5s 30s cmd` |
| **hyperfine** | Deterministic CLI benchmarker| `cargo install hyperfine` | `hyperfine 'bash script.sh'` |
| **parallel** | GNU job concurrency runner | `apt install parallel` | `parallel -j 4 ::: ...` |

---

## 6. Documentation, Specs & Cadence
| Tool | Version / Purpose | Installation Recipe | Verification Pattern |
| :--- | :--- | :--- | :--- |
| **pandoc** | Document converter | `apt install pandoc` | Convert markdown to manpages |
| **mandoc** | BSD manpage compiler | `apt install mandoc` | Validate groff output |
| **shdoc** | Docstring parser for shell | `git clone https://github.com/reconquest/shdoc.git` | `shdoc < script.sh` |
| **jq** | JSON query processor | `apt install jq` | Contract verification |
