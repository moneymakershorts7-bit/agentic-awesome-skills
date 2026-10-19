# Troubleshooting & Diagnostic Playbook

This runbook documents deterministic diagnostic patterns, error signatures, and verified remedies for common Shell and Bash systems programming pitfalls.

---

## 1. ShellCheck SC2086: Unquoted Variable Expansion
- **Error Signature**: `SC2086 (info): Double quote to prevent globbing and word splitting.`
- **Root Cause**: Unquoted parameter expansions (`$var` or `${var}`) undergo word splitting on `$IFS` and filename pathname expansion (globbing). If `var` contains spaces, newlines, or asterisks, arguments fragment into multiple tokens.
- **Diagnostic Command**:
  ```bash
  shellcheck -i SC2086 script.sh
  ```
- **Remedy**:
  ```bash
  # Vulnerable:
  cp $source $dest
  
  # Remediated:
  cp -- "${source}" "${dest}"
  ```
  *Note*: Always use `--` before target arguments when handling filenames that may begin with a dash (`-`).

---

## 2. ShellCheck SC2155: Masked Return Value in Local Declaration
- **Error Signature**: `SC2155 (warning): Declare and assign separately to avoid masking return values.`
- **Root Cause**: Builtin commands `local`, `export`, and `readonly` return exit status 0 even if the subshell command substitution inside them fails with a non-zero exit status. Under `set -e`, this masks fatal failures.
- **Diagnostic Command**:
  ```bash
  shellcheck -i SC2155 script.sh
  ```
- **Remedy**:
  ```bash
  # Vulnerable (masks failure of calculate_id):
  local my_id="$(calculate_id)"
  
  # Remediated (fails immediately under set -e):
  local my_id
  my_id="$(calculate_id)"
  readonly my_id
  ```

---

## 3. ShellCheck SC2046: Quote This to Prevent Word Splitting
- **Error Signature**: `SC2046 (warning): Quote this to prevent word splitting.`
- **Root Cause**: Unquoted command substitution `$(cmd)` causes output to split on IFS characters.
- **Diagnostic Command**:
  ```bash
  shellcheck -i SC2046 script.sh
  ```
- **Remedy**:
  ```bash
  # Vulnerable:
  files=$(ls *.txt)
  rm $files
  
  # Remediated (array in Bash):
  mapfile -t files < <(find . -maxdepth 1 -name '*.txt')
  rm -f -- "${files[@]}"
  ```

---

## 4. Concurrency: Lockfile TOCTOU & Stale Deadlocks
- **Error Signature**: `flock: 200: Resource temporarily unavailable` or race conditions between test and lock creation.
- **Root Cause**: Testing for lockfile existence (`if [ -f /tmp/lock ]; then ...`) before locking introduces a Time-of-Check to Time-of-Use (TOCTOU) race window. If a process crashes while holding an ad-hoc file lock, the lock remains stale indefinitely.
- **Diagnostic Command**:
  ```bash
  lsof /var/lock/bash-master.lock
  ```
- **Remedy**:
  Use atomic kernel-managed advisory locking via `flock` on an explicit file descriptor:
  ```bash
  exec 200>"/var/lock/service.lock"
  if ! flock -n 200; then
    printf 'Error: Concurrent instance already running\n' >&2
    exit 1
  fi
  # Lock is held for the lifetime of FD 200 and automatically released on exit/crash.
  ```

---

## 5. Subshell Pipeline Variable Loss
- **Error Signature**: Variable modified inside a `while` loop remains empty after the loop finishes.
- **Root Cause**: In standard POSIX shells and default Bash, each segment of a pipeline (`cat file | while read -r line; do ... done`) runs in a separate forked subshell. Any mutations to local variables inside the loop are lost when the subshell terminates.
- **Diagnostic Pattern**:
  ```bash
  count=0
  find . -type f | while read -r f; do count=$((count + 1)); done
  echo "Count: ${count}" # Outputs: Count: 0 !
  ```
- **Remedy**:
  Use process substitution or redirect the file directly into the loop in the parent process:
  ```bash
  # Option A: Redirect file into loop:
  count=0
  while IFS= read -r f; do
    count=$((count + 1))
  done < <(find . -type f)
  echo "Count: ${count}" # Outputs exact count in parent process.
  
  # Option B: Bash 4.2+ lastpipe:
  shopt -s lastpipe
  find . -type f | while read -r f; do count=$((count + 1)); done
  ```

---

## 6. Pipeline Early Termination (SIGPIPE / Exit Code 141)
- **Error Signature**: Pipeline fails with exit status 141 when piped to `head`, `sed 1q`, or early-closing consumer.
- **Root Cause**: Under `set -e -o pipefail`, if downstream consumer process closes its stdin (e.g. `head -n 5`), upstream producer receives `SIGPIPE` (signal 13), translating into exit code 128 + 13 = 141, triggering pipeline failure.
- **Diagnostic Command**:
  ```bash
  printf '%d\n' "$((141 - 128))" # Confirms Signal 13 (SIGPIPE)
  ```
- **Remedy**:
  Explicitly handle or mask expected SIGPIPE in streaming commands:
  ```bash
  # Mask SIGPIPE when consuming bounded slice:
  { generate_large_stream || [[ "$?" -eq 141 ]]; } | head -n 5
  ```

---

## 7. POSIX /bin/sh Portability (checkbashisms)
- **Error Signature**: `checkbashisms: possible bashism in script.sh: line X ($'...' or [[ ... ]] or ==)`
- **Root Cause**: Using Bash-exclusive extensions in scripts with shebang `#!/bin/sh` fails on strict POSIX environments (Debian/Ubuntu `dash`, Alpine `ash`, FreeBSD `sh`).
- **Remedy Matrix**:
  - Replace `[[ expr ]]` with `[ expr ]` or `test expr`.
  - Replace `==` in string test with single `=`.
  - Replace `function foo() { ... }` with standard `foo() { ... }`.
  - Replace `local` keyword (POSIX undefined) with clean variable scope conventions or prefixing.
  - Replace bash arrays with positional parameter shifting (`set -- "$@"`) or newline-delimited streams.
