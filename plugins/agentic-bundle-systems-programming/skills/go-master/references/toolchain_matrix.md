# 38+ FOSS Go Engineering Toolchain Matrix

This reference documents the canonical Go FOSS toolchain integrated into `go-master` across 6 operational categories.

---

## 1. Concurrency, Race & Leak Detectors

| Tool | Binary | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`go-test-race`** | `go` | Concurrency | ThreadSanitizer data race detection | Pre-installed |
| **`uber-goleak`** | `go` | Concurrency | Goroutine leak detection post-teardown | `go get go.uber.org/goleak` |
| **`go-deadlock`** | `go` | Concurrency | Runtime lock order tracking and timeout | `go get github.com/sasha-s/go-deadlock` |
| **`synctest`** | `go` | Concurrency | Fake-clock concurrent scheduling (Go 1.24+) | Built-in |
| **`goker`** | `goker` | Concurrency | Concurrency bug benchmark and detection | `go install github.com/system-pclub/GCatch/cmd/gcatch@latest` |

---

## 2. Security & Vulnerability Scanners (SecSDLC / SCA)

| Tool | Binary | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`govulncheck`** | `govulncheck` | Security | Official Go vulnerability scanner with call-graph reachability | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| **`gosec`** | `gosec` | Security | AST security inspection (G101-G601) | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| **`trivy`** | `trivy` | Security | Container and dependency scanner | Package manager |
| **`cyclonedx-gomod`** | `cyclonedx-gomod` | Security | CycloneDX SBOM generation | `go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest` |
| **`gitleaks`** | `gitleaks` | Security | Secret exfiltration detection | `go install github.com/zricethezav/gitleaks/v8@latest` |
| **`osv-scanner`** | `osv-scanner` | Security | Google OSV advisory database | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| **`nancy`** | `nancy` | Security | Nexus IQ dependency scanning | `go install github.com/sonatype-nexus-community/nancy@latest` |

---

## 3. Static Analysis & Linters

| Tool | Binary | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`golangci-lint`** | `golangci-lint` | Linter | Meta-linter orchestrating 50+ analyzers | `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` |
| **`staticcheck`** | `staticcheck` | Linter | Advanced static analysis | `go install honnef.co/go/tools/cmd/staticcheck@latest` |
| **`revive`** | `revive` | Linter | Configurable golint drop-in replacement | `go install github.com/mgechev/revive@latest` |
| **`nilerr`** | `nilerr` | Linter | Catches returning nil error when err != nil | `go install github.com/gostaticanalysis/nilerr/cmd/nilerr@latest` |
| **`errcheck`** | `errcheck` | Linter | Identifies unchecked error returns | `go install github.com/kisielk/errcheck@latest` |
| **`ineffassign`** | `ineffassign` | Linter | Ineffectual assignment detection | `go install github.com/gordonklaus/ineffassign@latest` |
| **`gocyclo`** | `gocyclo` | Linter | Cyclomatic complexity (limit CC <= 10) | `go install github.com/fzipp/gocyclo/cmd/gocyclo@latest` |
| **`gocognit`** | `gocognit` | Linter | Cognitive complexity enforcement | `go install github.com/uudashr/gocognit/cmd/gocognit@latest` |
| **`govet`** | `go` | Linter | Official compiler AST vet inspection | Built-in |
| **`bodyclose`** | `bodyclose` | Linter | HTTP response body socket leaks | `go install github.com/timakin/bodyclose@latest` |
| **`unparam`** | `unparam` | Linter | Unused function parameter detector | `go install mvdan.cc/unparam@latest` |
| **`goconst`** | `goconst` | Linter | Repeated string literal extraction | `go install github.com/jgautheron/goconst/cmd/goconst@latest` |

---

## 4. Performance, Profiling & Allocation

| Tool | Binary | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`pprof`** | `go` | Performance | CPU, heap, and mutex profiler | Built-in |
| **`benchstat`** | `benchstat` | Performance | Statistical benchmark delta testing | `go install golang.org/x/perf/cmd/benchstat@latest` |
| **`trace`** | `go` | Performance | Goroutine scheduling and latency trace | Built-in |
| **`godebug`** | `go` | Performance | Runtime GC pause and sched tracing | Built-in |
| **`viewcore`** | `viewcore` | Performance | Memory core dump post-mortem | `go install golang.org/x/debug/cmd/viewcore@latest` |
| **`flamegraph`** | `go` | Performance | SVG flame graph stack visualizer | Built-in with pprof |

---

## 5. Reliability, Fuzzing & Mutation

| Tool | Binary | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`go-test-fuzz`** | `go` | Testing | Native coverage-guided fuzz testing | Built-in |
| **`go-mutesting`** | `go-mutesting` | Testing | Mutation test quality benchmarking | `go install github.com/zimmski/go-mutesting/cmd/go-mutesting@latest` |
| **`gotestsum`** | `gotestsum` | Testing | Standardized JUnit/TAP test runner | `go install gotest.tools/gotestsum@latest` |
| **`testify`** | `go` | Testing | Assertions and mock suites | `go get github.com/stretchr/testify` |
| **`quickcheck`** | `go` | Testing | Property-based generative testing | Built-in (testing/quick) |

---

## 6. Formatters, Cleanliness & Tooling

| Tool | Binary | Category | Purpose | Installation |
| :--- | :--- | :--- | :--- | :--- |
| **`gofmt`** | `gofmt` | Formatter | Canonical source formatting | Built-in |
| **`gofumpt`** | `gofumpt` | Formatter | Stricter opinionated formatting | `go install mvdan.cc/gofumpt@latest` |
| **`goimports`** | `goimports` | Formatter | Automated import hygiene and grouping | `go install golang.org/x/tools/cmd/goimports@latest` |
| **`go-mod-tidy`** | `go` | Tooling | Deterministic module tree sync | Built-in |
| **`go-mod-verify`** | `go` | Tooling | Cryptographic checksum validation | Built-in |
