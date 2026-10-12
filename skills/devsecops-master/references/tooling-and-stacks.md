# DevSecOps Tooling Matrix Across Tech Stacks

This matrix defines the standard, deterministic open-source and industry-standard security tools for each layer of the SecSDLC across diverse programming ecosystems.

---

## 1. Stack Detection Heuristics

The audit engine examines project root markers to automatically activate the relevant tools:

| Marker Files | Tech Stack | Primary Linters & SAST | Dependency & SCA | Container / IaC |
| :--- | :--- | :--- | :--- | :--- |
| `package.json`, `pnpm-lock.yaml`, `bun.lock` | **Node / TypeScript** | ESLint (`eslint-plugin-security`), Biome | Trivy FS, npm audit, OSV-Scanner | Hadolint, Trivy Image |
| `pyproject.toml`, `requirements.txt`, `Pipfile` | **Python** | Ruff (`S` rules), Bandit, Semgrep | pip-audit, Trivy FS, OSV-Scanner | Hadolint, Trivy Image |
| `go.mod`, `go.sum` | **Go** | GoSec, Staticcheck, Semgrep | Trivy FS, govulncheck | Hadolint, Trivy Image |
| `Cargo.toml`, `Cargo.lock` | **Rust** | Clippy (`-D warnings`), Semgrep | cargo-audit, Trivy FS | Hadolint, Trivy Image |
| `pom.xml`, `build.gradle`, `build.gradle.kts` | **Java** | SpotBugs (FindSecBugs), Semgrep | Trivy FS, OWASP Dep-Check | Hadolint, Trivy Image |
| `*.csproj`, `*.sln` | **C# / .NET** | SecurityCodeScan.VS2019, Roslyn | Trivy FS, dotnet list package --vulnerable | Hadolint, Trivy Image |
| `Dockerfile`, `docker-compose.yml` | **Containerization** | Hadolint, Dockle | Trivy Image, Grype | CIS Docker Benchmark |
| `*.tf`, `*.tfvars`, `terragrunt.hcl` | **Terraform / IaC** | Checkov, Trivy config, KICS | Trivy IaC | CIS Cloud Benchmarks |
| `SKILL.md` | **AI Agent Skills** | Skillspector, Skill-Inspector | Skill-Scanner AST | Allowed-tools restriction |

---

## 2. Universal Tooling by SecSDLC Layer

### 2.1 Secret Scanning
* **Gitleaks (Go-based, ultra-fast):**
  ```bash
  # Pre-commit staged check (< 1 sec)
  gitleaks protect --staged --verbose --redact

  # CI pull request diff scan
  gitleaks detect --log-opts="origin/main..HEAD" --verbose --redact
  ```
* **TruffleHog (Active API verification):**
  ```bash
  trufflehog git file://. --since-commit HEAD~1 --only-verified --fail
  ```

### 2.2 Static Application Security Testing (SAST)
* **Semgrep OSS (Polyglot Semantic Analysis):**
  ```bash
  # Scan using security-audit ruleset outputting standard SARIF
  semgrep scan --config "p/security-audit" --config "p/secrets" --sarif --output semgrep.sarif
  ```
* **Language-Specific Invocation:**
  - **Python:** `bandit -r src/ -f sarif -o bandit.sarif` and `ruff check src/ --select S`
  - **Go:** `gosec -fmt=sarif -out=gosec.sarif ./...`
  - **Rust:** `cargo audit`

### 2.3 Software Composition Analysis (SCA)
* **Trivy (Filesystem Mode):**
  ```bash
  trivy fs --scanners vuln --severity HIGH,CRITICAL --format sarif -o trivy-deps.sarif .
  ```
* **OSV-Scanner (Google Vulnerability DB):**
  ```bash
  osv-scanner scan --format=sarif --output=osv.sarif .
  ```

### 2.4 Infrastructure as Code (IaC) & Container Security
* **Checkov:**
  ```bash
  checkov -d ./infra --output sarif --output-file-path checkov.sarif --framework terraform,kubernetes,dockerfile
  ```
* **Hadolint (Dockerfile AST Linter):**
  ```bash
  hadolint Dockerfile -f sarif > hadolint.sarif
  ```
* **Trivy Image Scan:**
  ```bash
  trivy image --severity HIGH,CRITICAL --format sarif -o trivy-image.sarif myapp:latest
  ```

### 2.5 Software Bill of Materials (SBOM) & Signing
* **Syft (CycloneDX Generation):**
  ```bash
  syft dir:. -o cyclonedx-json=bom.json
  ```
* **Cosign (Keyless Signing via OIDC):**
  ```bash
  cosign sign --yes "$IMAGE_DIGEST"
  ```
* **Cosign Verification:**
  ```bash
  cosign verify \
    --certificate-identity-regexp "^https://github.com/my-org/my-repo/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$IMAGE_DIGEST"
  ```

### 2.6 Dynamic Application Security Testing (DAST)
* **OWASP ZAP (Automation Framework):**
  ```bash
  zap.sh -cmd -autorun zap-config.yaml
  ```
* **Nuclei (Targeted Vulnerability Engine):**
  ```bash
  nuclei -u https://staging.internal -t cves/ -t misconfiguration/ -sarif-export nuclei.sarif
  ```

### 2.7 AI Agent & Skill Security
* **Skillspector (CLI / MCP):**
  ```bash
  skillspector scan --path ./skills --format sarif --output skillspector.sarif
  ```
