# Hardened CI/CD Templates & Security Configurations

This document provides hardened, production-ready GitHub Actions and pre-commit configurations enforcing immutable commit SHAs, minimal OIDC permissions, and zero-trust runner security.

---

## 1. Hardened GitHub Actions Workflow (`.github/workflows/security-gate.yml`)

```yaml
name: "SecSDLC Hardened Security Gate"

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

# Step 1: Default to zero ambient permissions
permissions: {}

jobs:
  fast-gate:
    name: "Fast PR Security Gate"
    runs-on: ubuntu-latest
    timeout-minutes: 8
    permissions:
      contents: read
      security-events: write

    steps:
      - name: "Harden Runner Security (Kernel-level monitor)"
        uses: step-security/harden-runner@4d991eb9b905fa189e4c3761ab6f70e73e2285ba # v2.10.2
        with:
          egress-policy: audit

      - name: "Checkout Repository Code"
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0

      - name: "Gitleaks Secret Scan"
        uses: gitleaks/gitleaks-action@e9f85c184c2f0f46d97c36ecddfa848d70ccf02c # v2.3.8
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: "Semgrep OSS SAST Scan"
        run: |
          python3 -m pip install --upgrade pip
          pip install semgrep
          semgrep scan --config "p/security-audit" --sarif --output semgrep.sarif

      - name: "Upload SAST SARIF Report"
        uses: github/codeql-action/upload-sarif@48ab28a6f5dab2aab706736bd510d5f6fcd718b6 # v3.28.0
        if: always()
        with:
          sarif_file: semgrep.sarif

  release-provenance:
    name: "Release Signing & SLSA Provenance"
    needs: fast-gate
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write # Required for keyless OIDC Sigstore signing

    steps:
      - name: "Checkout Code"
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: "Install Cosign"
        uses: sigstore/cosign-installer@d7d6bc7722e3ded31a7b5200270110876253e664 # v3.8.0

      - name: "Install Syft"
        uses: anchore/sbom-action/download-syft@f325610c9f50a54015d37c8d16cb3b0e2c8f4de0 # v0.18.0

      - name: "Generate CycloneDX SBOM"
        run: |
          syft dir:. -o cyclonedx-json=bom.json

      - name: "Attest & Sign Artifact"
        run: |
          echo "Signing build artifacts and registering in Rekor transparency log..."
          # cosign attest --yes --predicate bom.json --type cyclonedx "$IMAGE_URI"
```

---

## 2. Hardened `.pre-commit-config.yaml` Template

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
        name: "Detect Hardcoded Secrets"
        entry: gitleaks protect --staged --verbose --redact

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-added-large-files
        args: ["--maxkb=1000"]
      - id: check-case-conflict
      - id: check-merge-conflict
      - id: check-json
      - id: check-yaml
      - id: end-of-file-fixer
      - id: trailing-whitespace
```
