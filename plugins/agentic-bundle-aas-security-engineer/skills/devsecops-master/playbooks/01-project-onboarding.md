# Playbook 01: Project Onboarding & Baseline SecSDLC Audit

This playbook guides an engineer through onboarding a new or existing repository into the SecSDLC framework.

---

## Step 1: Run the Deterministic Audit Tool
Execute the bundled audit utility against the target repository root:
```bash
python3 /path/to/devsecops-master/scripts/devsecops_audit.py . --format markdown
```
The script evaluates:
1. Detected languages and application frameworks.
2. Secret scanning configuration (`.gitleaks.toml`, pre-commit hooks).
3. SAST & linter configurations (`ruff.toml`, `.eslintrc*`, `semgrep.yml`).
4. Dependency lockfiles & vulnerability scanner setup.
5. Containerization security (`Dockerfile` running as non-root, minimal base image).
6. IaC security (`checkov` / `trivy` setup for Terraform or Helm).
7. CI/CD workflow security (immutable action commit SHA pinning, restrictive token permissions).
8. Accidental exposure of unignored secret files (`.env`, `.pem`, `id_rsa`).

---

## Step 2: Establish Risk Tier & Branch Protection
1. Assign the repository to an asset tier (Tier 0, Tier 1, or Tier 2).
2. Configure GitHub / GitLab branch protection on `main`:
   - Require pull request before merging.
   - Require at least 1 (or 2 for Tier 0) approving reviews.
   - Dismiss stale pull request approvals when new commits are pushed.
   - Require status checks to pass before merging:
     - `fast-gate` (SAST, Secrets, SCA).
     - `test-suite`.
   - Require signed commits.

---

## Step 3: Install Workstation Pre-Commit Guardrails
1. Create or update `.pre-commit-config.yaml` using the template from [`references/ci-cd-hardening-templates.md`](../references/ci-cd-hardening-templates.md).
2. Install the hooks locally:
   ```bash
   pre-commit install
   ```
3. Run an initial baseline scan across all files:
   ```bash
   pre-commit run --all-files
   ```

---

## Step 4: Add the Hardened GitHub Actions Security Workflow
1. Copy the hardened workflow from [`references/ci-cd-hardening-templates.md`](../references/ci-cd-hardening-templates.md) to `.github/workflows/security-gate.yml`.
2. Run the pipeline integrity checker:
   ```bash
   python3 /path/to/devsecops-master/scripts/verify_pipeline_integrity.py .
   ```
3. Commit and submit a PR to verify that checks execute cleanly in under 8 minutes.
