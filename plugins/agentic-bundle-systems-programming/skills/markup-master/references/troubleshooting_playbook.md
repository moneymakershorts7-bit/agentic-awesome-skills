# Troubleshooting & Diagnostic Runbooks

This playbook details root causes, diagnostic recipes, and automated self-healing procedures for common markup, notation, and schema failures encountered during agentic verification.

---

## 1. WCAG 2.2 AA Accessibility & axe-core Failures

### A. Color Contrast Failure (`color-contrast`)
- **Symptom**: Insufficient color contrast ratio below required 4.5:1 baseline.
- **Root Cause**: Low luminance contrast between foreground text tokens and adjacent surface background.
- **Diagnostic Recipe**:
  1. Compute relative luminance using WCAG formula: L = 0.2126R + 0.7152G + 0.0722B.
  2. Increase foreground text contrast against card or body background token.
  3. Minimum contrast: 4.5:1 for regular text, 3.0:1 for large text (>= 18pt or >= 14pt bold).

### B. Missing Accessible Name (`button-name`, `label`)
- **Symptom**: Interactive button or form control lacking discernible accessible text.
- **Diagnostic Recipe**:
  - Add descriptive text inside button tags or provide `aria-label`.
  - For form inputs, pair with `<label for="...">` or apply `aria-label`.

---

## 2. XML External Entity (XXE) & Billion Laughs Attacks

### A. XXE External Entity Resolution
- **Symptom**: XML payload declaring external DTD entities (`SYSTEM` or `PUBLIC`).
- **Root Cause**: Insecure XML parser attempting to resolve external entity definitions.
- **Diagnostic Recipe**:
  1. Configure parser with `FEATURE_SECURE_PROCESSING`.
  2. Disallow external DTDs:
     ```python
     parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", True)
     ```
  3. Strip untrusted `<!DOCTYPE ...>` blocks prior to serialization.

### B. Billion Laughs / Exponential Expansion Bomb
- **Symptom**: Combinatorial entity expansion depth causing excessive resource consumption.
- **Diagnostic Recipe**:
  - Set hard limits on entity expansion: maximum expansion depth = 5, maximum node count = 10,000.
  - Employ `defusedxml` in Python or disable entity expansion in libxml2.

---

## 3. JSON Schema `additionalProperties` Leaks

- **Symptom**: Schema object definition omitting property boundaries.
- **Root Cause**: Permissive object definition allowing arbitrary unexpected fields.
- **Diagnostic Recipe**:
  1. Explicitly inject `"additionalProperties": false` into all object schema definitions.
  2. When using inheritance or composition (`allOf`, `$ref`), use `"unevaluatedProperties": false` (Draft 2020-12).

---

## 4. CSV Formula Injection (CWE-1236)

- **Symptom**: Cell content begins with formula prefix symbols (`=`, `+`, `-`, `@`, `|`, `%`).
- **Root Cause**: Spreadsheet software executes formula characters as calculation expressions.
- **Diagnostic Recipe**:
  1. Prepend an ASCII single quote (`'`) to any cell starting with formula symbols.
  2. Example: An entry starting with `=SUM(...)` becomes `'=SUM(...)`.
  3. Spreadsheets render the value as literal text without executing formula logic.

---

## 5. YAML "Norway Problem" & Unsafe Tags

- **Symptom**: Boolean ambiguity with values like `yes`, `no`, `on`, `off`, or unsafe tags.
- **Diagnostic Recipe**:
  1. Enforce strict double quoting on all boolean-like strings: `"yes"`, `"no"`, `"on"`, `"off"`, `"true"`, `"false"`.
  2. Prohibit non-standard tags; load strictly with `yaml.safe_load()`.
