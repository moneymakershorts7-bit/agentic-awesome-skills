# Troubleshooting & Diagnostic Playbook

This playbook provides actionable diagnostic runbooks for common failure patterns encountered during Ruby Master orchestration and verification.

---

## 1. YJIT Cache Invalidation & Inline Cache Churn

### Symptom
Runtime performance degrades under heavy load; YJIT runtime statistics show high `ratio_in_yjit` drops and elevated deoptimization counts.

### Diagnostic Command
```bash
ruby --yjit --yjit-stats -e '
  # Run workload
  puts RubyVM::YJIT.runtime_stats.slice(:code_region_size, :inline_code_size, :deopt_count)
'
```

### Remediation Recipe
1. **Locate Dynamic Method Definitions**: Grep for `alias_method`, `def`, or `define_method` invocations happening inside request handlers or loops.
2. **Freeze Ancestor Chains**: Ensure all module prepends/includes happen during application boot (initializers), never inside request lifecycles.
3. **Monomorphic Call Sites**: Avoid passing polymorphic object types to hot call sites where a uniform interface or `case ... in` pattern match can be used.

---

## 2. Packwerk Privacy & Dependency Violations

### Symptom
`bundle exec packwerk check` fails with `PrivacyViolation` or `DependencyViolation`.

### Failure Examples
- `PrivacyViolation: Cannot reference private constant Billing::InternalLedger from Web::Controllers`
- `DependencyViolation: packages/web depends on packages/billing but it is not declared in package.yml`

### Remediation Recipe
1. **Public API Exposure**: If the constant must be accessed externally, move it into the package's public directory (e.g., `packages/billing/app/public/billing/`) or declare it in `package.yml` under `public_path`.
2. **Declare Explicit Dependency**: If the cross-package boundary is intentional, open the calling package's `package.yml` and add the target package under `dependencies:`.
3. **Inversion of Control**: Introduce an event or interface contract to invert the dependency and decouple domain core from consumers.

---

## 3. Steep / RBS Static Type Errors

### Symptom
`bundle exec steep check` outputs diagnostic errors: `Steep::Diagnostic::Ruby::NoMethodError` or `IncompatibleAssignment`.

### Failure Example
```
app/domain/billing.rb:14:12: [error] Type `::Integer` does not have method `cents`
```

### Remediation Recipe
1. **Update RBS Signature**: Check the corresponding signature in `sig/app/domain/billing.rbs`. Ensure attribute names match the `Data.define` attributes.
2. **Exhaustive Matching**: If handling union types, ensure pattern matching `in` branches cover all variants or provide an explicit type assertion.
3. **Validate Signatures**: Run `bundle exec rbs validate` to catch syntax errors in RBS files before running Steep.

---

## 4. Brakeman Security Scanner Warnings

### Symptom
`bundle exec brakeman -z --no-pager` exits with non-zero status due to High or Medium severity findings.

### Failure Examples
- `SQL Injection: Near line 42: User.where("status = '#{params[:status]}'")`
- `Remote Code Execution: Near line 88: YAML.load(untrusted_str)`

### Remediation Recipe
1. **SQL Injection**: Replace string interpolation with parameterized binds:
   ```ruby
   # Replace:
   User.where("status = '#{params[:status]}'")
   # With:
   User.where(status: params[:status])
   ```
2. **Safe Deserialization**: Replace `YAML.load` with `YAML.safe_load`:
   ```ruby
   YAML.safe_load(str, permitted_classes: [Symbol, Date, Time, Integer, Float, String], aliases: false)
   ```
3. **Dynamic Evaluation**: Remove raw `send(params[:action])` and use an explicit hash lookup or allowlist.

---

## 5. Mutant Mutation Score Indicator (MSI) Below 80%

### Symptom
`bundle exec mutant run` reports a mutation score indicator below the 80% integration threshold.

### Diagnostic Recipe
1. **Identify Unkilled Mutants**: Review Mutant output for surviving mutants (`mutant-alive`). Surviving mutants point to unasserted edge cases.
2. **Boundary Testing**: Add explicit test cases for:
   - Empty collections (`[]`, `{}`)
   - Zero or negative values (`0`, `-1`)
   - Nil inputs and guard clause branches
3. **Deterministic Assertions**: Replace broad truthy assertions (`expect(result).to be_truthy`) with exact equality assertions (`expect(result).to eq(expected_value)`).
