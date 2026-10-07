# GitHub Custom Secret Pattern Reference

## Pattern Specification Format
```yaml
# secret-scanning.yml
patterns:
  - name: "Internal Production API Token"
    regex: "acme_prod_[0-9a-zA-Z]{32}"
    confidence: "high"
    match_level: "exact"
```