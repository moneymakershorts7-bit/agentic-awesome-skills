# Dependabot Configuration Reference

## `.github/dependabot.yml` Example
```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    groups:
      dev-dependencies:
        patterns: ["*"]
        dependency-type: "development"
    labels:
      - "dependencies"
      - "security"
```