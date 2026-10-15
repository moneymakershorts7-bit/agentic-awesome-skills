# GitHub Actions Hardening Checklist

## Secure Workflow Template
```yaml
name: Secure Build
on: [push, pull_request]

permissions: {} # Default to zero permissions

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Checkout Code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      
      - name: Run Hardened Step
        env:
          TITLE: ${{ github.event.issue.title }}
        run: |
          echo "Safe processing of context variable"
          python -c "import os; print(len(os.environ['TITLE']))"
```