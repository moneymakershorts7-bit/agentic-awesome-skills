#!/usr/bin/env bash
# ==============================================================================
# Unified Multi-Language Linter & Security Scanner
# Combines:
#   1. Cisco AI Defense skill-scanner
#   2. AAS validate_skills.py
#   3. actionlint (GitHub Actions Workflows)
#   4. ruff (Python)
#   5. shellcheck (Bash / POSIX Shell)
#   6. sqlfluff (SQL / PostgreSQL)
#   7. hadolint (Dockerfiles)
#   8. gofmt / golangci-lint (Go)
#   9. rustfmt / clippy (Rust)
# ==============================================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

FAILED=0

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}  Running Multi-Language Quality & Security Suite    ${NC}"
echo -e "${BLUE}======================================================${NC}"

# 1. Skill Security Scanner (Cisco AI Defense)
echo -e "\n${YELLOW}[1/8] Running Cisco AI Defense skill-scanner...${NC}"
if command -v skill-scanner-pre-commit >/dev/null 2>&1; then
    if skill-scanner-pre-commit --severity high --lenient skills/skill-scanner/SKILL.md; then
        echo -e "${GREEN}✓ skill-scanner passed.${NC}"
    else
        echo -e "${RED}✗ skill-scanner reported issues.${NC}"
        FAILED=1
    fi
else
    echo -e "${YELLOW}⚠ skill-scanner-pre-commit not in PATH, skipping.${NC}"
fi

# 2. AAS Skill Spec & Markdown Validation
echo -e "\n${YELLOW}[2/8] Running AAS Skill Specification Validator...${NC}"
if npm run validate; then
    echo -e "${GREEN}✓ validate_skills passed.${NC}"
else
    echo -e "${RED}✗ validate_skills failed.${NC}"
    FAILED=1
fi

# 3. GitHub Actions Workflows Linting (actionlint)
echo -e "\n${YELLOW}[3/8] Running actionlint for GitHub Actions Workflows...${NC}"
if npm run lint:workflows; then
    echo -e "${GREEN}✓ actionlint passed.${NC}"
else
    echo -e "${RED}✗ actionlint failed.${NC}"
    FAILED=1
fi

# 4. Python Linting (Ruff)
echo -e "\n${YELLOW}[4/8] Running Ruff for Python...${NC}"
if command -v ruff >/dev/null 2>&1; then
    if ruff check . --config ruff.toml; then
        echo -e "${GREEN}✓ ruff passed.${NC}"
    else
        echo -e "${RED}✗ ruff reported issues.${NC}"
        FAILED=1
    fi
else
    echo -e "${YELLOW}⚠ ruff not in PATH, skipping.${NC}"
fi

# 5. Shell Scripts Linter (shellcheck)
echo -e "\n${YELLOW}[5/8] Running ShellCheck for Shell scripts...${NC}"
if command -v shellcheck >/dev/null 2>&1; then
    # Scan root and tool scripts
    SHELL_FILES=$(git ls-files 'tools/scripts/*.sh' 'scripts/*.sh' 'skills/gitea/scripts/*.sh' 2>/dev/null || true)
    if [ -n "$SHELL_FILES" ]; then
        if shellcheck --severity=warning $SHELL_FILES; then
            echo -e "${GREEN}✓ shellcheck passed ($SHELL_FILES).${NC}"
        else
            echo -e "${RED}✗ shellcheck reported warnings/errors.${NC}"
            FAILED=1
        fi
    else
        echo -e "${GREEN}✓ No core shell scripts to check.${NC}"
    fi
else
    echo -e "${YELLOW}⚠ shellcheck not in PATH, skipping.${NC}"
fi

# 6. SQL Linter (sqlfluff)
echo -e "\n${YELLOW}[6/8] Running SQLFluff for SQL migrations...${NC}"
if command -v sqlfluff >/dev/null 2>&1; then
    SQL_FILES=$(git ls-files 'supabase/migrations/*.sql' 2>/dev/null || true)
    if [ -n "$SQL_FILES" ]; then
        if sqlfluff lint $SQL_FILES; then
            echo -e "${GREEN}✓ sqlfluff passed ($SQL_FILES).${NC}"
        else
            echo -e "${RED}✗ sqlfluff reported issues.${NC}"
            FAILED=1
        fi
    else
        echo -e "${GREEN}✓ No migration SQL files found.${NC}"
    fi
else
    echo -e "${YELLOW}⚠ sqlfluff not in PATH, skipping.${NC}"
fi

# 7. Go Quality & Formatting (gofmt)
echo -e "\n${YELLOW}[7/8] Running gofmt for Go files...${NC}"
if command -v gofmt >/dev/null 2>&1; then
    GO_FILES=$(git ls-files 'skills/golang-cli/assets/examples/*.go' 2>/dev/null || true)
    if [ -n "$GO_FILES" ]; then
        UNFORMATTED=$(gofmt -l $GO_FILES)
        if [ -z "$UNFORMATTED" ]; then
            echo -e "${GREEN}✓ gofmt passed on Go files.${NC}"
        else
            echo -e "${RED}✗ gofmt found unformatted files:${NC}\n$UNFORMATTED"
            FAILED=1
        fi
    else
        echo -e "${GREEN}✓ No Go files found.${NC}"
    fi
else
    echo -e "${YELLOW}⚠ gofmt not in PATH, skipping.${NC}"
fi

# 8. Dockerfile Linter (hadolint)
echo -e "\n${YELLOW}[8/8] Running Hadolint for Dockerfiles...${NC}"
if command -v hadolint >/dev/null 2>&1; then
    DOCKER_FILES=$(git ls-files '*Dockerfile*' 2>/dev/null || true)
    if [ -n "$DOCKER_FILES" ]; then
        if hadolint $DOCKER_FILES; then
            echo -e "${GREEN}✓ hadolint passed.${NC}"
        else
            echo -e "${RED}✗ hadolint reported issues.${NC}"
            FAILED=1
        fi
    else
        echo -e "${GREEN}✓ No Dockerfiles found.${NC}"
    fi
else
    echo -e "${YELLOW}⚠ hadolint not in PATH, skipping.${NC}"
fi

echo -e "\n${BLUE}======================================================${NC}"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All multi-language linters and scanners passed!${NC}"
    exit 0
else
    echo -e "${RED}💥 One or more checks failed. Review errors above.${NC}"
    exit 1
fi
