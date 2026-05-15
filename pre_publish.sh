#!/usr/bin/env bash
# =============================================================================
# LeightonSec Pre-Publish Quality Gate v1.0
# Usage: bash pre_publish.sh [path/to/repo]
# Runs automated checks mapped to the LeightonSec checklist.
# Judgment-only items are printed as manual reminders at the end.
# =============================================================================

set -euo pipefail

REPO="${1:-.}"
REPO="$(cd "$REPO" && pwd)"
PASS=0
FAIL=0
WARN=0
SKIP=0

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

pass()  { echo -e "  ${GREEN}✓${NC} $1"; ((PASS++))  || true; }
fail()  { echo -e "  ${RED}✗${NC} $1"; ((FAIL++))  || true; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $1"; ((WARN++))  || true; }
skip()  { echo -e "  ${DIM}–${NC} $1 ${DIM}(skipped — tool not installed)${NC}"; ((SKIP++)) || true; }
header(){ echo -e "\n${BOLD}${CYAN}[$1]${NC}"; }
manual(){ echo -e "  ${DIM}☐${NC} $1"; }

cmd_exists() { command -v "$1" &>/dev/null; }

# Common --exclude-dir flags reused across all grep/find scans
GREP_EXCL=(
  --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=__pycache__
  --exclude-dir=venv --exclude-dir=.venv --exclude-dir=site-packages
)

echo ""
echo -e "${BOLD}LeightonSec Quality Gate${NC} ${DIM}v1.0${NC}"
echo -e "${DIM}Repo: $REPO${NC}"
echo -e "${DIM}$(date '+%Y-%m-%d %H:%M')${NC}"
echo "─────────────────────────────────────────────"

cd "$REPO"

# =============================================================================
# 1. SECRETS & CREDENTIALS
# =============================================================================
header "1/8 · Secrets & credentials"

# Hardcoded secrets in working tree
if cmd_exists gitleaks; then
  _GL_CFG=$(mktemp /tmp/gitleaks-cfg-XXXXXX.toml)
  cat > "$_GL_CFG" <<'GITLEAKS_TOML'
title = "quality-gate"
[extend]
useDefault = true
[[allowlists]]
description = "Exclude vendored dependencies and virtual environments"
paths = ["venv", "\\.venv", "node_modules", "site-packages"]
GITLEAKS_TOML
  if gitleaks detect --source . --no-git --config "$_GL_CFG" 2>/dev/null; then
    pass "gitleaks — no secrets detected in working tree"
  else
    fail "gitleaks — potential secrets found in working tree (run: gitleaks detect --source . --no-git)"
  fi
  rm -f "$_GL_CFG"
elif cmd_exists trufflehog; then
  if trufflehog filesystem . --no-update --fail 2>/dev/null; then
    pass "trufflehog — no secrets detected"
  else
    fail "trufflehog — potential secrets found"
  fi
else
  # Fallback: grep
  SECRET_HITS=$(grep -rniE '(api_key|apikey|secret|password|token|private_key)\s*=\s*["\x27][^"\x27]{6,}' \
    --include="*.py" --include="*.js" --include="*.ts" --include="*.env" \
    "${GREP_EXCL[@]}" \
    . 2>/dev/null | grep -v "example\|dummy\|your_\|<\|TODO" || true)
  if [ -z "$SECRET_HITS" ]; then
    pass "grep fallback — no obvious hardcoded secrets"
  else
    fail "grep fallback — possible hardcoded secrets:\n$SECRET_HITS"
  fi
  warn "Install gitleaks or trufflehog for thorough scanning (brew install gitleaks)"
fi

# .env committed
if git ls-files | grep -qE '^\.env$'; then
  fail ".env file is tracked by git — remove and add to .gitignore"
else
  pass ".env not tracked by git"
fi

# .gitignore covers .env
if [ -f ".gitignore" ] && grep -q '\.env' .gitignore; then
  pass ".gitignore covers .env"
else
  fail ".gitignore missing — or .env not in .gitignore"
fi

# Secrets in commit history
HISTORY_HITS=$(git log -p --all -- ':(exclude)tests/' 2>/dev/null | \
  grep -iE '^\+.*(api_key|apikey|secret|password|token|private_key)\s*=\s*["\x27][^"\x27]{6,}' | \
  grep -v "example\|dummy\|your_\|<\|TODO" || true)
if [ -z "$HISTORY_HITS" ]; then
  pass "Commit history — no obvious secrets found"
else
  fail "Commit history — possible secrets in git log:\n$(echo "$HISTORY_HITS" | head -5)"
fi

# =============================================================================
# 2. README QUALITY
# =============================================================================
header "2/8 · README quality"

README_FILE=""
for f in README.md readme.md README.rst README; do
  [ -f "$f" ] && README_FILE="$f" && break
done

if [ -z "$README_FILE" ]; then
  fail "No README file found"
else
  pass "README exists ($README_FILE)"
  README_CONTENT="$(cat "$README_FILE")"

  # Version number
  if echo "$README_CONTENT" | grep -qiE 'v[0-9]+\.[0-9]+'; then
    pass "README — version number present"
  else
    warn "README — no version number found (add e.g. v0.1.0)"
  fi

  # Ethical use / authorised testing
  if echo "$README_CONTENT" | grep -qiE 'authoris|authoriz|legal|permission|responsible|ethical|testing only'; then
    pass "README — ethical use / authorised testing disclaimer present"
  else
    warn "README — no ethical use disclaimer found (required for network/PCAP tools)"
  fi

  # Limitations section
  if echo "$README_CONTENT" | grep -qiE 'limitation|known issue|caveat|not support|out of scope'; then
    pass "README — limitations or known issues section present"
  else
    warn "README — no limitations section found"
  fi

  # Scope / what it doesn't do
  if echo "$README_CONTENT" | grep -qiE 'not design|not intend|out of scope|does not|scope'; then
    pass "README — scope boundaries mentioned"
  else
    warn "README — scope boundaries not explicitly stated"
  fi

  # License
  if [ -f "LICENSE" ] || [ -f "LICENSE.md" ] || [ -f "LICENSE.txt" ]; then
    pass "LICENSE file present"
  else
    warn "No LICENSE file — add MIT or similar for portfolio credibility"
  fi
fi

# =============================================================================
# 3. CODE QUALITY & SECURITY
# =============================================================================
header "3/8 · Code quality & security"

# Bandit — scan only git-tracked Python files to avoid venv/third-party noise
if cmd_exists bandit; then
  BANDIT_PY=$(git ls-files '*.py' 2>/dev/null || true)
  if [ -n "$BANDIT_PY" ]; then
    BANDIT_OUT=$(echo "$BANDIT_PY" | xargs bandit -ll -q 2>/dev/null || true)
  else
    BANDIT_OUT=""
  fi
  if [ -z "$BANDIT_OUT" ]; then
    pass "bandit — no medium/high severity issues"
  else
    fail "bandit — issues found:\n$(echo "$BANDIT_OUT" | head -10)"
  fi
else
  skip "bandit (pip install bandit)"
fi

# Semgrep
if cmd_exists semgrep; then
  if semgrep --config=auto --quiet --error . 2>/dev/null; then
    pass "semgrep — no issues"
  else
    fail "semgrep — issues found (run: semgrep --config=auto .)"
  fi
else
  skip "semgrep (brew install semgrep)"
fi

# Shell injection — subprocess string usage in Python
SH_INJECT=$(grep -rn "subprocess\.\(run\|call\|Popen\|check_output\)" \
  --include="*.py" "${GREP_EXCL[@]}" \
  . 2>/dev/null | grep -v "#" | grep "shell=True\|f\"\|f'" || true)
if [ -z "$SH_INJECT" ]; then
  pass "No obvious shell injection risks (shell=True + f-string)"
else
  warn "Possible shell injection — review these lines:\n$SH_INJECT"
fi

# 0.0.0.0 binding
BIND_HITS=$(grep -rn "0\.0\.0\.0" --include="*.py" --include="*.js" --include="*.ts" \
  "${GREP_EXCL[@]}" . 2>/dev/null || true)
if [ -z "$BIND_HITS" ]; then
  pass "No 0.0.0.0 binding found"
else
  warn "0.0.0.0 binding detected — intentional?\n$BIND_HITS"
fi

# CVE check
if cmd_exists pip-audit && [ -f "requirements.txt" ]; then
  if pip-audit -r requirements.txt 2>/dev/null; then
    pass "pip-audit — no known CVEs in requirements.txt"
  else
    fail "pip-audit — vulnerable dependencies found (run: pip-audit -r requirements.txt)"
  fi
elif cmd_exists pip-audit; then
  skip "pip-audit — no requirements.txt (nothing to audit)"
elif cmd_exists npm && [ -f "package.json" ]; then
  AUDIT_OUT=$(npm audit --audit-level=high 2>/dev/null || true)
  if echo "$AUDIT_OUT" | grep -q "found 0"; then
    pass "npm audit — no high/critical CVEs"
  else
    fail "npm audit — vulnerabilities found:\n$(echo "$AUDIT_OUT" | tail -5)"
  fi
else
  skip "pip-audit / npm audit (pip install pip-audit)"
fi

# =============================================================================
# 4. TESTS
# =============================================================================
header "4/8 · Tests"

TEST_FILES=$(find . \
    \( -name "venv" -o -name ".venv" -o -name "node_modules" \
       -o -name "__pycache__" -o -name ".git" -o -name "site-packages" \) -prune \
    -o \( -name "test_*.py" -o -name "*_test.py" -o -name "*.test.js" -o -name "*.spec.js" \) -print \
    2>/dev/null || true)

if [ -z "$TEST_FILES" ]; then
  fail "No test files found — non-negotiable for portfolio credibility"
else
  pass "Test files present: $(echo "$TEST_FILES" | wc -l | tr -d ' ') file(s)"

  # Prefer repo venv pytest so the right dependencies are available
  if [ -f "$REPO/venv/bin/pytest" ]; then
    PYTEST_CMD="$REPO/venv/bin/pytest"
  elif [ -f "$REPO/.venv/bin/pytest" ]; then
    PYTEST_CMD="$REPO/.venv/bin/pytest"
  elif cmd_exists pytest; then
    PYTEST_CMD="pytest"
  else
    PYTEST_CMD=""
  fi

  if [ -n "$PYTEST_CMD" ]; then
    echo -e "  ${DIM}Running pytest...${NC}"
    if "$PYTEST_CMD" --tb=short -q 2>/dev/null; then
      pass "pytest — all tests pass"
    else
      fail "pytest — tests failing (run: pytest --tb=short for details)"
    fi
  elif cmd_exists python3 && [ -f "pytest.ini" -o -f "setup.cfg" -o -f "pyproject.toml" ]; then
    skip "pytest not found but config exists (pip install pytest)"
  else
    skip "pytest not found (pip install pytest)"
  fi
fi

# =============================================================================
# 5. GIT HYGIENE
# =============================================================================
header "5/8 · Git hygiene"

# .gitignore exists
if [ -f ".gitignore" ]; then
  pass ".gitignore present"
  # Common patterns
  for pattern in "__pycache__" "*.pyc" ".DS_Store" "node_modules" ".venv" "venv"; do
    if grep -q "$pattern" .gitignore; then
      : # fine
    else
      warn ".gitignore missing pattern: $pattern"
    fi
  done
else
  fail ".gitignore missing"
fi

# Large files committed
LARGE=$(git ls-files | xargs -I{} git ls-tree -r HEAD --long -- {} 2>/dev/null | \
  awk '$4 > 5000000 {print $5, $4/1000000 "MB"}' || true)
if [ -z "$LARGE" ]; then
  pass "No large files (>5MB) committed"
else
  warn "Large files in repo:\n$LARGE"
fi

# Lazy commit messages
LAZY=$(git log --oneline -20 2>/dev/null | grep -iE '^\w+ (fix|update|stuff|changes|misc|wip|test|asdf|temp)$' || true)
if [ -z "$LAZY" ]; then
  pass "Recent commit messages look meaningful"
else
  warn "Lazy commit messages detected:\n$LAZY"
fi

# __pycache__ tracked
if git ls-files | grep -q "__pycache__"; then
  fail "__pycache__ tracked by git — add to .gitignore and remove"
else
  pass "__pycache__ not tracked"
fi

# =============================================================================
# 6. PUBLIC EXPOSURE REVIEW
# =============================================================================
header "6/8 · Public exposure review"

# Bastion / BSV leakage
BASTION_HITS=$(grep -rniE 'bastion|bsv|teranode|metanet|gala.node|bastionprotocol' \
  "${GREP_EXCL[@]}" --exclude="pre_publish.sh" \
  . 2>/dev/null || true)
if [ -z "$BASTION_HITS" ]; then
  pass "No Bastion / BSV references found"
else
  fail "Bastion/BSV references detected — remove before publishing:\n$(echo "$BASTION_HITS" | head -5)"
fi

# Internal hostnames / IPs (private ranges)
IP_HITS=$(grep -rniE '(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.md" --include="*.env*" \
  "${GREP_EXCL[@]}" . 2>/dev/null || true)
if [ -z "$IP_HITS" ]; then
  pass "No private IP addresses found"
else
  warn "Private IP addresses found — intentional?\n$IP_HITS"
fi

# =============================================================================
# 7. OUTPUT & RUNTIME SAFETY
# =============================================================================
header "7/8 · Output & runtime safety"

# SIGINT / cleanup handling in Python
SIGINT_CHECK=$(grep -rn "signal\|atexit\|KeyboardInterrupt" \
  --include="*.py" "${GREP_EXCL[@]}" \
  . 2>/dev/null || true)
if [ -n "$SIGINT_CHECK" ]; then
  pass "Signal/cleanup handling found"
else
  warn "No SIGINT/cleanup handling detected — consider handling KeyboardInterrupt for network/file tools"
fi

# Writes to /tmp without cleanup
TMP_HITS=$(grep -rn "/tmp/" --include="*.py" --include="*.js" --include="*.sh" \
  "${GREP_EXCL[@]}" --exclude="pre_publish.sh" . 2>/dev/null | grep -v "#\|test_\|example" || true)
if [ -z "$TMP_HITS" ]; then
  pass "No unmanaged /tmp writes detected"
else
  warn "/tmp usage found — ensure cleanup on exit:\n$TMP_HITS"
fi

# =============================================================================
# 8. MANUAL CHECKLIST (judgment items)
# =============================================================================
header "8/8 · Manual checks (your judgment required)"
echo -e "  ${DIM}These cannot be automated. Review before pushing.${NC}\n"
manual "README explains the tool clearly in the first two sentences"
manual "README states what the tool is NOT designed to handle (scope boundaries)"
manual "Usage examples tested manually — accurate and run without modification"
manual "No false capability claims — tool only claims what it actually does"
manual "Nothing in repo ties back to Bastion Protocol, BSV, or private projects (visual scan)"
manual "No personal info: employer, home IP, internal hostnames in comments or docs"
manual "Tool requests only permissions it actually needs (no unnecessary root/admin)"
manual "API-calling tools: rate limiting or loop protection in place"
manual "Network tools: default to localhost or require explicit target confirmation"
manual "Cloned the repo fresh and followed the README end-to-end"
manual "Ran the tool against a real (benign) target or sample data"
manual "Would you be comfortable showing this in an interview tomorrow?"

# =============================================================================
# SUMMARY
# =============================================================================
TOTAL=$((PASS + FAIL + WARN + SKIP))
echo ""
echo "─────────────────────────────────────────────"
echo -e "${BOLD}Summary${NC}"
echo -e "  ${GREEN}✓ Pass${NC}   $PASS"
[ $FAIL -gt 0 ] && echo -e "  ${RED}✗ Fail${NC}   $FAIL  ← fix before publishing"
[ $WARN -gt 0 ] && echo -e "  ${YELLOW}⚠ Warn${NC}   $WARN  ← review and decide"
[ $SKIP -gt 0 ] && echo -e "  ${DIM}– Skip${NC}   $SKIP  ← install missing tools"
echo ""

if [ $FAIL -gt 0 ]; then
  echo -e "${RED}${BOLD}NOT READY to publish.${NC} Fix all failures first."
  exit 1
elif [ $WARN -gt 0 ]; then
  echo -e "${YELLOW}${BOLD}Review warnings before publishing.${NC} No hard blockers."
  exit 0
else
  echo -e "${GREEN}${BOLD}Automated checks passed.${NC} Complete the manual checklist above."
  exit 0
fi
