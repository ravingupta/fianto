#!/usr/bin/env bash
# Fianto — local machine setup: scanners, helper CLIs, Python environment, .env.
# Idempotent: safe to rerun. Usage: ./setup_scanners.sh [--with-snyk]
set -euo pipefail
cd "$(dirname "$0")"

WITH_SNYK=0
[[ "${1:-}" == "--with-snyk" ]] && WITH_SNYK=1

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }

bold "Fianto setup ($(uname -s))"

# ---------------------------------------------------------------- Homebrew (macOS / Linuxbrew)
if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required (https://brew.sh). Install it, then rerun this script."
  exit 1
fi
ok "Homebrew found"
brew update >/dev/null 2>&1 || warn "brew update failed (offline?) — continuing"

brew_ensure() {  # brew_ensure <formula> <binary>
  if command -v "$2" >/dev/null 2>&1; then
    ok "$2 already installed ($(command -v "$2"))"
  else
    echo "  installing $1 ..."
    brew install "$1"
    ok "$2 installed"
  fi
}

bold "Security scanners"
brew_ensure trufflehog trufflehog     # secrets in git history / filesystem (every repo)
brew_ensure semgrep semgrep           # SAST, --config=auto (every repo)
brew_ensure pip-audit pip-audit       # Python dependency CVEs (requirements.txt)
brew_ensure cargo-audit cargo-audit   # Rust dependency CVEs (Cargo.toml)
if command -v npm >/dev/null 2>&1; then ok "npm audit available ($(npm --version))"; else warn "Node.js/npm not found — install Node to get npm audit (brew install node)"; fi
if [[ $WITH_SNYK -eq 1 ]]; then brew_ensure snyk snyk; fi

bold "Helper CLIs"
brew_ensure gh gh                     # Create PR button
brew_ensure ripgrep rg                # fast grep tool for the review agents
brew_ensure git git

bold "Python environment"
if [[ ! -x venv/bin/python ]]; then
  python3 -m venv venv
  ok "created venv/"
fi
venv/bin/pip install -q --upgrade pip >/dev/null
venv/bin/pip install -q -r requirements.txt
ok "python deps installed ($(venv/bin/python --version))"

bold "Configuration"
if [[ ! -f .env ]]; then
  cp .env.example .env
  warn ".env created from .env.example — add ANTHROPIC_API_KEY (or add providers on the Settings page)"
else
  if grep -qE '^ANTHROPIC_API_KEY=.+' .env; then ok ".env has ANTHROPIC_API_KEY"; else warn ".env exists but ANTHROPIC_API_KEY is empty"; fi
fi
mkdir -p data

bold "Optional"
if semgrep login --help >/dev/null 2>&1; then
  if [[ -n "${SEMGREP_APP_TOKEN:-}" ]]; then ok "SEMGREP_APP_TOKEN set (authenticated Semgrep: more rules + code snippets)";
  else warn "run 'semgrep login' once for Pro rules and code snippets in reports (optional)"; fi
fi
if gh auth status >/dev/null 2>&1; then ok "gh is authenticated (PR creation ready)"; else warn "run 'gh auth login' to enable the Create PR button"; fi

bold "Versions"
for t in trufflehog semgrep pip-audit cargo-audit gh rg; do
  if command -v $t >/dev/null 2>&1; then printf '  %-12s %s\n' "$t" "$($t --version 2>&1 | head -n1 | cut -c1-60)"; fi
done

bold "Done. Start the dashboard with ./run.sh and open http://127.0.0.1:8000"
