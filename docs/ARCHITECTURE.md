# Fianto architecture

```
browser ──► FastAPI (app/main.py) ──► RunManager thread (app/runner.py)
                │                          │  per repo, sequentially
                │                          ├─ scanner.py      trufflehog / semgrep / npm / cargo / pip-audit
                │                          ├─ store.py        findings.db  (fingerprint-keyed, cross-run)
                │                          ├─ agents.py       surface agents ∥  →  verifier  →  patch agent
                │                          │     └ repotools.py  confined read/grep/list/git + write/run (patch only)
                │                          │     └ patches.py    git worktrees + gh PR
                │                          └─ claude_pipeline.py  PROJECT_SUMMARY.md + MASTER_REPORT.md
                └─ providers.py  model registry (data/settings.json) → Anthropic SDK | openai_compat.py
```

## Modules

| File | Responsibility |
|---|---|
| `app/config.py` | Environment-driven settings, `.env` loading, file name constants. |
| `app/main.py` | Routes and page rendering. No business logic. |
| `app/runner.py` | One background thread per run; stages per repo; live log consumed by SSE. Also ad-hoc patch jobs. |
| `app/scanner.py` | Builds scanner commands per repo, runs them with timeouts, parses every tool's JSON into `Finding`s, builds model-readable digests. |
| `app/store.py` | SQLite findings store. `make_fingerprint()` defines identity; statuses implement suppression and regression. |
| `app/agents.py` | `review_surface`, `verify_project`, `patch_finding`, plus `run_agent` which dispatches to the Anthropic tool runner or the OpenAI-compatible loop. Surface detection and scanner→store mapping live here too. |
| `app/repotools.py` | `RepoSandbox` (path confinement) and the `@beta_tool` closures handed to agents. |
| `app/patches.py` | Worktree lifecycle (`fianto/<fp8>` branches), commits, `gh pr create`. |
| `app/claude_pipeline.py` | Report prompts, count grid, cross-repo correlations, fallbacks when the model is unavailable. |
| `app/providers.py` | Providers, model roster, per-stage assignment, discovery and connection tests. |
| `app/openai_compat.py` | Chat and function-calling loop over `/v1/chat/completions` for non-Anthropic models. |
| `app/storage.py` | Run folders, history listing, report-hub tree, safe file resolution. |
| `app/fsbrowse.py` | Folder picker backends (directory listing, macOS Finder dialog). |
| `app/playbooks/*.md` | System prompts per surface; `_common.md` is prepended to each. |

## Data flow for one finding

1. A scanner hit or an agent `submit_finding` call becomes a row in `findings.db` keyed by fingerprint
   (`project | source | rule | file`, line numbers excluded) so it survives reruns and line shifts.
2. The verifier reads the code and records a verdict; the row's status becomes `confirmed`,
   `false_positive` or `needs_review`, severity and exploit path may be corrected.
3. At depth `patch`, or from the board's **Generate patch**, the patch agent fixes it in a worktree and the
   diff, checks run and commit are stored on the row.
4. **Create PR** pushes the branch and opens a PR; the URL is stored on the row.
5. Humans change status on the board; `false_positive` / `accepted_risk` suppress the fingerprint on future runs,
   and a `fixed` finding that reappears is marked `regressed` in its history.

## Run folder

```
data/run_YYYYMMDD_HHMMSS/
├── MASTER_REPORT.md              (older runs: MASTER_GAMEDAY_REPORT.md, still served)
├── run_manifest.json             statuses, counts, models used, token usage
└── <repo>/
    ├── PROJECT_SUMMARY.md
    ├── trufflehog.json  semgrep.json  npm_audit.json  cargo_audit.json  pip_audit.json
    └── <tool>.stderr.log
```

## Extending

- **New scanner**: add a `ScanCommand` in `scanner.build_commands`, a parser in `scanner.parse_output`, and a
  surface rule in `agents.classify_scanner_surface`.
- **New surface**: add `app/playbooks/<name>.md`, list it in `agents.SURFACES`, and teach `detect_surfaces` how to spot it.
- **New provider type**: extend `providers.PROVIDER_TYPES` and `ModelSpec.anthropic_client` (Anthropic family) or
  route `family == "openai"` through `openai_compat`.
