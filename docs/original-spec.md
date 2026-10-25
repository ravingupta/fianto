# Product Specification: Multi-Page AI Security Gameday Web App

You are an expert Full-Stack Engineer and Security Architect. Your task is to build a lightweight, multi-page server-side rendered (SSR) local web application. It acts as a multi-project dashboard that runs security CLI scanners sequentially, isolates reports by date, and uses Claude to write automated patches.

---

## 1. Tech Stack Requirements
*   **Backend & Routing:** Node.js with Express + EJS templates, OR Python with FastAPI/Flask + Jinja2 templates.
*   **Frontend UI:** Standard multi-page HTML styled with Tailwind CSS (via CDN link, no build step required). 
*   **API Integration:** Direct connection to the Anthropic API (`claude-3-5-sonnet-20241022`) using the system's `process.env.ANTHROPIC_API_KEY`.

---

## 2. Page Architecture & Routing Map

The application must be split into four core server-rendered pages:

### Page 1: Configure & Launch (`GET /`)
*   **UI Elements:** A large text area to paste absolute local file paths to multiple repositories (one per line). A list displaying local environment status (checks if `trufflehog` and `semgrep` are globally installed on the machine).
*   **Action (`POST /run`):** Submits the array of paths to the backend queue and instantly redirects the user to the live progress tracking screen.

### Page 2: Live Progress Tracker (`GET /run/status`)
*   **UI Elements:** A clean console-style tracking screen that shows exactly what the backend is executing in real-time.
*   **Behavior:** Uses simple polling or Server-Sent Events (SSE) to update the user as the system iterates through projects: *"Scanning project 2 of 4: `backend-api` -> Running Semgrep..."*
*   **Completion:** Once all scans and Claude reports are generated, this page automatically displays a "View Final Report" button linking to Page 3.

### Page 3: Past Scans History Vault (`GET /history`)
*   **UI Elements:** A landing page displaying a list of all historical runs found in the local filesystem, sorted chronologically by date/time (e.g., `Run: Oct 22, 2026 - 02:15 AM`).
*   **Behavior:** Clicking a run card takes the user to the dedicated multi-project report summary page for that specific date.

### Page 4: Interactive Markdown Report Hub (`GET /history/:run_id`)
*   **UI Elements:** A two-column interface. 
    *   *Left Sidebar:* A tree navigation showing the `MASTER_GAMEDAY_REPORT.md` file at the top, followed by a list of individual project names.
    *   *Right Content Area:* A viewport that dynamically renders the Markdown text of the selected report into beautiful HTML with proper code-syntax highlighting blocks for the patches.

---

## 3. Core Automation & File Management Engines

### Engine A: Auto-Detect Project Types & Subprocess Runner
When a run begins, the backend must process directories **1-by-1 sequentially**. For each directory, it determines the language stack by checking for root configuration files:
1.  **Universal Scans (Run on every directory):**
    *   `trufflehog git file://<PROJECT_PATH> --json` (Secrets/Keys)
    *   `semgrep scan --config=auto --json <PROJECT_PATH>` (SAST Logic bugs)
2.  **Language-Specific Checks (Conditional):**
    *   If `package.json` exists → Run `npm audit --json` (Node.js/React Native)
    *   If `Cargo.toml` exists → Run `cargo audit --json` (Rust)
    *   If `requirements.txt` exists → Run `pip-audit --json` (Python)

### Engine B: Date-Isolated File Storage
*   All data must be kept inside a central directory: `ai-security-scanner/data/`.
*   A new folder must be provisioned for each trigger instance using the execution time: `data/run_YYYYMMDD_HHMMSS/`.
*   Inside that folder, create separate subfolders for each unique project name (e.g., `data/run_YYYYMMDD_HHMMSS/my-mobile-app/`).
*   Save the raw scanner JSON files inside their respective project subfolders.

---

## 4. The Claude Triage & Patch Pipeline
Once all system command scanners exit for a project, the backend initiates the AI processing pipeline using your API credits:

*   **Step 1 (Individual Summaries):** Bundle the raw scan files for a project and pass them to Claude. Instruct Claude to output a localized file named `PROJECT_SUMMARY.md` containing a triaged vulnerability list and complete, copy-pasteable code patches or package upgrades.
*   **Step 2 (The Master Aggregator):** Once all individual summaries are complete, pass all summaries back to Claude in one final call. Instruct it to output a master file at `data/run_YYYYMMDD_HHMMSS/MASTER_GAMEDAY_REPORT.md` outlining a total vulnerability count grid, cross-repo leak correlations, and an executive roadmap of what patches to apply first.

---

## Implementation Instruction
Build this web application entirely, writing clean server-side code and HTML templates. Ensure all terminal subprocess commands handle non-zero exit codes (since security scanners exit with codes > 0 when bugs are found) gracefully so that one project finding a bug does not crash the overnight queue. Begin building now.
