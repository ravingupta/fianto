# Contributing to Fianto

Thanks for your interest! Bug reports, playbook improvements, docs and code are all welcome.

## Ground rules

- Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Security problems in Fianto itself go through [private reporting](SECURITY.md), not public issues.
- **Never share scan output from real repositories** in issues or pull requests. Raw scanner files
  contain real secrets and findings about other people's code. Reproduce problems with a small sample
  repo instead (or describe the shape of the data).
- Only point Fianto at code you are authorized to test.

## Ways to help

- **Report a bug** or **suggest a feature** with the [issue templates](../../issues/new/choose).
- Pick up an issue labelled [`good first issue`](../../labels/good%20first%20issue) or
  [`help wanted`](../../labels/help%20wanted).
- **Improve the playbooks** in [app/playbooks/](app/playbooks/): they decide what the review agents look
  for on each surface. Better checks there improve every run without touching code.
- **Add a scanner** (e.g. `gosec`, `bandit`, `osv-scanner`): see how existing scanners are wired in
  [app/scanner.py](app/scanner.py).
- **Add a provider**: OpenAI-compatible endpoints work already; see [app/providers.py](app/providers.py).

## Development setup

```sh
git clone https://github.com/ravingupta/fianto && cd fianto
./setup_scanners.sh            # scanners, Python venv, .env (idempotent)
RELOAD=1 ./run.sh              # http://127.0.0.1:8000, restarts on code changes
```

You don't need an API key to work on most of the app: without one, scans still run and reports are
written as automated summaries. Use a throwaway data directory so test runs don't mix with your real
history:

```sh
SCANNER_DATA_DIR=/tmp/fianto-dev RELOAD=1 ./run.sh
```

Architecture notes live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Tests

```sh
venv/bin/pip install pytest httpx
venv/bin/python -m pytest -q
```

Tests never call a model provider. If you add a feature, add a test that runs without network access.

## Making a change

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Fork the repo and create a branch: `git checkout -b feat/short-description`.
3. Keep to the existing stack: FastAPI, Jinja2 templates, Tailwind via CDN, no build step.
4. Run the tests and try the change in the browser.
5. Commit with a clear message and open a pull request using the template. CI runs the tests on
   Python 3.11 and 3.13.

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
