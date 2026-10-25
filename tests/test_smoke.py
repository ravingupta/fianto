"""Smoke tests: the app starts and every page renders with no API key and an empty data dir."""
import os
import tempfile

os.environ.setdefault("SCANNER_DATA_DIR", tempfile.mkdtemp(prefix="fianto-test-"))
os.environ["ANTHROPIC_API_KEY"] = ""  # never call a model from tests

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)


def test_health():
    body = client.get("/health").json()
    assert body["ok"] is True
    assert body["running"] is False


def test_pages_render():
    for path in ("/", "/findings", "/history", "/settings", "/run/status"):
        assert client.get(path).status_code == 200, path
