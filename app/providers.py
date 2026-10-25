"""Model providers and per-stage model assignment, configured from the dashboard.

Settings live in data/settings.json. Provider types:
  anthropic          Claude API (api key, optional base_url for proxies)
  anthropic_bedrock  Claude on Amazon Bedrock (AWS credentials from the environment)
  anthropic_vertex   Claude on Google Vertex AI (ADC credentials)
  anthropic_foundry  Claude on Microsoft Foundry
  openai_compatible  Any /v1/chat/completions endpoint: OpenAI (incl. Daybreak), OpenRouter, Groq, Ollama, vLLM ...
"""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime
from typing import Any, Optional

import anthropic

from .config import (CLAUDE_AGENT_MODEL, CLAUDE_FALLBACKS, CLAUDE_MODEL, CLAUDE_PATCH_MODEL, CLAUDE_VERIFY_MODEL,
                     DATA_DIR)

STAGES = {"report": "Reports (project summaries + master report)", "agent": "Surface review agents",
          "verify": "Adversarial verifier", "patch": "Patch agent"}
PROVIDER_TYPES = {
    "anthropic": "Claude API (Anthropic)",
    "anthropic_bedrock": "Claude on Amazon Bedrock",
    "anthropic_vertex": "Claude on Google Vertex AI",
    "anthropic_foundry": "Claude on Microsoft Foundry",
    "openai_compatible": "OpenAI-compatible (OpenAI / Daybreak, OpenRouter, Groq, Ollama, vLLM ...)",
}
SETTINGS_FILE = DATA_DIR / "settings.json"
_lock = threading.RLock()

# Curated roster seeded on first start so the dropdowns are useful immediately.
CURATED_CLAUDE = [
    ("claude-opus-5-5", "Claude Opus 5.5 (default)"), ("claude-sonnet-5-5", "Claude Sonnet 5.5"),
    ("claude-haiku-5-5", "Claude Haiku 5.5"), ("claude-fable-5-1", "Claude Fable 5.1 (most capable)"),
    ("claude-mythos-5-1", "Claude Mythos 5.1 (Project Glasswing access required)"),
    ("claude-opus-5", "Claude Opus 5"), ("claude-opus-4-8", "Claude Opus 4.8"),
]
ADAPTIVE_RE = re.compile(r"^claude-(opus-(4-[678]|5)|sonnet-(4-6|5)|haiku-5|fable-5|mythos-5)")
FALLBACK_RE = re.compile(r"^claude-(opus-5|fable-5|sonnet-5-5|mythos-5)")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _default_settings() -> dict:
    pid = "anthropic-default"
    providers = [{"id": pid, "name": "Anthropic (API key from .env)", "type": "anthropic",
                  "api_key": "", "base_url": "", "region": "", "project_id": "", "resource": "",
                  "note": "Uses ANTHROPIC_API_KEY from .env / environment when api_key is empty", "created": _now()}]
    models = []
    seen = set()
    for mid in [CLAUDE_MODEL, CLAUDE_AGENT_MODEL, CLAUDE_VERIFY_MODEL, CLAUDE_PATCH_MODEL] + [m for m, _ in CURATED_CLAUDE]:
        if mid in seen:
            continue
        seen.add(mid)
        label = dict(CURATED_CLAUDE).get(mid, mid)
        models.append(_model_entry(pid, mid, label, "anthropic"))
    stages = {"report": f"{pid}::{CLAUDE_MODEL}", "agent": f"{pid}::{CLAUDE_AGENT_MODEL}",
              "verify": f"{pid}::{CLAUDE_VERIFY_MODEL}", "patch": f"{pid}::{CLAUDE_PATCH_MODEL}"}
    return {"providers": providers, "models": models, "stages": stages}


def _model_entry(provider_id: str, model_id: str, label: str, ptype: str) -> dict:
    is_claude = model_id.startswith("claude-") or "anthropic.claude" in model_id
    return {
        "key": f"{provider_id}::{model_id}", "provider": provider_id, "model": model_id, "label": label or model_id,
        "thinking": "adaptive" if (is_claude and ADAPTIVE_RE.search(model_id.replace("anthropic.", ""))) else "off",
        "effort": "high" if is_claude else "",
        "fallbacks": bool(ptype == "anthropic" and FALLBACK_RE.search(model_id) and CLAUDE_FALLBACKS != "off"),
        "max_tokens": 64000 if is_claude else 16000,
        "tools": True, "enabled": True, "added": _now(),
    }


# --------------------------------------------------------------------------- persistence

def load() -> dict:
    with _lock:
        if SETTINGS_FILE.is_file():
            try:
                data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
                if data.get("providers") and data.get("models"):
                    return data
            except ValueError:
                pass
        data = _default_settings()
        save(data)
        return data


def save(data: dict) -> None:
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = SETTINGS_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(SETTINGS_FILE)


def masked(data: dict) -> dict:
    """Copy of settings safe to render: API keys reduced to a hint."""
    out = json.loads(json.dumps(data))
    for p in out["providers"]:
        k = p.get("api_key") or ""
        p["api_key_hint"] = (k[:7] + "…" + k[-4:]) if len(k) > 14 else ("set" if k else "")
        p["api_key"] = ""
    return out


def get_provider(data: dict, pid: str) -> Optional[dict]:
    return next((p for p in data["providers"] if p["id"] == pid), None)


def get_model(data: dict, key: str) -> Optional[dict]:
    return next((m for m in data["models"] if m["key"] == key), None)


def add_provider(form: dict) -> dict:
    data = load()
    ptype = form.get("type", "anthropic")
    if ptype not in PROVIDER_TYPES:
        raise ValueError("unknown provider type")
    pid = re.sub(r"[^a-z0-9]+", "-", (form.get("name") or ptype).lower()).strip("-")[:40] or ptype
    if get_provider(data, pid):
        pid = f"{pid}-{uuid.uuid4().hex[:4]}"
    base_url = (form.get("base_url") or "").strip().rstrip("/")
    if ptype == "openai_compatible" and not base_url:
        raise ValueError("an OpenAI-compatible provider needs a base URL such as https://api.openai.com/v1")
    p = {"id": pid, "name": form.get("name") or PROVIDER_TYPES[ptype], "type": ptype,
         "api_key": (form.get("api_key") or "").strip(), "base_url": base_url,
         "region": (form.get("region") or "").strip(), "project_id": (form.get("project_id") or "").strip(),
         "resource": (form.get("resource") or "").strip(), "note": (form.get("note") or "").strip(), "created": _now()}
    data["providers"].append(p)
    save(data)
    return p


def update_provider_key(pid: str, api_key: str) -> None:
    data = load()
    p = get_provider(data, pid)
    if p is None:
        raise ValueError("provider not found")
    p["api_key"] = api_key.strip()
    save(data)


def delete_provider(pid: str) -> None:
    data = load()
    if pid == "anthropic-default":
        raise ValueError("the default Anthropic provider cannot be deleted")
    data["providers"] = [p for p in data["providers"] if p["id"] != pid]
    data["models"] = [m for m in data["models"] if m["provider"] != pid]
    fallback = data["models"][0]["key"] if data["models"] else ""
    for stage, key in data["stages"].items():
        if key.startswith(pid + "::"):
            data["stages"][stage] = fallback
    save(data)


def add_model(pid: str, model_id: str, label: str = "") -> dict:
    data = load()
    p = get_provider(data, pid)
    if p is None:
        raise ValueError("provider not found")
    model_id = model_id.strip()
    if not model_id:
        raise ValueError("model id is required")
    existing = get_model(data, f"{pid}::{model_id}")
    if existing:
        return existing
    m = _model_entry(pid, model_id, label.strip() or model_id, p["type"])
    data["models"].append(m)
    save(data)
    return m


def update_model(key: str, **fields) -> None:
    data = load()
    m = get_model(data, key)
    if m is None:
        raise ValueError("model not found")
    for k, v in fields.items():
        if k in ("thinking", "effort", "label"):
            m[k] = v
        elif k in ("fallbacks", "tools", "enabled"):
            m[k] = bool(v)
        elif k == "max_tokens":
            m[k] = max(1024, min(int(v), 128000))
    save(data)


def delete_model(key: str) -> None:
    data = load()
    data["models"] = [m for m in data["models"] if m["key"] != key]
    fallback = data["models"][0]["key"] if data["models"] else ""
    for stage, k in data["stages"].items():
        if k == key:
            data["stages"][stage] = fallback
    save(data)


def set_stages(assign: dict) -> None:
    data = load()
    for stage, key in assign.items():
        if stage in STAGES and get_model(data, key):
            data["stages"][stage] = key
    save(data)


# --------------------------------------------------------------------------- resolution

class ModelSpec:
    """Everything a call site needs: the provider record, the model record, and a client factory."""

    def __init__(self, provider: dict, model: dict):
        self.provider = provider
        self.model = model

    @property
    def id(self) -> str:
        return self.model["model"]

    @property
    def key(self) -> str:
        return self.model["key"]

    @property
    def label(self) -> str:
        return f"{self.model['label']} @ {self.provider['name']}"

    @property
    def family(self) -> str:
        return "openai" if self.provider["type"] == "openai_compatible" else "anthropic"

    def anthropic_client(self) -> anthropic.Anthropic:
        p = self.provider
        t = p["type"]
        if t == "anthropic":
            kwargs: dict[str, Any] = {}
            if p.get("api_key"):
                kwargs["api_key"] = p["api_key"]
            if p.get("base_url"):
                kwargs["base_url"] = p["base_url"]
            return anthropic.Anthropic(**kwargs)
        if t == "anthropic_bedrock":
            return anthropic.AnthropicBedrockMantle(aws_region=p.get("region") or os.environ.get("AWS_REGION", "us-east-1"))
        if t == "anthropic_vertex":
            return anthropic.AnthropicVertex(project_id=p.get("project_id") or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", ""),
                                             region=p.get("region") or "global")
        if t == "anthropic_foundry":
            return anthropic.AnthropicFoundry(api_key=p.get("api_key") or None, resource=p.get("resource") or None)
        raise ValueError(f"provider type {t} is not an Anthropic client")

    def anthropic_kwargs(self) -> dict:
        """Request parameters that depend on the model record (thinking, effort, fallbacks)."""
        m = self.model
        kw: dict[str, Any] = {"model": self.id, "max_tokens": int(m.get("max_tokens") or 16000)}
        if m.get("thinking") == "adaptive":
            kw["thinking"] = {"type": "adaptive"}
        if m.get("effort"):
            kw["output_config"] = {"effort": m["effort"]}
        if m.get("fallbacks") and self.provider["type"] == "anthropic":
            kw["betas"] = ["server-side-fallback-2026-07-01"]
            kw["fallbacks"] = "default"
        return kw


def resolve(stage: str, override_key: str = "") -> ModelSpec:
    data = load()
    key = override_key or data["stages"].get(stage) or data["stages"].get("report")
    m = get_model(data, key) or (data["models"][0] if data["models"] else None)
    if m is None:
        raise RuntimeError("no models configured; open Settings")
    p = get_provider(data, m["provider"])
    if p is None:
        raise RuntimeError(f"provider {m['provider']} for model {m['model']} is missing")
    return ModelSpec(p, m)


def stage_specs(overrides: Optional[dict] = None) -> dict[str, ModelSpec]:
    overrides = overrides or {}
    return {s: resolve(s, overrides.get(s, "")) for s in STAGES}


# --------------------------------------------------------------------------- discovery & testing

def discover_models(pid: str) -> dict:
    """List models the provider exposes. Returns {"models": [{id, label}], "error": str|None}."""
    data = load()
    p = get_provider(data, pid)
    if p is None:
        return {"models": [], "error": "provider not found"}
    try:
        if p["type"] == "openai_compatible":
            from .openai_compat import list_models
            return {"models": list_models(p), "error": None}
        spec = ModelSpec(p, {"model": "", "key": "", "label": ""})
        client = spec.anthropic_client()
        out = []
        for m in client.models.list():
            out.append({"id": m.id, "label": getattr(m, "display_name", m.id)})
        return {"models": out, "error": None}
    except anthropic.AuthenticationError:
        return {"models": [], "error": "authentication failed (check the API key)"}
    except anthropic.APIConnectionError as e:
        return {"models": [], "error": f"could not connect: {e}"}
    except anthropic.APIStatusError as e:
        return {"models": [], "error": f"API error {e.status_code}: {e.message}"}
    except Exception as e:  # noqa: BLE001 - surfaced to the UI
        return {"models": [], "error": f"{type(e).__name__}: {str(e)[:300]}"}


def test_model(key: str) -> dict:
    """One tiny completion to prove the connection + model work. Returns {ok, detail}."""
    try:
        data = load()
        m = get_model(data, key)
        if m is None:
            return {"ok": False, "detail": "model not found"}
        spec = ModelSpec(get_provider(data, m["provider"]), m)
        if spec.family == "openai":
            from .openai_compat import chat
            res = chat(spec, system="Reply with the single word: pong", user="ping", max_tokens=64)
            return {"ok": True, "detail": f"reply: {res['text'][:60]!r}; usage {res['usage']}"}
        client = spec.anthropic_client()
        kw = spec.anthropic_kwargs()
        kw["max_tokens"] = 64
        kw.pop("output_config", None)
        msg = client.beta.messages.create(system="Reply with the single word: pong",
                                          messages=[{"role": "user", "content": "ping"}], **kw)
        text = "".join(b.text for b in msg.content if b.type == "text")
        return {"ok": True, "detail": f"reply: {text[:60]!r}; served by {msg.model}; {msg.usage.input_tokens} in / {msg.usage.output_tokens} out"}
    except anthropic.APIStatusError as e:
        return {"ok": False, "detail": f"API error {e.status_code}: {e.message[:300]}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": f"{type(e).__name__}: {str(e)[:300]}"}
