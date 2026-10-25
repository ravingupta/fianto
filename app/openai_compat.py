"""Execution layer for OpenAI-compatible chat-completions endpoints (OpenAI incl. Daybreak, OpenRouter,
Groq, Ollama, vLLM ...). Implements the same two operations the Anthropic path provides:
  chat()       - single system+user completion returning text
  run_tools()  - agentic loop that executes the app's @beta_tool functions via function calling
"""
from __future__ import annotations

import json
from typing import Callable

import httpx2 as httpx

Logger = Callable[[str, str], None]


class OpenAICompatError(Exception):
    pass


def _headers(provider: dict) -> dict:
    h = {"Content-Type": "application/json"}
    if provider.get("api_key"):
        h["Authorization"] = f"Bearer {provider['api_key']}"
    if "api.anthropic.com" in (provider.get("base_url") or ""):  # Anthropic's OpenAI-compat layer needs this on /models
        h["anthropic-version"] = "2023-06-01"
        h["x-api-key"] = provider.get("api_key", "")
    return h


def _post(provider: dict, path: str, body: dict, timeout: float = 600.0) -> dict:
    url = provider["base_url"].rstrip("/") + path
    try:
        with httpx.Client(timeout=timeout) as c:
            r = c.post(url, headers=_headers(provider), json=body)
    except httpx.HTTPError as e:
        raise OpenAICompatError(f"could not reach {url}: {e}") from e
    if r.status_code == 400 and "max_completion_tokens" in r.text and "max_tokens" in body:
        body = {**body, "max_completion_tokens": body.pop("max_tokens")}
        with httpx.Client(timeout=timeout) as c:
            r = c.post(url, headers=_headers(provider), json=body)
    if r.status_code >= 400:
        raise OpenAICompatError(f"HTTP {r.status_code} from {url}: {r.text[:400]}")
    try:
        return r.json()
    except ValueError as e:
        raise OpenAICompatError(f"non-JSON response from {url}: {r.text[:200]}") from e


def list_models(provider: dict) -> list[dict]:
    url = provider["base_url"].rstrip("/") + "/models"
    try:
        with httpx.Client(timeout=30.0) as c:
            r = c.get(url, headers=_headers(provider))
    except httpx.HTTPError as e:
        raise OpenAICompatError(f"could not reach {url}: {e}") from e
    if r.status_code >= 400:
        raise OpenAICompatError(f"HTTP {r.status_code} from {url}: {r.text[:300]}")
    data = r.json()
    items = data.get("data") if isinstance(data, dict) else data
    out = []
    for it in items or []:
        mid = it.get("id") if isinstance(it, dict) else str(it)
        if mid:
            out.append({"id": mid, "label": (it.get("name") if isinstance(it, dict) else None) or mid})
    return sorted(out, key=lambda x: x["id"])


def _usage(resp: dict, acc: dict) -> None:
    u = resp.get("usage") or {}
    acc["input_tokens"] += int(u.get("prompt_tokens") or 0)
    acc["output_tokens"] += int(u.get("completion_tokens") or 0)
    cached = ((u.get("prompt_tokens_details") or {}).get("cached_tokens")) or 0
    acc["cache_read_input_tokens"] += int(cached)


def chat(spec, system: str, user: str, max_tokens: int | None = None) -> dict:
    body = {"model": spec.id, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": int(max_tokens or spec.model.get("max_tokens") or 16000)}
    resp = _post(spec.provider, "/chat/completions", body)
    usage = {"model": resp.get("model") or spec.id, "input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0,
             "cache_creation_input_tokens": 0}
    _usage(resp, usage)
    choice = (resp.get("choices") or [{}])[0]
    text = ((choice.get("message") or {}).get("content")) or ""
    if isinstance(text, list):  # some servers return content parts
        text = "".join(p.get("text", "") for p in text if isinstance(p, dict))
    return {"text": text.strip(), "usage": usage, "finish_reason": choice.get("finish_reason"), "stop_reason": "end_turn"}


def run_tools(spec, system: str, user: str, tools: list, max_iterations: int, log: Logger, label: str) -> dict:
    """Agentic loop over the app's @beta_tool objects using OpenAI function calling."""
    by_name = {t.name: t for t in tools}
    tool_defs = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                   "parameters": t.input_schema}} for t in tools]
    messages: list[dict] = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    usage = {"model": spec.id, "input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    text, turns, hit_cap = "", 0, False
    for turn in range(max_iterations):
        turns += 1
        body = {"model": spec.id, "messages": messages, "tools": tool_defs, "tool_choice": "auto",
                "max_tokens": int(spec.model.get("max_tokens") or 16000)}
        resp = _post(spec.provider, "/chat/completions", body)
        _usage(resp, usage)
        usage["model"] = resp.get("model") or spec.id
        choice = (resp.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        calls = msg.get("tool_calls") or []
        content = msg.get("content")
        if isinstance(content, list):
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
        if not calls:
            text = (content or "").strip()
            break
        messages.append({"role": "assistant", "content": content or None, "tool_calls": calls})
        log("cmd", f"    [{label}] " + "; ".join(f"{c['function']['name']}({c['function'].get('arguments', '')[:80]})" for c in calls)[:400])
        for c in calls:
            name = c["function"]["name"]
            try:
                args = json.loads(c["function"].get("arguments") or "{}")
            except ValueError:
                result = "ERROR: tool arguments were not valid JSON"
            else:
                tool = by_name.get(name)
                if tool is None:
                    result = f"ERROR: unknown tool {name}"
                else:
                    try:
                        result = tool.call(args)
                    except Exception as e:  # noqa: BLE001 - tool errors go back to the model
                        result = f"ERROR: {type(e).__name__}: {e}"
            messages.append({"role": "tool", "tool_call_id": c.get("id", name), "content": str(result)})
    else:
        hit_cap = True
        log("warn", f"    [{label}] stopped at the {max_iterations}-turn cap; findings submitted so far are kept")
    return {"text": text, "usage": usage, "turns": turns, "hit_cap": hit_cap}
