"""LLM backends. One Protocol; a deterministic offline mock; one OpenAI-compatible
adapter that covers every provider (OpenAI/Azure/Gemini/Anthropic compat endpoints,
OpenRouter, Ollama, LM Studio, llama.cpp, vLLM). Zero third-party HTTP deps."""
from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.request
from typing import Protocol

_MARKER = re.compile(r"^\[SCPE:([A-Z_]+)\]")


def extract_tag(prompt: str) -> str:
    m = _MARKER.match(prompt.strip())
    return m.group(1) if m else ""


class BackendConfigError(RuntimeError):
    pass


class LLMBackend(Protocol):
    @property
    def label(self) -> str: ...
    async def complete(self, system: str, prompt: str, *, temperature: float = 0.2) -> str: ...


class MockBackend:
    """Deterministic, offline, zero-cost. Dispatches on the [SCPE:TAG] marker."""

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        self._responses = dict(responses or {})

    @property
    def label(self) -> str:
        return "mock"

    async def complete(self, system: str, prompt: str, *, temperature: float = 0.2) -> str:
        tag = extract_tag(prompt)
        if tag in self._responses:
            return self._responses[tag]
        return json.dumps({"mock": True, "tag": tag})


class OpenAICompatBackend:
    """Any provider speaking the OpenAI chat/completions dialect, local or cloud."""

    def __init__(self, base_url: str | None = None, model: str | None = None,
                 api_key: str | None = None, timeout: int = 180) -> None:
        self.base_url = (base_url or os.environ.get("SCPE_BASE_URL", "")).rstrip("/")
        self.model = model or os.environ.get("SCPE_MODEL", "")
        self._api_key = api_key or os.environ.get("SCPE_API_KEY", "")
        self.timeout = timeout
        if not self.base_url or not self.model:
            raise BackendConfigError(
                "set SCPE_BASE_URL and SCPE_MODEL "
                "(e.g. http://localhost:11434/v1 + llama3, or an OpenRouter URL + model)")

    @property
    def label(self) -> str:
        return f"openai-compat:{self.model}"

    async def complete(self, system: str, prompt: str, *, temperature: float = 0.2) -> str:
        return await asyncio.to_thread(self._post, system, prompt, temperature)

    def _post(self, system: str, prompt: str, temperature: float) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
        }).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "scpe/0.1"}
        if self._api_key:  # never log the value
            headers["Authorization"] = f"Bearer {self._api_key}"
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.load(resp)
        return data["choices"][0]["message"]["content"]


def make_backend(kind: str | None = None) -> LLMBackend:
    kind = (kind or os.environ.get("SCPE_BACKEND", "mock")).lower()
    if kind == "mock":
        return MockBackend()
    if kind == "openai":
        return OpenAICompatBackend()
    raise BackendConfigError(f"unknown backend {kind!r} (use 'mock' or 'openai')")
