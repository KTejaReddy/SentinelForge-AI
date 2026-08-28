"""Groq client - the platform's central AI reasoning service.

- OpenAI-compatible chat completions against the configured base URL
- structured JSON mode for agent outputs
- native tool calling for the agent loop
- token + cost tracking (deterministic per-request estimate)
- graceful degradation: every failure is reported, never fatal
"""
from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from config import settings
from security import redact_text

# Rough per-1M-token pricing used for the documented cost *estimate*.
PRICING: dict[str, tuple[float, float]] = {
    "openai/gpt-oss-120b": (0.15, 0.60),
    "openai/gpt-oss-20b": (0.10, 0.40),
    "llama-3.3-70b-versatile": (0.59, 0.79),
    "llama-3.1-8b-instant": (0.05, 0.08),
    "llama-3.3-70b-specdec": (0.59, 0.99),
    "deepseek-r1-distill-llama-70b": (0.99, 1.49),
    "qwen-qwq-32b": (0.24, 0.48),
}
DEFAULT_PRICE = (0.59, 0.79)


@dataclass
class ChatResult:
    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    ok: bool = False
    error: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class GroqUnavailable(Exception):
    pass


class GroqClient:
    def __init__(self, api_key: str = "", model: str = "", base_url: str = "", max_tokens: int = 0, temperature: float | None = None):
        self.api_key = api_key or settings.groq_api_key
        self.model = model or settings.groq_model
        self.base_url = base_url or settings.groq_base_url
        self.max_tokens = max_tokens or settings.groq_max_tokens
        self.temperature = settings.groq_temperature if temperature is None else temperature

    def available(self) -> bool:
        return bool(self.api_key)

    def _pricing(self) -> tuple[float, float]:
        for key, price in PRICING.items():
            if key in self.model:
                return price
        return DEFAULT_PRICE

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        json_mode: bool = False,
        max_tokens: int | None = None,
        temperature: float | None = None,
        retries: int = 1,
    ) -> ChatResult:
        if not self.available():
            return ChatResult(error="Groq API key not configured", ok=False)
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": self.temperature if temperature is None else temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        last_error = ""
        attempts = 0
        rate_limit_waits = 0
        while True:
            try:
                with httpx.Client(timeout=settings.groq_timeout_seconds) as client:
                    resp = client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            except httpx.HTTPError as exc:
                attempts += 1
                last_error = f"network error: {exc}"
                if attempts > retries + 1:
                    break
                time.sleep(1)
                continue
            if resp.status_code == 429:
                # Transient rate limit — exponential backoff with jitter.
                last_error = "rate limited (429)"
                rate_limit_waits += 1
                if rate_limit_waits <= 3:
                    base = min(8, 2 ** rate_limit_waits)
                    jitter = random.uniform(0, base * 0.5)
                    time.sleep(base + jitter)
                    continue
                break
            attempts += 1
            if resp.status_code >= 400:
                body = resp.text[:300]
                last_error = f"HTTP {resp.status_code}: {body}"
                if resp.status_code in (401, 403):
                    break
                if attempts > retries + 1:
                    break
                time.sleep(1)
                continue
            try:
                data = resp.json()
            except json.JSONDecodeError:
                last_error = "malformed JSON response"
                time.sleep(1)
                continue
            choice = (data.get("choices") or [{}])[0]
            message = choice.get("message", {})
            usage = data.get("usage", {})
            in_tokens = int(usage.get("prompt_tokens", 0))
            out_tokens = int(usage.get("completion_tokens", 0))
            pin, pout = self._pricing()
            cost = (in_tokens / 1_000_000) * pin + (out_tokens / 1_000_000) * pout
            result = ChatResult(
                content=message.get("content") or "",
                tool_calls=message.get("tool_calls") or [],
                input_tokens=in_tokens,
                output_tokens=out_tokens,
                cost_usd=round(cost, 6),
                ok=True,
                raw=data,
            )
            return result
        return ChatResult(error=last_error or "unknown error", ok=False)

    def test_connection(self) -> tuple[bool, str, int]:
        start = time.time()
        result = self.chat(
            [{"role": "user", "content": "Reply with exactly: ok"}],
            max_tokens=16, temperature=0,
        )
        latency = int((time.time() - start) * 1000)
        if result.ok:
            return True, f"Connected - model {self.model} responded in {latency} ms", latency
        return False, result.error or "unexpected response", latency


def parse_json_content(content: str) -> dict[str, Any] | None:
    """Parse an agent's JSON output, tolerating markdown fences."""
    text = (content or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return None
        return None
