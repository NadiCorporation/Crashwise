# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
"""Hybrid AI inference provider — supports local (Ollama) and cloud
(Venice) backends with a unified interface.

The factory reads ``AI_PROVIDER`` from settings and returns the
appropriate :class:`BaseInference` implementation.  When no provider is
configured, operations gracefully fall back to heuristics.

Usage::

    from crashwise.core.ai_provider import get_provider

    provider = get_provider()
    result = await provider.analyze(crash_context)
    # result = {"bug_type": "use-after-free", "exploitability": 8.5, "root_cause": "..."}
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import httpx

from crashwise.core.config import get_settings
from crashwise.core.logging import get_logger

log = get_logger(__name__)

# ── Security researcher system prompt ─────────────────────────────────────────

_TRIAGE_SYSTEM_PROMPT = """\
You are an elite vulnerability researcher specialising in memory-safety
crash triage.  You analyse AddressSanitizer logs, GDB backtraces,
register dumps, and disassembly snippets to classify bugs and assess
exploitability.

You MUST respond with a single JSON object (no markdown fences, no prose):

{
  "bug_type": "<one of: use-after-free|double-free|heap-buffer-overflow|stack-buffer-overflow|buffer-overflow|out-of-bounds-read|out-of-bounds-write|integer-overflow|null-pointer-dereference|divide-by-zero|uninitialized-read|memory-leak|race-condition|unknown>",
  "exploitability": <0.0-10.0>,
  "root_cause": "<one-paragraph technical explanation of WHY the crash happened>",
  "vulnerability_type": "<cwe-119|cwe-120|cwe-125|cwe-416|cwe-415|cwe-476|cwe-190|cwe-369|cwe-362|unknown>",
  "confidence": <0.0-1.0>
}

Scoring rubric for exploitability (0-10):
  • 9-10: Trivially exploitable (e.g., controllable heap UAF with full
           read/write primitives, no ASLR bypass needed).
  • 7-8:  Exploitable with effort (e.g., limited write primitive,
           requires infoleak or ASLR bypass).
  • 5-6:  Potentially exploitable (e.g., OOB read leaking data, but
           no direct control-flow hijack).
  • 3-4:  Low exploitability (e.g., null dereference, DoS only).
  • 0-2:  Not exploitable (e.g., benign memory leak, assertion failure).

Rules:
  • If ASAN says "heap-buffer-overflow" → bug_type must be heap-buffer-overflow.
  • If ASAN says "use-after-free" → bug_type must be use-after-free.
  • If the PC is 0x0 or near-null → null-pointer-dereference, exploitability ≤ 4.
  • Be conservative: when uncertain set confidence < 0.5.
"""

_PATCH_SYSTEM_PROMPT = """\
You are a senior systems engineer specialising in secure C/C++ development.
Given a root-cause analysis of a memory-safety bug, suggest a minimal,
production-quality patch.

You MUST respond with a single JSON object:

{
  "patch": "<minimal C/C++ diff or code snippet showing the fix>",
  "explanation": "<one-paragraph explanation of the fix>",
  "confidence": <0.0-1.0>
}

Guidelines:
  • Keep the patch minimal — change as few lines as possible.
  • Prefer bounds checks, null checks, and safe API usage.
  • Avoid refactoring unrelated code.
  • If the root cause is unclear, set confidence < 0.5 and explain why.
"""


# ── Base class ───────────────────────────────────────────────────────────────

class BaseInference(ABC):
    """Abstract inference provider for crash analysis and patch generation."""

    @abstractmethod
    async def analyze(self, crash_context: str) -> dict[str, Any]:
        """Analyse a crash and return structured findings.

        Returns
        -------
        dict with keys: bug_type, exploitability, root_cause,
        vulnerability_type, confidence.
        """

    @abstractmethod
    async def suggest_patch(self, root_cause: str) -> dict[str, Any]:
        """Suggest a minimal C/C++ patch for the given root cause.

        Returns
        -------
        dict with keys: patch, explanation, confidence.
        """

    async def health_check(self) -> bool:
        """Return ``True`` if the provider is reachable."""
        return True


class _NullProvider(BaseInference):
    """Fallback provider when no AI backend is configured."""

    async def analyze(self, crash_context: str) -> dict[str, Any]:
        log.debug("ai_provider.null.analyze")
        return {
            "bug_type": "unknown",
            "exploitability": 0.0,
            "root_cause": "AI provider not configured — skipping deep analysis",
            "vulnerability_type": "unknown",
            "confidence": 0.0,
        }

    async def suggest_patch(self, root_cause: str) -> dict[str, Any]:
        log.debug("ai_provider.null.patch")
        return {
            "patch": "",
            "explanation": "AI provider not configured — skipping patch generation",
            "confidence": 0.0,
        }


# ── Ollama provider (local) ─────────────────────────────────────────────────

class OllamaProvider(BaseInference):
    """Inference via a local Ollama instance."""

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.1:8b",
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    async def analyze(self, crash_context: str) -> dict[str, Any]:
        return await self._chat(
            system=_TRIAGE_SYSTEM_PROMPT,
            user=crash_context,
        )

    async def suggest_patch(self, root_cause: str) -> dict[str, Any]:
        return await self._chat(
            system=_PATCH_SYSTEM_PROMPT,
            user=f"Root cause analysis:\n{root_cause}",
        )

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def _chat(self, system: str, user: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": "json",
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        raw = data.get("message", {}).get("content", "")
        return _safe_parse_json(raw)


# ── Venice provider (cloud) ──────────────────────────────────────────────────

class VeniceProvider(BaseInference):
    """Inference via the Venice API (OpenAI-compatible)."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str = "llama-3.3-70b",
        base_url: str = "https://api.venice.ai/api/v1",
        timeout: float = 120.0,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def analyze(self, crash_context: str) -> dict[str, Any]:
        return await self._chat(
            system=_TRIAGE_SYSTEM_PROMPT,
            user=crash_context,
        )

    async def suggest_patch(self, root_cause: str) -> dict[str, Any]:
        return await self._chat(
            system=_PATCH_SYSTEM_PROMPT,
            user=f"Root cause analysis:\n{root_cause}",
        )

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return resp.status_code == 200
        except Exception:
            return False

    async def _chat(self, system: str, user: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        raw = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return _safe_parse_json(raw)


# ── Factory ───────────────────────────────────────────────────────────────────


def get_provider() -> BaseInference:
    """Return the configured inference provider.

    Falls back to :class:`_NullProvider` when no provider is configured.
    """
    settings = get_settings()
    provider_name = (settings.ai_provider or "").lower().strip()

    if provider_name == "ollama":
        log.info("ai_provider.ollama", model=settings.ai_model)
        return OllamaProvider(
            base_url=getattr(settings, "ollama_url", "http://localhost:11434"),
            model=settings.ai_model or "llama3.1:8b",
        )

    if provider_name == "venice":
        api_key = settings.ai_api_key
        if not api_key:
            log.warning("ai_provider.venice.no_api_key")
            return _NullProvider()
        log.info("ai_provider.venice", model=settings.ai_model)
        return VeniceProvider(
            api_key=api_key,
            model=settings.ai_model or "llama-3.3-70b",
        )

    if provider_name:
        log.warning("ai_provider.unknown", provider=provider_name)

    log.debug("ai_provider.null")
    return _NullProvider()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _safe_parse_json(text: str) -> dict[str, Any]:
    """Best-effort JSON extraction from an LLM response."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    try:
        data: object = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                data = json.loads(text[start : end + 1])
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass
    log.warning("ai_provider.json_parse_failed", text_preview=text[:200])
    return {}


__all__ = [
    "BaseInference",
    "OllamaProvider",
    "VeniceProvider",
    "get_provider",
]
