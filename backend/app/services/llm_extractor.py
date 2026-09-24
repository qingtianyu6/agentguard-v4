from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any

from .p2cv import parse_policy

SCHEMA_VERSION = "requirement-v3.0"

SYSTEM_PROMPT = """You are AgentGuard's policy compiler front-end. Convert the policy to strict JSON only.
Required keys: subject, action, resource, destination, effect, conditions, temporal_constraints,
exception, evidence_spans, ambiguity_flags. Do not invent permissions or exceptions that are not
supported by the source text. Keep canonical values compatible with AgentGuard's policy schema.
"""


@dataclass
class ExtractionResult:
    structured: dict[str, Any]
    provider: str
    model: str
    fallback_used: bool
    raw: dict[str, Any] | None = None
    warning: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "structured": self.structured,
            "provider": self.provider,
            "model": self.model,
            "fallback_used": self.fallback_used,
            "schema_version": SCHEMA_VERSION,
            "warning": self.warning,
        }


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].lstrip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("LLM response did not contain a JSON object")
    return json.loads(text[start : end + 1])


def _normalize(structured: dict[str, Any], source_text: str) -> dict[str, Any]:
    deterministic = parse_policy(source_text)
    out = dict(deterministic)
    for key in [
        "subject", "action", "resource", "destination", "effect", "conditions",
        "temporal_constraints", "exception", "evidence_spans", "ambiguity_flags",
    ]:
        if key in structured and structured[key] not in (None, ""):
            out[key] = structured[key]
    out["source_text"] = source_text
    out.setdefault("clauses", deterministic.get("clauses", []))
    out.setdefault("conditions", [])
    out.setdefault("temporal_constraints", [])
    out.setdefault("ambiguity_flags", [])
    out.setdefault("evidence_spans", deterministic.get("evidence_spans", []))
    return out


def deterministic_extract(text: str) -> ExtractionResult:
    return ExtractionResult(
        structured=parse_policy(text),
        provider="deterministic",
        model="agentguard-rule-extractor-v3",
        fallback_used=False,
    )


def openai_compatible_extract(text: str) -> ExtractionResult:
    base = os.getenv("AGENTGUARD_LLM_BASE_URL", "").rstrip("/")
    model = os.getenv("AGENTGUARD_LLM_MODEL", "")
    key = os.getenv("AGENTGUARD_LLM_API_KEY", "")
    if not base or not model:
        raise RuntimeError("AGENTGUARD_LLM_BASE_URL and AGENTGUARD_LLM_MODEL are required")
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
    }
    req = urllib.request.Request(
        base + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            **({"Authorization": f"Bearer {key}"} if key else {}),
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=float(os.getenv("AGENTGUARD_LLM_TIMEOUT", "8"))) as response:
        raw = json.loads(response.read().decode("utf-8"))
    content = raw["choices"][0]["message"]["content"]
    structured = _normalize(_extract_json(content), text)
    return ExtractionResult(
        structured=structured,
        provider="openai-compatible",
        model=model,
        fallback_used=False,
        raw=raw,
    )


def extract_policy(text: str, provider: str | None = None) -> ExtractionResult:
    provider = (provider or os.getenv("AGENTGUARD_EXTRACTOR", "auto")).lower()
    if provider in {"deterministic", "rules", "local"}:
        return deterministic_extract(text)
    if provider in {"openai-compatible", "llm", "auto"}:
        configured = bool(os.getenv("AGENTGUARD_LLM_BASE_URL") and os.getenv("AGENTGUARD_LLM_MODEL"))
        if provider != "auto" or configured:
            try:
                return openai_compatible_extract(text)
            except Exception as exc:
                fallback = deterministic_extract(text)
                fallback.fallback_used = True
                fallback.warning = f"LLM extractor unavailable; deterministic fallback used: {type(exc).__name__}: {exc}"
                return fallback
    return deterministic_extract(text)


def provider_status() -> dict[str, Any]:
    configured = bool(os.getenv("AGENTGUARD_LLM_BASE_URL") and os.getenv("AGENTGUARD_LLM_MODEL"))
    return {
        "default": os.getenv("AGENTGUARD_EXTRACTOR", "auto"),
        "providers": [
            {"id": "deterministic", "available": True, "offline": True},
            {
                "id": "openai-compatible",
                "available": configured,
                "offline": False,
                "model": os.getenv("AGENTGUARD_LLM_MODEL", ""),
                "base_url_configured": bool(os.getenv("AGENTGUARD_LLM_BASE_URL")),
            },
        ],
        "schema_version": SCHEMA_VERSION,
    }
