"""
Local LLM client (Ollama) with Pydantic schema-constrained output.

ECHO calls Ollama with format=<json_schema_dict> so the model is forced
to produce JSON that conforms to a Pydantic model. If the model still
emits malformed JSON (rare, but happens), we retry once with a clarified
prompt, then fall back to a regex JSON extractor.

ENV:
    OLLAMA_HOST     — e.g. http://127.0.0.1:11434 (default)
    ECHO_MODEL      — e.g. qwen2.5:7b-instruct-q4_K_M (default)
    ECHO_CRITIC_MODEL — optional, distinct model for the critic
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Type, TypeVar

import ollama
from pydantic import BaseModel, ValidationError

log = logging.getLogger("echo.llm")

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
ECHO_MODEL = os.environ.get("ECHO_MODEL", "qwen2.5:7b-instruct-q4_K_M")
ECHO_CRITIC_MODEL = os.environ.get("ECHO_CRITIC_MODEL", ECHO_MODEL)

T = TypeVar("T", bound=BaseModel)

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


class LLMError(RuntimeError):
    """LLM produced something we cannot use, even after retry+fallback."""


def _client() -> ollama.Client:
    return ollama.Client(host=OLLAMA_HOST)


def chat_json(
    *,
    schema: Type[T],
    system: str,
    user: str,
    model: str | None = None,
    temperature: float = 0.1,
    num_predict: int = 1024,
) -> tuple[T, int]:
    """Call Ollama and parse the response into `schema`.

    Returns (validated_model, tokens_used_estimate).
    """
    use_model = model or ECHO_MODEL
    client = _client()

    json_schema = schema.model_json_schema()

    def _attempt(extra_user: str = "") -> str:
        resp = client.chat(
            model=use_model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user + extra_user},
            ],
            format=json_schema,           # grammar-constrained
            options={
                "temperature": temperature,
                "num_predict": num_predict,
            },
        )
        return resp["message"]["content"]

    raw = _attempt()
    tokens = max(len(raw) // 4, 1)  # rough estimate

    try:
        return schema.model_validate_json(raw), tokens
    except ValidationError:
        pass

    # retry with explicit "JSON only, conform to schema" addendum
    log.warning("LLM produced malformed JSON, retrying with stricter prompt")
    raw2 = _attempt(
        "\n\nIMPORTANT: respond with ONE JSON object that conforms exactly "
        "to the requested schema. No prose. No code fences."
    )
    try:
        return schema.model_validate_json(raw2), tokens + len(raw2) // 4
    except ValidationError:
        pass

    # Fallback: extract first {...} block via regex.
    m = _JSON_RE.search(raw2)
    if m:
        try:
            return schema.model_validate_json(m.group(0)), tokens + len(raw2) // 4
        except ValidationError as e:
            raise LLMError(f"validation failed after fallback: {e}") from e

    raise LLMError(f"could not extract JSON from LLM output: {raw2[:200]!r}")
