"""LLM factory with a deterministic offline fallback.

The rest of the system never instantiates a chat model directly. Instead it
calls :func:`get_chat_model` / :func:`complete`. When ``OPENAI_API_KEY`` is set
(and offline mode is off) a real ``ChatOpenAI`` model is returned. Otherwise a
:class:`FallbackLLM` is used, which produces concise, template-based summaries
from the structured findings the tools already computed.

This keeps the whole product runnable, testable and demonstrable without any
third-party credentials, while remaining a drop-in upgrade to a live model.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional

from config import get_logger, get_settings

logger = get_logger(__name__)


class FallbackLLM:
    """A tiny, deterministic stand-in for a chat model.

    It does not attempt to be clever: given a prompt that embeds structured
    JSON findings, it returns a readable, bounded summary. This guarantees the
    agents produce useful, reproducible output offline (important for evals).
    """

    model_name = "fallback-deterministic"

    def invoke(self, prompt: str, **_: Any) -> str:
        return self._summarise(prompt)

    # The orchestrator/agents call ``generate`` for a plain-string completion.
    def generate(self, prompt: str, **_: Any) -> str:
        return self._summarise(prompt)

    @staticmethod
    def _summarise(prompt: str) -> str:
        """Extract any embedded JSON findings and render a short narrative."""
        findings = _extract_json_block(prompt)
        if findings is None:
            # Echo a bounded, sanitised view of the request.
            text = prompt.strip().replace("\n", " ")
            return (
                "[offline-summary] "
                + (text[:400] + ("..." if len(text) > 400 else ""))
            )

        lines: List[str] = ["[offline-summary]"]
        if isinstance(findings, dict):
            findings = [findings]
        for i, item in enumerate(findings[:10], start=1):
            if not isinstance(item, dict):
                lines.append(f"{i}. {item}")
                continue
            title = (
                item.get("title")
                or item.get("issue")
                or item.get("rule")
                or item.get("name")
                or item.get("control")
                or "finding"
            )
            sev = item.get("severity") or item.get("risk") or "info"
            detail = (
                item.get("recommendation")
                or item.get("description")
                or item.get("detail")
                or ""
            )
            lines.append(f"{i}. [{str(sev).upper()}] {title} — {detail}".rstrip(" —"))
        if not lines[1:]:
            lines.append("No structured findings were detected in the input.")
        return "\n".join(lines)


def _extract_json_block(prompt: str) -> Optional[Any]:
    """Best-effort extraction of the last JSON array/object in a prompt."""
    for opener, closer in (("[", "]"), ("{", "}")):
        start = prompt.find(opener)
        end = prompt.rfind(closer)
        if start != -1 and end != -1 and end > start:
            snippet = prompt[start : end + 1]
            try:
                return json.loads(snippet)
            except Exception:
                continue
    return None


class ChatModelWrapper:
    """Uniform ``.generate(prompt) -> str`` wrapper over a LangChain model."""

    def __init__(self, model: Any) -> None:
        self._model = model
        self.model_name = getattr(model, "model_name", getattr(model, "model", "llm"))

    def generate(self, prompt: str, **kwargs: Any) -> str:
        try:
            from langchain_core.messages import HumanMessage

            result = self._model.invoke([HumanMessage(content=prompt)], **kwargs)
            return getattr(result, "content", str(result))
        except Exception as exc:  # pragma: no cover - network/credential errors
            logger.warning("Live LLM call failed (%s); using fallback.", exc)
            return FallbackLLM().generate(prompt)

    def invoke(self, prompt: str, **kwargs: Any) -> str:
        return self.generate(prompt, **kwargs)


_CACHED_MODEL: Optional[Any] = None


def get_chat_model(force_offline: bool = False) -> Any:
    """Return a chat model exposing ``.generate(prompt) -> str``.

    Returns a live ``ChatOpenAI`` (wrapped) when configured, otherwise a
    :class:`FallbackLLM`.
    """
    global _CACHED_MODEL
    if _CACHED_MODEL is not None and not force_offline:
        return _CACHED_MODEL

    settings = get_settings()
    if force_offline or settings.offline:
        logger.info("LLM: using deterministic offline fallback model.")
        _CACHED_MODEL = FallbackLLM()
        return _CACHED_MODEL

    try:
        from langchain_openai import ChatOpenAI

        model = ChatOpenAI(
            model=settings.csai_llm_model,
            temperature=settings.csai_temperature,
            api_key=settings.openai_api_key,
        )
        logger.info("LLM: using live ChatOpenAI model '%s'.", settings.csai_llm_model)
        _CACHED_MODEL = ChatModelWrapper(model)
    except Exception as exc:  # pragma: no cover - import/credential errors
        logger.warning("Could not init ChatOpenAI (%s); using fallback.", exc)
        _CACHED_MODEL = FallbackLLM()
    return _CACHED_MODEL


def complete(prompt: str, force_offline: bool = False) -> str:
    """Convenience one-shot completion."""
    return get_chat_model(force_offline=force_offline).generate(prompt)


def reset_llm_cache() -> None:
    """Reset the cached model (used by tests / when settings change)."""
    global _CACHED_MODEL
    _CACHED_MODEL = None
