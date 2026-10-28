"""Picks the AI that reads messages, based on LLM_PROVIDER."""

from __future__ import annotations

from typing import Protocol

from app.config import Settings
from app.llm import LinkChecker, LLMResult, ScamAnalyzer


class Analyzer(Protocol):
    async def analyze(self, text: str | None, image: tuple[str, str] | None, check_links: LinkChecker) -> LLMResult: ...


def make_analyzer(settings: Settings) -> Analyzer:
    if settings.llm_provider == "ollama":
        from app.llm_ollama import OllamaAnalyzer

        return OllamaAnalyzer(settings)
    return ScamAnalyzer(settings)


def model_label(settings: Settings) -> str:
    return f"ollama/{settings.ollama_model}" if settings.llm_provider == "ollama" else settings.anthropic_model
