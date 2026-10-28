"""Test doubles: a fake Anthropic client and canned analyses. No network, no API spend."""

from __future__ import annotations

import json
from types import SimpleNamespace

from app.llm import LLMResult, LLMUnavailable, ScamAnalyzer
from app.schemas import AIAnalysis


def usage(inp=1000, out=300):
    return SimpleNamespace(input_tokens=inp, output_tokens=out, cache_read_input_tokens=0, cache_creation_input_tokens=0)


def tool_use_response(urls: list[str]):
    return SimpleNamespace(
        model="claude-opus-5-5",
        usage=usage(),
        stop_reason="tool_use",
        stop_details=None,
        content=[SimpleNamespace(type="tool_use", id="toolu_1", name="check_links", input={"urls": urls})],
    )


def final_response(analysis: dict):
    return SimpleNamespace(
        model="claude-opus-5-5",
        usage=usage(),
        stop_reason="end_turn",
        stop_details=None,
        content=[SimpleNamespace(type="text", text=json.dumps(analysis))],
    )


def refusal_response():
    return SimpleNamespace(
        model="claude-opus-5-5",
        usage=usage(10, 0),
        stop_reason="refusal",
        stop_details=SimpleNamespace(category="cyber"),
        content=[],
    )


class FakeClient:
    """Mimics client.beta.messages.create by replaying scripted responses."""

    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.calls: list[dict] = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


def analysis(**overrides) -> dict:
    base = {
        "extracted_text": "",
        "channel": "sms",
        "claimed_sender": "",
        "urls": [],
        "scam_type": "none",
        "scam_probability": 5,
        "red_flags": [],
        "safe_signals": ["Looks like a normal personal message."],
        "headline": "This looks like a normal message.",
        "what_to_do": ["No action needed."],
    }
    return base | overrides


class FakeAnalyzer(ScamAnalyzer):
    """Skips Claude entirely; optionally exercises the link tool like the model would."""

    def __init__(self, result: dict | None = None, fail: str | None = None, call_tool_with: list[str] | None = None):
        self.result, self.fail, self.call_tool_with = result, fail, call_tool_with

    async def analyze(self, text, image, check_links):
        if self.fail:
            raise LLMUnavailable(self.fail)
        checked = await check_links(self.call_tool_with) if self.call_tool_with else []
        return LLMResult(
            analysis=AIAnalysis.model_validate(self.result or analysis()),
            model="fake-model",
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.001,
            links_checked=checked,
        )
