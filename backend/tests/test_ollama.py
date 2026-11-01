import json

import httpx
import pytest
import respx

from app.config import Settings
from app.llm import LLMUnavailable
from app.llm_ollama import LOCAL_SYSTEM_PROMPT, OllamaAnalyzer
from app.providers import make_analyzer
from app.schemas import LinkReport
from app.signals.links import normalize_url
from tests.fakes import analysis

BASE = "http://ollama.test"


def settings(**kw) -> Settings:
    return Settings(llm_provider="ollama", ollama_base_url=BASE, ollama_model="vision-model", **kw)


def chat_reply(content: dict, **extra) -> httpx.Response:
    return httpx.Response(
        200, json={"message": {"content": json.dumps(content)}, "prompt_eval_count": 100, "eval_count": 40} | extra
    )


async def fake_check(urls: list[str]) -> list[LinkReport]:
    # Like the real checker: normalize and de-duplicate.
    unique = dict.fromkeys(normalize_url(u) for u in urls)
    return [LinkReport(url=u, host=u, registrable_domain=u) for u in unique if u]


def test_factory_and_prompt():
    assert isinstance(make_analyzer(settings()), OllamaAnalyzer)
    assert "check_links" not in LOCAL_SYSTEM_PROMPT and "<link_checks>" in LOCAL_SYSTEM_PROMPT


@respx.mock
async def test_text_scan_is_one_call_with_link_facts():
    route = respx.post(f"{BASE}/api/chat").mock(
        return_value=chat_reply(analysis(scam_probability=92, scam_type="package_delivery"))
    )
    result = await OllamaAnalyzer(settings()).analyze("USPS: fix your address at usps-help.top", None, fake_check)

    assert route.call_count == 1
    body = json.loads(route.calls[0].request.content)
    assert body["format"]["type"] == "object" and body["stream"] is False
    assert "think" not in body  # only sent when configured
    assert "usps-help.top" in body["messages"][1]["content"].split("<link_checks>")[1]
    assert result.analysis.scam_probability == 92 and result.cost_usd == 0 and result.model == "ollama/vision-model"


@respx.mock
async def test_screenshot_reads_first_then_decides():
    route = respx.post(f"{BASE}/api/chat").mock(
        side_effect=[
            chat_reply({"extracted_text": "Pay toll at ezpass-pay.xyz", "urls": ["ezpass-pay.xyz"]}),
            chat_reply(analysis(scam_probability=88, extracted_text="ignored")),
        ]
    )
    result = await OllamaAnalyzer(settings(ollama_think=False)).analyze(None, ("image/png", "QUJD"), fake_check)

    first, second = (json.loads(c.request.content) for c in route.calls)
    assert first["messages"][1]["images"] == ["QUJD"] and second["messages"][1]["images"] == ["QUJD"]
    assert second["think"] is False
    assert "Pay toll at ezpass-pay.xyz" in second["messages"][1]["content"]
    assert result.analysis.extracted_text == "Pay toll at ezpass-pay.xyz"  # our copy wins over the model's
    assert [r.url for r in result.links_checked] == ["http://ezpass-pay.xyz"]


@respx.mock
@pytest.mark.parametrize(
    "response, message",
    [
        (httpx.ConnectError("refused"), "offline"),
        (httpx.Response(404, json={"error": "model not found"}), "offline"),
        (httpx.Response(200, json={"message": {"content": "not json"}}), "unreadable"),
        (chat_reply({"headline": "half an answer"}), "incomplete"),
    ],
)
async def test_failures_become_llm_unavailable(response, message):
    route = respx.post(f"{BASE}/api/chat")
    if isinstance(response, Exception):
        route.mock(side_effect=response)
    else:
        route.mock(return_value=response)
    with pytest.raises(LLMUnavailable, match=message):
        await OllamaAnalyzer(settings()).analyze("hello", None, fake_check)


@respx.mock
async def test_unreachable_ai_never_reveals_its_address():
    respx.post(f"{BASE}/api/chat").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(LLMUnavailable) as err:
        await OllamaAnalyzer(settings()).analyze("hello", None, fake_check)
    assert BASE not in str(err.value) and "11434" not in str(err.value)


async def test_a_full_queue_falls_back_instead_of_waiting():
    import asyncio

    analyzer = OllamaAnalyzer(settings(ollama_max_concurrent=1, ollama_queue_seconds=0.05))
    await analyzer._slots.acquire()  # another scan holds the only slot
    with pytest.raises(LLMUnavailable, match="busy"):
        await analyzer.analyze("hello", None, fake_check)
    analyzer._slots.release()
    assert not analyzer._slots.locked()
    await asyncio.sleep(0)


def test_edge_client_ip_header_is_used_for_rate_limits(tmp_path):
    from tests.fakes import FakeAnalyzer
    from tests.test_api import make_client

    with make_client(tmp_path, FakeAnalyzer(), client_ip_header="fly-client-ip", rate_limit_per_minute=2) as c:
        for _ in range(2):
            assert c.post("/api/domain", json={"domain": "a.com"}, headers={"fly-client-ip": "1.1.1.1"}).status_code == 200
        assert c.post("/api/domain", json={"domain": "a.com"}, headers={"fly-client-ip": "1.1.1.1"}).status_code == 429
        assert c.post("/api/domain", json={"domain": "a.com"}, headers={"fly-client-ip": "2.2.2.2"}).status_code == 200
