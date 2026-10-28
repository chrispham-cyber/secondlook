"""API and model-output schemas."""

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high"]
Verdict = Literal["likely_safe", "suspicious", "likely_scam", "scam"]
Source = Literal["ai", "link_check", "pattern"]

SCAM_TYPES = [
    "none",
    "toll_or_parking_payment",
    "package_delivery",
    "bank_or_payment_app",
    "account_login_phishing",
    "government_impersonation",
    "tech_support",
    "family_emergency",
    "romance",
    "investment_or_crypto",
    "job_or_task",
    "prize_or_lottery",
    "marketplace_or_overpayment",
    "subscription_or_invoice",
    "utility_shutoff",
    "wrong_number_opener",
    "other",
]

CHANNELS = ["sms", "email", "chat_app", "social_media", "web_page", "phone_call", "marketplace", "other", "unknown"]


# ---------- What Claude returns (structured output) ----------


class AIRedFlag(BaseModel):
    title: str
    detail: str
    severity: Severity


class AIAnalysis(BaseModel):
    extracted_text: str
    channel: str
    claimed_sender: str
    urls: list[str]
    scam_type: str
    scam_probability: int
    red_flags: list[AIRedFlag]
    safe_signals: list[str]
    headline: str
    what_to_do: list[str]


def ai_analysis_json_schema() -> dict:
    """JSON schema for structured outputs. Kept explicit (no min/max keywords) so it
    stays inside the structured-output schema subset; values are clamped in code."""
    red_flag = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "detail": {"type": "string"},
            "severity": {"type": "string", "enum": ["low", "medium", "high"]},
        },
        "required": ["title", "detail", "severity"],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "properties": {
            "extracted_text": {"type": "string"},
            "channel": {"type": "string", "enum": CHANNELS},
            "claimed_sender": {"type": "string"},
            "urls": {"type": "array", "items": {"type": "string"}},
            "scam_type": {"type": "string", "enum": SCAM_TYPES},
            "scam_probability": {"type": "integer"},
            "red_flags": {"type": "array", "items": red_flag},
            "safe_signals": {"type": "array", "items": {"type": "string"}},
            "headline": {"type": "string"},
            "what_to_do": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "extracted_text",
            "channel",
            "claimed_sender",
            "urls",
            "scam_type",
            "scam_probability",
            "red_flags",
            "safe_signals",
            "headline",
            "what_to_do",
        ],
        "additionalProperties": False,
    }


# ---------- Link checks ----------


class LinkCheck(BaseModel):
    name: str
    detail: str
    severity: Severity


class LinkReport(BaseModel):
    url: str
    host: str
    registrable_domain: str
    official_brand: str | None = None  # set when the domain IS a known official domain
    domain_age_days: int | None = None
    on_blocklist: bool = False
    checks: list[LinkCheck] = []


# ---------- API response ----------


class RedFlag(BaseModel):
    title: str
    detail: str
    severity: Severity
    source: Source


class ScoreAdjustment(BaseModel):
    reason: str
    min_score: int


class ScoreBreakdown(BaseModel):
    ai_score: int | None
    text_model_score: int | None = None
    adjustments: list[ScoreAdjustment]


class ScanMeta(BaseModel):
    model: str | None
    latency_ms: int
    cost_usd: float
    input_tokens: int
    output_tokens: int
    degraded: bool = False
    degraded_reason: str | None = None


class ScanResponse(BaseModel):
    id: str
    risk_score: int = Field(ge=0, le=100)
    verdict: Verdict
    headline: str
    scam_type: str
    channel: str
    claimed_sender: str
    red_flags: list[RedFlag]
    safe_signals: list[str]
    what_to_do: list[str]
    links: list[LinkReport]
    extracted_text: str
    score_breakdown: ScoreBreakdown
    meta: ScanMeta


class FeedbackRequest(BaseModel):
    correct: bool
    note: str | None = Field(default=None, max_length=500)


class StatsResponse(BaseModel):
    total_scans: int
    by_verdict: dict[str, int]
    top_scam_types: list[tuple[str, int]]
    avg_latency_ms: float | None
    avg_cost_usd: float | None
    feedback_count: int
    feedback_agreement: float | None
    degraded_scans: int
