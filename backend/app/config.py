from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Which AI reads the messages: "anthropic" (Claude API) or "ollama" (a local model, free).
    llm_provider: Literal["anthropic", "ollama"] = "anthropic"

    # Ollama. Run `ollama pull <model>` first; the model must support vision for screenshots.
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3.5:35b"  # best of the local models we evaluated; see evals/METRICS.md
    ollama_think: bool | None = None  # None = model default; false speeds up thinking models like qwen3.5
    ollama_num_ctx: int = 8192
    ollama_timeout_seconds: float = 180.0

    # Claude. Read from the environment or backend/.env; never commit it.
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-opus-5-5"
    anthropic_effort: str = "medium"  # low | medium | high | xhigh | max
    llm_timeout_seconds: float = 60.0
    llm_max_tool_rounds: int = 3

    # Storage (only scan metadata, never the screenshot or message text)
    database_url: str = "sqlite:///./secondlook.db"

    # Network-based link checks (RDAP domain age, phishing feeds)
    network_checks: bool = True
    rdap_timeout_seconds: float = 4.0
    feeds_refresh_hours: float = 6.0

    # Abuse protection
    max_upload_mb: float = 8.0
    max_text_chars: int = 10_000
    rate_limit_per_minute: int = 10

    # Uploaded documents (PDF, .docx). Read only in a separate, resource-limited process.
    max_document_pages: int = 30
    document_timeout_seconds: float = 15.0
    document_memory_mb: int = 512
    document_concurrency: int = 2
    # Optional ClamAV daemon. When set, every document is virus-scanned first, and documents are
    # refused while it is unreachable (fail closed).
    clamav_host: str | None = None
    clamav_port: int = 3310
    trust_proxy_headers: bool = False  # set true when running behind the Next.js proxy

    cors_origins: str = "http://localhost:3000"


@lru_cache
def get_settings() -> Settings:
    return Settings()
