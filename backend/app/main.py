from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.db import Store
from app.images import ImageError, prepare_image
from app.pipeline import LinkAnalyzer, ScanPipeline, ScanUnavailable
from app.providers import Analyzer, make_analyzer, model_label
from app.ratelimit import RateLimiter
from app.schemas import FeedbackRequest, ScanResponse, StatsResponse
from app.signals.blocklist import Blocklist

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("secondlook")


def create_app(
    settings: Settings | None = None, analyzer: Analyzer | None = None, http: httpx.AsyncClient | None = None
) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = http or httpx.AsyncClient(headers={"User-Agent": "SecondLook/0.1 (scam checker)"})
        blocklist = Blocklist()
        task = None
        if settings.network_checks:
            task = asyncio.create_task(blocklist.refresh_forever(client, settings.feeds_refresh_hours))
        app.state.settings = settings
        app.state.blocklist = blocklist
        app.state.store = Store(settings.database_url)
        app.state.limiter = RateLimiter(settings.rate_limit_per_minute)
        app.state.pipeline = ScanPipeline(
            settings, analyzer or make_analyzer(settings), LinkAnalyzer(settings, client, blocklist)
        )
        yield
        if task:
            task.cancel()
        if http is None:
            await client.aclose()

    app = FastAPI(title="Second Look API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    def client_ip(request: Request) -> str:
        if settings.trust_proxy_headers:
            # The right-most entry is the one our own proxy added; anything to its left is client-supplied.
            fwd = request.headers.get("x-forwarded-for")
            if fwd:
                return fwd.split(",")[-1].strip()
        return request.client.host if request.client else "unknown"

    @app.get("/api/health")
    async def health(request: Request) -> dict:
        bl: Blocklist = request.app.state.blocklist
        return {
            "status": "ok",
            "provider": settings.llm_provider,
            "model": model_label(settings),
            "ai_key_configured": settings.llm_provider == "ollama"
            or bool(settings.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")),
            "blocklist": {"sources": bl.sources_ok, "entries": len(bl.urls), "loaded_at": bl.loaded_at},
        }

    @app.post("/api/scan", response_model=ScanResponse)
    async def scan(request: Request, image: UploadFile | None = File(None), text: str | None = Form(None)):
        allowed, retry_after = request.app.state.limiter.allow(client_ip(request))
        if not allowed:
            return JSONResponse(
                {"detail": "Too many scans. Please wait a minute and try again."},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        text = (text or "").strip() or None
        if text and len(text) > settings.max_text_chars:
            raise HTTPException(413, f"Text is too long (max {settings.max_text_chars:,} characters).")

        prepared = None
        if image is not None and image.filename:
            max_bytes = int(settings.max_upload_mb * 1_000_000)
            data = await image.read(max_bytes + 1)
            try:
                prepared = await run_in_threadpool(prepare_image, data, max_bytes)
            except ImageError as exc:
                raise HTTPException(400, str(exc)) from exc
        if prepared is None and not text:
            raise HTTPException(400, "Upload a screenshot or paste the message text.")

        try:
            result = await request.app.state.pipeline.run(text, prepared)
        except ScanUnavailable as exc:
            raise HTTPException(503, f"We can't read screenshots right now: {exc} You can paste the text instead.") from exc

        kind = "image+text" if prepared and text else "image" if prepared else "text"
        try:
            await run_in_threadpool(request.app.state.store.save_scan, result, kind)
        except Exception:  # metrics must never break a scan
            log.exception("failed to record scan metadata")
        log.info(
            "scan %s kind=%s verdict=%s score=%d latency=%dms cost=$%.4f degraded=%s",
            result.id,
            kind,
            result.verdict,
            result.risk_score,
            result.meta.latency_ms,
            result.meta.cost_usd,
            result.meta.degraded,
        )
        return result

    @app.post("/api/scans/{scan_id}/feedback", status_code=204)
    async def feedback(scan_id: str, body: FeedbackRequest, request: Request):
        allowed, retry_after = request.app.state.limiter.allow(client_ip(request))
        if not allowed:
            return JSONResponse(
                {"detail": "Too many requests. Please wait a minute and try again."},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        ok = await run_in_threadpool(request.app.state.store.save_feedback, scan_id, body.correct, body.note)
        if not ok:
            raise HTTPException(404, "Scan not found.")

    @app.get("/api/stats", response_model=StatsResponse)
    async def stats(request: Request) -> StatsResponse:
        return await run_in_threadpool(request.app.state.store.stats)

    return app


app = create_app()
