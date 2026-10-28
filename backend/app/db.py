"""Stores scan METADATA only (verdict, score, latency, cost). Never the screenshot or message text."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.schemas import ScanResponse, StatsResponse


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    input_kind: Mapped[str] = mapped_column(String(16))
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    ai_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scam_type: Mapped[str] = mapped_column(String(40))
    link_count: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    model: Mapped[str | None] = mapped_column(String(40), nullable=True)
    degraded: Mapped[bool] = mapped_column(Boolean, default=False)


class FeedbackRow(Base):
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    correct: Mapped[bool] = mapped_column(Boolean)
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)


class Store:
    def __init__(self, url: str) -> None:
        kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {"pool_pre_ping": True}
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
        self.engine = create_engine(url, **kwargs)
        self.Session = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)

    def save_scan(self, scan: ScanResponse, input_kind: str) -> None:
        with self.Session.begin() as s:
            s.add(
                ScanRow(
                    id=scan.id,
                    input_kind=input_kind,
                    verdict=scan.verdict,
                    risk_score=scan.risk_score,
                    ai_score=scan.score_breakdown.ai_score,
                    scam_type=scan.scam_type,
                    link_count=len(scan.links),
                    latency_ms=scan.meta.latency_ms,
                    cost_usd=scan.meta.cost_usd,
                    model=scan.meta.model,
                    degraded=scan.meta.degraded,
                )
            )

    def save_feedback(self, scan_id: str, correct: bool, note: str | None) -> bool:
        with self.Session.begin() as s:
            if s.get(ScanRow, scan_id) is None:
                return False
            # One answer per scan: a second submit replaces the first, so the feedback numbers can't be stuffed.
            row = s.scalar(select(FeedbackRow).where(FeedbackRow.scan_id == scan_id))
            if row is None:
                s.add(FeedbackRow(scan_id=scan_id, correct=correct, note=note))
            else:
                row.correct, row.note, row.created_at = correct, note, datetime.now(UTC)
            return True

    def stats(self) -> StatsResponse:
        with Session(self.engine) as s:
            total = s.scalar(select(func.count(ScanRow.id))) or 0
            by_verdict = dict(s.execute(select(ScanRow.verdict, func.count()).group_by(ScanRow.verdict)).all())
            types = Counter(
                dict(
                    s.execute(
                        select(ScanRow.scam_type, func.count()).where(ScanRow.scam_type != "none").group_by(ScanRow.scam_type)
                    ).all()
                )
            )
            avg_latency, avg_cost = s.execute(
                select(func.avg(ScanRow.latency_ms), func.avg(ScanRow.cost_usd)).where(ScanRow.degraded.is_(False))
            ).one()
            fb_total = s.scalar(select(func.count(FeedbackRow.id))) or 0
            fb_correct = s.scalar(select(func.count(FeedbackRow.id)).where(FeedbackRow.correct.is_(True))) or 0
            degraded = s.scalar(select(func.count(ScanRow.id)).where(ScanRow.degraded.is_(True))) or 0
        return StatsResponse(
            total_scans=total,
            by_verdict=by_verdict,
            top_scam_types=types.most_common(6),
            avg_latency_ms=round(avg_latency, 1) if avg_latency is not None else None,
            avg_cost_usd=round(avg_cost, 5) if avg_cost is not None else None,
            feedback_count=fb_total,
            feedback_agreement=round(fb_correct / fb_total, 3) if fb_total else None,
            degraded_scans=degraded,
        )
