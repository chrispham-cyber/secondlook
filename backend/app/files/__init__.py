"""Uploaded documents (PDF, Word .docx): check that a file is safe before anything reads it.

Order, safest first:
  1. What the file really is, from its bytes. Programs, scripts, shortcuts, old Office files, archives,
     and web pages are refused without being opened.
  2. Raw-byte checks: the EICAR test signature and, for PDFs, active features such as JavaScript.
  3. ClamAV, when configured. If it is configured but unreachable, files are refused (fail closed).
  4. The sandboxed reader (worker.py, a separate resource-limited process) walks the structure for
     macros, embedded programs, remote templates, and DDE, and only then extracts text and links.

Any finding with risk >= BLOCK_AT blocks the file: its contents are never read into the app or sent
to the AI, and the person is told why. Lesser findings are shown as warnings and the text is checked
like any message.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field

from app.files.clamav import ClamAVError, scan_bytes
from app.files.sandbox import SandboxError, read_document
from app.files.static import BLOCK_AT, Finding, eicar, pdf_names, sniff
from app.schemas import FileCheck, FileFinding

ACCEPTED = ("pdf", "docx")


class AntivirusUnavailable(RuntimeError):
    pass


@dataclass
class Inspection:
    check: FileCheck
    risk: int  # 0-100, the worst finding's risk
    text: str = ""
    urls: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.check.status == "blocked"


class DocumentInspector:
    def __init__(
        self,
        *,
        max_pages: int = 30,
        max_chars: int = 10_000,
        timeout_s: float = 15.0,
        memory_mb: int = 512,
        concurrency: int = 2,
        clamav_host: str | None = None,
        clamav_port: int = 3310,
    ) -> None:
        self.max_pages, self.max_chars = max_pages, max_chars
        self.timeout_s, self.memory_mb = timeout_s, memory_mb
        self.concurrency = concurrency
        self.clamav_host, self.clamav_port = clamav_host, clamav_port
        self._slots: asyncio.Semaphore | None = None

    async def inspect(self, data: bytes) -> Inspection:
        sha = hashlib.sha256(data).hexdigest()
        checks_run = ["file type from its contents"]
        sniffed = sniff(data)
        findings: list[Finding] = list(sniffed.findings) + eicar(data)
        checks_run.append("antivirus test signature")

        def result(file_type: str, extra: list[Finding] = (), **kw) -> Inspection:
            allf = _dedupe(findings + list(extra))
            risk = max((f.risk for f in allf), default=0)
            status = "blocked" if risk >= BLOCK_AT else "warning" if any(f.severity != "low" for f in allf) else "clean"
            check = FileCheck(
                file_type=file_type,
                sha256=sha,
                status=status,
                findings=[FileFinding(name=f.name, title=f.title, detail=f.detail, severity=f.severity) for f in allf],
                checks_run=checks_run,
                pages=kw.get("pages"),
                text_chars=len(kw.get("text", "")),
                truncated=kw.get("truncated", False),
            )
            return Inspection(check, risk, kw.get("text", "") if status != "blocked" else "", kw.get("urls", []))

        if sniffed.file_type not in ACCEPTED or _worst(findings) >= BLOCK_AT:
            return result(sniffed.file_type)

        if sniffed.file_type == "pdf":
            findings += pdf_names(data)
            checks_run.append("PDF active-content scan")
            if _worst(findings) >= BLOCK_AT:
                return result("pdf")

        if self.clamav_host:
            try:
                hit = await scan_bytes(data, self.clamav_host, self.clamav_port)
            except ClamAVError as exc:
                raise AntivirusUnavailable(str(exc)) from exc
            checks_run.append("ClamAV antivirus")
            if hit:
                findings.append(
                    Finding(
                        "antivirus_detection",
                        "high",
                        "Antivirus found malware",
                        f"ClamAV identified this file as {hit}.",
                        99,
                    )
                )
                return result(sniffed.file_type)

        if self._slots is None:
            self._slots = asyncio.Semaphore(self.concurrency)
        checks_run.append("structure scan in an isolated reader")
        try:
            read = await read_document(
                sniffed.file_type,
                data,
                slots=self._slots,
                max_pages=self.max_pages,
                max_chars=self.max_chars,
                timeout_s=self.timeout_s,
                memory_mb=self.memory_mb,
            )
        except SandboxError as exc:
            reason = {
                "timeout": "It took too long to read, which happens with files built to hang document readers.",
                "memory": "It needed far more memory than a normal document.",
            }.get(str(exc), "Our reader couldn't make sense of it, which can mean it was built to attack document readers.")
            return result(
                sniffed.file_type,
                [Finding("unreadable_file", "high", "The file couldn't be read safely", reason, 70)],
            )

        extra = [
            Finding(f["name"], f["severity"], f["title"], f["detail"], int(f.get("risk", 0)))
            for f in read.get("findings", [])
            if isinstance(f, dict)
        ]
        text = str(read.get("text", ""))[: self.max_chars]
        urls = [str(u) for u in read.get("urls", [])][:50]
        return result(
            str(read.get("file_type", sniffed.file_type)),
            extra,
            pages=read.get("pages"),
            text=text,
            urls=urls,
            truncated=bool(read.get("truncated")),
        )


def _worst(findings: list[Finding]) -> int:
    return max((f.risk for f in findings), default=0)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    by_name: dict[str, Finding] = {}
    for f in findings:
        if f.name not in by_name or f.risk > by_name[f.name].risk:
            by_name[f.name] = f
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(by_name.values(), key=lambda f: (order.get(f.severity, 3), -f.risk))
