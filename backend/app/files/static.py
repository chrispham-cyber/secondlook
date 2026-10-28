"""Checks that look at a file's raw bytes without parsing it, so they are safe on anything.

- What the file really is, from its first bytes (the name and the browser's content type are ignored).
- The EICAR antivirus test string.
- For PDFs: the names of active features (JavaScript, Launch, embedded files...), including names
  disguised with #xx escapes the way pdfid does it. Compressed object streams can hide these, so
  the sandboxed reader (worker.py) walks the parsed document too.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# The industry-standard antivirus test file. Harmless, but every scanner reports it as malware.
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@dataclass(frozen=True)
class Finding:
    name: str
    severity: str  # low | medium | high
    title: str
    detail: str
    # How risky the file is if this is the worst finding. Anything >= BLOCK_AT is never parsed or sent to the AI.
    risk: int = 0


BLOCK_AT = 60

# What the first bytes say a file really is, for files we refuse. (prefix, type, finding)
_REFUSED: list[tuple[bytes, str, Finding]] = []


def _refuse(prefixes: tuple[bytes, ...], ftype: str, title: str, detail: str, risk: int) -> None:
    for p in prefixes:
        _REFUSED.append((p, ftype, Finding(f"file_is_{ftype}", "high", title, detail, risk)))


_PROGRAM = "This is a program that runs on a computer, not a document. Opening it could install malware."
_refuse((b"MZ",), "windows_program", "This file is a Windows program", _PROGRAM, 99)
_refuse((b"\x7fELF",), "linux_program", "This file is a program", _PROGRAM, 99)
_refuse(
    (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"),
    "mac_program",
    "This file is a Mac program",
    _PROGRAM,
    99,
)
_refuse((b"#!",), "script", "This file is a script", "This is a script that runs commands on a computer.", 95)
_refuse(
    (b"L\x00\x00\x00\x01\x14\x02\x00",),
    "windows_shortcut",
    "This file is a Windows shortcut",
    "Shortcut (.lnk) files can run any command when opened. They are a favorite way to spread malware.",
    95,
)
_refuse(
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
    "legacy_office",
    "Old-style Office file (.doc, .xls, .msg)",
    "Old Office formats can hide macros and exploits that we can't check safely. Ask the sender for a PDF, or take a "
    "screenshot of it on a device you trust.",
    70,
)
_refuse(
    (b"{\\rtf",),
    "rtf",
    "Rich Text file (.rtf)",
    "RTF files are often used to deliver exploits for old versions of Word, so we don't open them.",
    70,
)
_refuse(
    (b"Rar!", b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b"),
    "archive",
    "Compressed archive",
    "Archives can hide programs inside. We only accept PDF and Word (.docx) documents.",
    65,
)


@dataclass
class Sniffed:
    file_type: str  # pdf | docx | the refused type | unknown
    findings: list[Finding] = field(default_factory=list)


def sniff(data: bytes) -> Sniffed:
    head = data[:16]
    if data.startswith(b"%PDF-"):
        return Sniffed("pdf")
    if data.startswith(b"PK\x03\x04"):
        return Sniffed("docx")  # confirmed (or refused) by the sandboxed reader, which looks inside the zip
    for prefix, ftype, finding in _REFUSED:
        if head.startswith(prefix):
            return Sniffed(ftype, [finding])
    start = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if start.startswith((b"<!doctype html", b"<html", b"<svg", b"<?xml", b"<script")):
        return Sniffed(
            "web_page",
            [
                Finding(
                    "file_is_web_page",
                    "high",
                    "This file is a web page",
                    "Web page and SVG files can run code when opened, and are used to show fake sign-in pages offline.",
                    85,
                )
            ],
        )
    if b"%PDF-" in data[:1024]:
        # A PDF header after other bytes: a file that is two formats at once, a trick to slip past scanners.
        return Sniffed(
            "polyglot",
            [
                Finding(
                    "polyglot_file",
                    "high",
                    "A disguised file",
                    "The file starts like something else and only later says it is a PDF. Files built to be two "
                    "formats at once are used to sneak malware past scanners.",
                    85,
                )
            ],
        )
    return Sniffed(
        "unknown",
        [
            Finding(
                "unsupported_file",
                "medium",
                "Unsupported file type",
                "We can check PDF and Word (.docx) documents and screenshots. Other files aren't opened.",
                60,
            )
        ],
    )


def eicar(data: bytes) -> list[Finding]:
    if EICAR in data:
        return [
            Finding(
                "antivirus_test_file",
                "high",
                "Antivirus test signature found",
                "The file contains the EICAR test signature that every antivirus program reports as malware.",
                99,
            )
        ]
    return []


_NAME = re.compile(rb"/[^\s/<>\[\]()%{}]+")
_HEX = re.compile(rb"#([0-9a-fA-F]{2})")

# PDF name -> (finding name, severity, title, detail, risk)
_PDF_NAMES: dict[bytes, tuple[str, str, str, str, int]] = {
    b"/JavaScript": (
        "pdf_javascript",
        "high",
        "The PDF contains JavaScript",
        "Code inside a PDF can run when the file is opened. Ordinary letters, bills, and statements don't need it.",
        95,
    ),
    b"/JS": ("pdf_javascript", "high", "The PDF contains JavaScript", "", 95),
    b"/Launch": (
        "pdf_launch",
        "high",
        "The PDF tries to open a program",
        "The file contains an instruction to start another program on your computer.",
        95,
    ),
    b"/RichMedia": (
        "pdf_rich_media",
        "high",
        "The PDF contains embedded Flash or media code",
        "Embedded Flash and media players have been a common way to attack PDF readers.",
        90,
    ),
    b"/EmbeddedFile": (
        "pdf_embedded_file",
        "medium",
        "The PDF carries a hidden attachment",
        "Files can be tucked inside a PDF. We don't open them; the sandboxed reader checks what kind they are.",
        0,
    ),
    b"/XFA": (
        "pdf_xfa_form",
        "medium",
        "The PDF uses an XFA form",
        "XFA forms can contain scripts. They are rare outside government and tax forms.",
        0,
    ),
}


def pdf_names(data: bytes) -> list[Finding]:
    found: dict[str, Finding] = {}
    obfuscated = False
    for m in _NAME.finditer(data):
        raw = m.group(0)
        name = _HEX.sub(lambda h: bytes([int(h.group(1), 16)]), raw)
        hit = _PDF_NAMES.get(name)
        if hit is None:
            continue
        if name != raw:
            obfuscated = True
        key, severity, title, detail, risk = hit
        if key not in found:
            detail = detail or _PDF_NAMES[b"/JavaScript"][3]
            found[key] = Finding(key, severity, title, detail, risk)
    if obfuscated:
        found["pdf_obfuscated_names"] = Finding(
            "pdf_obfuscated_names",
            "high",
            "The PDF disguises its features",
            "Some feature names are written in code (#xx escapes) to hide them from scanners. Normal PDF software "
            "doesn't do this.",
            95,
        )
    return list(found.values())
