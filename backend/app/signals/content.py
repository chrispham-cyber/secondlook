"""Checks the message text for content that can harm the device, not just trick the person:
hidden direction-reversing characters, script links, and program file names.

Links that download programs are checked in links.py; files are checked in app/files/.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from app.schemas import ScoreAdjustment, Severity

# Right-to-left overrides and isolates: "invoice" + U+202E + "fdp.exe" displays as "invoiceexe.pdf".
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
# Zero-width characters hidden inside a word ("Pay\u200bPal") to dodge filters. U+200D is left out:
# emoji sequences use it legitimately.
_ZERO_WIDTH_IN_WORD = re.compile(r"(?<=\w)[\u200b\u200c\u2060\ufeff](?=\w)")
_SCRIPT_URI = re.compile(r"(?i)\b(?:javascript|vbscript)\s*:|\bdata\s*:\s*(?:text/html|application/|image/svg)")

PROGRAM_EXTENSIONS = (
    # Not ".com", ".app" or ".js": they are also web addresses and everyday words ("node.js").
    "exe scr msi msix bat cmd pif cpl hta jar jse vbs vbe wsf ps1 lnk reg apk xapk dmg pkg "
    "appimage deb rpm iso img vhd vhdx docm xlsm pptm"
).split()
ARCHIVE_EXTENSIONS = "zip rar 7z gz tgz tar cab ace arj".split()
_EXT = "|".join(PROGRAM_EXTENSIONS)
# "invoice.pdf.exe": a document extension followed by a program extension.
# Anchored on the extension with a fixed-width look-behind, so matching stays linear and a name of any
# length is caught. The name shown to the person is taken from a short window before the match.
_DOUBLE_EXT = re.compile(rf"(?i)(?<=[\w-])\.(?:pdf|docx?|xlsx?|jpe?g|png|txt|zip)\s*\.(?:{_EXT})\b")
_PROGRAM_NAME = re.compile(rf"(?i)(?<=[\w-]{{2}})\.(?:{_EXT})\b")
_NAME_TAIL = re.compile(r"[\w-]{1,40}$")


def _file_name(plain: str, m: re.Match) -> str:
    tail = _NAME_TAIL.search(plain, max(0, m.start() - 40), m.start())
    return (tail.group(0) if tail else "") + m.group(0)


@dataclass(frozen=True)
class ContentFinding:
    name: str
    severity: Severity
    title: str
    detail: str
    min_score: int = 0  # score floor; 0 means it only shows as a red flag


def scan_content(text: str) -> list[ContentFinding]:
    if not text:
        return []
    found: list[ContentFinding] = []
    if _BIDI.search(text):
        found.append(
            ContentFinding(
                "hidden_direction_characters",
                "high",
                "Hidden characters that disguise text",
                "The message contains invisible characters that flip the order of letters. They are used to make a "
                'program file look like a harmless document, for example showing "invoiceexe.pdf" for a file that is '
                "really a .exe program.",
                85,
            )
        )
    if _ZERO_WIDTH_IN_WORD.search(text):
        found.append(
            ContentFinding(
                "hidden_zero_width_characters",
                "medium",
                "Invisible characters inside words",
                "Some words contain invisible characters, a trick for slipping past spam filters.",
            )
        )
    m = _SCRIPT_URI.search(text)
    if m:
        found.append(
            ContentFinding(
                "script_link",
                "high",
                "A link that runs code",
                f'The message contains "{m.group(0).strip()}", a link that runs code in your browser instead of opening '
                "a web page.",
                85,
            )
        )
    plain = unicodedata.normalize("NFKC", _BIDI.sub("", text))
    m = _DOUBLE_EXT.search(plain)
    if m:
        found.append(
            ContentFinding(
                "double_extension",
                "high",
                "A program disguised as a document",
                f'"{_file_name(plain, m)}" looks like a document, but the real ending is a program that would run on '
                "your device.",
                85,
            )
        )
    else:
        m = _PROGRAM_NAME.search(plain)
        if m:
            found.append(
                ContentFinding(
                    "program_file",
                    "medium",
                    "Mentions a program or app file",
                    f'The message refers to "{_file_name(plain, m)}", a file that installs or runs software. Don\'t open files '
                    "or install apps that arrive in a message.",
                )
            )
    return found


def content_floors(findings: list[ContentFinding]) -> list[ScoreAdjustment]:
    return [ScoreAdjustment(reason=f.title, min_score=f.min_score) for f in findings if f.min_score]
