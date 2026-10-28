"""Sandboxed document reader. Never imported by the app: it runs as its own process, started by
app/files/sandbox.py as `python -I worker.py <pdf|docx> <max_pages> <max_chars> <mem_mb> <cpu_s>`, reads the
file from stdin, and prints one JSON object to stdout.

Before it reads a single byte of the file it caps its own CPU time and memory, forbids writing
files and starting other processes, and only then parses. If a malformed or hostile file makes
the parser hang, blow up memory, or crash, only this process dies; the server keeps running.

It only reads: text, link targets, and the structure that tells us whether the file carries code.
Nothing in the file is executed, rendered, or fetched. XML is parsed with defusedxml, so entity and
DTD tricks (XXE, "billion laughs") are refused. It depends on the standard library, pypdf, and
defusedxml only, so `python -I` (no current directory or script directory on the path) is enough.
"""

from __future__ import annotations

import io
import json
import re
import sys
import zipfile

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException
from pypdf import PdfReader
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NullObject

PROGRAM_EXTENSIONS = set(
    "exe scr msi msix com bat cmd pif cpl hta jar js jse vbs vbe wsf ps1 lnk reg apk xapk dmg pkg app "
    "appimage deb rpm iso img vhd vhdx docm xlsm pptm dotm xlam html htm svg".split()
)
MAX_OBJECTS = 50_000  # PDF objects walked before giving up
MAX_ZIP_ENTRIES = 2_000
MAX_ZIP_TOTAL = 100_000_000  # bytes once uncompressed
MAX_ZIP_RATIO = 200  # a 1 KB entry that inflates past 200 KB is a zip bomb
MAX_PART = 20_000_000  # one XML part


def limit_self(mem_mb: int, cpu_s: int) -> None:
    try:
        import resource
    except ImportError:  # not on Windows; the parent's timeout still applies
        return
    limits = [
        (resource.RLIMIT_CPU, cpu_s),
        (resource.RLIMIT_FSIZE, 0),  # may not create or grow files
        (getattr(resource, "RLIMIT_NPROC", None), 0),  # may not start processes
        (getattr(resource, "RLIMIT_CORE", None), 0),
        (getattr(resource, "RLIMIT_AS", None), mem_mb * 1024 * 1024),
    ]
    for res, value in limits:
        if res is None:
            continue
        try:
            resource.setrlimit(res, (value, value))
        except (ValueError, OSError):
            pass  # macOS ignores some of these; Linux (production) applies them all


def finding(name: str, severity: str, title: str, detail: str, risk: int = 0) -> dict:
    return {"name": name, "severity": severity, "title": title, "detail": detail, "risk": risk}


def _ext(name: str) -> str:
    base = name.replace("\\", "/").rpartition("/")[2].lower().strip()
    return base.rpartition(".")[2] if "." in base else ""


# ---------------------------------------------------------------- PDF


def read_pdf(data: bytes, max_pages: int, max_chars: int) -> dict:
    out: dict = {"file_type": "pdf", "findings": [], "urls": [], "text": "", "pages": 0, "truncated": False}
    reader = PdfReader(io.BytesIO(data), strict=False)
    if reader.is_encrypted:
        try:
            opened = reader.decrypt("")  # many PDFs are "encrypted" with an empty password just to set permissions
        except Exception:
            opened = 0
        if not opened:
            out["findings"].append(
                finding(
                    "password_protected",
                    "high",
                    "The file is locked with a password",
                    "We can't look inside a locked file. Scammers lock attachments so security scanners can't see "
                    "what's in them, then send the password in the message.",
                    70,
                )
            )
            return out

    found: dict[str, dict] = {}
    urls: list[str] = []

    def add(key: str, *args) -> None:
        found.setdefault(key, finding(key, *args))

    # Objects the file says it has. pypdf turns a damaged one into null instead of failing, so a null
    # for a listed object means a part we couldn't check.
    listed = set(getattr(reader, "xref_objStm", {}) or {})
    for table in (getattr(reader, "xref", {}) or {}).values():
        listed.update(table)

    seen: set[int] = set()
    stack = [reader.trailer]
    walked = 0
    broken = 0
    while stack and walked < MAX_OBJECTS:
        obj = stack.pop()
        if isinstance(obj, IndirectObject):
            if obj.idnum in seen:
                continue
            seen.add(obj.idnum)
            idnum = obj.idnum
            try:
                obj = obj.get_object()
            except Exception:
                broken += 1  # an object we can't check might be the one hiding the script
                continue
            if (obj is None or isinstance(obj, NullObject)) and idnum in listed:
                broken += 1
                continue
        walked += 1
        if isinstance(obj, ArrayObject):
            stack.extend(obj)
            continue
        if not isinstance(obj, DictionaryObject):
            continue
        keys = set(obj.keys())
        action = obj.get("/S")
        if "/JS" in keys or "/JavaScript" in keys or action == "/JavaScript":
            add("pdf_javascript", "high", "The PDF contains JavaScript", "Code inside a PDF can run when the file is opened.", 95)
        if action == "/Launch":
            add("pdf_launch", "high", "The PDF tries to open a program", "It tells your computer to start another program.", 95)
        if action in ("/SubmitForm", "/ImportData"):
            add("pdf_sends_data", "medium", "The PDF can send form data", "Filling it in can send what you type to a website.")
        if action in ("/GoToR", "/GoToE"):
            add("pdf_opens_files", "medium", "The PDF opens other files", "It links to other documents outside itself.")
        if "/RichMedia" in keys:
            add(
                "pdf_rich_media",
                "high",
                "The PDF contains embedded media code",
                "Embedded media players can attack PDF readers.",
                90,
            )
        if "/XFA" in keys:
            add("pdf_xfa_form", "medium", "The PDF uses an XFA form", "XFA forms can contain scripts.")
        if action == "/URI" and "/URI" in keys:
            try:
                urls.append(str(obj["/URI"])[:2000])
            except Exception:
                pass
        if obj.get("/Type") == "/Filespec" or obj.get("/Type") == "/EmbeddedFile" or "/EF" in keys:
            name = str(obj.get("/UF") or obj.get("/F") or "")
            if _ext(name) in PROGRAM_EXTENSIONS:
                add(
                    "pdf_embedded_program",
                    "high",
                    "The PDF hides a program inside",
                    f'It carries an attached file named "{name[:80]}", which is a program or script.',
                    95,
                )
            elif "/EF" in keys:
                add("pdf_embedded_file", "low", "The PDF carries an attachment", f'Attached file: "{name[:80] or "unnamed"}".')
        stack.extend(obj.values())

    # Fail closed: anything we couldn't walk is treated as dangerous, not as clean.
    if stack:
        add(
            "too_complex",
            "high",
            "The file is too complex to check",
            "It has far more internal parts than a normal document, which is a way to hide code from scanners.",
            70,
        )
    if broken:
        add(
            "unreadable_parts",
            "high",
            "Parts of the file couldn't be checked",
            f"{broken} internal part(s) are damaged or hidden, so we can't confirm the file has no code in it.",
            70,
        )

    out["findings"] = list(found.values())
    out["urls"] = urls[:50]
    if any(f["risk"] >= 60 for f in out["findings"]):
        return out  # don't read the text of a file we will refuse anyway

    pages = reader.pages
    out["pages"] = len(pages)
    parts: list[str] = []
    total = 0
    for i, page in enumerate(pages):
        if i >= max_pages or total >= max_chars:
            out["truncated"] = True
            break
        try:
            t = page.extract_text() or ""
        except Exception:
            t = ""
        parts.append(t)
        total += len(t)
    text = "\n\n".join(p.strip() for p in parts if p.strip())
    if len(text) > max_chars:
        text, out["truncated"] = text[:max_chars], True
    out["text"] = text
    return out


# ---------------------------------------------------------------- DOCX

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"
CT = "{http://schemas.openxmlformats.org/package/2006/content-types}"
_UNSAFE_SCHEME = re.compile(r"(?i)^\s*(?:mhtml:|ms-[a-z-]+:|search-ms:|file:|\\\\|javascript:|vbscript:)")
_FIELD_DDE = re.compile(r"(?i)^\s*(?:DDE|DDEAUTO)\b")
_FIELD_INCLUDE = re.compile(r"(?i)^\s*(?:INCLUDETEXT|INCLUDEPICTURE|IMPORT|LINK)\b")
_FIELD_LINK = re.compile(r'(?i)^\s*HYPERLINK\s+"([^"]+)"')
TEXT_PARTS = re.compile(r"^word/(?:document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$")


def read_docx(data: bytes, max_chars: int) -> dict:
    out: dict = {"file_type": "docx", "findings": [], "urls": [], "text": "", "pages": None, "truncated": False}
    found: dict[str, dict] = {}

    def add(key: str, *args) -> None:
        found.setdefault(key, finding(key, *args))

    def done() -> dict:
        out["findings"] = list(found.values())
        return out

    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = z.infolist()
    except (zipfile.BadZipFile, OSError, ValueError):
        add("broken_file", "high", "The file is damaged", "It claims to be a Word document but can't be read.", 70)
        return done()

    total = sum(i.file_size for i in infos)
    bomb = len(infos) > MAX_ZIP_ENTRIES or total > MAX_ZIP_TOTAL
    bomb = bomb or any(i.file_size > 1_000_000 and i.file_size > MAX_ZIP_RATIO * max(1, i.compress_size) for i in infos)
    if bomb:
        add(
            "zip_bomb",
            "high",
            "The file is built to overload computers",
            'It expands to a huge size when opened (a "zip bomb"), which is only done to crash or slip past scanners.',
            85,
        )
        return done()

    names = {i.filename for i in infos}
    if "[Content_Types].xml" not in names or "word/document.xml" not in names:
        kind = "an Excel or PowerPoint file" if any(n.startswith(("xl/", "ppt/")) for n in names) else "a zip archive"
        add(
            "not_a_word_document",
            "high",
            "Not a Word document",
            f"The file is really {kind}. We only open PDF and Word (.docx) documents.",
            65,
        )
        out["file_type"] = "xlsx_or_pptx" if kind.startswith("an") else "zip"
        return done()

    def read(name: str) -> bytes:
        with z.open(name) as f:
            return f.read(MAX_PART + 1)[:MAX_PART]

    def parse(name: str):
        try:
            return SafeET.fromstring(read(name), forbid_dtd=True)
        except DefusedXmlException:
            add(
                "xml_entity_trick",
                "high",
                "The file contains a hidden-entity trick",
                "Its XML declares entities or a DTD, which Word never needs and which is used to attack document readers.",
                90,
            )
        except Exception:
            # Fail closed: a part we can't parse might be the one carrying the attack.
            add(
                "unreadable_parts",
                "high",
                "Parts of the file couldn't be checked",
                f"The part {name[:80]} is damaged or malformed, so we can't confirm the file is safe.",
                70,
            )
        return None

    # Macros, ActiveX, and embedded objects.
    ctypes = parse("[Content_Types].xml")
    content_types = [e.get("ContentType", "") for e in ctypes.iter()] if ctypes is not None else []
    if any("vbaProject" in n for n in names) or any("macroEnabled" in c for c in content_types):
        add(
            "macros",
            "high",
            "The document contains macros",
            "Macros are small programs inside Office files. Malware hides in them, and a real .docx never has them.",
            95,
        )
    if any(n.startswith("word/activeX/") for n in names):
        add("activex", "high", "The document contains ActiveX controls", "ActiveX controls can run code on Windows.", 95)
    for n in names:
        if not n.startswith("word/embeddings/"):
            continue
        ext = _ext(n)
        if ext == "bin" or ext in PROGRAM_EXTENSIONS:
            add(
                "embedded_object",
                "high",
                "The document hides an embedded object",
                "It carries a packaged object, which can contain a program that runs when double-clicked.",
                90,
            )
        elif ext not in ("xlsx", "docx", "pptx", "emf", "wmf", "png", "jpeg", "jpg"):
            add("embedded_file", "medium", "The document carries an embedded file", f"Embedded file type: .{ext}.")

    # External relationships: remote templates (how "Follina" and many others worked) and links.
    urls: list[str] = []
    for n in sorted(names):
        if not n.endswith(".rels"):
            continue
        root = parse(n)
        if root is None:
            continue
        for rel in root.iter(f"{REL}Relationship"):
            target = rel.get("Target", "")
            rtype = rel.get("Type", "").rpartition("/")[2]
            if _UNSAFE_SCHEME.match(target):
                add(
                    "unsafe_link_handler",
                    "high",
                    "The document calls a dangerous Windows handler",
                    "It contains a link that makes Windows run a built-in tool instead of opening a web page, the "
                    'trick used by the "Follina" attack.',
                    95,
                )
                continue
            if rel.get("TargetMode") != "External":
                continue
            if rtype == "hyperlink":
                urls.append(target[:2000])
            elif rtype in ("attachedTemplate", "oleObject", "frame", "subDocument", "aFChunk", "package"):
                add(
                    "remote_template",
                    "high",
                    "The document downloads content when opened",
                    "It is set up to fetch a template or object from the internet as soon as it opens. That is how "
                    "many Word attacks deliver their malware.",
                    95,
                )
            elif rtype == "image":
                add(
                    "remote_image",
                    "medium",
                    "The document loads a picture from the internet",
                    "Remote pictures tell the sender when and where the file was opened.",
                )
            else:
                add("external_content", "medium", "The document links to outside content", f"Link type: {rtype}.")

    # Text, field codes (DDE), and embedded HTML chunks.
    texts: list[str] = []
    length = 0
    for n in sorted(names, key=lambda x: (x != "word/document.xml", x)):
        if not TEXT_PARTS.match(n):
            continue
        root = parse(n)
        if root is None:
            continue
        for el in root.iter():
            tag = el.tag
            instr = el.text if tag == f"{W}instrText" else el.get(f"{W}instr") if tag == f"{W}fldSimple" else None
            if instr:
                if _FIELD_DDE.match(instr):
                    add(
                        "dde_field",
                        "high",
                        "The document tries to run a command",
                        "It contains a DDE field, an old Office feature attackers use to run commands when a document opens.",
                        95,
                    )
                elif _FIELD_INCLUDE.match(instr) and re.search(r"(?i)https?:|\\\\", instr):
                    add(
                        "include_field",
                        "medium",
                        "The document pulls in outside content",
                        "A field loads content from elsewhere.",
                    )
                m = _FIELD_LINK.match(instr)
                if m:
                    urls.append(m.group(1)[:2000])
            if tag == f"{W}altChunk":
                add("alt_chunk", "medium", "The document embeds web content", "Part of it is stored as HTML or RTF.")
        if length < max_chars:
            paras = []
            for p in root.iter(f"{W}p"):
                bits = []
                for el in p.iter():
                    if el.tag == f"{W}t" and el.text:
                        bits.append(el.text)
                    elif el.tag == f"{W}tab":
                        bits.append("\t")
                    elif el.tag in (f"{W}br", f"{W}cr"):
                        bits.append("\n")
                line = "".join(bits).strip()
                if line:
                    paras.append(line)
            chunk = "\n".join(paras)
            texts.append(chunk)
            length += len(chunk)

    out["urls"] = [u for u in urls if u.lower().startswith(("http://", "https://", "mailto:", "www."))][:50]
    out["findings"] = list(found.values())
    if not any(f["risk"] >= 60 for f in out["findings"]):
        text = "\n\n".join(t for t in texts if t)
        if len(text) > max_chars:
            text, out["truncated"] = text[:max_chars], True
        out["text"] = text
    return out


def main() -> None:
    kind, max_pages, max_chars, mem_mb, cpu_s = sys.argv[1], *map(int, sys.argv[2:6])
    data = sys.stdin.buffer.read()
    limit_self(mem_mb, cpu_s)
    try:
        result = read_pdf(data, max_pages, max_chars) if kind == "pdf" else read_docx(data, max_chars)
    except MemoryError:
        result = {"error": "memory"}
    except RecursionError:
        result = {"error": "structure"}
    except Exception as exc:  # a parser bug on a malformed file
        result = {"error": "parse", "detail": type(exc).__name__}
    sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main()
