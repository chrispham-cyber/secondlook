"""Small PDF and Word files built in memory for tests, harmless versions of the tricks the checks look for."""

from __future__ import annotations

import io
import zipfile


def pdf(
    text: str = "Your package is waiting. Pay the fee at usps-redelivery-help.com", *, extra: str = "", uri: str = ""
) -> bytes:
    """A one-page PDF with real text. `extra` is added to the catalog, `uri` becomes a link annotation."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    annots = "/Annots [5 0 R]" if uri else ""
    objs = [
        f"<< /Type /Catalog /Pages 2 0 R {extra} >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        f"/Resources << /Font << /F1 6 0 R >> >> {annots} >>",
        None,  # content stream
        f"<< /Type /Annot /Subtype /Link /Rect [72 700 300 720] /A << /S /URI /URI ({uri}) >> >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.7\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(out.tell())
        if body is None:
            out.write(f"{i} 0 obj\n<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream\nendobj\n")
        else:
            out.write(f"{i} 0 obj\n{body}\nendobj\n".encode())
    xref = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def pdf_hidden_js() -> bytes:
    """JavaScript inside a compressed object stream, where a raw-byte scan can't see it."""
    import zlib

    stream = b"BT /F1 12 Tf 72 720 Td (Invoice attached) Tj ET"
    hidden = b"<< /S /JavaScript /JS (app.alert(1)) >>"
    objstm = zlib.compress(b"7 0 " + hidden)
    plain = {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 7 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> >>",
        4: b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        6: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        8: b"<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length %d >>\nstream\n" % len(objstm) + objstm + b"\nendstream",
    }
    out = io.BytesIO()
    out.write(b"%PDF-1.7\n")
    offsets = {}
    for num, body in plain.items():
        offsets[num] = out.tell()
        out.write(b"%d 0 obj\n" % num + body + b"\nendobj\n")
    offsets[9] = out.tell()
    rows = b""
    for num in range(10):
        if num == 7:
            rows += bytes([2]) + (8).to_bytes(4, "big") + (0).to_bytes(2, "big")
        elif num in offsets:
            rows += bytes([1]) + offsets[num].to_bytes(4, "big") + (0).to_bytes(2, "big")
        else:
            rows += bytes([0]) + bytes(4) + (65535 if num == 0 else 0).to_bytes(2, "big")
    xref = zlib.compress(rows)
    out.write(
        b"9 0 obj\n<< /Type /XRef /Size 10 /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /Length %d >>\nstream\n" % len(xref)
        + xref
        + b"\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n" % offsets[9]
    )
    return out.getvalue()


_CT = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="{main}"/>
</Types>"""
_MAIN = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""


def docx(
    paragraphs: tuple[str, ...] = ("Hi, this is Mark from HR.", "Your interview is on Telegram: add @HR_Careers_Dept"),
    *,
    rels: str = "",
    body_extra: str = "",
    files: dict[str, bytes] | None = None,
    macro: bool = False,
) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs) + body_extra
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}</w:body></w:document>"
    )
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>'
    )
    main = _MAIN.replace("document.main", "document.macroEnabled.main") if macro else _MAIN
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CT.replace("{main}", main))
        z.writestr("_rels/.rels", _ROOT_RELS)
        z.writestr("word/document.xml", document)
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        for name, data in (files or {}).items():
            z.writestr(name, data)
    return out.getvalue()


def rel(rtype: str, target: str, external: bool = True) -> str:
    mode = ' TargetMode="External"' if external else ""
    return (
        f'<Relationship Id="r{abs(hash(target)) % 9999}" '
        f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{rtype}" Target="{target}"{mode}/>'
    )
