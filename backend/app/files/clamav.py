"""Optional virus scan through a ClamAV daemon (clamd), using its INSTREAM command over TCP.

Turned on by setting CLAMAV_HOST (docker compose: `--profile antivirus`). The file is streamed to
clamd from memory; nothing is written to disk.
"""

from __future__ import annotations

import asyncio
import struct

CHUNK = 64 * 1024


class ClamAVError(RuntimeError):
    pass


async def scan_bytes(data: bytes, host: str, port: int = 3310, timeout_s: float = 30.0) -> str | None:
    """Returns the malware name if clamd finds something, None if the file is clean."""

    async def run() -> bytes:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(b"zINSTREAM\0")
            for i in range(0, len(data), CHUNK):
                chunk = data[i : i + CHUNK]
                writer.write(struct.pack("!I", len(chunk)) + chunk)
                await writer.drain()
            writer.write(struct.pack("!I", 0))
            await writer.drain()
            return await reader.readuntil(b"\0")
        finally:
            writer.close()

    try:
        reply = (await asyncio.wait_for(run(), timeout=timeout_s)).rstrip(b"\0").decode("utf-8", "replace")
    except (OSError, TimeoutError, asyncio.IncompleteReadError) as exc:
        raise ClamAVError(f"antivirus unreachable: {exc}") from exc
    # "stream: OK" | "stream: Win.Test.EICAR_HDB-1 FOUND" | "INSTREAM size limit exceeded. ERROR"
    if reply.endswith("FOUND"):
        return reply.removeprefix("stream:").removesuffix("FOUND").strip() or "malware"
    if reply.endswith("OK"):
        return None
    raise ClamAVError(f"antivirus error: {reply[:200]}")
