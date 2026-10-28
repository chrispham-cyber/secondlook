"""Runs worker.py in its own resource-limited process and returns what it read."""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from pathlib import Path

WORKER = Path(__file__).with_name("worker.py")


class SandboxError(RuntimeError):
    """The reader crashed, ran out of time or memory, or returned nonsense. Treated as a refused file."""


async def read_document(
    kind: str, data: bytes, *, slots: asyncio.Semaphore, max_pages: int, max_chars: int, timeout_s: float, memory_mb: int
) -> dict:
    async with slots:  # a flood of uploads can't start unlimited parsers
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",  # isolated: ignores PYTHON* variables, the current directory, and user site-packages
            str(WORKER),
            kind,
            str(max_pages),
            str(max_chars),
            str(memory_mb),
            str(max(1, int(timeout_s))),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},  # nothing from the server's environment, no API keys
            cwd="/",
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(data), timeout=timeout_s)
        except TimeoutError as exc:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
            raise SandboxError("timeout") from exc
    if proc.returncode != 0:
        raise SandboxError(f"exit {proc.returncode}")  # killed by its CPU or memory limit, or crashed
    try:
        result = json.loads(out[:5_000_000])
    except ValueError as exc:
        raise SandboxError("bad output") from exc
    if not isinstance(result, dict):
        raise SandboxError("bad output")
    if "error" in result:
        raise SandboxError(str(result["error"]))
    return result
