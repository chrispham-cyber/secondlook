"""Public phishing / malware URL feeds, refreshed in the background.

Fail-open: if a feed can't be downloaded, scans still work; the check is just skipped.
"""

from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlsplit

import httpx

from app.signals.brands import SHARED_HOSTING_SUFFIXES

log = logging.getLogger(__name__)

FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
}


def _key(url: str) -> str:
    p = urlsplit(url if "://" in url else "http://" + url)
    return f"{(p.hostname or '').lower()}{p.path.rstrip('/')}"


def _is_shared_host(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in SHARED_HOSTING_SUFFIXES)


class Blocklist:
    def __init__(self) -> None:
        self.urls: set[str] = set()
        self.hosts: set[str] = set()
        self.loaded_at: float | None = None
        self.sources_ok: list[str] = []

    def load_lines(self, lines: list[str]) -> None:
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key = _key(line)
            self.urls.add(key)
            host = key.split("/", 1)[0]
            if host and not _is_shared_host(host):
                self.hosts.add(host)

    def match(self, url: str) -> bool:
        key = _key(url)
        if key in self.urls:
            return True
        host = key.split("/", 1)[0]
        return host in self.hosts

    async def refresh(self, client: httpx.AsyncClient) -> None:
        fresh = Blocklist()
        for name, feed_url in FEEDS.items():
            try:
                resp = await client.get(feed_url, timeout=20.0, follow_redirects=True)
                resp.raise_for_status()
                fresh.load_lines(resp.text.splitlines())
                fresh.sources_ok.append(name)
            except httpx.HTTPError as exc:
                log.warning("blocklist feed %s failed: %s", name, exc)
        if fresh.sources_ok:
            self.urls, self.hosts, self.sources_ok = fresh.urls, fresh.hosts, fresh.sources_ok
            self.loaded_at = time.time()
            log.info("blocklist loaded: %d urls, %d hosts from %s", len(self.urls), len(self.hosts), fresh.sources_ok)

    async def refresh_forever(self, client: httpx.AsyncClient, every_hours: float) -> None:
        while True:
            await self.refresh(client)
            await asyncio.sleep(every_hours * 3600)
