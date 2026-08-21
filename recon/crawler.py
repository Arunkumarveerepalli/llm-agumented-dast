"""
BFS crawler.

Walks the target application breadth-first from a seed URL, staying
same-origin, respecting a max depth and max page count, and handing each
fetched page to the extractor. Deduplicates both visited pages and
discovered endpoints.
"""

from __future__ import annotations

from collections import deque
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import logging

import requests

from models import ReconResult, Endpoint
from extractor import extract_forms, extract_query_param_links, extract_links

logger = logging.getLogger(__name__)


def normalize_url(url: str) -> str:
    """Strip fragments and sort query params so equivalent URLs dedup cleanly."""
    parsed = urlparse(url)
    query_pairs = sorted(parse_qsl(parsed.query))
    normalized_query = urlencode(query_pairs)
    return urlunparse(parsed._replace(query=normalized_query, fragment=""))


class Crawler:
    def __init__(
        self,
        session: requests.Session,
        seed_url: str,
        max_depth: int = 5,
        max_pages: int = 200,
        request_timeout: int = 10,
    ):
        self.session = session
        self.seed_url = seed_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.request_timeout = request_timeout
        self.allowed_netloc = urlparse(seed_url).netloc

        self._visited: set[str] = set()
        self._endpoint_keys: set[tuple] = set()

    def _add_endpoints(self, result: ReconResult, endpoints: list[Endpoint]) -> None:
        for ep in endpoints:
            key = ep.dedup_key()
            if key not in self._endpoint_keys:
                self._endpoint_keys.add(key)
                result.add(ep)

    def run(self) -> ReconResult:
        result = ReconResult(target=self.seed_url)
        queue: deque[tuple[str, int]] = deque([(self.seed_url, 0)])

        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.popleft()
            norm_url = normalize_url(url)

            if norm_url in self._visited:
                continue
            if depth > self.max_depth:
                continue

            self._visited.add(norm_url)
            logger.info("Fetching (depth=%d): %s", depth, url)

            try:
                resp = self.session.get(url, timeout=self.request_timeout)
            except requests.RequestException as exc:
                logger.warning("Failed to fetch %s: %s", url, exc)
                continue

            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            html = resp.text

            # Extract injectable surface from this page
            self._add_endpoints(result, extract_forms(html, url))
            self._add_endpoints(
                result, extract_query_param_links(html, url, self.allowed_netloc)
            )

            # Queue same-origin links for the next depth level
            if depth < self.max_depth:
                for link in extract_links(html, url, self.allowed_netloc):
                    if normalize_url(link) not in self._visited:
                        queue.append((link, depth + 1))

        logger.info(
            "Crawl complete: %d pages visited, %d endpoints found",
            len(self._visited),
            len(result.endpoints),
        )
        return result