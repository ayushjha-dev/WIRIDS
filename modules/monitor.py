"""WIDIRS website monitoring module.

Captures pages (HTML + screenshot), normalizes and hashes content,
persists snapshots and compares against the stored baseline.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import aiohttp
import structlog
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config import Settings
from database import Database
from models import ScanResult

logger = structlog.get_logger(__name__)


class ScanError(Exception):
    """Raised when any stage of a scan fails.

    Attributes:
        url: The URL being scanned when the failure occurred.
        cause: The underlying exception.
    """

    def __init__(self, url: str, cause: BaseException) -> None:
        self.url = url
        self.cause = cause
        super().__init__(f"Scan failed for {url}: {cause!r}")


class WebsiteMonitor:
    """Captures, normalizes and snapshots web pages for defacement detection."""

    #: Pool of realistic desktop/mobile user agents (rotated per request).
    USER_AGENTS: tuple[str, ...] = (
        # Chrome / Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        # Chrome / macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        # Firefox / Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
        "Gecko/20100101 Firefox/126.0",
        # Firefox / Linux
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        # Safari / macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        # Edge / Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        # Chrome / Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        # Chrome / Android
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
        # Safari / iPhone
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
        "Mobile/15E148 Safari/604.1",
        # Opera / Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    )

    #: Ad / tracking domains blocked during screenshot capture.
    BLOCKED_DOMAINS: tuple[str, ...] = (
        "doubleclick.net",
        "googletagmanager.com",
        "google-analytics.com",
        "googlesyndication.com",
        "googleadservices.com",
        "facebook.net",
        "connect.facebook.com",
        "adsystem.com",
        "adservice.google.com",
        "scorecardresearch.com",
        "hotjar.com",
        "criteo.com",
        "taboola.com",
        "outbrain.com",
    )

    MAX_REDIRECTS: int = 5
    CONNECT_TIMEOUT: float = 15.0
    TOTAL_TIMEOUT: float = 30.0
    SCREENSHOT_VIEWPORT: Dict[str, int] = {"width": 1280, "height": 800}
    NETWORKIDLE_TIMEOUT_MS: int = 15_000

    def __init__(self, config: Settings) -> None:
        """Initialize the monitor.

        Args:
            config: Application settings (snapshot dir, DB path, thresholds).
        """
        self.config = config
        self.snapshot_dir: Path = Path(config.snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. fetch_page
    # ------------------------------------------------------------------
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(
            (aiohttp.ClientError, asyncio.TimeoutError)
        ),
        reraise=True,
    )
    async def fetch_page(self, url: str) -> Dict[str, Any]:
        """Fetch a page over HTTP with rotation, redirects and retries.

        Args:
            url: Target URL.

        Returns:
            Dict with keys: html, status_code, headers, response_time_ms,
            final_url, timestamp.

        Raises:
            aiohttp.ClientError: On unrecoverable HTTP failures (after retries).
            asyncio.TimeoutError: When the request exceeds configured timeouts.
        """
        user_agent = random.choice(self.USER_AGENTS)
        timeout = aiohttp.ClientTimeout(
            total=self.TOTAL_TIMEOUT, connect=self.CONNECT_TIMEOUT
        )
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;"
                      "q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        logger.info("fetch_started", url=url, user_agent=user_agent[:40])
        start = time.perf_counter()

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                headers=headers,
                allow_redirects=True,
                max_redirects=self.MAX_REDIRECTS,
            ) as response:
                html = await response.text(errors="replace")
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                result: Dict[str, Any] = {
                    "html": html,
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "response_time_ms": round(elapsed_ms, 2),
                    "final_url": str(response.url),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

        logger.info(
            "fetch_completed",
            url=url,
            status=result["status_code"],
            final_url=result["final_url"],
        )
        logger.debug(
            "fetch_timing",
            url=url,
            response_time_ms=result["response_time_ms"],
            html_bytes=len(html),
        )
        return result

    # ------------------------------------------------------------------
    # 2. screenshot_page
    # ------------------------------------------------------------------
    async def screenshot_page(self, url: str) -> bytes:
        """Capture a full-page PNG screenshot with headless Chromium.

        Ad and tracking domains are blocked to stabilise rendering and
        avoid noise in visual diffs.

        Args:
            url: Target URL.

        Returns:
            PNG image bytes.

        Raises:
            playwright.async_api.Error: On browser/navigation failures.
        """
        logger.info("screenshot_started", url=url)
        start = time.perf_counter()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page(
                    viewport=self.SCREENSHOT_VIEWPORT,
                    user_agent=random.choice(self.USER_AGENTS),
                )

                async def _route_handler(route: Any) -> None:
                    host = urlparse(route.request.url).hostname or ""
                    if any(
                        host == d or host.endswith("." + d)
                        for d in self.BLOCKED_DOMAINS
                    ):
                        await route.abort()
                    else:
                        await route.continue_()

                await page.route("**/*", _route_handler)
                await page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=self.NETWORKIDLE_TIMEOUT_MS,
                )
                png_bytes: bytes = await page.screenshot(
                    full_page=True, type="png"
                )
            finally:
                await browser.close()

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        logger.info("screenshot_completed", url=url, size_bytes=len(png_bytes))
        logger.debug("screenshot_timing", url=url, elapsed_ms=round(elapsed_ms, 2))
        return png_bytes

    # ------------------------------------------------------------------
    # 3. compute_html_hash
    # ------------------------------------------------------------------
    @staticmethod
    def compute_html_hash(html: str) -> str:
        """Compute a normalized SHA-256 hash of an HTML document.

        Normalization steps:
          1. Parse with BeautifulSoup (lxml).
          2. Empty <script>/<style> contents (tags retained so structural
             changes are still detected).
          3. Sort each tag's attributes alphabetically.
          4. Prettify to normalize whitespace.

        Args:
            html: Raw HTML string.

        Returns:
            SHA-256 hex digest of the normalized HTML.
        """
        soup = BeautifulSoup(html, "lxml")

        # Strip script/style contents but keep the tags themselves.
        for tag in soup.find_all(["script", "style"]):
            tag.clear()

        # Sort attributes alphabetically for stable serialization.
        for tag in soup.find_all(True):
            tag.attrs = dict(sorted(tag.attrs.items()))

        normalized = soup.prettify()
        # Collapse runs of whitespace inside lines for extra stability.
        normalized = re.sub(r"[ \t]+", " ", normalized)

        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        logger.debug("html_hash_computed", sha256=digest[:16])
        return digest

    # ------------------------------------------------------------------
    # 4. save_snapshot
    # ------------------------------------------------------------------
    def save_snapshot(
        self,
        url: str,
        html: str,
        screenshot_bytes: bytes,
        metadata: Dict[str, Any],
    ) -> str:
        """Persist a snapshot (HTML, screenshot, metadata) to disk.

        Layout: {SNAPSHOT_DIR}/{domain}/{YYYYMMDD_HHMMSS}/
                 page.html | screenshot.png | metadata.json

        Args:
            url: The scanned URL.
            html: Raw HTML content.
            screenshot_bytes: PNG screenshot bytes.
            metadata: Extra fields (status_code, response_time_ms, html_hash...).

        Returns:
            Absolute path to the snapshot directory as a string.

        Raises:
            OSError: If files cannot be written.
        """
        domain = urlparse(url).hostname or "unknown"
        # Sanitize domain for filesystem safety (Windows-friendly).
        domain = re.sub(r"[^A-Za-z0-9.-]", "_", domain)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snap_dir = self.snapshot_dir / domain / stamp
        snap_dir.mkdir(parents=True, exist_ok=True)

        html_bytes = html.encode("utf-8")
        (snap_dir / "page.html").write_bytes(html_bytes)
        (snap_dir / "screenshot.png").write_bytes(screenshot_bytes)

        meta = {
            "url": url,
            "timestamp": metadata.get(
                "timestamp", datetime.now(timezone.utc).isoformat()
            ),
            "html_hash": metadata.get("html_hash", ""),
            "status_code": metadata.get("status_code", 0),
            "response_time_ms": metadata.get("response_time_ms", 0.0),
            "screenshot_size_bytes": len(screenshot_bytes),
            "html_size_bytes": len(html_bytes),
        }
        (snap_dir / "metadata.json").write_text(
            json.dumps(meta, indent=2), encoding="utf-8"
        )

        path_str = str(snap_dir.resolve())
        logger.info("snapshot_saved", url=url, path=path_str)
        return path_str

    # ------------------------------------------------------------------
    # 5. load_baseline
    # ------------------------------------------------------------------
    async def load_baseline(self, url: str, db: Optional[Database] = None) -> Optional[Dict[str, Any]]:
        """Load the most recent stored snapshot (baseline) for a URL.

        Queries the database for the latest snapshot row, then loads the
        on-disk metadata.json and page.html.

        Args:
            url: The monitored URL.
            db: Optional Database connection to reuse.

        Returns:
            Dict merging metadata.json fields with 'html' and
            'snapshot_id'/'site_id' keys, or None if no baseline exists.

        Raises:
            ScanError: If a baseline row exists but its files are unreadable.
        """
        if db is not None:
            return await self._load_baseline_with_db(url, db)
        async with Database(self.config.db_path) as conn:
            return await self._load_baseline_with_db(url, conn)

    async def _load_baseline_with_db(self, url: str, db: Database) -> Optional[Dict[str, Any]]:
        site = await db.get_site_by_url(url)
        if not site:
            logger.info("baseline_missing", url=url, reason="site_unknown")
            return None
        # Use the most recent snapshot as baseline.
        cur = await db.conn.execute(
            "SELECT * FROM snapshots WHERE site_id = ? "
            "ORDER BY created_at DESC, id DESC LIMIT 1",
            (site["id"],),
        )
        row = await cur.fetchone()
        snapshot = dict(row) if row else None

        if not snapshot:
            logger.info("baseline_missing", url=url, reason="no_snapshots")
            return None

        try:
            html_path = self.config.resolve_snapshot_path(snapshot["html_path"])
            snap_dir = html_path.parent
            metadata: Dict[str, Any] = json.loads(
                (snap_dir / "metadata.json").read_text(encoding="utf-8")
            )
            html = html_path.read_text(
                encoding="utf-8", errors="replace"
            )
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("baseline_load_failed", url=url, error=str(exc))
            raise ScanError(url, exc) from exc

        metadata.update(
            {
                "html": html,
                "snapshot_id": snapshot["id"],
                "site_id": snapshot["site_id"],
                "html_hash": snapshot["html_hash"] or metadata.get("html_hash", ""),
            }
        )
        logger.info(
            "baseline_loaded",
            url=url,
            snapshot_id=snapshot["id"],
            html_hash=metadata["html_hash"][:16],
        )
        return metadata

    # ------------------------------------------------------------------
    # 6. run_scan
    # ------------------------------------------------------------------
    async def run_scan(self, url: str, db: Optional[Database] = None) -> ScanResult:
        """Run a full capture-and-compare scan for one URL.

        Pipeline: fetch -> screenshot -> normalize+hash -> load baseline ->
        compare -> persist snapshot (disk + DB).

        Args:
            url: Target URL.
            db: Optional Database connection to reuse.

        Returns:
            Populated ScanResult. is_baseline=True when no prior baseline
            existed; has_changes=True when the normalized hash differs.

        Raises:
            ScanError: Wrapping any underlying failure.
        """
        log = logger.bind(url=url)
        log.info("scan_started")
        scan_start = time.perf_counter()

        try:
            # Fetch HTML and screenshot concurrently.
            fetch_task = asyncio.create_task(self.fetch_page(url))
            shot_task = asyncio.create_task(self.screenshot_page(url))
            page, screenshot_bytes = await asyncio.gather(fetch_task, shot_task)

            html: str = page["html"]
            html_hash = self.compute_html_hash(html)

            baseline = await self.load_baseline(url, db)
            is_baseline = baseline is None
            has_changes = (
                not is_baseline and baseline["html_hash"] != html_hash
            )

            metadata = {
                "timestamp": page["timestamp"],
                "html_hash": html_hash,
                "status_code": page["status_code"],
                "response_time_ms": page["response_time_ms"],
            }
            snap_dir = self.save_snapshot(url, html, screenshot_bytes, metadata)
            html_path = str(Path(snap_dir) / "page.html")
            screenshot_path = str(Path(snap_dir) / "screenshot.png")

            # Persist the snapshot row in the database.
            if db is not None:
                site_id = await db.upsert_site(
                    url, scan_interval=self.config.scan_interval
                )
                await db.insert_snapshot(
                    site_id=site_id,
                    html_hash=html_hash,
                    screenshot_path=screenshot_path,
                    html_path=html_path,
                    metadata=metadata,
                )
            else:
                async with Database(self.config.db_path) as conn:
                    site_id = await conn.upsert_site(
                        url, scan_interval=self.config.scan_interval
                    )
                    await conn.insert_snapshot(
                        site_id=site_id,
                        html_hash=html_hash,
                        screenshot_path=screenshot_path,
                        html_path=html_path,
                        metadata=metadata,
                    )

            result = ScanResult(
                url=url,
                site_id=site_id,
                status_code=page["status_code"],
                html_hash=html_hash,
                html_path=html_path,
                screenshot_path=screenshot_path,
                dom_node_count=len(
                    BeautifulSoup(html, "lxml").find_all(True)
                ),
                load_time_ms=page["response_time_ms"],
                headers={
                    k: v for k, v in page["headers"].items()
                },
                is_baseline=is_baseline,
                has_changes=has_changes,
                snapshot_dir=snap_dir,
            )

            elapsed = time.perf_counter() - scan_start
            log.info(
                "scan_completed",
                is_baseline=is_baseline,
                has_changes=has_changes,
                html_hash=html_hash[:16],
            )
            log.debug("scan_timing", elapsed_seconds=round(elapsed, 2))
            return result

        except ScanError:
            raise
        except Exception as exc:  # noqa: BLE001 - wrap everything per spec
            log.error("scan_failed", error=str(exc), error_type=type(exc).__name__)
            raise ScanError(url, exc) from exc
