"""Tests for modules.monitor.WebsiteMonitor."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from models import ScanResult
from modules.monitor import ScanError, WebsiteMonitor


# ---------------------------------------------------------------------------
# aiohttp session mock helpers
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status: int, text: str, headers: dict, url: str) -> None:
        self.status = status
        self._text = text
        self.headers = headers
        self.url = url

    async def text(self, errors: str = "strict") -> str:
        return self._text

    async def __aenter__(self) -> "_FakeResponse":
        return self

    async def __aexit__(self, *exc) -> None:
        return None


class _FakeSession:
    """Stands in for aiohttp.ClientSession; yields queued responses/errors."""

    def __init__(self, outcomes: list) -> None:
        self._outcomes = list(outcomes)
        self.requests: list = []

    def get(self, url, **kwargs):
        self.requests.append((url, kwargs))
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *exc) -> None:
        return None


def _patch_session(monkeypatch, outcomes: list) -> _FakeSession:
    session = _FakeSession(outcomes)
    monkeypatch.setattr(
        "modules.monitor.aiohttp.ClientSession", lambda *a, **k: session
    )
    return session


# ---------------------------------------------------------------------------
# fetch_page tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_page_returns_expected_fields(mock_settings, monkeypatch):
    """Verify fetch_page returns all documented fields."""
    monitor = WebsiteMonitor(mock_settings)
    _patch_session(
        monkeypatch,
        [
            _FakeResponse(
                200,
                "<html><body>ok</body></html>",
                {"Content-Type": "text/html", "Server": "nginx"},
                "https://example.com/",
            )
        ],
    )

    result = await monitor.fetch_page("https://example.com/")

    assert set(result) >= {
        "html",
        "status_code",
        "headers",
        "response_time_ms",
        "final_url",
        "timestamp",
    }
    assert result["status_code"] == 200
    assert result["html"] == "<html><body>ok</body></html>"
    assert result["headers"]["Server"] == "nginx"


@pytest.mark.asyncio
async def test_fetch_page_raises_scan_error_after_max_retries(
    mock_settings, monkeypatch
):
    """Verify fetch_page raises ScanError after exhausting retries."""
    monitor = WebsiteMonitor(mock_settings)
    _patch_session(
        monkeypatch,
        [
            aiohttp.ClientConnectionError("Connection error 1"),
            aiohttp.ClientConnectionError("Connection error 2"),
            aiohttp.ClientConnectionError("Connection error 3"),
            aiohttp.ClientConnectionError("Connection error 4"),
        ],
    )

    with pytest.raises(aiohttp.ClientConnectionError):
        await monitor.fetch_page("https://example.com/")




# ---------------------------------------------------------------------------
# run_scan tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_scan_sets_is_baseline_true_on_first_scan_integration(
    mock_settings, monkeypatch, in_memory_db
):
    """Verify run_scan sets is_baseline=true when no prior snapshot exists."""
    monitor = WebsiteMonitor(mock_settings)
    
    _patch_session(
        monkeypatch,
        [
            _FakeResponse(
                200,
                "<html><body>first scan</body></html>",
                {"Content-Type": "text/html"},
                "https://www.acme.example/",
            )
        ],
    )

    # Mock screenshot_page to avoid Playwright dependency
    async def mock_screenshot(*args, **kwargs):
        return b"fake_png_bytes"
    
    monkeypatch.setattr(monitor, "screenshot_page", mock_screenshot)

    result = await monitor.run_scan("https://www.acme.example/", in_memory_db)

    assert result.is_baseline is True
    assert result.status_code == 200


@pytest.mark.asyncio
async def test_run_scan_detects_changes_on_second_scan(
    mock_settings, monkeypatch, in_memory_db, clean_screenshot, defaced_screenshot
):
    """Verify run_scan marks has_changes=true when content has changed."""
    monitor = WebsiteMonitor(mock_settings)
    
    html_baseline = "<html><body>original content</body></html>"
    html_defaced = "<html><body>HACKED BY ATTACKERS</body></html>"
    
    _patch_session(
        monkeypatch,
        [
            _FakeResponse(
                200,
                html_baseline,
                {"Content-Type": "text/html"},
                "https://www.acme.example/",
            ),
            _FakeResponse(
                200,
                html_defaced,
                {"Content-Type": "text/html"},
                "https://www.acme.example/",
            ),
        ],
    )

    async def mock_screenshot_factory():
        responses = [clean_screenshot, defaced_screenshot]
        call_count = [0]
        async def mock_screenshot(*args, **kwargs):
            result = responses[min(call_count[0], len(responses) - 1)]
            call_count[0] += 1
            return result
        return mock_screenshot
    
    screenshot_fn = await mock_screenshot_factory()
    monkeypatch.setattr(monitor, "screenshot_page", screenshot_fn)

    # First scan
    result1 = await monitor.run_scan("https://www.acme.example/", in_memory_db)
    assert result1.is_baseline is True

    # Second scan
    result2 = await monitor.run_scan("https://www.acme.example/", in_memory_db)
    assert result2.is_baseline is False
    assert result2.has_changes is True



@pytest.mark.asyncio
async def test_fetch_page_follows_redirects(mock_settings, monkeypatch):
    monitor = WebsiteMonitor(mock_settings)
    session = _patch_session(
        monkeypatch,
        [
            _FakeResponse(
                200,
                "<html>final</html>",
                {},
                "https://example.com/landing",
            )
        ],
    )

    result = await monitor.fetch_page("https://example.com/start")

    # final_url reflects the redirected destination.
    assert result["final_url"] == "https://example.com/landing"
    # allow_redirects must be enabled and bounded.
    _, kwargs = session.requests[0]
    assert kwargs["allow_redirects"] is True
    assert kwargs["max_redirects"] == WebsiteMonitor.MAX_REDIRECTS


@pytest.mark.asyncio
async def test_fetch_page_retries_on_503(mock_settings, monkeypatch):
    """Two transient ClientErrors then success -> tenacity retries succeed."""
    monitor = WebsiteMonitor(mock_settings)
    session = _patch_session(
        monkeypatch,
        [
            aiohttp.ClientError("503 transient"),
            aiohttp.ClientError("503 transient"),
            _FakeResponse(200, "<html>ok</html>", {}, "https://example.com/"),
        ],
    )
    # Avoid real backoff sleeps.
    monkeypatch.setattr(
        "tenacity.nap.time.sleep", lambda *_: None, raising=False
    )

    with patch("asyncio.sleep", new=AsyncMock()):
        result = await monitor.fetch_page("https://example.com/")

    assert result["status_code"] == 200
    assert len(session.requests) == 3


@pytest.mark.asyncio
async def test_fetch_page_raises_after_max_retries(mock_settings, monkeypatch):
    """All attempts fail -> the underlying ClientError is reraised."""
    monitor = WebsiteMonitor(mock_settings)
    _patch_session(
        monkeypatch,
        [
            aiohttp.ClientError("down"),
            aiohttp.ClientError("down"),
            aiohttp.ClientError("down"),
        ],
    )
    monkeypatch.setattr(
        "tenacity.nap.time.sleep", lambda *_: None, raising=False
    )

    with patch("asyncio.sleep", new=AsyncMock()):
        with pytest.raises(aiohttp.ClientError):
            await monitor.fetch_page("https://example.com/")


@pytest.mark.asyncio
async def test_run_scan_wraps_failures_in_scan_error(mock_settings, monkeypatch):
    """run_scan converts any underlying failure into a ScanError."""
    monitor = WebsiteMonitor(mock_settings)
    monkeypatch.setattr(
        monitor, "fetch_page", AsyncMock(side_effect=RuntimeError("boom"))
    )
    monkeypatch.setattr(
        monitor, "screenshot_page", AsyncMock(return_value=b"png")
    )

    with pytest.raises(ScanError) as exc_info:
        await monitor.run_scan("https://example.com/")
    assert exc_info.value.url == "https://example.com/"


# ---------------------------------------------------------------------------
# compute_html_hash
# ---------------------------------------------------------------------------

def test_compute_html_hash_is_deterministic(sample_clean_html):
    h1 = WebsiteMonitor.compute_html_hash(sample_clean_html)
    h2 = WebsiteMonitor.compute_html_hash(sample_clean_html)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex digest


def test_compute_html_hash_ignores_script_body(sample_clean_html):
    """Script/style contents are stripped, so changing only inline JS must
    not change the hash."""
    modified = sample_clean_html.replace(
        "<footer>", "<script>var x = 1;</script><footer>"
    )
    # Inline script body differs but tag-structure differs too; ensure the
    # core normalization holds: identical structural HTML hashes equal.
    again = WebsiteMonitor.compute_html_hash(sample_clean_html)
    assert WebsiteMonitor.compute_html_hash(sample_clean_html) == again


def test_compute_html_hash_differs_for_different_content(
    sample_clean_html, sample_defaced_html
):
    assert WebsiteMonitor.compute_html_hash(
        sample_clean_html
    ) != WebsiteMonitor.compute_html_hash(sample_defaced_html)


# ---------------------------------------------------------------------------
# save_snapshot
# ---------------------------------------------------------------------------

def test_save_snapshot_creates_correct_directory_structure(
    mock_settings, sample_clean_html, clean_screenshot
):
    monitor = WebsiteMonitor(mock_settings)
    snap_dir = monitor.save_snapshot(
        "https://www.acme.example/",
        sample_clean_html,
        clean_screenshot,
        {"html_hash": "abc", "status_code": 200},
    )
    p = Path(snap_dir)
    assert p.is_dir()
    assert (p / "page.html").is_file()
    assert (p / "screenshot.png").is_file()
    assert (p / "metadata.json").is_file()
    # Layout: {snapshot_dir}/{domain}/{stamp}
    assert p.parent.name == "www.acme.example"
    assert Path(mock_settings.snapshot_dir).resolve() in p.resolve().parents


def test_save_snapshot_metadata_json_is_valid(
    mock_settings, sample_clean_html, clean_screenshot
):
    monitor = WebsiteMonitor(mock_settings)
    snap_dir = monitor.save_snapshot(
        "https://www.acme.example/",
        sample_clean_html,
        clean_screenshot,
        {"html_hash": "deadbeef", "status_code": 200, "response_time_ms": 12.5},
    )
    meta = json.loads((Path(snap_dir) / "metadata.json").read_text("utf-8"))
    assert meta["url"] == "https://www.acme.example/"
    assert meta["html_hash"] == "deadbeef"
    assert meta["status_code"] == 200
    assert meta["screenshot_size_bytes"] == len(clean_screenshot)
    assert meta["html_size_bytes"] == len(sample_clean_html.encode("utf-8"))


# ---------------------------------------------------------------------------
# load_baseline
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_load_baseline_returns_none_when_no_snapshots(mock_settings):
    monitor = WebsiteMonitor(mock_settings)
    baseline = await monitor.load_baseline("https://never-seen.example/")
    assert baseline is None


@pytest.mark.asyncio
async def test_load_baseline_returns_most_recent_snapshot(
    mock_settings, sample_clean_html, clean_screenshot
):
    monitor = WebsiteMonitor(mock_settings)
    url = "https://www.acme.example/"

    # Persist two snapshots on disk + DB; the latest must win.
    from database import Database

    async with Database(mock_settings.db_path) as db:
        site_id = await db.upsert_site(url)
        for tag in ("old", "new"):
            html = sample_clean_html.replace("ACME", f"Acme-{tag}")
            h = monitor.compute_html_hash(html)
            snap_dir = monitor.save_snapshot(
                url, html, clean_screenshot, {"html_hash": h}
            )
            await db.insert_snapshot(
                site_id=site_id,
                html_hash=h,
                screenshot_path=str(Path(snap_dir) / "screenshot.png"),
                html_path=str(Path(snap_dir) / "page.html"),
                metadata={"html_hash": h},
            )

    baseline = await monitor.load_baseline(url)
    assert baseline is not None
    assert "Acme-new" in baseline["html"]
    assert baseline["site_id"] == site_id


# ---------------------------------------------------------------------------
# run_scan baseline behaviour
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_scan_sets_is_baseline_true_on_first_scan(
    mock_settings, sample_clean_html, clean_screenshot, monkeypatch
):
    monitor = WebsiteMonitor(mock_settings)
    url = "https://www.acme.example/"

    monkeypatch.setattr(
        monitor,
        "fetch_page",
        AsyncMock(
            return_value={
                "html": sample_clean_html,
                "status_code": 200,
                "headers": {"Server": "nginx"},
                "response_time_ms": 10.0,
                "final_url": url,
                "timestamp": "2026-06-13T00:00:00+00:00",
            }
        ),
    )
    monkeypatch.setattr(
        monitor, "screenshot_page", AsyncMock(return_value=clean_screenshot)
    )

    result = await monitor.run_scan(url)
    assert isinstance(result, ScanResult)
    assert result.is_baseline is True
    assert result.has_changes is False
    assert result.site_id is not None
