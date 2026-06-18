"""End-to-end pipeline test for run_full_incident_pipeline.

External boundaries are mocked (HTTP fetch, headless browser screenshot,
Google Gemini LLM, and threat-intel HTTP); all detection / extraction / scoring /
reporting logic runs for real against a :memory: database.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

import main
from database import Database
from modules.ai_classify import ThreatClassifier
from modules.monitor import WebsiteMonitor
from modules.threat_intel import ThreatIntelligenceEngine

# Gemini-style mock response
class _FakeGeminiResponse:
    def __init__(self, text: str) -> None:
        self.text = text
        self.usage_metadata = type('Meta', (), {'prompt_token_count': 100, 'candidates_token_count': 50})()


CLASSIFICATION_JSON = json.dumps(
    {
        "threat_type": "hacktivist_defacement",
        "confidence": 0.92,
        "severity": "high",
        "severity_score": 85,
        "threat_actor_category": "hacktivist",
        "attack_vectors": ["cms_exploit"],
        "ioc_hints": ["evil-c2-server.ru"],
        "affected_components": ["homepage"],
        "recommended_actions": ["Take site offline", "Restore from backup"],
        "false_positive_probability": 0.03,
        "analyst_notes": "GhostSquad hacktivist defacement.",
    }
)


@pytest.mark.asyncio
async def test_run_full_incident_pipeline_processes_incident(
    mock_settings,
    sample_clean_html,
    sample_defaced_html,
    clean_screenshot,
    defaced_screenshot,
    monkeypatch,
):
    url = "https://www.acme.example/"

    # --- 1. Seed a baseline snapshot so the scan reports a change ---
    baseline_monitor = WebsiteMonitor(mock_settings)
    async with Database(mock_settings.db_path) as seed_db:
        site_id = await seed_db.upsert_site(url)
        h = baseline_monitor.compute_html_hash(sample_clean_html)
        snap_dir = baseline_monitor.save_snapshot(
            url, sample_clean_html, clean_screenshot, {"html_hash": h}
        )
        await seed_db.insert_snapshot(
            site_id=site_id,
            html_hash=h,
            screenshot_path=str(Path(snap_dir) / "screenshot.png"),
            html_path=str(Path(snap_dir) / "page.html"),
            metadata={"html_hash": h},
        )

    # --- 2. Mock the network + browser so run_scan returns the defaced page ---
    async def _fake_fetch(self, target_url):
        return {
            "html": sample_defaced_html,
            "status_code": 200,
            "headers": {"Server": "nginx", "X-Powered-By": "PHP/7.4"},
            "response_time_ms": 42.0,
            "final_url": target_url,
            "timestamp": "2026-06-13T00:00:00+00:00",
        }

    monkeypatch.setattr(WebsiteMonitor, "fetch_page", _fake_fetch)
    monkeypatch.setattr(
        WebsiteMonitor,
        "screenshot_page",
        AsyncMock(return_value=defaced_screenshot),
    )

    # --- 3. Mock the Gemini model used by the classifier ---
    fake_model = AsyncMock()
    fake_model.generate_content_async = AsyncMock(
        return_value=_FakeGeminiResponse(CLASSIFICATION_JSON)
    )
    original_init = ThreatClassifier.__init__

    def _patched_init(self, config):
        original_init(self, config)
        self._model = fake_model
        self._client = fake_model  # attribution module reads _client

    monkeypatch.setattr(ThreatClassifier, "__init__", _patched_init)

    # --- 4. Mock threat-intel HTTP (no real API calls) ---
    async def _fake_request(self, session, method, target_url, **kwargs):
        return {}, "offline-test"

    monkeypatch.setattr(ThreatIntelligenceEngine, "_request", _fake_request)

    # --- 5. Run the full pipeline ---
    async with Database(mock_settings.db_path) as db:
        result = await main.run_full_incident_pipeline(url, mock_settings, db)

        # status == incident_processed
        assert result.status == "incident_processed"
        assert result.success is True

        # classification.threat_type != false_positive and risk > 30
        # (verified via the persisted incident row)
        incident_row = await db.get_incident(result.db_row_id)
        assert incident_row is not None
        assert incident_row["threat_type"] != "false_positive"
        assert incident_row["risk_score"] > 30

        # At least 1 IOC extracted and stored
        iocs = await db.get_iocs_for_incident(result.db_row_id)
        assert len(iocs) >= 1

        # DB has exactly 1 incident record
        cur = await db.conn.execute("SELECT COUNT(*) AS c FROM incidents")
        assert (await cur.fetchone())["c"] == 1

    # --- 6. Report artefacts exist on disk ---
    report_dir = Path(mock_settings.report_dir) / result.incident_id
    assert (report_dir / "report.html").is_file()
    # PDF is produced when WeasyPrint is installed; otherwise the generator
    # degrades to HTML-only. Accept either, but require HTML always.
    pdf = report_dir / "report.pdf"
    assert pdf.is_file() or not pdf.exists()


@pytest.mark.asyncio
async def test_pipeline_baseline_set_on_first_scan(
    mock_settings, sample_clean_html, clean_screenshot, monkeypatch
):
    """With no prior baseline, the first scan terminates as baseline_set."""
    url = "https://first-seen.example/"

    async def _fake_fetch(self, target_url):
        return {
            "html": sample_clean_html,
            "status_code": 200,
            "headers": {},
            "response_time_ms": 10.0,
            "final_url": target_url,
            "timestamp": "2026-06-13T00:00:00+00:00",
        }

    monkeypatch.setattr(WebsiteMonitor, "fetch_page", _fake_fetch)
    monkeypatch.setattr(
        WebsiteMonitor, "screenshot_page", AsyncMock(return_value=clean_screenshot)
    )

    async with Database(mock_settings.db_path) as db:
        result = await main.run_full_incident_pipeline(url, mock_settings, db)

    assert result.status == "baseline_set"
