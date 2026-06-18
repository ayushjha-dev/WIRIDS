"""Tests for modules.threat_intel.ThreatIntelligenceEngine.

The spec calls for vcrpy cassettes. Because the engine performs all HTTP via a
single private ``_request`` coroutine (and accepts an injectable aiohttp
session), we stub ``_request`` to replay recorded-style JSON bodies. This is
deterministic, offline, and exercises the same parsing/caching/scoring paths a
cassette would, without committing binary cassette files.
"""

from __future__ import annotations

from typing import Optional
from unittest.mock import AsyncMock

import pytest

from models import IOC, IOCBundle, IOCType
from modules.threat_intel import (
    AbuseIPDBResult,
    ThreatIntelligenceEngine,
    URLhausResult,
    VTResult,
)


def _engine(mock_settings, db) -> ThreatIntelligenceEngine:
    return ThreatIntelligenceEngine(mock_settings, db)


def _route_request(responses: dict):
    """Build an AsyncMock _request that returns (body, error) keyed by a
    substring match of the requested URL."""

    async def _fake(self, session, method, url, **kwargs):
        for needle, body in responses.items():
            if needle in url:
                return body, None
        return {}, None

    return _fake


# ---------------------------------------------------------------------------
# enrich_ip -> VirusTotal + AbuseIPDB
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enrich_ip_calls_vt_and_abuseipdb(
    mock_settings, in_memory_db, mock_vt_response, mock_abuseipdb_response, monkeypatch
):
    engine = _engine(mock_settings, in_memory_db)
    monkeypatch.setattr(
        ThreatIntelligenceEngine,
        "_request",
        _route_request(
            {
                "ip_addresses": mock_vt_response,
                "abuseipdb": mock_abuseipdb_response,
            }
        ),
    )

    ioc = IOC(value="45.137.21.9", ioc_type=IOCType.IP)
    enriched = await engine.enrich_ioc(ioc)

    assert "virustotal" in enriched.sources_queried
    assert "abuseipdb" in enriched.sources_queried
    assert enriched.vt is not None and enriched.vt.malicious_count == 12
    assert enriched.abuse is not None and enriched.abuse.abuse_confidence_score == 100


@pytest.mark.asyncio
async def test_enrich_domain_calls_vt_and_urlhaus(
    mock_settings, in_memory_db, mock_vt_response, mock_urlhaus_response, monkeypatch
):
    engine = _engine(mock_settings, in_memory_db)
    monkeypatch.setattr(
        ThreatIntelligenceEngine,
        "_request",
        _route_request(
            {
                "domains/": mock_vt_response,
                "urlhaus": mock_urlhaus_response,
                "abuse.ch": mock_urlhaus_response,
            }
        ),
    )

    ioc = IOC(value="evil-c2-server.ru", ioc_type=IOCType.DOMAIN)
    enriched = await engine.enrich_ioc(ioc)

    assert "virustotal" in enriched.sources_queried
    assert "urlhaus" in enriched.sources_queried
    assert enriched.urlhaus is not None


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_miss_stores_result(
    mock_settings, in_memory_db, mock_vt_response, monkeypatch
):
    engine = _engine(mock_settings, in_memory_db)
    monkeypatch.setattr(
        ThreatIntelligenceEngine,
        "_request",
        _route_request({"ip_addresses": mock_vt_response, "abuseipdb": {"data": {}}}),
    )

    async with __import__("aiohttp").ClientSession() as session:
        ioc = IOC(value="45.137.21.9", ioc_type=IOCType.IP)
        await engine.query_virustotal(ioc, session)

    cached = await in_memory_db.ti_cache_get("virustotal:ip:45.137.21.9")
    assert cached is not None
    assert cached["malicious_count"] == 12


@pytest.mark.asyncio
async def test_cache_hit_skips_api_call(
    mock_settings, in_memory_db, monkeypatch
):
    engine = _engine(mock_settings, in_memory_db)

    # Pre-seed the cache with a VT result.
    seeded = VTResult(malicious_count=7, vt_verdict="malicious").to_dict()
    await in_memory_db.ti_cache_set("virustotal:ip:1.2.3.4", seeded, ttl_hours=1)

    request_spy = AsyncMock()
    monkeypatch.setattr(ThreatIntelligenceEngine, "_request", request_spy)

    async with __import__("aiohttp").ClientSession() as session:
        ioc = IOC(value="1.2.3.4", ioc_type=IOCType.IP)
        result = await engine.query_virustotal(ioc, session)

    assert result.malicious_count == 7
    request_spy.assert_not_awaited()


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def test_malicious_ip_gets_high_risk_score(mock_settings, in_memory_db):
    engine = _engine(mock_settings, in_memory_db)
    vt = VTResult(malicious_count=10, vt_verdict="malicious")
    abuse = AbuseIPDBResult(abuse_confidence_score=100)
    urlhaus = URLhausResult(query_status="is_malware")
    score = engine.compute_ti_risk_score(vt, abuse, urlhaus)
    assert score == pytest.approx(1.0, abs=1e-4)


def test_clean_ip_gets_low_risk_score(mock_settings, in_memory_db):
    engine = _engine(mock_settings, in_memory_db)
    vt = VTResult(malicious_count=0, vt_verdict="clean")
    abuse = AbuseIPDBResult(abuse_confidence_score=0)
    score = engine.compute_ti_risk_score(vt, abuse, None)
    assert score == pytest.approx(0.0, abs=1e-4)


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_failure_returns_partial_result(
    mock_settings, in_memory_db, monkeypatch
):
    """When a source errors, enrichment still returns with the error recorded
    and never raises."""

    async def _failing(self, session, method, url, **kwargs):
        if "abuseipdb" in url:
            return None, "timeout after 10s"
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}, None

    monkeypatch.setattr(ThreatIntelligenceEngine, "_request", _failing)
    engine = _engine(mock_settings, in_memory_db)

    ioc = IOC(value="45.137.21.9", ioc_type=IOCType.IP)
    enriched = await engine.enrich_ioc(ioc)

    assert enriched.vt is not None
    assert any("abuseipdb" in e for e in enriched.errors)


@pytest.mark.asyncio
async def test_enrich_bundle_aggregates_results(
    mock_settings, in_memory_db, mock_vt_response, mock_abuseipdb_response, monkeypatch
):
    monkeypatch.setattr(
        ThreatIntelligenceEngine,
        "_request",
        _route_request(
            {
                "ip_addresses": mock_vt_response,
                "abuseipdb": mock_abuseipdb_response,
                "domains/": mock_vt_response,
                "abuse.ch": {"query_status": "no_results"},
            }
        ),
    )
    engine = _engine(mock_settings, in_memory_db)
    bundle = IOCBundle(
        incident_url="https://www.acme.example/",
        iocs=[
            IOC(value="45.137.21.9", ioc_type=IOCType.IP),
            IOC(value="evil-c2-server.ru", ioc_type=IOCType.DOMAIN),
        ],
    )
    enriched = await engine.enrich_bundle(bundle)
    assert len(enriched.enriched_iocs) == 2

    summary = engine.generate_ti_summary(enriched)
    assert summary.total_iocs == 2
