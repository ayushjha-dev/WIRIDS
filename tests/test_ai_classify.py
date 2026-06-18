"""Tests for modules.ai_classify.ThreatClassifier (Anthropic API mocked)."""

from __future__ import annotations

import json

import pytest

from models import ChangeReport, Severity, ThreatClassification, ThreatType
from modules.ai_classify import (
    HTML_SNIPPET_CHARS,
    ClassificationError,
    ThreatClassifier,
)


@pytest.fixture
def change_report() -> ChangeReport:
    return ChangeReport(
        url="https://www.acme.example/",
        change_score=0.72,
        visual_similarity=0.31,
        text_diff_ratio=0.65,
        added_scripts=["http://malware-cdn.top/loader.js"],
        added_iframes=["http://evil-c2-server.ru/track"],
        dom_changes={
            "changed_title": True,
            "changed_area_pct": 0.55,
            "phash_distance": 28,
            "injections": [
                {
                    "pattern_type": "hidden_iframe",
                    "severity": "critical",
                    "matched_text": "<iframe ...>",
                }
            ],
        },
    )


def _classifier(mock_settings, client) -> ThreatClassifier:
    clf = ThreatClassifier(mock_settings)
    clf._model = client  # inject the mocked Gemini GenerativeModel
    clf._client = client  # also keep _client reference (used by attribution)
    return clf


# ---------------------------------------------------------------------------
# Schema / happy path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_classify_returns_valid_schema(
    mock_settings, mock_anthropic_client, change_report
):
    clf = _classifier(mock_settings, mock_anthropic_client)
    result = await clf.classify(change_report, new_html="<html>HACKED</html>")

    assert isinstance(result, ThreatClassification)
    assert isinstance(result.threat_type, ThreatType)
    assert isinstance(result.severity, Severity)
    assert 0.0 <= result.confidence <= 1.0
    assert result.model_used


@pytest.mark.asyncio
async def test_threat_type_is_valid_taxonomy_value(
    mock_settings, mock_anthropic_client, change_report
):
    clf = _classifier(mock_settings, mock_anthropic_client)
    result = await clf.classify(change_report)
    assert result.threat_type in set(ThreatType)


@pytest.mark.asyncio
async def test_risk_score_is_within_bounds(
    mock_settings, mock_anthropic_client, change_report
):
    clf = _classifier(mock_settings, mock_anthropic_client)
    result = await clf.classify(change_report)
    assert 0.0 <= result.risk_score <= 100.0


# ---------------------------------------------------------------------------
# Retry on malformed JSON
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_classify_handles_json_parse_error_with_retry(
    mock_settings, make_anthropic_client, change_report
):
    """First response is junk, second is valid JSON -> retry succeeds."""
    valid = json.dumps(
        {
            "threat_type": "malware_injection",
            "confidence": 0.8,
            "severity": "high",
            "severity_score": 75,
            "threat_actor_category": "criminal",
            "attack_vectors": ["drive_by"],
            "ioc_hints": [],
            "affected_components": [],
            "recommended_actions": ["isolate"],
            "false_positive_probability": 0.1,
            "analyst_notes": "obfuscated loader",
        }
    )
    client = make_anthropic_client("this is not json at all", valid)
    clf = _classifier(mock_settings, client)

    result = await clf.classify(change_report)

    assert result.threat_type == ThreatType.MALWARE_INJECTION
    assert client.await_count == 2


@pytest.mark.asyncio
async def test_classify_raises_after_failed_retry(
    mock_settings, make_anthropic_client, change_report
):
    client = make_anthropic_client("garbage one", "garbage two")
    clf = _classifier(mock_settings, client)
    with pytest.raises(ClassificationError):
        await clf.classify(change_report)


# ---------------------------------------------------------------------------
# False positive
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_false_positive_returns_low_risk_score(
    mock_settings, make_anthropic_client, change_report
):
    fp_json = json.dumps(
        {
            "threat_type": "false_positive",
            "confidence": 0.2,
            "severity": "info",
            "severity_score": 5,
            "threat_actor_category": "none",
            "attack_vectors": [],
            "ioc_hints": [],
            "affected_components": [],
            "recommended_actions": ["No action"],
            "false_positive_probability": 0.95,
            "analyst_notes": "CDN asset rotation",
        }
    )
    clf = _classifier(mock_settings, make_anthropic_client(fp_json))
    result = await clf.classify(change_report)

    assert result.threat_type == ThreatType.FALSE_POSITIVE
    # Low severity + low confidence + high FP probability -> low score.
    assert result.risk_score < 30.0


# ---------------------------------------------------------------------------
# compute_risk_score bounds
# ---------------------------------------------------------------------------

def test_compute_risk_score_clamped_to_100():
    tc = ThreatClassification(
        severity=Severity.CRITICAL,
        severity_score=100,
        confidence=1.0,
        false_positive_probability=0.0,
    )
    score = ThreatClassifier.compute_risk_score(tc)
    assert 0 <= score <= 100
    assert score == 100


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------

def test_build_prompt_truncates_html_to_2000_chars(change_report):
    long_html = "A" * 5000
    prompt = ThreatClassifier.build_classification_prompt(change_report, long_html)
    # The snippet portion must be capped at HTML_SNIPPET_CHARS.
    assert "A" * HTML_SNIPPET_CHARS in prompt
    assert "A" * (HTML_SNIPPET_CHARS + 1) not in prompt


def test_build_prompt_includes_change_metadata(change_report):
    prompt = ThreatClassifier.build_classification_prompt(change_report, "")
    assert change_report.url in prompt
    assert "CHANGE SCORE" in prompt
    assert "hidden_iframe" in prompt
