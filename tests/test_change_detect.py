"""Tests for modules.change_detect.ChangeDetector."""

from __future__ import annotations

from pathlib import Path

import pytest

from modules.change_detect import (
    ChangeDetector,
    HTMLDiff,
    InjectedContent,
    VisualDiff,
)


@pytest.fixture
def detector() -> ChangeDetector:
    return ChangeDetector()


# ---------------------------------------------------------------------------
# Screenshot comparison
# ---------------------------------------------------------------------------

def test_identical_screenshots_have_zero_change(detector, clean_screenshot):
    diff = detector.compare_screenshots(clean_screenshot, clean_screenshot)
    assert diff.phash_distance == 0
    assert diff.ssim_score == pytest.approx(1.0, abs=1e-4)
    assert diff.changed_area_pct == pytest.approx(0.0, abs=1e-4)
    assert diff.has_significant_change is False


def test_small_change_below_threshold(detector, clean_screenshot):
    """A tiny pixel change should not be flagged as significant."""
    from io import BytesIO

    from PIL import Image, ImageDraw

    img = Image.open(BytesIO(clean_screenshot)).convert("RGB")
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, 3, 3], fill=(0, 0, 0))  # 16 px out of 320*240
    buf = BytesIO()
    img.save(buf, format="PNG")

    diff = detector.compare_screenshots(clean_screenshot, buf.getvalue())
    assert diff.changed_area_pct < detector.change_area_threshold
    assert diff.has_significant_change is False


def test_full_replacement_above_threshold(
    detector, clean_screenshot, defaced_screenshot
):
    diff = detector.compare_screenshots(clean_screenshot, defaced_screenshot)
    assert diff.has_significant_change is True
    assert diff.changed_area_pct > detector.change_area_threshold


def test_diff_image_saved_to_disk(detector, clean_screenshot, defaced_screenshot):
    diff = detector.compare_screenshots(clean_screenshot, defaced_screenshot)
    assert diff.diff_image_path
    assert Path(diff.diff_image_path).is_file()


# ---------------------------------------------------------------------------
# HTML diff & injection detection
# ---------------------------------------------------------------------------

def test_injected_script_detected_in_html_diff(
    detector, sample_clean_html, sample_defaced_html
):
    html_diff = detector.compare_html(sample_clean_html, sample_defaced_html)
    assert isinstance(html_diff, HTMLDiff)
    # The defaced page adds an external loader script.
    assert any("malware-cdn.top" in s for s in html_diff.added_scripts)
    assert html_diff.changed_title is True


def test_hidden_iframe_detected_as_injection(detector, sample_defaced_html):
    findings = detector.detect_injections(sample_defaced_html)
    types = {f.pattern_type for f in findings}
    assert "hidden_iframe" in types
    iframe = next(f for f in findings if f.pattern_type == "hidden_iframe")
    assert iframe.severity == "critical"


def test_eval_atob_detected_as_injection(detector, sample_defaced_html):
    findings = detector.detect_injections(sample_defaced_html)
    types = {f.pattern_type for f in findings}
    assert "eval_encoded" in types or "base64_in_script" in types


def test_phishing_form_detected_as_injection(detector, sample_phishing_html):
    findings = detector.detect_injections(
        sample_phishing_html, base_domain="acme.example"
    )
    types = {f.pattern_type for f in findings}
    assert "phishing_form" in types


# ---------------------------------------------------------------------------
# Change score
# ---------------------------------------------------------------------------

def test_change_score_reflects_severity(detector):
    """More injections + larger visual/text diff -> higher score."""
    low_visual = VisualDiff(ssim_score=0.99, changed_area_pct=0.0)
    low_html = HTMLDiff(text_diff_ratio=0.01, changed_title=False)
    low_score = detector.compute_change_score(low_visual, low_html, [])

    high_visual = VisualDiff(ssim_score=0.20, changed_area_pct=0.8)
    high_html = HTMLDiff(
        text_diff_ratio=0.9,
        changed_title=True,
        added_scripts=["http://evil.top/a.js", "http://evil.top/b.js"],
    )
    high_injections = [
        InjectedContent(pattern_type="hidden_iframe", severity="critical"),
        InjectedContent(pattern_type="eval_encoded", severity="high"),
    ]
    high_score = detector.compute_change_score(
        high_visual, high_html, high_injections
    )

    assert 0.0 <= low_score <= 1.0
    assert 0.0 <= high_score <= 1.0
    assert high_score > low_score


def test_build_change_report_sets_exceeded_threshold(
    detector, sample_clean_html, sample_defaced_html
):
    html_diff = detector.compare_html(sample_clean_html, sample_defaced_html)
    injections = detector.detect_injections(sample_defaced_html)
    visual = VisualDiff(ssim_score=0.3, changed_area_pct=0.5)
    report = detector.build_change_report(
        url="https://www.acme.example/",
        visual=visual,
        html_diff=html_diff,
        injections=injections,
        min_change_score=0.10,
    )
    assert report.change_score >= 0.10
    assert report.exceeded_threshold is True
    assert report.added_scripts
