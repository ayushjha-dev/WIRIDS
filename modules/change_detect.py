"""WIDIRS visual & structural change detection module.

Compares screenshots (pHash, SSIM, pixel-level diff) and HTML documents
(structure, scripts, iframes, text), scans for injected malicious content,
and produces a weighted 0.0-1.0 change score.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import cv2
import imagehash
import numpy as np
import structlog
from bs4 import BeautifulSoup
from PIL import Image
from skimage.metrics import structural_similarity

from models import ChangeReport, SerializableMixin

logger = structlog.get_logger(__name__)

DEFAULT_THRESHOLDS: Dict[str, float] = {
    "phash_threshold": 10,         # Hamming distance (0-64)
    "ssim_threshold": 0.85,        # Structural Similarity (0-1)
    "change_area_threshold": 0.05, # 5% of pixels changed
}

#: Trusted CDN hosts; external scripts from elsewhere are flagged.
CDN_ALLOWLIST: Tuple[str, ...] = (
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
)

#: Crypto-miner signatures (case-insensitive substring match).
MINER_SIGNATURES: Tuple[str, ...] = (
    "coinhive",
    "cryptonight",
    "monero",
    "coinimp",
    "jsecoin",
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class VisualDiff(SerializableMixin):
    """Result of comparing two screenshots."""

    phash_distance: int = 0
    ssim_score: float = 1.0
    changed_area_pct: float = 0.0
    bounding_boxes: List[Tuple[int, int, int, int]] = field(default_factory=list)
    diff_image_path: str = ""
    has_significant_change: bool = False


@dataclass
class HTMLDiff(SerializableMixin):
    """Result of comparing two HTML documents."""

    changed_title: bool = False
    old_title: str = ""
    new_title: str = ""
    added_scripts: List[str] = field(default_factory=list)
    removed_scripts: List[str] = field(default_factory=list)
    added_iframes: List[str] = field(default_factory=list)
    new_external_links: List[str] = field(default_factory=list)
    changed_meta_tags: List[str] = field(default_factory=list)
    text_diff_ratio: float = 0.0   # 0.0 identical .. 1.0 completely different
    unified_diff: str = ""


@dataclass
class InjectedContent(SerializableMixin):
    """A suspicious pattern found in HTML content."""

    pattern_type: str = ""
    matched_text: str = ""
    severity: str = "medium"       # low | medium | high | critical


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class ChangeDetector:
    """Visual + structural change detector for defacement analysis."""

    #: (pattern_type, compiled regex, severity)
    INJECTION_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]", str], ...] = (
        (
            "base64_in_script",
            re.compile(r"<script[^>]*>[^<]*atob\s*\([^)]*\)", re.I | re.S),
            "high",
        ),
        (
            "eval_encoded",
            re.compile(
                r"eval\s*\(\s*(?:[^)]*?)(?:atob|unescape|String\.fromCharCode)",
                re.I,
            ),
            "high",
        ),
        (
            "hidden_iframe",
            re.compile(
                r"<iframe[^>]+(?:display:\s*none|width=[\"']?0[\"']?"
                r"|height=[\"']?0[\"']?)[^>]*>",
                re.I,
            ),
            "critical",
        ),
    )

    DIFF_PIXEL_THRESHOLD: int = 30   # grayscale delta to count as "changed"
    MAX_BOXES: int = 5
    MAX_MATCH_LEN: int = 200         # truncate matched_text for reports

    def __init__(self, thresholds: Optional[Dict[str, float]] = None) -> None:
        """Initialize the detector.

        Args:
            thresholds: Optional overrides for phash_threshold,
                ssim_threshold and change_area_threshold.
        """
        merged = dict(DEFAULT_THRESHOLDS)
        merged.update(thresholds or {})
        self.phash_threshold: float = merged["phash_threshold"]
        self.ssim_threshold: float = merged["ssim_threshold"]
        self.change_area_threshold: float = merged["change_area_threshold"]
        self.diff_dir = Path("data/diffs")
        self.diff_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Image helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _load_rgb(img_bytes: bytes) -> Image.Image:
        """Load image bytes as RGB, normalizing grayscale/RGBA/palette inputs."""
        img = Image.open(BytesIO(img_bytes))
        if img.mode != "RGB":
            # Handles L (grayscale), LA, RGBA, P (palette), CMYK, etc.
            img = img.convert("RGB")
        return img

    @staticmethod
    def _to_gray(arr: np.ndarray) -> np.ndarray:
        """Convert an HxW, HxWx3, or HxWx4 array to single-channel grayscale."""
        if arr.ndim == 2:
            return arr
        if arr.shape[2] == 4:
            arr = cv2.cvtColor(arr, cv2.COLOR_RGBA2RGB)
        return cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)

    # ------------------------------------------------------------------
    # 1. compare_screenshots
    # ------------------------------------------------------------------
    def compare_screenshots(self, img_old: bytes, img_new: bytes) -> VisualDiff:
        """Compare two screenshots with pHash, SSIM and pixel diffing.

        Args:
            img_old: Baseline screenshot bytes (any common format/mode).
            img_new: Current screenshot bytes.

        Returns:
            VisualDiff with similarity metrics, changed-region bounding
            boxes, a saved red-overlay diff image and a significance flag.
        """
        pil_old = self._load_rgb(img_old)
        pil_new = self._load_rgb(img_new)

        # Normalize dimensions: resize the new capture to the baseline size.
        if pil_new.size != pil_old.size:
            pil_new = pil_new.resize(pil_old.size, Image.LANCZOS)

        # --- perceptual hash ---
        hash_old = imagehash.phash(pil_old)
        hash_new = imagehash.phash(pil_new)
        phash_distance = int(hash_old - hash_new)

        # --- SSIM on grayscale ---
        arr_old = np.asarray(pil_old)
        arr_new = np.asarray(pil_new)
        gray_old = self._to_gray(arr_old)
        gray_new = self._to_gray(arr_new)
        ssim_score = float(structural_similarity(gray_old, gray_new))

        # --- pixel diff + binary mask ---
        diff = cv2.absdiff(gray_old, gray_new)
        _, mask = cv2.threshold(
            diff, self.DIFF_PIXEL_THRESHOLD, 255, cv2.THRESH_BINARY
        )
        changed_area_pct = float(np.count_nonzero(mask)) / float(mask.size)

        # --- bounding boxes (top 5 by area) ---
        contours, _ = cv2.findContours(
            mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
        )
        contours = sorted(contours, key=cv2.contourArea, reverse=True)
        bounding_boxes: List[Tuple[int, int, int, int]] = [
            tuple(int(v) for v in cv2.boundingRect(c))  # type: ignore[misc]
            for c in contours[: self.MAX_BOXES]
        ]

        # --- red-overlay diff image ---
        overlay = arr_new.copy()
        if overlay.ndim == 2:
            overlay = cv2.cvtColor(overlay, cv2.COLOR_GRAY2RGB)
        elif overlay.shape[2] == 4:
            overlay = cv2.cvtColor(overlay, cv2.COLOR_RGBA2RGB)
        red = np.zeros_like(overlay)
        red[..., 0] = 255  # RGB red channel
        changed = mask.astype(bool)
        overlay[changed] = (
            0.5 * overlay[changed] + 0.5 * red[changed]
        ).astype(np.uint8)
        for (x, y, w, h) in bounding_boxes:
            cv2.rectangle(overlay, (x, y), (x + w, y + h), (255, 0, 0), 2)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        diff_image_path = str(self.diff_dir / f"diff_{stamp}.png")
        Image.fromarray(overlay).save(diff_image_path)

        has_significant_change = (
            phash_distance > self.phash_threshold
            or ssim_score < self.ssim_threshold
            or changed_area_pct > self.change_area_threshold
        )

        # Guard against tiny pixel changes/noise triggering a false significant change.
        if changed_area_pct < 0.005 and ssim_score >= 0.99:
            has_significant_change = False

        result = VisualDiff(
            phash_distance=phash_distance,
            ssim_score=round(ssim_score, 4),
            changed_area_pct=round(changed_area_pct, 4),
            bounding_boxes=bounding_boxes,
            diff_image_path=diff_image_path,
            has_significant_change=has_significant_change,
        )
        logger.info(
            "screenshots_compared",
            phash_distance=phash_distance,
            ssim=result.ssim_score,
            changed_area_pct=result.changed_area_pct,
            significant=has_significant_change,
        )
        return result

    # ------------------------------------------------------------------
    # HTML extraction helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_features(html: str) -> Dict[str, Any]:
        """Extract comparable features from an HTML document."""
        soup = BeautifulSoup(html, "lxml")
        title = soup.title.get_text(strip=True) if soup.title else ""
        metas = sorted(
            {
                f"{m.get('name') or m.get('property') or m.get('http-equiv') or 'meta'}"
                f"={m.get('content', '')}"
                for m in soup.find_all("meta")
            }
        )
        scripts = {
            s["src"].strip() for s in soup.find_all("script", src=True)
        }
        links = {
            l["href"].strip() for l in soup.find_all("link", href=True)
        }
        iframes = {
            i["src"].strip() for i in soup.find_all("iframe", src=True)
        }
        external_urls = {
            a["href"].strip()
            for a in soup.find_all("a", href=True)
            if a["href"].startswith(("http://", "https://"))
        }
        # Visible text: drop script/style first.
        for tag in soup.find_all(["script", "style", "noscript"]):
            tag.decompose()
        visible_text = " ".join(soup.get_text(separator=" ").split())
        return {
            "title": title,
            "metas": metas,
            "scripts": scripts,
            "links": links,
            "iframes": iframes,
            "external_urls": external_urls,
            "text": visible_text,
        }

    # ------------------------------------------------------------------
    # 2. compare_html
    # ------------------------------------------------------------------
    def compare_html(self, html_old: str, html_new: str) -> HTMLDiff:
        """Compare two HTML documents structurally and textually.

        Args:
            html_old: Baseline HTML.
            html_new: Current HTML.

        Returns:
            HTMLDiff describing title/meta/script/iframe/link changes,
            text difference ratio (0=identical, 1=fully different) and a
            truncated unified diff.
        """
        old = self._extract_features(html_old)
        new = self._extract_features(html_new)

        matcher = difflib.SequenceMatcher(None, old["text"], new["text"])
        # SequenceMatcher.ratio() is *similarity*; invert for a diff ratio.
        text_diff_ratio = round(1.0 - matcher.ratio(), 4)

        udiff_lines = list(
            difflib.unified_diff(
                old["text"].splitlines(),
                new["text"].splitlines(),
                fromfile="baseline",
                tofile="current",
                lineterm="",
            )
        )[:50]

        result = HTMLDiff(
            changed_title=old["title"] != new["title"],
            old_title=old["title"],
            new_title=new["title"],
            added_scripts=sorted(new["scripts"] - old["scripts"]),
            removed_scripts=sorted(old["scripts"] - new["scripts"]),
            added_iframes=sorted(new["iframes"] - old["iframes"]),
            new_external_links=sorted(
                new["external_urls"] - old["external_urls"]
            ),
            changed_meta_tags=sorted(
                set(new["metas"]).symmetric_difference(old["metas"])
            ),
            text_diff_ratio=text_diff_ratio,
            unified_diff="\n".join(udiff_lines),
        )
        logger.info(
            "html_compared",
            changed_title=result.changed_title,
            added_scripts=len(result.added_scripts),
            added_iframes=len(result.added_iframes),
            text_diff_ratio=text_diff_ratio,
        )
        return result

    # ------------------------------------------------------------------
    # 3. detect_injections
    # ------------------------------------------------------------------
    def detect_injections(
        self, html: str, base_domain: Optional[str] = None
    ) -> List[InjectedContent]:
        """Scan HTML for known malicious injection patterns.

        Args:
            html: HTML document to scan.
            base_domain: The site's own hostname; used to flag phishing
                forms posting to foreign domains. If None, the phishing
                check flags any absolute external form action.

        Returns:
            List of InjectedContent findings (may be empty).
        """
        findings: List[InjectedContent] = []

        # --- regex-based patterns ---
        for pattern_type, regex, severity in self.INJECTION_PATTERNS:
            for match in regex.finditer(html):
                findings.append(
                    InjectedContent(
                        pattern_type=pattern_type,
                        matched_text=match.group(0)[: self.MAX_MATCH_LEN],
                        severity=severity,
                    )
                )

        # --- crypto miner signatures ---
        lower = html.lower()
        for sig in MINER_SIGNATURES:
            idx = lower.find(sig)
            if idx != -1:
                findings.append(
                    InjectedContent(
                        pattern_type="crypto_miner",
                        matched_text=html[idx: idx + self.MAX_MATCH_LEN],
                        severity="critical",
                    )
                )

        # --- DOM-based checks (more reliable than lookahead regexes) ---
        soup = BeautifulSoup(html, "lxml")

        # External scripts not on the CDN allowlist.
        for script in soup.find_all("script", src=True):
            src = script["src"].strip()
            if not src.startswith(("http://", "https://")):
                continue
            host = (urlparse(src).hostname or "").lower()
            on_allowlist = any(
                host == cdn or host.endswith("." + cdn)
                for cdn in CDN_ALLOWLIST
            )
            same_site = base_domain and (
                host == base_domain or host.endswith("." + base_domain)
            )
            if not on_allowlist and not same_site:
                findings.append(
                    InjectedContent(
                        pattern_type="external_script_non_cdn",
                        matched_text=src[: self.MAX_MATCH_LEN],
                        severity="high",
                    )
                )

        # Forms posting to a foreign domain (credential phishing).
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if not action.startswith(("http://", "https://")):
                continue
            host = (urlparse(action).hostname or "").lower()
            same_site = base_domain and (
                host == base_domain or host.endswith("." + base_domain)
            )
            if not same_site:
                findings.append(
                    InjectedContent(
                        pattern_type="phishing_form",
                        matched_text=action[: self.MAX_MATCH_LEN],
                        severity="critical",
                    )
                )

        logger.info(
            "injection_scan_completed",
            findings=len(findings),
            types=sorted({f.pattern_type for f in findings}),
        )
        return findings

    # ------------------------------------------------------------------
    # 4. compute_change_score
    # ------------------------------------------------------------------
    @staticmethod
    def compute_change_score(
        visual: VisualDiff,
        html_diff: HTMLDiff,
        injections: List[InjectedContent],
    ) -> float:
        """Combine visual, structural and injection signals into one score.

        Weighted formula (clamped to 0.0-1.0):
            visual  = (1 - ssim) * 0.25 + min(changed_area * 5, 1) * 0.15
            html    = text_diff_ratio * 0.20 + min(added_scripts * 0.1, 0.2)
            inject  = min(injections * 0.15, 0.30)
            title   = 0.10 if title changed

        Args:
            visual: Output of compare_screenshots.
            html_diff: Output of compare_html.
            injections: Output of detect_injections.

        Returns:
            Change score in [0.0, 1.0].
        """
        visual_score = (
            (1.0 - visual.ssim_score) * 0.25
            + min(visual.changed_area_pct * 5.0, 1.0) * 0.15
        )
        html_score = (
            html_diff.text_diff_ratio * 0.20
            + min(len(html_diff.added_scripts) * 0.1, 0.2)
        )
        inject_score = min(len(injections) * 0.15, 0.30)
        title_bonus = 0.10 if html_diff.changed_title else 0.0

        score = visual_score + html_score + inject_score + title_bonus
        score = max(0.0, min(1.0, score))

        logger.debug(
            "change_score_computed",
            visual=round(visual_score, 4),
            html=round(html_score, 4),
            inject=round(inject_score, 4),
            title_bonus=title_bonus,
            total=round(score, 4),
        )
        return round(score, 4)

    # ------------------------------------------------------------------
    # Convenience: build a models.ChangeReport
    # ------------------------------------------------------------------
    def build_change_report(
        self,
        url: str,
        visual: VisualDiff,
        html_diff: HTMLDiff,
        injections: List[InjectedContent],
        site_id: Optional[int] = None,
        min_change_score: float = 0.10,
    ) -> ChangeReport:
        """Assemble a models.ChangeReport from the individual diff results.

        Args:
            url: Scanned URL.
            visual: Screenshot comparison result.
            html_diff: HTML comparison result.
            injections: Injection scan findings.
            site_id: Optional DB site ID.
            min_change_score: Threshold used to set exceeded_threshold.

        Returns:
            Populated ChangeReport for downstream AI analysis.
        """
        score = self.compute_change_score(visual, html_diff, injections)
        return ChangeReport(
            url=url,
            site_id=site_id,
            change_score=score,
            visual_similarity=visual.ssim_score,
            text_diff_ratio=html_diff.text_diff_ratio,
            dom_changes={
                "phash_distance": visual.phash_distance,
                "changed_area_pct": visual.changed_area_pct,
                "changed_title": html_diff.changed_title,
                "changed_meta_tags": html_diff.changed_meta_tags,
                "removed_scripts": html_diff.removed_scripts,
                "bounding_boxes": visual.bounding_boxes,
                "diff_image_path": visual.diff_image_path,
                "injections": [i.to_dict() for i in injections],
            },
            added_scripts=html_diff.added_scripts,
            removed_scripts=html_diff.removed_scripts,
            added_iframes=html_diff.added_iframes,
            added_links=html_diff.new_external_links,
            suspicious_keywords=sorted(
                {i.pattern_type for i in injections}
            ),
            exceeded_threshold=score >= min_change_score,
        )
