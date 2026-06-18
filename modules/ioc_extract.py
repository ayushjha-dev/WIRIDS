"""WIDIRS indicator-of-compromise (IOC) extraction module.

Extracts IOCs (IPs, domains, URLs, file hashes, emails, crypto wallets and
attacker handles) from defaced HTML and HTTP response headers using a set of
vetted regular expressions, then normalises and de-duplicates them into an
``IOCBundle`` ready for threat-intel enrichment and attribution.

Design notes:
- Pure-CPU and synchronous; no network calls. Safe to run inline in the
  pipeline.
- Self/benign noise is filtered: the site's own domain, RFC1918/loopback IPs,
  and common CDN asset hosts are dropped to keep the bundle high-signal.
- All matched text is treated as untrusted; values are length-bounded.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import structlog
from bs4 import BeautifulSoup

from models import IOC, IOCBundle, IOCType

logger = structlog.get_logger(__name__)

MAX_VALUE_LEN = 256

# Hosts whose assets are routine and should not be reported as IOCs.
_BENIGN_HOSTS: Tuple[str, ...] = (
    "w3.org",
    "schema.org",
    "gravatar.com",
    "gstatic.com",
    "googleapis.com",
    "jsdelivr.net",
    "cloudflare.com",
    "cdnjs.cloudflare.com",
    "jquery.com",
    "bootstrapcdn.com",
    "fontawesome.com",
)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_URL = re.compile(r"\bhttps?://[^\s\"'<>()]+", re.I)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|ir|info|biz|xyz|top|onion|gov|edu|co|uk|de|tk|ml)\b",
    re.I,
)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
# Crypto wallets: BTC (legacy/bech32), ETH.
_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
# Attacker handles in defacement bragging text: "Hacked by X", "by ~X~".
_HANDLE = re.compile(
    r"(?:hacked\s+by|defaced\s+by|owned\s+by|greetz\s+to|by)\s*[:~\-]?\s*"
    r"([A-Za-z0-9_\-\.]{3,32})",
    re.I,
)


def _is_benign_host(host: str) -> bool:
    host = host.lower()
    return any(host == b or host.endswith("." + b) for b in _BENIGN_HOSTS)


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(("10.", "127.", "169.254.", "192.168.", "0.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


class IOCExtractor:
    """Regex-based IOC extractor for defaced web content."""

    def __init__(self, max_per_type: int = 200) -> None:
        """Initialize the extractor.

        Args:
            max_per_type: Safety cap on the number of IOCs kept per type.
        """
        self.max_per_type = max_per_type

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def extract_all(
        self,
        html: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> IOCBundle:
        """Extract and de-duplicate all IOCs from page content + headers.

        Args:
            html: Raw (possibly defaced) HTML.
            url: The incident URL (its domain is treated as self/benign).
            headers: HTTP response headers to also scan (values only).

        Returns:
            A populated IOCBundle for the incident.
        """
        html = html or ""
        self_host = (urlparse(url).hostname or "").lower()
        corpus = html
        if headers:
            corpus = corpus + "\n" + "\n".join(str(v) for v in headers.values())

        # Visible text (for handles) with scripts/styles stripped.
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag in soup.find_all(["script", "style", "noscript"]):
                tag.decompose()
            visible_text = soup.get_text(" ")
        except Exception:  # parsing must never break extraction
            visible_text = html

        seen: Set[Tuple[str, str]] = set()
        iocs: List[IOC] = []

        def _add(value: str, ioc_type: IOCType, confidence: float, context: str) -> None:
            value = (value or "").strip().strip(".,;)\"'")
            if not value or len(value) > MAX_VALUE_LEN:
                return
            key = (ioc_type.value, value.lower())
            if key in seen:
                return
            counts = sum(1 for i in iocs if i.ioc_type == ioc_type)
            if counts >= self.max_per_type:
                return
            seen.add(key)
            iocs.append(
                IOC(value=value, ioc_type=ioc_type, confidence=confidence, context=context)
            )

        # --- URLs (extract host -> domain too) ---
        for m in _URL.finditer(corpus):
            raw = m.group(0)
            host = (urlparse(raw).hostname or "").lower()
            if host and host != self_host and not _is_benign_host(host):
                _add(raw, IOCType.URL, 0.7, "url in content")

        # --- domains ---
        for m in _DOMAIN.finditer(corpus):
            dom = m.group(0).lower()
            if dom != self_host and not _is_benign_host(dom) and not dom.endswith("." + self_host):
                _add(dom, IOCType.DOMAIN, 0.6, "domain in content")

        # --- IPs ---
        for m in _IPV4.finditer(corpus):
            ip = m.group(0)
            if not _is_private_ip(ip):
                _add(ip, IOCType.IP, 0.7, "ip in content")

        # --- hashes (longest first to avoid sha256 matching md5 substrings) ---
        for m in _SHA256.finditer(corpus):
            _add(m.group(0), IOCType.HASH_SHA256, 0.8, "sha256 hash")
        for m in _SHA1.finditer(corpus):
            _add(m.group(0), IOCType.HASH_SHA1, 0.75, "sha1 hash")
        for m in _MD5.finditer(corpus):
            _add(m.group(0), IOCType.HASH_MD5, 0.7, "md5 hash")

        # --- emails ---
        for m in _EMAIL.finditer(corpus):
            email = m.group(0)
            host = email.split("@")[-1].lower()
            if host != self_host and not _is_benign_host(host):
                _add(email, IOCType.EMAIL, 0.7, "email in content")

        # --- crypto wallets ---
        for m in _BTC.finditer(corpus):
            _add(m.group(0), IOCType.WALLET, 0.85, "bitcoin wallet")
        for m in _ETH.finditer(corpus):
            _add(m.group(0), IOCType.WALLET, 0.85, "ethereum wallet")

        # --- attacker handles (visible text only) ---
        for m in _HANDLE.finditer(visible_text):
            handle = m.group(1)
            if handle and handle.lower() not in ("the", "and", "you"):
                _add(handle, IOCType.HANDLE, 0.6, "defacement signature text")

        bundle = IOCBundle(
            incident_url=url,
            iocs=iocs,
            extraction_method="regex",
        )
        logger.info(
            "iocs_extracted",
            url=url,
            count=bundle.count,
            types=sorted({i.ioc_type.value for i in iocs}),
        )
        return bundle
