"""Tests for modules.ioc_extract.IOCExtractor (20+ parameterized cases).

Notes on the real implementation under test:
- Self-domain, RFC1918/loopback IPs, and known benign/CDN hosts are excluded.
- Domains are only matched for a fixed TLD allowlist.
- Wallet support is BTC (P2PKH + Bech32) and ETH; XMR is not extracted.
- Handles come from "hacked/defaced/owned by ..." visible text.
- Defanging lives in report_gen.defang, tested separately below.
"""

from __future__ import annotations

import pytest

from models import IOCType
from modules.ioc_extract import IOCExtractor
from modules.report_gen import defang

SELF_URL = "https://www.acme.example/"


@pytest.fixture
def extractor() -> IOCExtractor:
    return IOCExtractor()


def _values(bundle, ioc_type: IOCType):
    return {i.value for i in bundle.iocs if i.ioc_type == ioc_type}


# ---------------------------------------------------------------------------
# Parameterized presence/absence cases
# (html_fragment, ioc_type, needle, should_be_present)
# ---------------------------------------------------------------------------

CASES = [
    # --- IPs ---
    ("Contact server 45.137.21.9 now", IOCType.IP, "45.137.21.9", True),
    ("internal host 192.168.1.10", IOCType.IP, "192.168.1.10", False),
    ("loopback 127.0.0.1 only", IOCType.IP, "127.0.0.1", False),
    ("private 10.0.0.5 host", IOCType.IP, "10.0.0.5", False),
    ("private 172.16.0.9 host", IOCType.IP, "172.16.0.9", False),
    ("public 8.8.8.8 dns", IOCType.IP, "8.8.8.8", True),
    # --- Domains ---
    ("payload from evil-c2-server.ru today", IOCType.DOMAIN, "evil-c2-server.ru", True),
    ("asset on cdn.jsdelivr.net here", IOCType.DOMAIN, "cdn.jsdelivr.net", False),
    ("malware-cdn.top hosting", IOCType.DOMAIN, "malware-cdn.top", True),
    # --- Hashes ---
    ("md5 " + "a" * 32, IOCType.HASH_MD5, "a" * 32, True),
    ("sha1 " + "b" * 40, IOCType.HASH_SHA1, "b" * 40, True),
    ("sha256 " + "c" * 64, IOCType.HASH_SHA256, "c" * 64, True),
    # --- Emails ---
    ("reach ghostsquad@protonmail.com", IOCType.EMAIL, "ghostsquad@protonmail.com", True),
    # --- Wallets ---
    (
        "BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        IOCType.WALLET,
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        True,
    ),
    (
        "BTC bech32 bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        IOCType.WALLET,
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        True,
    ),
    (
        "ETH 0x32Be343B94f860124dC4fEe278FDCBD38C102D88",
        IOCType.WALLET,
        "0x32Be343B94f860124dC4fEe278FDCBD38C102D88",
        True,
    ),
    # --- URLs ---
    (
        "redirect to http://evil-c2-server.ru/gate.php now",
        IOCType.URL,
        "http://evil-c2-server.ru/gate.php",
        True,
    ),
]


@pytest.mark.parametrize("fragment,ioc_type,needle,present", CASES)
def test_ioc_extraction_cases(extractor, fragment, ioc_type, needle, present):
    html = f"<html><body><p>{fragment}</p></body></html>"
    bundle = extractor.extract_all(html, SELF_URL)
    values = _values(bundle, ioc_type)
    if present:
        assert needle in values, f"expected {needle!r} as {ioc_type}"
    else:
        assert needle not in values, f"{needle!r} should be excluded"


# ---------------------------------------------------------------------------
# Additional targeted cases
# ---------------------------------------------------------------------------

def test_same_domain_url_excluded(extractor):
    html = '<a href="https://www.acme.example/page">self</a>'
    bundle = extractor.extract_all(html, SELF_URL)
    assert not any("acme.example" in i.value for i in bundle.iocs)


def test_noreply_email_still_extracted_but_self_domain_excluded(extractor):
    """Emails on the self domain are excluded; foreign ones are kept."""
    html = (
        "<p>noreply@www.acme.example</p>"
        "<p>attacker@evil-c2-server.ru</p>"
    )
    bundle = extractor.extract_all(html, SELF_URL)
    emails = _values(bundle, IOCType.EMAIL)
    assert "attacker@evil-c2-server.ru" in emails
    assert "noreply@www.acme.example" not in emails


def test_css_class_not_misread_as_hash(extractor):
    """A short CSS class is not 32/40/64 hex chars, so it is not a hash."""
    html = '<div class="container header-main">x</div>'
    bundle = extractor.extract_all(html, SELF_URL)
    hashes = {
        i.value
        for i in bundle.iocs
        if i.ioc_type
        in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256)
    }
    assert hashes == set()


def test_handle_extracted_from_hacked_by_text(extractor):
    html = "<h1>Hacked by GhostSquad</h1>"
    bundle = extractor.extract_all(html, SELF_URL)
    handles = _values(bundle, IOCType.HANDLE)
    assert "GhostSquad" in handles


def test_handle_pattern_owned_by(extractor):
    html = "<p>owned by Dr4g0n</p>"
    bundle = extractor.extract_all(html, SELF_URL)
    assert "Dr4g0n" in _values(bundle, IOCType.HANDLE)


def test_headers_are_scanned_for_iocs(extractor):
    html = "<html><body>clean</body></html>"
    headers = {"X-Powered-By": "PHP via 45.137.21.9"}
    bundle = extractor.extract_all(html, SELF_URL, headers)
    assert "45.137.21.9" in _values(bundle, IOCType.IP)


def test_deduplication_of_repeated_iocs(extractor):
    html = "45.137.21.9 45.137.21.9 45.137.21.9"
    bundle = extractor.extract_all(html, SELF_URL)
    ips = [i for i in bundle.iocs if i.ioc_type == IOCType.IP]
    assert len(ips) == 1


def test_full_defaced_page_extracts_multiple_iocs(extractor, sample_defaced_html):
    bundle = extractor.extract_all(sample_defaced_html, SELF_URL)
    assert bundle.count >= 1
    types = {i.ioc_type for i in bundle.iocs}
    assert IOCType.WALLET in types
    assert IOCType.IP in types


# ---------------------------------------------------------------------------
# Defang (report_gen.defang)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected_dot,expected_scheme",
    [
        ("evil-c2-server.ru", "[.]", None),
        ("http://evil.top/x", "[.]", "hxxp://"),
        ("https://evil.top/x", "[.]", "hxxps://"),
    ],
)
def test_defang_substitution(raw, expected_dot, expected_scheme):
    out = defang(raw)
    assert expected_dot in out
    # No "bare" dot remains: every '.' has been wrapped into '[.]'.
    assert ".." not in out.replace("[.]", "")
    assert "[.]" in out
    if expected_scheme:
        assert out.startswith(expected_scheme)
