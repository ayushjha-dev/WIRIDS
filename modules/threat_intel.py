"""WIDIRS multi-source threat-intelligence enrichment module.

Enriches extracted IOCs against multiple threat-intelligence sources
(VirusTotal, AbuseIPDB, URLhaus) using async aiohttp lookups, with a
SQLite-backed cache (via the shared Database.ti_cache_* helpers) to avoid
redundant API calls.

Design notes:
- All network calls are async, time-bounded (10s) and retried (2 attempts).
- Every source result is cached individually under the key
  ``{source}:{ioc_type}:{ioc_value}`` with a TTL of TI_CACHE_TTL_HOURS.
- Enrichment is graceful: API/network failures are logged, recorded in the
  bundle's ``api_errors`` list and never propagate out of ``enrich_ioc``.
- The spec's richer result shapes (VTResult, AbuseIPDBResult, ...) are defined
  locally here, mirroring how attribution.py defines its own dataclasses.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import structlog

from config import Settings
from database import Database
from models import IOC, IOCBundle, IOCType, SerializableMixin

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_TIMEOUT_SECONDS = 10
MAX_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.0
MAX_CONCURRENT_REQUESTS = 4

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"

# Risk-score weights (per spec).
VT_WEIGHT = 0.50
ABUSE_WEIGHT = 0.30
URLHAUS_WEIGHT = 0.20

VT_MALICIOUS_THRESHOLD = 3

# IOCType groupings.
_HASH_TYPES = (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256)


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


# ---------------------------------------------------------------------------
# Source result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class VTResult(SerializableMixin):
    """Normalized VirusTotal result for a single IOC."""

    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    last_analysis_date: Optional[int] = None
    popular_threat_names: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    vt_verdict: str = "unknown"  # malicious | suspicious | clean | unknown
    error: Optional[str] = None


@dataclass
class AbuseIPDBResult(SerializableMixin):
    """Normalized AbuseIPDB result for an IP."""

    abuse_confidence_score: int = 0
    total_reports: int = 0
    isp: str = ""
    country_code: str = ""
    usage_type: str = ""
    last_reported_at: Optional[str] = None
    error: Optional[str] = None


@dataclass
class URLhausResult(SerializableMixin):
    """Normalized URLhaus result for a URL/domain/hash."""

    query_status: str = "unknown"
    threat_type: str = ""
    urls_on_host: int = 0
    payloads: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class EnrichedIOC(SerializableMixin):
    """An IOC augmented with multi-source threat-intelligence context.

    This is the module-local, spec-aligned enrichment shape (richer than the
    shared models.EnrichedIOC).
    """

    ioc: IOC = field(default_factory=lambda: IOC(value=""))
    vt: Optional[VTResult] = None
    abuse: Optional[AbuseIPDBResult] = None
    urlhaus: Optional[URLhausResult] = None
    ti_risk_score: float = 0.0
    verdict: str = "unknown"  # malicious | suspicious | clean | unknown
    sources_queried: List[str] = field(default_factory=list)
    cache_hit: bool = False
    errors: List[str] = field(default_factory=list)


@dataclass
class EnrichedBundle(SerializableMixin):
    """All enriched IOCs for one incident."""

    incident_url: str = ""
    enriched_iocs: List[EnrichedIOC] = field(default_factory=list)
    enrichment_timestamp: str = ""
    api_errors: List[str] = field(default_factory=list)


@dataclass
class TISummary(SerializableMixin):
    """Aggregate summary of an enriched bundle."""

    total_iocs: int = 0
    total_malicious: int = 0
    total_suspicious: int = 0
    total_clean: int = 0
    highest_risk_ioc: Optional[EnrichedIOC] = None
    aggregate_risk_score: float = 0.0
    api_error_count: int = 0


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ThreatIntelligenceEngine:
    """Enrich IOCs against VirusTotal, AbuseIPDB and URLhaus.

    Results are cached per-source in the ``ti_cache`` table. The engine never
    raises out of ``enrich_ioc`` / ``enrich_bundle``; failures degrade to
    partial results with errors recorded.
    """

    def __init__(self, config: Settings, db: Database) -> None:
        """Initialize the engine.

        Args:
            config: Application settings (API keys, cache TTL).
            db: Connected async Database wrapper for the ti_cache table.
        """
        self.config = config
        self.db = db
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _cache_key(source: str, ioc_type: str, ioc_value: str) -> str:
        return f"{source}:{ioc_type}:{ioc_value}"

    async def _cache_get(
        self, source: str, ioc_type: str, ioc_value: str
    ) -> Optional[Dict[str, Any]]:
        """Return fresh cached source data, or None on miss/expiry/error."""
        key = self._cache_key(source, ioc_type, ioc_value)
        try:
            return await self.db.ti_cache_get(key)
        except Exception as exc:  # pragma: no cover - cache must never break flow
            logger.warning("ti_cache_get_failed", key=key, error=str(exc))
            return None

    async def _cache_set(
        self, source: str, ioc_type: str, ioc_value: str, data: Dict[str, Any]
    ) -> None:
        """Persist source data with the configured TTL; swallow errors."""
        key = self._cache_key(source, ioc_type, ioc_value)
        try:
            await self.db.ti_cache_set(
                key, data, ttl_hours=self.config.ti_cache_ttl_hours
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("ti_cache_set_failed", key=key, error=str(exc))

    # ------------------------------------------------------------------
    # HTTP helper (timeout + retry)
    # ------------------------------------------------------------------
    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Perform an HTTP request with timeout and bounded retries.

        Returns:
            (json_body, error). On success error is None; on failure
            json_body is None and error holds a human-readable message.
        """
        timeout = aiohttp.ClientTimeout(total=API_TIMEOUT_SECONDS)
        last_error = "unknown error"

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    timeout=timeout,
                ) as resp:
                    if resp.status == 404:
                        # Not found is a valid "no data" answer, not an error.
                        return {}, None
                    if resp.status == 429:
                        last_error = "rate limited (429)"
                        logger.warning("ti_rate_limited", url=url, attempt=attempt)
                    elif resp.status >= 400:
                        last_error = f"HTTP {resp.status}"
                        logger.warning(
                            "ti_http_error", url=url, status=resp.status
                        )
                    else:
                        try:
                            return await resp.json(content_type=None), None
                        except Exception as exc:  # malformed body
                            return None, f"invalid JSON: {exc}"
            except asyncio.TimeoutError:
                last_error = f"timeout after {API_TIMEOUT_SECONDS}s"
                logger.warning("ti_timeout", url=url, attempt=attempt)
            except aiohttp.ClientError as exc:
                last_error = f"client error: {exc}"
                logger.warning("ti_client_error", url=url, error=str(exc))

            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)

        return None, last_error

    # ------------------------------------------------------------------
    # 1. VirusTotal
    # ------------------------------------------------------------------
    async def query_virustotal(
        self, ioc: IOC, session: aiohttp.ClientSession
    ) -> VTResult:
        """Query VirusTotal for a single IOC, routed by type.

        Args:
            ioc: The indicator to look up.
            session: Shared aiohttp session.

        Returns:
            A VTResult (populated from cache, API, or with ``error`` set).
        """
        ioc_type = self._vt_type(ioc.ioc_type)
        if ioc_type is None:
            return VTResult(error=f"unsupported VT type: {ioc.ioc_type}")

        cached = await self._cache_get("virustotal", ioc_type, ioc.value)
        if cached is not None:
            return _vt_from_dict(cached)

        if not self.config.virustotal_api_key:
            return VTResult(error="VirusTotal API key not configured")

        headers = {"x-apikey": self.config.virustotal_api_key}
        body, error = await self._fetch_vt_attributes(
            ioc, ioc_type, session, headers
        )
        if error is not None:
            return VTResult(error=error)

        result = self._parse_vt(body or {})
        await self._cache_set("virustotal", ioc_type, ioc.value, result.to_dict())
        return result

    async def _fetch_vt_attributes(
        self,
        ioc: IOC,
        ioc_type: str,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Resolve the VT 'attributes' object for the IOC, routing by type."""
        if ioc_type == "ip":
            url = f"{VT_BASE}/ip_addresses/{ioc.value}"
            return await self._request(session, "GET", url, headers=headers)
        if ioc_type == "domain":
            url = f"{VT_BASE}/domains/{ioc.value}"
            return await self._request(session, "GET", url, headers=headers)
        if ioc_type == "hash":
            url = f"{VT_BASE}/files/{ioc.value}"
            return await self._request(session, "GET", url, headers=headers)

        # url: submit then poll the analysis.
        submit, error = await self._request(
            session,
            "POST",
            f"{VT_BASE}/urls",
            headers=headers,
            data={"url": ioc.value},
        )
        if error is not None:
            return None, error
        analysis_id = (
            (submit or {}).get("data", {}).get("id", "")
        )
        if not analysis_id:
            return None, "VT URL submission returned no analysis id"
        return await self._request(
            session,
            "GET",
            f"{VT_BASE}/analyses/{analysis_id}",
            headers=headers,
        )

    @staticmethod
    def _vt_type(ioc_type: IOCType) -> Optional[str]:
        """Map an IOCType to the VT route family, or None if unsupported."""
        if ioc_type == IOCType.IP:
            return "ip"
        if ioc_type == IOCType.DOMAIN:
            return "domain"
        if ioc_type == IOCType.URL:
            return "url"
        if ioc_type in _HASH_TYPES:
            return "hash"
        return None

    @staticmethod
    def _parse_vt(body: Dict[str, Any]) -> VTResult:
        """Extract the fields of interest from a VT v3 response body."""
        attributes = (body.get("data", {}) or {}).get("attributes", {}) or {}

        # /analyses returns stats under attributes.stats; object endpoints use
        # attributes.last_analysis_stats. Support both.
        stats = (
            attributes.get("last_analysis_stats")
            or attributes.get("stats")
            or {}
        )
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)

        threat_names = [
            str(n) for n in attributes.get("popular_threat_names", []) or []
        ]
        if not threat_names:
            classification = attributes.get(
                "popular_threat_classification", {}
            ) or {}
            threat_names = [
                str(item.get("value", ""))
                for item in classification.get("popular_threat_name", []) or []
                if item.get("value")
            ]

        categories_raw = attributes.get("categories", {}) or {}
        if isinstance(categories_raw, dict):
            categories = sorted({str(v) for v in categories_raw.values() if v})
        else:
            categories = [str(c) for c in categories_raw or []]

        if malicious >= VT_MALICIOUS_THRESHOLD:
            verdict = "malicious"
        elif malicious > 0 or suspicious > 0:
            verdict = "suspicious"
        elif harmless > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        return VTResult(
            malicious_count=malicious,
            suspicious_count=suspicious,
            harmless_count=harmless,
            last_analysis_date=attributes.get("last_analysis_date"),
            popular_threat_names=threat_names,
            categories=categories,
            vt_verdict=verdict,
        )

    # ------------------------------------------------------------------
    # 2. AbuseIPDB
    # ------------------------------------------------------------------
    async def query_abuseipdb(
        self, ip: str, session: aiohttp.ClientSession
    ) -> AbuseIPDBResult:
        """Query AbuseIPDB for an IP (90-day window).

        Args:
            ip: The IP address to check.
            session: Shared aiohttp session.

        Returns:
            An AbuseIPDBResult (from cache, API, or with ``error`` set).
        """
        cached = await self._cache_get("abuseipdb", "ip", ip)
        if cached is not None:
            return _abuse_from_dict(cached)

        if not self.config.abuseipdb_api_key:
            return AbuseIPDBResult(error="AbuseIPDB API key not configured")

        headers = {
            "Key": self.config.abuseipdb_api_key,
            "Accept": "application/json",
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        body, error = await self._request(
            session,
            "GET",
            f"{ABUSEIPDB_BASE}/check",
            headers=headers,
            params=params,
        )
        if error is not None:
            return AbuseIPDBResult(error=error)

        data = (body or {}).get("data", {}) or {}
        result = AbuseIPDBResult(
            abuse_confidence_score=int(data.get("abuseConfidenceScore", 0) or 0),
            total_reports=int(data.get("totalReports", 0) or 0),
            isp=str(data.get("isp", "") or ""),
            country_code=str(data.get("countryCode", "") or ""),
            usage_type=str(data.get("usageType", "") or ""),
            last_reported_at=data.get("lastReportedAt"),
        )
        await self._cache_set("abuseipdb", "ip", ip, result.to_dict())
        return result

    # ------------------------------------------------------------------
    # 3. URLhaus
    # ------------------------------------------------------------------
    async def query_urlhaus(
        self, value: str, ioc_type: str, session: aiohttp.ClientSession
    ) -> URLhausResult:
        """Query URLhaus for a url/domain/hash.

        Args:
            value: The IOC value.
            ioc_type: One of the spec families: 'url', 'domain', 'hash'.
            session: Shared aiohttp session.

        Returns:
            A URLhausResult (from cache, API, or with ``error`` set).
        """
        cached = await self._cache_get("urlhaus", ioc_type, value)
        if cached is not None:
            return _urlhaus_from_dict(cached)

        # Hashes hit the payload endpoint; url/domain hit the url endpoint.
        if ioc_type == "hash":
            endpoint = f"{URLHAUS_BASE}/payload/"
            payload = {"md5_hash": value} if len(value) == 32 else {
                "sha256_hash": value
            }
        else:
            endpoint = f"{URLHAUS_BASE}/url/"
            payload = {"url": value} if ioc_type == "url" else {"host": value}
            if ioc_type == "domain":
                endpoint = f"{URLHAUS_BASE}/host/"

        body, error = await self._request(
            session, "POST", endpoint, data=payload
        )
        if error is not None:
            return URLhausResult(error=error)

        body = body or {}
        result = URLhausResult(
            query_status=str(body.get("query_status", "unknown") or "unknown"),
            threat_type=str(body.get("threat_type", "") or ""),
            urls_on_host=int(body.get("url_count", 0) or 0)
            if body.get("url_count") is not None
            else len(body.get("urls", []) or []),
            payloads=list(body.get("payloads", []) or []),
        )
        await self._cache_set("urlhaus", ioc_type, value, result.to_dict())
        return result

    # ------------------------------------------------------------------
    # 4. enrich_ioc
    # ------------------------------------------------------------------
    async def enrich_ioc(
        self,
        ioc: IOC,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> EnrichedIOC:
        """Enrich a single IOC across the relevant sources.

        Routing:
            ip     -> VirusTotal + AbuseIPDB
            domain -> VirusTotal + URLhaus
            url    -> VirusTotal + URLhaus
            hash   -> VirusTotal + URLhaus
            other  -> no enrichment

        Never raises; on failure returns a partial EnrichedIOC with errors set.

        Args:
            ioc: The indicator to enrich.
            session: Optional shared aiohttp session. If omitted, a temporary
                session is created for this call.

        Returns:
            A populated EnrichedIOC.
        """
        owns_session = session is None
        try:
            if owns_session:
                session = aiohttp.ClientSession()
            return await self._enrich_ioc_inner(ioc, session)  # type: ignore[arg-type]
        except Exception as exc:  # absolute safety net
            logger.error(
                "enrich_ioc_unexpected_error", value=ioc.value, error=str(exc)
            )
            return EnrichedIOC(ioc=ioc, errors=[f"unexpected: {exc}"])
        finally:
            if owns_session and session is not None:
                await session.close()

    async def _enrich_ioc_inner(
        self, ioc: IOC, session: aiohttp.ClientSession
    ) -> EnrichedIOC:
        """Core enrichment logic (assumes a live session)."""
        log = logger.bind(value=ioc.value, ioc_type=ioc.ioc_type.value)
        enriched = EnrichedIOC(ioc=ioc)

        family = self._enrichment_family(ioc.ioc_type)
        if family is None:
            log.info("enrich_skip_unsupported_type")
            return enriched

        vt: Optional[VTResult] = None
        abuse: Optional[AbuseIPDBResult] = None
        urlhaus: Optional[URLhausResult] = None

        # VirusTotal applies to every supported family.
        vt = await self.query_virustotal(ioc, session)
        enriched.sources_queried.append("virustotal")
        if vt.error:
            enriched.errors.append(f"virustotal: {vt.error}")
            log.warning("vt_partial", error=vt.error)

        if family == "ip":
            abuse = await self.query_abuseipdb(ioc.value, session)
            enriched.sources_queried.append("abuseipdb")
            if abuse.error:
                enriched.errors.append(f"abuseipdb: {abuse.error}")
                log.warning("abuseipdb_partial", error=abuse.error)
        else:
            urlhaus = await self.query_urlhaus(ioc.value, family, session)
            enriched.sources_queried.append("urlhaus")
            if urlhaus.error:
                enriched.errors.append(f"urlhaus: {urlhaus.error}")
                log.warning("urlhaus_partial", error=urlhaus.error)

        enriched.vt = vt
        enriched.abuse = abuse
        enriched.urlhaus = urlhaus
        enriched.ti_risk_score = self.compute_ti_risk_score(vt, abuse, urlhaus)
        enriched.verdict = self._verdict(enriched.ti_risk_score, vt)

        log.info(
            "ioc_enriched",
            risk_score=enriched.ti_risk_score,
            verdict=enriched.verdict,
            sources=enriched.sources_queried,
        )
        return enriched

    @staticmethod
    def _enrichment_family(ioc_type: IOCType) -> Optional[str]:
        """Map an IOCType to its enrichment family ('ip'|'domain'|'url'|'hash')."""
        if ioc_type == IOCType.IP:
            return "ip"
        if ioc_type == IOCType.DOMAIN:
            return "domain"
        if ioc_type == IOCType.URL:
            return "url"
        if ioc_type in _HASH_TYPES:
            return "hash"
        return None

    @staticmethod
    def _verdict(risk_score: float, vt: Optional[VTResult]) -> str:
        """Derive an overall verdict from the risk score and VT verdict."""
        if vt is not None and vt.vt_verdict == "malicious":
            return "malicious"
        if risk_score >= 0.5:
            return "malicious"
        if risk_score >= 0.2:
            return "suspicious"
        if vt is not None and vt.vt_verdict == "clean":
            return "clean"
        return "unknown"

    # ------------------------------------------------------------------
    # 5. enrich_bundle
    # ------------------------------------------------------------------
    async def enrich_bundle(self, bundle: IOCBundle) -> EnrichedBundle:
        """Enrich every IOC in a bundle concurrently (max 4 in flight).

        Args:
            bundle: The IOC bundle for one incident.

        Returns:
            An EnrichedBundle with results, a timestamp and aggregated errors.
        """
        from datetime import datetime, timezone

        log = logger.bind(url=bundle.incident_url, count=bundle.count)
        log.info("enrich_bundle_started")

        async with aiohttp.ClientSession() as session:

            async def _guarded(ioc: IOC) -> EnrichedIOC:
                async with self._semaphore:
                    return await self.enrich_ioc(ioc, session)

            enriched_iocs = await asyncio.gather(
                *(_guarded(ioc) for ioc in bundle.iocs)
            )

        api_errors: List[str] = []
        for item in enriched_iocs:
            for err in item.errors:
                api_errors.append(f"{item.ioc.value}: {err}")

        result = EnrichedBundle(
            incident_url=bundle.incident_url,
            enriched_iocs=list(enriched_iocs),
            enrichment_timestamp=datetime.now(timezone.utc).isoformat(),
            api_errors=api_errors,
        )
        log.info(
            "enrich_bundle_completed",
            enriched=len(enriched_iocs),
            api_errors=len(api_errors),
        )
        return result

    # ------------------------------------------------------------------
    # 6. compute_ti_risk_score
    # ------------------------------------------------------------------
    def compute_ti_risk_score(
        self,
        vt: Optional[VTResult],
        abuse: Optional[AbuseIPDBResult],
        urlhaus: Optional[URLhausResult],
    ) -> float:
        """Compute a weighted 0.0-1.0 threat-intel risk score.

            vt_score      = min(malicious_count / 10, 1.0) * 0.50
            abuse_score   = (abuse_confidence_score / 100) * 0.30
            urlhaus_score = 0.20 if query_status == "is_malware" else 0

        Args:
            vt: VirusTotal result (or None).
            abuse: AbuseIPDB result (or None).
            urlhaus: URLhaus result (or None).

        Returns:
            Clamped composite score in [0.0, 1.0].
        """
        vt_score = 0.0
        if vt is not None and not vt.error:
            vt_score = min(vt.malicious_count / 10.0, 1.0) * VT_WEIGHT

        abuse_score = 0.0
        if abuse is not None and not abuse.error:
            abuse_score = (abuse.abuse_confidence_score / 100.0) * ABUSE_WEIGHT

        urlhaus_score = 0.0
        if (
            urlhaus is not None
            and not urlhaus.error
            and urlhaus.query_status == "is_malware"
        ):
            urlhaus_score = URLHAUS_WEIGHT

        return round(_clamp(vt_score + abuse_score + urlhaus_score), 4)

    # ------------------------------------------------------------------
    # 7. generate_ti_summary
    # ------------------------------------------------------------------
    def generate_ti_summary(self, bundle: EnrichedBundle) -> TISummary:
        """Summarize an enriched bundle.

        Args:
            bundle: The enriched bundle to summarize.

        Returns:
            A TISummary with verdict tallies, the highest-risk IOC and the
            mean aggregate risk score.
        """
        iocs = bundle.enriched_iocs
        total = len(iocs)
        malicious = sum(1 for e in iocs if e.verdict == "malicious")
        suspicious = sum(1 for e in iocs if e.verdict == "suspicious")
        clean = sum(1 for e in iocs if e.verdict == "clean")

        highest = max(iocs, key=lambda e: e.ti_risk_score, default=None)
        aggregate = (
            round(sum(e.ti_risk_score for e in iocs) / total, 4) if total else 0.0
        )

        summary = TISummary(
            total_iocs=total,
            total_malicious=malicious,
            total_suspicious=suspicious,
            total_clean=clean,
            highest_risk_ioc=highest,
            aggregate_risk_score=aggregate,
            api_error_count=len(bundle.api_errors),
        )
        logger.info(
            "ti_summary_generated",
            total=total,
            malicious=malicious,
            aggregate=aggregate,
        )
        return summary


# ---------------------------------------------------------------------------
# Cache (de)serialization helpers
# ---------------------------------------------------------------------------

def _vt_from_dict(data: Dict[str, Any]) -> VTResult:
    return VTResult(
        malicious_count=int(data.get("malicious_count", 0) or 0),
        suspicious_count=int(data.get("suspicious_count", 0) or 0),
        harmless_count=int(data.get("harmless_count", 0) or 0),
        last_analysis_date=data.get("last_analysis_date"),
        popular_threat_names=list(data.get("popular_threat_names", []) or []),
        categories=list(data.get("categories", []) or []),
        vt_verdict=str(data.get("vt_verdict", "unknown") or "unknown"),
    )


def _abuse_from_dict(data: Dict[str, Any]) -> AbuseIPDBResult:
    return AbuseIPDBResult(
        abuse_confidence_score=int(data.get("abuse_confidence_score", 0) or 0),
        total_reports=int(data.get("total_reports", 0) or 0),
        isp=str(data.get("isp", "") or ""),
        country_code=str(data.get("country_code", "") or ""),
        usage_type=str(data.get("usage_type", "") or ""),
        last_reported_at=data.get("last_reported_at"),
    )


def _urlhaus_from_dict(data: Dict[str, Any]) -> URLhausResult:
    return URLhausResult(
        query_status=str(data.get("query_status", "unknown") or "unknown"),
        threat_type=str(data.get("threat_type", "") or ""),
        urls_on_host=int(data.get("urls_on_host", 0) or 0),
        payloads=list(data.get("payloads", []) or []),
    )
