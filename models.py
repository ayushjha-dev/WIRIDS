"""WIDIRS shared data models.

All dataclasses used across detection, analysis, enrichment, attribution,
reporting and alerting modules.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    """Threat taxonomy used by the AI classifier."""

    HACKTIVIST_DEFACEMENT = "hacktivist_defacement"
    MALWARE_INJECTION = "malware_injection"
    PHISHING_OVERLAY = "phishing_overlay"
    SEO_SPAM_INJECTION = "seo_spam_injection"
    RANSOMWARE_NOTICE = "ransomware_notice"
    NATION_STATE_OP = "nation_state_op"
    SCRIPT_KIDDIE = "script_kiddie"
    FALSE_POSITIVE = "false_positive"
    UNKNOWN = "unknown"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    HANDLE = "handle"        # attacker alias / hacker handle
    WALLET = "wallet"        # crypto wallet address
    FILE_PATH = "file_path"


class AlertChannel(str, Enum):
    TELEGRAM = "telegram"
    EMAIL = "email"


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------

def _serialize(value: Any) -> Any:
    """Recursively convert a value into a JSON-serializable structure."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _serialize(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _serialize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serialize(v) for v in value]
    return value


class SerializableMixin:
    """Adds a to_dict() returning a JSON-serializable dict."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            f.name: _serialize(getattr(self, f.name))
            for f in dataclasses.fields(self)  # type: ignore[arg-type]
        }


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@dataclass
class ScanResult(SerializableMixin):
    """Output of a single site scan (capture phase)."""

    url: str
    site_id: Optional[int] = None
    status_code: int = 0
    html_hash: str = ""
    html_path: str = ""
    screenshot_path: str = ""
    dom_node_count: int = 0
    load_time_ms: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    external_resources: List[str] = field(default_factory=list)
    error: Optional[str] = None
    is_baseline: bool = False
    has_changes: bool = False
    snapshot_dir: str = ""
    scanned_at: datetime = field(default_factory=_utcnow)


@dataclass
class ChangeReport(SerializableMixin):
    """Output of the diff engine comparing a scan against the baseline."""

    url: str
    site_id: Optional[int] = None
    change_score: float = 0.0            # 0.0 (identical) .. 1.0 (fully changed)
    visual_similarity: float = 1.0       # perceptual-hash / SSIM similarity
    text_diff_ratio: float = 0.0
    dom_changes: Dict[str, Any] = field(default_factory=dict)
    added_scripts: List[str] = field(default_factory=list)
    removed_scripts: List[str] = field(default_factory=list)
    added_iframes: List[str] = field(default_factory=list)
    added_links: List[str] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    baseline_snapshot_id: Optional[int] = None
    current_snapshot_id: Optional[int] = None
    exceeded_threshold: bool = False
    compared_at: datetime = field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# AI Analysis
# ---------------------------------------------------------------------------

@dataclass
class ThreatClassification(SerializableMixin):
    """LLM-driven classification of a detected change."""

    threat_type: ThreatType = ThreatType.UNKNOWN
    severity: Severity = Severity.LOW
    severity_score: int = 0              # 0 .. 100, as judged by the LLM
    risk_score: float = 0.0              # 0 .. 100, computed composite
    confidence: float = 0.0              # 0.0 .. 1.0
    false_positive_probability: float = 0.0
    threat_actor_category: str = ""
    attack_vectors: List[str] = field(default_factory=list)
    ioc_hints: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    summary: str = ""
    analyst_notes: str = ""
    indicators: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    model_used: str = ""
    raw_response: Optional[str] = None
    analyzed_at: datetime = field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# IOC extraction & enrichment
# ---------------------------------------------------------------------------

@dataclass
class IOC(SerializableMixin):
    """A single indicator of compromise extracted from defaced content."""

    value: str
    ioc_type: IOCType = IOCType.URL
    confidence: float = 0.5
    context: str = ""                    # where/how it was found
    extracted_at: datetime = field(default_factory=_utcnow)


@dataclass
class IOCBundle(SerializableMixin):
    """All IOCs extracted for one incident."""

    incident_url: str = ""
    iocs: List[IOC] = field(default_factory=list)
    extraction_method: str = "regex+llm"
    created_at: datetime = field(default_factory=_utcnow)

    @property
    def count(self) -> int:
        return len(self.iocs)


@dataclass
class EnrichedIOC(SerializableMixin):
    """An IOC augmented with threat-intelligence context."""

    ioc: IOC = field(default_factory=lambda: IOC(value=""))
    vt_malicious_count: int = 0
    vt_total_engines: int = 0
    abuseipdb_score: int = 0
    shodan_data: Dict[str, Any] = field(default_factory=dict)
    misp_hits: List[Dict[str, Any]] = field(default_factory=list)
    geo_country: str = ""
    asn: str = ""
    is_known_malicious: bool = False
    sources_queried: List[str] = field(default_factory=list)
    cache_hit: bool = False
    enriched_at: datetime = field(default_factory=_utcnow)


@dataclass
class EnrichedBundle(SerializableMixin):
    """All enriched IOCs for one incident."""

    incident_url: str = ""
    enriched: List[EnrichedIOC] = field(default_factory=list)
    malicious_count: int = 0
    created_at: datetime = field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------

@dataclass
class AttributionReport(SerializableMixin):
    """Best-effort attribution of the defacement actor."""

    suspected_actor: str = "unknown"
    actor_handles: List[str] = field(default_factory=list)
    suspected_group: str = ""
    motivation: str = ""                 # hacktivism, financial, vandalism...
    ttp_summary: str = ""
    similar_incidents: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    attributed_at: datetime = field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Incident aggregation
# ---------------------------------------------------------------------------

@dataclass
class Incident(SerializableMixin):
    """Aggregates outputs of all pipeline modules for one detection event."""

    incident_id: str = ""
    url: str = ""
    site_id: Optional[int] = None
    scan: Optional[ScanResult] = None
    change: Optional[ChangeReport] = None
    classification: Optional[ThreatClassification] = None
    ioc_bundle: Optional[IOCBundle] = None
    enriched_bundle: Optional[EnrichedBundle] = None
    attribution: Optional[AttributionReport] = None
    status: str = "open"                 # open | triaged | resolved | false_positive
    created_at: datetime = field(default_factory=_utcnow)

    @property
    def severity(self) -> Severity:
        return self.classification.severity if self.classification else Severity.LOW

    @property
    def risk_score(self) -> float:
        return self.classification.risk_score if self.classification else 0.0


@dataclass
class IncidentResult(SerializableMixin):
    """Outcome of persisting/processing an incident through the pipeline."""

    incident_id: str = ""
    success: bool = False
    #: Terminal pipeline outcome: baseline_set | no_change | below_threshold |
    #: false_positive | incident_processed.
    status: str = ""
    db_row_id: Optional[int] = None
    stages_completed: List[str] = field(default_factory=list)
    stages_failed: List[str] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0
    completed_at: datetime = field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Reporting & alerting
# ---------------------------------------------------------------------------

@dataclass
class ReportResult(SerializableMixin):
    """Outcome of report generation for an incident."""

    incident_id: str = ""
    html_path: str = ""
    pdf_path: str = ""
    sha256: str = ""
    success: bool = False
    error: Optional[str] = None
    generated_at: datetime = field(default_factory=_utcnow)


@dataclass
class AlertResult(SerializableMixin):
    """Outcome of dispatching an alert on a channel."""

    incident_id: str = ""
    channel: AlertChannel = AlertChannel.TELEGRAM
    recipients: List[str] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None
    sent_at: datetime = field(default_factory=_utcnow)
