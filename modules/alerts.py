"""WIDIRS multi-channel alerting module.

Dispatches real-time defacement incident notifications across Telegram and
email, with severity-based channel routing, per-URL deduplication cooldowns,
an hourly low-severity email digest, and per-channel delivery accounting
persisted to the ``alerts`` table.

Design notes:
- Telegram uses python-telegram-bot (v20+ async API). MarkdownV2 messages have
  every dynamic value escaped; the diff screenshot is attached as a photo and
  three inline callback buttons are added.
- Email supports two transports: SMTP+STARTTLS (port 587) when SMTP_HOST is
  set, otherwise the SendGrid REST API (called via aiohttp to avoid adding a
  dependency). HTML is fully inline-styled and mobile-responsive.
- Blocking I/O (smtplib, telegram sync helpers) is run in a thread via
  asyncio.to_thread so the event loop is never blocked.
- dispatch_alert never raises; failures are captured per channel.
"""

from __future__ import annotations

import asyncio
import base64
import smtplib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
import structlog

from config import Settings
from database import Database
from models import AlertChannel, Incident, Severity, SerializableMixin

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_COOLDOWN_SECONDS = 30 * 60  # 30 minutes per URL
DIGEST_INTERVAL_SECONDS = 60 * 60   # hourly low-severity digest

TELEGRAM_MAX_RETRIES = 3
TELEGRAM_RETRY_BACKOFF_SECONDS = 5.0
TELEGRAM_TIMEOUT_SECONDS = 20.0

SENDGRID_API = "https://api.sendgrid.com/v3/mail/send"
WIDIRS_VERSION = "1.0.0"

# Severity banner colors (per spec).
SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#C0392B",  # red
    "high": "#E67E22",      # orange
    "medium": "#F1C40F",    # yellow
    "low": "#2980B9",       # blue
    "info": "#7F8C8D",      # grey (log-only)
}

# Risk-score badge colors for the IOC table.
_BADGE_HIGH = "#C0392B"
_BADGE_MED = "#E67E22"
_BADGE_LOW = "#27AE60"

# MarkdownV2 reserved characters that must be escaped.
_MDV2_SPECIALS = "_*[]()~`>#+-=|{}.!\\"


def _escape_mdv2(text: Any) -> str:
    """Escape a value for Telegram MarkdownV2."""
    out = str(text)
    return "".join("\\" + ch if ch in _MDV2_SPECIALS else ch for ch in out)


def _domain_of(url: str) -> str:
    return urlparse(url).hostname or url


def _severity_from_score(risk_score: float) -> Severity:
    """Map a 0-100 risk score to a Severity bucket (per routing spec)."""
    if risk_score >= 90:
        return Severity.CRITICAL
    if risk_score >= 70:
        return Severity.HIGH
    if risk_score >= 40:
        return Severity.MEDIUM
    if risk_score >= 1:
        return Severity.LOW
    return Severity.INFO


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class AlertResult(SerializableMixin):
    """Outcome of dispatching an incident across all routed channels."""

    incident_id: str = ""
    severity: str = ""
    channels_attempted: List[str] = field(default_factory=list)
    channels_succeeded: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    dispatched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class AlertManager:
    """Routes and delivers defacement alerts across Telegram and email.

    Channel routing by computed severity:
        critical / high -> telegram + email (immediate)
        medium          -> telegram only
        low             -> email digest (batched hourly)
        info            -> log only
    """

    def __init__(
        self,
        config: Settings,
        db: Database,
        cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS,
    ) -> None:
        """Initialize the manager.

        Args:
            config: Application settings (channel credentials).
            db: Connected async Database wrapper for the alerts table.
            cooldown_seconds: Per-URL dedup window (default 30 minutes).
        """
        self.config = config
        self.db = db
        self.cooldown_seconds = cooldown_seconds

        # In-memory dedup state: {url: last_alert_epoch_seconds}.
        self._last_alert: Dict[str, float] = {}
        # Pending low-severity digest entries.
        self._digest_queue: List[Incident] = []
        self._digest_lock = asyncio.Lock()

        self._bot: Optional[Any] = None  # lazily constructed telegram.Bot

    # ==================================================================
    # Deduplication
    # ==================================================================
    def _is_on_cooldown(self, url: str) -> bool:
        last = self._last_alert.get(url)
        if last is None:
            return False
        return (time.monotonic() - last) < self.cooldown_seconds

    def _mark_alerted(self, url: str) -> None:
        self._last_alert[url] = time.monotonic()

    # ==================================================================
    # Severity routing
    # ==================================================================
    @staticmethod
    def _channels_for(severity: Severity) -> List[AlertChannel]:
        """Return the immediate channels for a severity (digest handled apart)."""
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return [AlertChannel.TELEGRAM, AlertChannel.EMAIL]
        if severity == Severity.MEDIUM:
            return [AlertChannel.TELEGRAM]
        return []  # low -> digest, info -> log only

    # ==================================================================
    # Telegram
    # ==================================================================
    def _get_bot(self) -> Any:
        """Lazily build and cache the telegram.Bot instance."""
        if self._bot is None:
            from telegram import Bot  # imported lazily; optional dependency

            self._bot = Bot(token=self.config.telegram_bot_token)
        return self._bot

    @staticmethod
    def _build_telegram_message(incident: Incident) -> str:
        """Render the MarkdownV2 message body for an incident."""
        cls = incident.classification
        threat_type = cls.threat_type.value if cls else "unknown"
        severity = cls.severity.value if cls else "low"
        risk_score = int(round(incident.risk_score))
        confidence_pct = int(round((cls.confidence if cls else 0.0) * 100))
        timestamp = incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        notes = (cls.analyst_notes if cls else "")[:200]

        bundle = incident.ioc_bundle
        ioc_count = bundle.count if bundle else 0
        type_counts: Dict[str, int] = {}
        if bundle:
            for ioc in bundle.iocs:
                key = ioc.ioc_type.value
                type_counts[key] = type_counts.get(key, 0) + 1
        top_3 = sorted(type_counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
        ioc_lines = (
            "\n".join(
                f"  • {_escape_mdv2(t)}: {_escape_mdv2(c)}" for t, c in top_3
            )
            or f"  • {_escape_mdv2('none')}"
        )

        bar = _escape_mdv2("━━━━━━━━━━━━━━━━━━━━━━━━━")
        return (
            "🚨 *DEFACEMENT DETECTED*\n"
            f"{bar}\n"
            f"🌐 *Target:* `{_escape_mdv2(incident.url)}`\n"
            f"⚠️ *Threat:* {_escape_mdv2(threat_type)}\n"
            f"🔥 *Severity:* {_escape_mdv2(severity)} "
            f"\\({_escape_mdv2(risk_score)}/100\\)\n"
            f"🎯 *Confidence:* {_escape_mdv2(confidence_pct)}%\n"
            f"🕐 *Detected:* {_escape_mdv2(timestamp)}\n"
            f"{bar}\n"
            f"📋 *IOCs Found:* {_escape_mdv2(ioc_count)}\n"
            f"{ioc_lines}\n"
            f"{bar}\n"
            f"{_escape_mdv2(notes)}"
        )

    def _build_keyboard(self, incident_id: str) -> Any:
        """Build the 3-button inline keyboard."""
        from telegram import InlineKeyboardButton, InlineKeyboardMarkup

        return InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        "📄 Full Report", callback_data=f"report_{incident_id}"
                    ),
                    InlineKeyboardButton(
                        "✅ False Positive", callback_data=f"fp_{incident_id}"
                    ),
                    InlineKeyboardButton(
                        "🚨 Escalate", callback_data=f"escalate_{incident_id}"
                    ),
                ]
            ]
        )

    @staticmethod
    def _diff_image_path(incident: Incident) -> Optional[str]:
        """Resolve the diff screenshot path from the incident, if present."""
        change = incident.change
        path = None
        if change is not None:
            dom = change.dom_changes or {}
            path = dom.get("diff_image_path") or dom.get("diff_image")
        if path and Path(path).is_file():
            return path
        return None

    async def send_telegram_alert(self, incident: Incident) -> bool:
        """Send a Telegram alert to all configured chat IDs.

        Retries on telegram.error.TimedOut up to 3 times with 5s backoff.

        Args:
            incident: The incident to notify.

        Returns:
            True if delivered to at least one chat, else False.
        """
        if not self.config.is_telegram_configured:
            logger.warning("telegram_not_configured", incident=incident.incident_id)
            return False

        from telegram.error import TelegramError, TimedOut

        bot = self._get_bot()
        text = self._build_telegram_message(incident)
        keyboard = self._build_keyboard(incident.incident_id)
        image_path = self._diff_image_path(incident)
        log = logger.bind(incident=incident.incident_id, channel="telegram")

        delivered = 0
        for chat_id in self.config.telegram_chat_id_list:
            for attempt in range(1, TELEGRAM_MAX_RETRIES + 1):
                try:
                    if image_path:
                        with open(image_path, "rb") as fh:
                            await bot.send_photo(
                                chat_id=chat_id,
                                photo=fh,
                                caption=text,
                                parse_mode="MarkdownV2",
                                reply_markup=keyboard,
                                read_timeout=TELEGRAM_TIMEOUT_SECONDS,
                                write_timeout=TELEGRAM_TIMEOUT_SECONDS,
                            )
                    else:
                        await bot.send_message(
                            chat_id=chat_id,
                            text=text,
                            parse_mode="MarkdownV2",
                            reply_markup=keyboard,
                            disable_web_page_preview=True,
                            read_timeout=TELEGRAM_TIMEOUT_SECONDS,
                            write_timeout=TELEGRAM_TIMEOUT_SECONDS,
                        )
                    delivered += 1
                    break
                except TimedOut:
                    log.warning("telegram_timeout", chat_id=chat_id, attempt=attempt)
                    if attempt < TELEGRAM_MAX_RETRIES:
                        await asyncio.sleep(TELEGRAM_RETRY_BACKOFF_SECONDS)
                except TelegramError as exc:
                    log.error("telegram_error", chat_id=chat_id, error=str(exc))
                    break

        log.info("telegram_dispatch_done", delivered=delivered,
                 total=len(self.config.telegram_chat_id_list))
        return delivered > 0

    # ==================================================================
    # Email
    # ==================================================================
    @staticmethod
    def _subject(incident: Incident) -> str:
        sev = (incident.severity.value if incident.classification else "low").upper()
        domain = _domain_of(incident.url)
        stamp = incident.created_at.strftime("%Y%m%d %H:%M")
        return f"[WIDIRS] {sev} | Defacement on {domain} | {stamp} UTC"

    @staticmethod
    def _badge(score: float) -> str:
        """Return an inline-styled risk-score badge span."""
        if score >= 0.7:
            color = _BADGE_HIGH
        elif score >= 0.4:
            color = _BADGE_MED
        else:
            color = _BADGE_LOW
        return (
            f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:{color};color:#ffffff;font-size:12px;font-weight:bold;">'
            f"{score:.2f}</span>"
        )

    def build_email_html(
        self, incident: Incident, has_inline_image: bool
    ) -> str:
        """Build the full inline-styled, mobile-responsive HTML email body.

        Args:
            incident: The incident to render.
            has_inline_image: Whether a CID diff image is attached.

        Returns:
            HTML string.
        """
        cls = incident.classification
        severity = (cls.severity.value if cls else "low")
        banner = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
        risk_score = int(round(incident.risk_score))
        timestamp = incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        threat_type = cls.threat_type.value if cls else "unknown"
        report_id = incident.incident_id

        def _row(label: str, value: str) -> str:
            return (
                '<tr>'
                '<td style="padding:6px 12px;font-weight:bold;color:#555;'
                'border-bottom:1px solid #eee;width:35%;">'
                f"{label}</td>"
                '<td style="padding:6px 12px;color:#222;'
                f'border-bottom:1px solid #eee;">{value}</td></tr>'
            )

        summary_table = (
            '<table role="presentation" width="100%" cellpadding="0" '
            'cellspacing="0" style="border-collapse:collapse;font-size:14px;">'
            + _row("URL", f'<a href="{incident.url}" style="color:#2980B9;">'
                          f"{incident.url}</a>")
            + _row("Threat Type", threat_type)
            + _row("Severity", f"{severity.upper()} ({risk_score}/100)")
            + _row("Detected", timestamp)
            + "</table>"
        )

        # Section 2: top 10 IOC rows.
        ioc_rows = ""
        bundle = incident.enriched_bundle
        if bundle and getattr(bundle, "enriched", None):
            for enriched in bundle.enriched[:10]:
                ioc = enriched.ioc
                score = float(getattr(enriched, "is_known_malicious", 0) or 0)
                # enriched models vary; fall back gracefully.
                score = float(getattr(enriched, "ti_risk_score", score) or 0.0)
                ioc_rows += (
                    '<tr>'
                    f'<td style="padding:6px 12px;border-bottom:1px solid #eee;'
                    f'word-break:break-all;">{ioc.value}</td>'
                    f'<td style="padding:6px 12px;border-bottom:1px solid #eee;">'
                    f"{ioc.ioc_type.value}</td>"
                    f'<td style="padding:6px 12px;border-bottom:1px solid #eee;">'
                    f"{self._badge(score)}</td></tr>"
                )
        elif incident.ioc_bundle:
            for ioc in incident.ioc_bundle.iocs[:10]:
                ioc_rows += (
                    '<tr>'
                    f'<td style="padding:6px 12px;border-bottom:1px solid #eee;'
                    f'word-break:break-all;">{ioc.value}</td>'
                    f'<td style="padding:6px 12px;border-bottom:1px solid #eee;">'
                    f"{ioc.ioc_type.value}</td>"
                    f'<td style="padding:6px 12px;border-bottom:1px solid #eee;">'
                    f"{self._badge(float(ioc.confidence))}</td></tr>"
                )
        if not ioc_rows:
            ioc_rows = (
                '<tr><td colspan="3" style="padding:6px 12px;color:#888;">'
                "No IOCs extracted</td></tr>"
            )

        ioc_table = (
            '<table role="presentation" width="100%" cellpadding="0" '
            'cellspacing="0" style="border-collapse:collapse;font-size:13px;">'
            '<tr style="background:#f5f5f5;">'
            '<th align="left" style="padding:6px 12px;">Value</th>'
            '<th align="left" style="padding:6px 12px;">Type</th>'
            '<th align="left" style="padding:6px 12px;">Risk</th></tr>'
            f"{ioc_rows}</table>"
        )

        # Section 3: recommended actions.
        actions = cls.recommended_actions if cls else []
        if actions:
            action_items = "".join(
                f'<li style="margin-bottom:6px;">{a}</li>' for a in actions
            )
        else:
            action_items = '<li>Review the full forensic report.</li>'
        actions_list = (
            f'<ol style="padding-left:20px;font-size:14px;color:#222;">'
            f"{action_items}</ol>"
        )

        # Section 4: CTA + optional inline diff image.
        report_url = f"#report-{report_id}"
        cta = (
            f'<a href="{report_url}" style="display:inline-block;'
            f"background:{banner};color:#ffffff;text-decoration:none;"
            'padding:12px 24px;border-radius:4px;font-weight:bold;'
            'font-size:14px;">View Full Forensic Report</a>'
        )
        image_block = (
            '<tr><td style="padding:16px 24px;">'
            '<img src="cid:diffimage" alt="Defacement diff" '
            'style="max-width:100%;height:auto;border:1px solid #ddd;"></td></tr>'
            if has_inline_image
            else ""
        )

        def _section(title: str, body: str) -> str:
            return (
                '<tr><td style="padding:16px 24px;">'
                f'<h3 style="margin:0 0 10px;font-size:16px;color:#222;'
                f'font-family:Arial,sans-serif;">{title}</h3>{body}</td></tr>'
            )

        return f"""\
<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;background:#eceff1;
font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"
style="background:#eceff1;padding:20px 0;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0"
style="max-width:600px;width:100%;background:#ffffff;border-radius:6px;
overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.1);">
  <tr><td style="background:{banner};padding:20px 24px;color:#ffffff;
  font-size:20px;font-weight:bold;">🚨 WIDIRS Defacement Alert
  &mdash; {severity.upper()}</td></tr>
  {_section("Incident Summary", summary_table)}
  {_section("Indicators of Compromise (top 10)", ioc_table)}
  {_section("Recommended Actions", actions_list)}
  {image_block}
  <tr><td align="center" style="padding:8px 24px 24px;">{cta}</td></tr>
  <tr><td style="background:#f5f5f5;padding:16px 24px;color:#888;
  font-size:12px;text-align:center;">
    WIDIRS v{WIDIRS_VERSION} &bull; Report ID: {report_id}<br>
    Do not reply to this email.
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>"""

    async def send_email_alert(self, incident: Incident) -> bool:
        """Send an HTML email alert via SMTP or SendGrid.

        Uses SMTP (STARTTLS, port 587) when SMTP_HOST is configured, otherwise
        the SendGrid REST API.

        Args:
            incident: The incident to notify.

        Returns:
            True on successful delivery, else False.
        """
        recipients = list(self.config.alert_email_to_list)
        if not recipients:
            logger.warning("email_no_recipients", incident=incident.incident_id)
            return False

        image_path = self._diff_image_path(incident)
        subject = self._subject(incident)
        html = self.build_email_html(incident, has_inline_image=bool(image_path))

        if self.config.smtp_host:
            return await self._send_via_smtp(
                subject, html, recipients, image_path, incident
            )
        return await self._send_via_sendgrid(
            subject, html, recipients, image_path, incident
        )

    async def _send_via_smtp(
        self,
        subject: str,
        html: str,
        recipients: List[str],
        image_path: Optional[str],
        incident: Incident,
    ) -> bool:
        """Build a MIME message and send it via SMTP STARTTLS in a thread."""
        log = logger.bind(incident=incident.incident_id, channel="email",
                          transport="smtp")
        sender = (
            self.config.alert_email_from
            or self.config.smtp_user
            or "widirs@localhost"
        )

        root = MIMEMultipart("related")
        root["Subject"] = subject
        root["From"] = sender
        root["To"] = ", ".join(recipients)
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText("Defacement detected. View in an HTML client.",
                            "plain", "utf-8"))
        alt.attach(MIMEText(html, "html", "utf-8"))
        root.attach(alt)

        if image_path:
            try:
                with open(image_path, "rb") as fh:
                    img = MIMEImage(fh.read())
                img.add_header("Content-ID", "<diffimage>")
                img.add_header("Content-Disposition", "inline",
                               filename="diff.png")
                root.attach(img)
            except OSError as exc:
                log.warning("email_image_attach_failed", error=str(exc))

        def _send() -> None:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port,
                              timeout=30) as server:
                server.starttls()
                if self.config.smtp_user and self.config.smtp_pass:
                    server.login(self.config.smtp_user, self.config.smtp_pass)
                server.sendmail(sender, recipients, root.as_string())

        try:
            await asyncio.to_thread(_send)
            log.info("email_sent", recipients=len(recipients))
            return True
        except (smtplib.SMTPException, OSError) as exc:
            log.error("email_smtp_failed", error=str(exc))
            return False

    async def _send_via_sendgrid(
        self,
        subject: str,
        html: str,
        recipients: List[str],
        image_path: Optional[str],
        incident: Incident,
    ) -> bool:
        """Send the email through the SendGrid v3 REST API via aiohttp."""
        log = logger.bind(incident=incident.incident_id, channel="email",
                          transport="sendgrid")
        api_key = getattr(self.config, "sendgrid_api_key", "")
        if not api_key:
            log.error("sendgrid_not_configured")
            return False

        sender = (
            self.config.alert_email_from
            or self.config.smtp_user
            or "widirs@localhost"
        )
        payload: Dict[str, Any] = {
            "personalizations": [
                {"to": [{"email": r} for r in recipients]}
            ],
            "from": {"email": sender},
            "subject": subject,
            "content": [{"type": "text/html", "value": html}],
        }
        if image_path:
            try:
                with open(image_path, "rb") as fh:
                    encoded = base64.b64encode(fh.read()).decode("ascii")
                payload["attachments"] = [
                    {
                        "content": encoded,
                        "type": "image/png",
                        "filename": "diff.png",
                        "disposition": "inline",
                        "content_id": "diffimage",
                    }
                ]
            except OSError as exc:
                log.warning("email_image_attach_failed", error=str(exc))

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    SENDGRID_API, json=payload, headers=headers
                ) as resp:
                    if resp.status in (200, 202):
                        log.info("email_sent", recipients=len(recipients))
                        return True
                    body = await resp.text()
                    log.error("sendgrid_error", status=resp.status, body=body[:300])
                    return False
        except aiohttp.ClientError as exc:
            log.error("sendgrid_request_failed", error=str(exc))
            return False

    # ==================================================================
    # Low-severity digest
    # ==================================================================
    async def queue_digest(self, incident: Incident) -> None:
        """Add a low-severity incident to the hourly email digest queue."""
        async with self._digest_lock:
            self._digest_queue.append(incident)
        logger.info("digest_queued", incident=incident.incident_id,
                    queue_size=len(self._digest_queue))

    async def flush_digest(self) -> bool:
        """Send the batched low-severity digest email and clear the queue.

        Returns:
            True if a digest was sent, False if the queue was empty or failed.
        """
        async with self._digest_lock:
            if not self._digest_queue:
                return False
            batch = self._digest_queue
            self._digest_queue = []

        recipients = list(self.config.alert_email_to_list)
        if not recipients:
            logger.warning("digest_no_recipients", count=len(batch))
            return False

        rows = "".join(
            '<tr>'
            f'<td style="padding:6px 12px;border-bottom:1px solid #eee;">'
            f"{inc.url}</td>"
            f'<td style="padding:6px 12px;border-bottom:1px solid #eee;">'
            f"{int(round(inc.risk_score))}/100</td>"
            f'<td style="padding:6px 12px;border-bottom:1px solid #eee;">'
            f"{inc.created_at.strftime('%H:%M UTC')}</td></tr>"
            for inc in batch
        )
        html = (
            '<table role="presentation" width="600" '
            'style="max-width:600px;border-collapse:collapse;'
            'font-family:Arial,sans-serif;font-size:14px;">'
            f'<tr><td style="background:{SEVERITY_COLORS["low"]};color:#fff;'
            'padding:16px;font-weight:bold;font-size:18px;">'
            f"WIDIRS Low-Severity Digest ({len(batch)} incidents)</td></tr>"
            '<tr><td><table width="100%" style="border-collapse:collapse;">'
            '<tr style="background:#f5f5f5;">'
            '<th align="left" style="padding:6px 12px;">URL</th>'
            '<th align="left" style="padding:6px 12px;">Risk</th>'
            '<th align="left" style="padding:6px 12px;">Time</th></tr>'
            f"{rows}</table></td></tr>"
            '<tr><td style="background:#f5f5f5;padding:12px;color:#888;'
            f'font-size:12px;text-align:center;">WIDIRS v{WIDIRS_VERSION} '
            "&bull; Do not reply to this email.</td></tr></table>"
        )
        subject = (
            f"[WIDIRS] LOW | {len(batch)} defacement incidents | "
            f"{datetime.now(timezone.utc).strftime('%Y%m%d %H:%M')} UTC"
        )

        if self.config.smtp_host:
            ok = await self._send_via_smtp(
                subject, html, recipients, None, batch[-1]
            )
        else:
            ok = await self._send_via_sendgrid(
                subject, html, recipients, None, batch[-1]
            )
        logger.info("digest_flushed", count=len(batch), success=ok)
        return ok

    # ==================================================================
    # Orchestration
    # ==================================================================
    async def dispatch_alert(self, incident: Incident) -> AlertResult:
        """Route, deduplicate and deliver an incident alert.

        Steps:
            1. Compute severity routing.
            2. Apply per-URL dedup cooldown.
            3. asyncio.gather all routed channel sends.
            4. Persist per-channel outcome to the alerts table.
            5. Return an AlertResult.

        Never raises; failures are captured in the result.

        Args:
            incident: The incident to alert on.

        Returns:
            A populated AlertResult.
        """
        severity = (
            incident.severity
            if incident.classification
            else _severity_from_score(incident.risk_score)
        )
        result = AlertResult(
            incident_id=incident.incident_id, severity=severity.value
        )
        log = logger.bind(incident=incident.incident_id, severity=severity.value)

        # info -> log only.
        if severity == Severity.INFO:
            log.info("alert_log_only")
            result.skipped = True
            result.skip_reason = "info_severity_log_only"
            return result

        # Dedup cooldown.
        if self._is_on_cooldown(incident.url):
            log.info("alert_suppressed_cooldown", url=incident.url)
            result.skipped = True
            result.skip_reason = "cooldown"
            return result

        # low -> digest queue (no immediate channels).
        if severity == Severity.LOW:
            await self.queue_digest(incident)
            self._mark_alerted(incident.url)
            result.channels_attempted.append("email_digest")
            result.channels_succeeded.append("email_digest")
            await self._record(incident, AlertChannel.EMAIL, "queued")
            return result

        channels = self._channels_for(severity)
        result.channels_attempted = [c.value for c in channels]

        async def _run(channel: AlertChannel) -> Tuple[AlertChannel, bool, str]:
            try:
                if channel == AlertChannel.TELEGRAM:
                    ok = await self.send_telegram_alert(incident)
                else:
                    ok = await self.send_email_alert(incident)
                return channel, ok, "" if ok else "delivery failed"
            except Exception as exc:  # never let a channel crash dispatch
                logger.error("channel_dispatch_error",
                             channel=channel.value, error=str(exc))
                return channel, False, str(exc)

        outcomes = await asyncio.gather(*(_run(c) for c in channels))

        any_success = False
        for channel, ok, err in outcomes:
            if ok:
                any_success = True
                result.channels_succeeded.append(channel.value)
            else:
                result.errors.append(f"{channel.value}: {err}")
            await self._record(
                incident, channel, "sent" if ok else "failed"
            )

        if any_success:
            self._mark_alerted(incident.url)

        log.info(
            "alert_dispatched",
            attempted=result.channels_attempted,
            succeeded=result.channels_succeeded,
            errors=len(result.errors),
        )
        return result

    async def _record(
        self, incident: Incident, channel: AlertChannel, status: str
    ) -> None:
        """Persist a per-channel alert outcome to the alerts table.

        Resolves the incident's DB row id from its report_id; logs and skips
        persistence if no matching incident row exists.
        """
        try:
            incident_row_id = await self._resolve_incident_row(incident)
            if incident_row_id is None:
                logger.debug("alert_not_persisted_no_incident_row",
                             incident=incident.incident_id)
                return
            await self.db.insert_alert(incident_row_id, channel.value, status)
        except Exception as exc:  # persistence must not break dispatch
            logger.warning("alert_persist_failed",
                           incident=incident.incident_id, error=str(exc))

    async def _resolve_incident_row(self, incident: Incident) -> Optional[int]:
        """Best-effort lookup of the integer incidents.id for this incident.

        The DB schema keys incidents by an auto-increment id and stores the
        string incident_id in report_id. We match on report_id via the site.
        """
        site = await self.db.get_site_by_url(incident.url)
        if not site:
            return None
        cur = await self.db.conn.execute(
            "SELECT id FROM incidents WHERE site_id = ? AND report_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (site["id"], incident.incident_id),
        )
        row = await cur.fetchone()
        return int(row["id"]) if row else None
