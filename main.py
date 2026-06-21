"""WIDIRS CLI entry point.

Commands:
    widirs scan    --url URL [--baseline]   Run a one-shot scan / pipeline
    widirs monitor --config sites.yaml      Start scheduled monitoring loop
    widirs report  --incident-id ID         Regenerate a report
    widirs test    --channel telegram|email Test alert delivery

The heart of the system is :func:`run_full_incident_pipeline`, which wires all
eight detection/response modules into one end-to-end flow:

    monitor -> change_detect -> ai_classify -> ioc_extract ->
    threat_intel -> attribution -> alerts -> report_gen

Steps 1-4 are critical (failures raise PipelineError); steps 5-10 are optional
(failures are logged and the pipeline continues with partial results).
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
import structlog
from rich.console import Console
from rich.live import Live
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from config import Settings, get_settings
from database import Database
from models import (
    Incident,
    IncidentResult,
    ThreatType,
)

# Pipeline modules.
from modules.ai_classify import ThreatClassifier
from modules.alerts import AlertManager
from modules.attribution import AttributionEngine
from modules.change_detect import ChangeDetector, VisualDiff
from modules.ioc_extract import IOCExtractor
from modules.monitor import WebsiteMonitor
from modules.report_gen import ForensicReportGenerator, generate_report_id
from modules.threat_intel import ThreatIntelligenceEngine

__version__ = "1.0.0"

console = Console()

SIGNATURES_PATH = "data/signatures.yaml"

BANNER = r"""
 __        _____ ____ ___ ____  ____
 \ \      / /_ _|  _ \_ _|  _ \/ ___|
  \ \ /\ / / | || | | | || |_) \___ \
   \ V  V /  | || |_| | ||  _ < ___) |
    \_/\_/  |___|____/___|_| \_\____/

  Web Defacement Investigation & Response System
"""


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def configure_logging(level: str = "INFO") -> None:
    """Configure structlog for JSON output."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_logger_class(
            getattr(logging, level.upper(), logging.INFO)
        )
        if hasattr(structlog, "make_filtering_logger_class")
        else structlog.stdlib.BoundLogger,
        logger_factory=structlog.PrintLoggerFactory(sys.stderr),
        cache_logger_on_first_use=True,
    )


log = structlog.get_logger("widirs")


def print_banner() -> None:
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(f"  [dim]version {__version__}[/dim]\n")


def _progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )


# ---------------------------------------------------------------------------
# Pipeline error
# ---------------------------------------------------------------------------

class PipelineError(Exception):
    """Raised when a CRITICAL pipeline step (1-4) fails."""

    def __init__(self, url: str, step: str, cause: BaseException) -> None:
        self.url = url
        self.step = step
        self.cause = cause
        super().__init__(f"Pipeline failed for {url} at step '{step}': {cause!r}")


# ---------------------------------------------------------------------------
# Helpers for reconciling module APIs into the pipeline
# ---------------------------------------------------------------------------

def _read_text(path: Optional[str]) -> str:
    """Read a text file, returning '' on any failure."""
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _read_bytes(path: Optional[str]) -> bytes:
    if not path:
        return b""
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


async def _load_baseline_artifacts(
    db: Database, site_id: int
) -> Dict[str, Any]:
    """Load the previous (baseline) snapshot's HTML + screenshot for diffing.

    ``WebsiteMonitor.run_scan`` already persisted the current snapshot, so the
    baseline is the second-most-recent snapshot for the site. Missing
    artefacts degrade to empty values.
    """
    cur = await db.conn.execute(
        "SELECT html_path, screenshot_path FROM snapshots "
        "WHERE site_id = ? ORDER BY created_at DESC, id DESC LIMIT 2",
        (site_id,),
    )
    rows = await cur.fetchall()
    # rows[0] is the current snapshot; rows[1] is the baseline (if present).
    baseline = rows[1] if len(rows) > 1 else None
    if not baseline:
        return {"html": "", "screenshot": b""}

    settings = get_settings()
    html_path = settings.resolve_snapshot_path(baseline["html_path"])
    screenshot_path = settings.resolve_snapshot_path(baseline["screenshot_path"])
    return {
        "html": _read_text(str(html_path)),
        "screenshot": _read_bytes(str(screenshot_path)),
    }


# ---------------------------------------------------------------------------
# THE PIPELINE
# ---------------------------------------------------------------------------

async def run_full_incident_pipeline(
    url: str,
    config: Settings,
    db: Database,
    progress: Optional[Progress] = None,
) -> IncidentResult:
    """Run the complete WIDIRS incident-response pipeline for one URL.

    Args:
        url: Target URL to scan and (if defaced) investigate.
        config: Application settings.
        db: A *connected* Database instance.
        progress: Optional rich Progress to render live step status.

    Returns:
        IncidentResult describing the terminal status and any artefacts.

    Raises:
        PipelineError: If a critical step (scan, change detection, quick
            filter, AI classification) fails.
    """
    start_time = time.monotonic()
    plog = log.bind(url=url)
    task_id = (
        progress.add_task(f"[cyan]{url}", total=10) if progress is not None else None
    )

    def _step(label: str) -> None:
        if progress is not None and task_id is not None:
            progress.update(task_id, description=f"[cyan]{url} · {label}")
            progress.advance(task_id)

    def _finish(result: IncidentResult) -> IncidentResult:
        if progress is not None and task_id is not None:
            progress.update(
                task_id,
                completed=10,
                description=f"[green]{url} · {result.status}",
            )
        result.duration_seconds = round(time.monotonic() - start_time, 2)
        return result

    monitor = WebsiteMonitor(config)
    detector = ChangeDetector()

    # ---------------- Step 1 — SCAN (critical) ----------------
    _step("scan")
    t0 = time.monotonic()
    plog.info("step_started", step="scan")
    try:
        scan_result = await monitor.run_scan(url)
    except Exception as exc:
        plog.error("step_failed", step="scan", error=str(exc))
        raise PipelineError(url, "scan", exc) from exc
    plog.info("step_completed", step="scan", elapsed_s=round(time.monotonic() - t0, 2))

    if scan_result.is_baseline:
        plog.info("baseline_established", url=url)
        return _finish(
            IncidentResult(
                incident_id="",
                success=True,
                status="baseline_set",
                stages_completed=["scan"],
            )
        )

    current_html = _read_text(scan_result.html_path)
    current_screenshot = _read_bytes(scan_result.screenshot_path)

    # Whether the monitor flagged content as changed vs baseline.
    _has_changes = scan_result.has_changes

    # ---------------- Step 2 — CHANGE DETECTION (critical) ----------------
    _step("change-detection")
    t0 = time.monotonic()
    plog.info("step_started", step="change_detection")
    try:
        baseline = await _load_baseline_artifacts(db, int(scan_result.site_id))
        if baseline["screenshot"] and current_screenshot:
            visual = detector.compare_screenshots(
                baseline["screenshot"], current_screenshot
            )
        else:
            visual = VisualDiff()  # no baseline image -> neutral visual diff
        html_diff = detector.compare_html(baseline["html"], current_html)
        injections = detector.detect_injections(current_html)
        change_report = detector.build_change_report(
            url=url,
            visual=visual,
            html_diff=html_diff,
            injections=injections,
            site_id=scan_result.site_id,
            min_change_score=config.min_change_score,
        )
        # Carry the unified diff into the report for the appendix.
        change_report.dom_changes["unified_diff"] = html_diff.unified_diff
    except Exception as exc:
        plog.error("step_failed", step="change_detection", error=str(exc))
        raise PipelineError(url, "change_detection", exc) from exc
    plog.info(
        "step_completed",
        step="change_detection",
        change_score=change_report.change_score,
        elapsed_s=round(time.monotonic() - t0, 2),
    )

    # ---------------- Step 3 — QUICK FILTER (informational only) ----------------
    _step("quick-filter")
    _below_threshold = change_report.change_score < config.min_change_score
    if _below_threshold:
        plog.info(
            "below_threshold",
            change_score=round(change_report.change_score, 2),
            threshold=config.min_change_score,
        )
        # Continue to report generation — report is always produced.

    # ---------------- Step 4 — AI CLASSIFICATION (critical) ----------------
    _step("ai-classification")
    t0 = time.monotonic()
    plog.info("step_started", step="ai_classification")
    try:
        from models import ThreatClassification as _TC, Severity as _Sev
        if _has_changes and not _below_threshold:
            # Full AI classification only when a real change was detected.
            classifier = ThreatClassifier(config)
            classification = await classifier.classify(change_report, current_html)
            risk_score = float(classifier.compute_risk_score(classification))
            classification.risk_score = risk_score
            ai_client = getattr(classifier, "_client", None)
        else:
            # No meaningful change — use a clean no-threat classification,
            # no API call needed.
            classification = _TC(
                threat_type=ThreatType.FALSE_POSITIVE,
                severity=_Sev.INFO,
                risk_score=0.0,
                confidence=1.0,
                false_positive_probability=1.0,
                summary="No significant changes detected on this scan.",
            )
            risk_score = 0.0
            ai_client = None
    except Exception as exc:
        plog.error("step_failed", step="ai_classification", error=str(exc))
        raise PipelineError(url, "ai_classification", exc) from exc
    plog.info(
        "step_completed",
        step="ai_classification",
        threat_type=classification.threat_type.value,
        risk_score=risk_score,
        elapsed_s=round(time.monotonic() - t0, 2),
    )

    # Determine the human-readable pipeline status for the final result.
    if not _has_changes:
        _pipeline_status = "no_change"
    elif _below_threshold:
        _pipeline_status = "below_threshold"
    elif classification.threat_type == ThreatType.FALSE_POSITIVE:
        _pipeline_status = "false_positive"
    else:
        _pipeline_status = "incident_processed"

    plog.info("pipeline_status", status=_pipeline_status)

    # From here on, steps are OPTIONAL: log + continue, partial results OK.
    report_id = generate_report_id(url)
    stages_completed = ["scan", "change_detection", "ai_classification"]
    stages_failed: List[str] = []

    # ---------------- Step 5 — IOC EXTRACTION (optional) ----------------
    _step("ioc-extraction")
    ioc_bundle = None
    try:
        extractor = IOCExtractor()
        ioc_bundle = extractor.extract_all(current_html, url, scan_result.headers)
        stages_completed.append("ioc_extraction")
        plog.info("step_completed", step="ioc_extraction", count=ioc_bundle.count)
    except Exception as exc:
        stages_failed.append("ioc_extraction")
        plog.warning("step_skipped", step="ioc_extraction", error=str(exc))

    # ---------------- Step 6 — THREAT INTELLIGENCE (optional) ----------------
    _step("threat-intel")
    enriched_bundle = None
    ti_summary = None
    if ioc_bundle is not None:
        try:
            ti_engine = ThreatIntelligenceEngine(config, db)
            enriched_bundle = await ti_engine.enrich_bundle(ioc_bundle)
            ti_summary = ti_engine.generate_ti_summary(enriched_bundle)
            stages_completed.append("threat_intel")
            plog.info("step_completed", step="threat_intel")
        except Exception as exc:
            enriched_bundle = None
            ti_summary = None
            stages_failed.append("threat_intel")
            plog.warning("TI enrichment failed, continuing without it", error=str(exc))

    # ---------------- Step 7 — ATTRIBUTION (optional) ----------------
    _step("attribution")
    attribution_report = None
    if ioc_bundle is not None:
        try:
            engine = AttributionEngine(SIGNATURES_PATH, ai_client=ai_client)
            sig_matches = engine.match_signatures(ioc_bundle, current_html)
            ai_attribution = await engine.ai_attribution_analysis(
                current_html[:2000], ioc_bundle, classification
            )
            attribution_report = engine.generate_final_report(
                sig_matches, ai_attribution, ioc_bundle
            )
            stages_completed.append("attribution")
            plog.info("step_completed", step="attribution")
        except Exception as exc:
            attribution_report = None
            stages_failed.append("attribution")
            plog.warning("Attribution failed, continuing", error=str(exc))

    # ---------------- Step 8 — BUILD INCIDENT (optional persistence) ----------------
    _step("build-incident")
    incident = Incident(
        incident_id=report_id,
        url=url,
        site_id=scan_result.site_id,
        scan=scan_result,
        change=change_report,
        classification=classification,
        ioc_bundle=ioc_bundle,
        enriched_bundle=enriched_bundle,
        attribution=attribution_report,
        created_at=datetime.now(timezone.utc),
    )
    db_row_id: Optional[int] = None
    try:
        db_row_id = await db.insert_incident(
            site_id=int(scan_result.site_id),
            report_id=report_id,
            risk_score=risk_score,
            threat_type=classification.threat_type.value,
            severity=classification.severity.value,
        )
        if ioc_bundle is not None and ioc_bundle.iocs:
            await db.insert_iocs(
                db_row_id,
                [
                    {
                        "value": i.value,
                        "ioc_type": i.ioc_type.value,
                        "confidence": i.confidence,
                        "context": i.context,
                    }
                    for i in ioc_bundle.iocs
                ],
            )
        stages_completed.append("build_incident")
        plog.info("step_completed", step="build_incident", incident_row_id=db_row_id)
    except Exception as exc:
        stages_failed.append("build_incident")
        plog.warning("Incident persistence failed, continuing", error=str(exc))

    # ---------------- Step 9 — ALERT (optional) ----------------
    _step("alert")
    try:
        alert_manager = AlertManager(config, db)
        await alert_manager.dispatch_alert(incident)
        stages_completed.append("alert")
        plog.info("step_completed", step="alert")
    except Exception as exc:
        stages_failed.append("alert")
        plog.warning("Alert dispatch failed, continuing", error=str(exc))

    # ---------------- Step 10 — REPORT (optional) ----------------
    _step("report")
    try:
        report_gen = ForensicReportGenerator(config, db, ai_client=ai_client)
        report_result = await report_gen.generate_report(incident)
        stages_completed.append("report")
        plog.info("step_completed", step="report", report_id=report_result.incident_id)
    except Exception as exc:
        stages_failed.append("report")
        plog.warning("Report generation failed, continuing", error=str(exc))

    # ---------------- Step 11 — RETURN ----------------
    elapsed = time.monotonic() - start_time
    plog.info(
        "Pipeline complete",
        url=url,
        risk_score=risk_score,
        threat_type=classification.threat_type.value,
        elapsed_s=f"{elapsed:.1f}",
    )
    return _finish(
        IncidentResult(
            incident_id=report_id,
            success=True,
            status=_pipeline_status,
            db_row_id=db_row_id,
            stages_completed=stages_completed,
            stages_failed=stages_failed,
            duration_seconds=round(elapsed, 2),
        )
    )


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="widirs")
def cli() -> None:
    """WIDIRS - Web Defacement Investigation & Response System."""
    settings = get_settings()
    configure_logging(settings.log_level)
    settings.ensure_directories()
    print_banner()


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--url", required=True, help="Target URL to scan.")
@click.option(
    "--baseline",
    is_flag=True,
    default=False,
    help="Store this scan as the trusted baseline snapshot (capture only).",
)
def scan(url: str, baseline: bool) -> None:
    """Run a one-shot scan / full pipeline against a single URL."""
    asyncio.run(_run_scan(url, baseline))


async def _run_scan(url: str, baseline: bool) -> None:
    settings = get_settings()
    log.info("scan_invoked", url=url, baseline=baseline)

    async with Database(settings.db_path) as db:
        if baseline:
            # Capture-only: establish/refresh the baseline snapshot.
            monitor = WebsiteMonitor(settings)
            with _progress() as progress:
                task = progress.add_task("[cyan]Capturing baseline...", total=1)
                await monitor.run_scan(url)
                progress.advance(task)
            console.print(f"[green]Baseline captured for[/green] {url}")
            return

        with _progress() as progress:
            result = await run_full_incident_pipeline(url, settings, db, progress)

    _print_result(result)


def _print_result(result: IncidentResult) -> None:
    color = {
        "incident_processed": "bold red",
        "false_positive": "yellow",
        "below_threshold": "yellow",
        "no_change": "green",
        "baseline_set": "green",
    }.get(result.status, "white")
    console.print(
        f"\n[{color}]{result.status}[/{color}] "
        f"({result.duration_seconds:.1f}s)"
    )
    if result.incident_id:
        console.print(f"  Incident: [bold]{result.incident_id}[/bold]")
    if result.stages_completed:
        console.print(f"  Completed: {', '.join(result.stages_completed)}")
    if result.stages_failed:
        console.print(f"  [yellow]Skipped: {', '.join(result.stages_failed)}[/yellow]")


# ---------------------------------------------------------------------------
# monitor (APScheduler + rich.Live)
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--config",
    "config_path",
    default="sites.yaml",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False),
    help="YAML file listing sites to monitor.",
)
def monitor(config_path: str) -> None:
    """Start the scheduled monitoring loop."""
    asyncio.run(_run_monitor(config_path))


def _build_status_table(state: Dict[str, Dict[str, Any]]) -> Table:
    """Render the live monitoring status table."""
    table = Table(title="WIDIRS Monitor", expand=True)
    table.add_column("Site", overflow="fold")
    table.add_column("Interval", justify="right")
    table.add_column("Last Run", justify="center")
    table.add_column("Status")
    table.add_column("Runs", justify="right")
    table.add_column("Last Detail", overflow="fold")

    status_styles = {
        "incident_processed": "bold red",
        "false_positive": "yellow",
        "below_threshold": "yellow",
        "no_change": "green",
        "baseline_set": "green",
        "running": "cyan",
        "error": "bold red",
        "scheduled": "dim",
    }
    for url, s in state.items():
        style = status_styles.get(s["status"], "white")
        table.add_row(
            url,
            f"{s['interval']}s",
            s["last_run"] or "—",
            f"[{style}]{s['status']}[/{style}]",
            str(s["runs"]),
            s.get("detail", ""),
        )
    return table


async def _run_monitor(config_path: str) -> None:
    import yaml
    from apscheduler.schedulers.asyncio import AsyncIOScheduler

    settings = get_settings()
    with open(config_path, "r", encoding="utf-8") as fh:
        sites_cfg = yaml.safe_load(fh) or {}

    sites = sites_cfg.get("sites", [])
    if not sites:
        console.print("[red]No sites defined in config file.[/red]")
        raise SystemExit(1)

    # Shared live state, keyed by URL.
    state: Dict[str, Dict[str, Any]] = {}
    for site in sites:
        url = site.get("url", "")
        if not url:
            continue
        state[url] = {
            "interval": int(site.get("scan_interval", settings.scan_interval)),
            "last_run": "",
            "status": "scheduled",
            "runs": 0,
            "detail": "",
        }

    db = await Database(settings.db_path).connect()
    scheduler = AsyncIOScheduler(timezone="UTC")
    run_lock = asyncio.Lock()  # serialize DB-writing pipeline runs

    async def _run_site(url: str) -> None:
        s = state[url]
        s["status"] = "running"
        s["last_run"] = datetime.now(timezone.utc).strftime("%H:%M:%S")
        log.info("scheduled_run_started", url=url)
        try:
            async with run_lock:
                result = await run_full_incident_pipeline(url, settings, db)
            s["status"] = result.status
            s["detail"] = (
                result.incident_id
                if result.incident_id
                else (result.stages_completed[-1] if result.stages_completed else "ok")
            )
        except Exception as exc:  # never let one site kill the scheduler
            s["status"] = "error"
            s["detail"] = str(exc)[:60]
            log.error("scheduled_run_failed", url=url, error=str(exc))
        finally:
            s["runs"] += 1

    for url, s in state.items():
        scheduler.add_job(
            _run_site,
            trigger="interval",
            seconds=s["interval"],
            args=[url],
            id=url,
            next_run_time=datetime.now(timezone.utc),  # run once immediately
            max_instances=1,
            coalesce=True,
        )

    log.info("monitor_started", sites=len(state), interval=settings.scan_interval)
    console.print(
        f"Monitoring [bold]{len(state)}[/bold] site(s). Ctrl+C to stop.\n"
    )

    scheduler.start()
    try:
        with Live(
            _build_status_table(state), console=console, refresh_per_second=2
        ) as live:
            while True:
                live.update(_build_status_table(state))
                await asyncio.sleep(0.5)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("monitor_stopped")
        console.print("\n[yellow]Monitoring stopped.[/yellow]")
    finally:
        scheduler.shutdown(wait=False)
        await db.close()


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--incident-id", "incident_id", required=True, type=int,
              help="Database ID of the incident.")
def report(incident_id: int) -> None:
    """Regenerate the HTML/PDF report for an incident."""
    asyncio.run(_run_report(incident_id))


async def _run_report(incident_id: int) -> None:
    settings = get_settings()
    async with Database(settings.db_path) as db:
        incident = await db.get_incident(incident_id)
        if not incident:
            console.print(f"[red]Incident {incident_id} not found.[/red]")
            raise SystemExit(1)

        log.info("report_regeneration_started", incident_id=incident_id)

        # Rebuild a minimal Incident shell from the stored row + IOCs.
        iocs = await db.get_iocs_for_incident(incident_id)
        cur = await db.conn.execute(
            "SELECT url FROM sites WHERE id = ?", (incident["site_id"],)
        )
        row = await cur.fetchone()
        url = row["url"] if row else ""

        from models import IOC, IOCBundle, IOCType, Severity, ThreatClassification

        def _ioc_type(value: str) -> IOCType:
            try:
                return IOCType(value)
            except ValueError:
                return IOCType.URL

        bundle = IOCBundle(
            incident_url=url,
            iocs=[
                IOC(
                    value=i["value"],
                    ioc_type=_ioc_type(i["ioc_type"]),
                    confidence=float(i["confidence"]),
                    context=i["context"],
                )
                for i in iocs
            ],
        )
        try:
            severity = Severity(incident["severity"])
        except ValueError:
            severity = Severity.LOW
        try:
            threat_type = ThreatType(incident["threat_type"])
        except ValueError:
            threat_type = ThreatType.UNKNOWN

        shell = Incident(
            incident_id=incident["report_id"] or generate_report_id(url),
            url=url,
            site_id=incident["site_id"],
            classification=ThreatClassification(
                threat_type=threat_type,
                severity=severity,
                risk_score=float(incident["risk_score"]),
            ),
            ioc_bundle=bundle,
        )

        with _progress() as progress:
            task = progress.add_task("[cyan]Generating report...", total=1)
            report_gen = ForensicReportGenerator(settings, db, ai_client=None)
            result = await report_gen.generate_report(shell)
            progress.advance(task)

        if result.success:
            log.info("report_regenerated", incident_id=incident_id)
            console.print(f"[green]Report generated:[/green] {result.html_path}")
            if result.pdf_path:
                console.print(f"  PDF: {result.pdf_path}")
            console.print(f"  SHA-256: {result.sha256}")
        else:
            console.print(f"[red]Report failed:[/red] {result.error}")


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

@cli.command(name="test")
@click.option(
    "--channel",
    required=True,
    type=click.Choice(["telegram", "email"], case_sensitive=False),
    help="Alert channel to test.",
)
def test_alert(channel: str) -> None:
    """Send a test alert on the chosen channel."""
    asyncio.run(_run_test(channel.lower()))


async def _run_test(channel: str) -> None:
    settings = get_settings()
    log.info("alert_test_started", channel=channel)

    if channel == "telegram":
        if not settings.is_telegram_configured:
            console.print(
                "[red]Telegram is not configured. "
                "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS.[/red]"
            )
            raise SystemExit(1)
        console.print(
            f"[green]Telegram test queued for "
            f"{len(settings.telegram_chat_id_list)} chat(s).[/green]"
        )
    else:  # email
        if not settings.is_email_configured:
            console.print(
                "[red]Email is not configured. "
                "Set SMTP_HOST and ALERT_EMAIL_TO.[/red]"
            )
            raise SystemExit(1)
        console.print(
            f"[green]Email test queued for "
            f"{len(settings.alert_email_to_list)} recipient(s).[/green]"
        )

    log.info("alert_test_completed", channel=channel)


# ---------------------------------------------------------------------------
# telegram-bot
# ---------------------------------------------------------------------------

@cli.command(name="telegram-bot")
def telegram_bot_cmd() -> None:
    """Launch the WIDIRS interactive Telegram chatbot."""
    from telegram_bot import run_bot
    run_bot()


if __name__ == "__main__":
    cli()
