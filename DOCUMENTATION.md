# WIDIRS — Web Defacement Investigation & Response System
### Technical Documentation v1.0.0

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [File Structure](#3-file-structure)
4. [Core Scripts](#4-core-scripts)
   - [main.py — Pipeline Orchestrator](#41-mainpy--pipeline-orchestrator)
   - [dashboard.py — Web Dashboard](#42-dashboardpy--web-dashboard)
   - [config.py — Configuration](#43-configpy--configuration)
   - [database.py — Persistence Layer](#44-databasepy--persistence-layer)
   - [models.py — Data Models](#45-modelspy--data-models)
5. [Modules](#5-modules)
   - [monitor.py — Website Scanner](#51-monitorpy--website-scanner)
   - [change_detect.py — Change Detection](#52-change_detectpy--change-detection)
   - [ai_classify.py — AI Threat Classification](#53-ai_classifypy--ai-threat-classification)
   - [ioc_extract.py — IOC Extraction](#54-ioc_extractpy--ioc-extraction)
   - [threat_intel.py — Threat Intelligence](#55-threat_intelpy--threat-intelligence)
   - [attribution.py — Threat Attribution](#56-attributionpy--threat-attribution)
   - [alerts.py — Alert System](#57-alertspy--alert-system)
   - [report_gen.py — Report Generation](#58-report_genpy--report-generation)
6. [Pipeline Flow](#6-pipeline-flow)
7. [API Keys Required](#7-api-keys-required)
8. [Setup & Running](#8-setup--running)
9. [Data Storage](#9-data-storage)

---

## 1. Project Overview

WIDIRS is an automated **Web Defacement Investigation & Response System** built in Python. It monitors websites for unauthorised changes, uses Google Gemini AI to classify threats, extracts indicators of compromise (IOCs), enriches them against threat-intelligence APIs, and generates professional forensic HTML reports — all accessible through a web dashboard.

**Core capabilities:**
- Automated website scanning with headless Chromium (Playwright)
- Visual screenshot diffing (pHash, SSIM, pixel-level)
- HTML structural change detection
- Google Gemini AI-powered threat classification (9 threat types)
- IOC extraction (IPs, domains, URLs, hashes, wallets, handles)
- VirusTotal + AbuseIPDB + URLhaus threat intelligence enrichment
- AI-driven attribution analysis
- Telegram + Email alerting
- Professional HTML forensic reports with SHA-256 chain-of-custody
- Flask web dashboard with real-time scan progress

---

## 2. Architecture

```
User / Dashboard
      │
      ▼
dashboard.py  ──────────────────────────────────►  Flask HTTP Server
      │                                             (port 5000)
      │  POST /api/scan
      ▼
main.py  run_full_incident_pipeline()
      │
      ├──► modules/monitor.py        Step 1: Fetch page + screenshot
      ├──► modules/change_detect.py  Step 2: Diff vs baseline
      │                              Step 3: Score filter
      ├──► modules/ai_classify.py    Step 4: Google Gemini classification
      ├──► modules/ioc_extract.py    Step 5: Regex IOC extraction
      ├──► modules/threat_intel.py   Step 6: VirusTotal / AbuseIPDB / URLhaus
      ├──► modules/attribution.py    Step 7: Signature + AI attribution
      ├──► database.py               Step 8: SQLite persistence
      ├──► modules/alerts.py         Step 9: Telegram / Email alerts
      └──► modules/report_gen.py     Step 10: HTML report generation
```

---

## 3. File Structure

```
widirs/
├── main.py              # CLI entry point + pipeline orchestrator
├── dashboard.py         # Flask web dashboard
├── config.py            # Settings loaded from .env
├── database.py          # Async SQLite wrapper (aiosqlite)
├── models.py            # Shared dataclasses and enums
├── requirements.txt     # Python dependencies
├── .env                 # API keys and settings (never commit)
├── .env.example         # Template for .env
├── data/
│   ├── db/widirs.db     # SQLite database
│   ├── snapshots/       # Per-site HTML + screenshot snapshots
│   ├── diffs/           # Visual diff PNG overlays
│   ├── reports/         # Generated HTML forensic reports
│   └── signatures.yaml  # Threat-group attribution signatures
├── modules/
│   ├── monitor.py       # Website fetch + screenshot + snapshot
│   ├── change_detect.py # Visual + HTML diff engine
│   ├── ai_classify.py   # Google Gemini threat classifier
│   ├── ioc_extract.py   # Regex IOC extractor
│   ├── threat_intel.py  # VirusTotal / AbuseIPDB / URLhaus
│   ├── attribution.py   # Signature + AI attribution engine
│   ├── alerts.py        # Telegram + Email alert dispatcher
│   └── report_gen.py    # Jinja2 HTML + WeasyPrint PDF reports
└── templates/
    └── report.html.j2   # Forensic report Jinja2 template
```

---

## 4. Core Scripts

### 4.1 `main.py` — Pipeline Orchestrator

**Purpose:** CLI entry point and the heart of the system. Wires all 10 pipeline modules into a single end-to-end incident response flow.

**Key class/function:**

```python
async def run_full_incident_pipeline(url, config, db, progress) -> IncidentResult
```

Runs 10 sequential steps for one URL. Steps 1–4 are **critical** (failure raises `PipelineError`). Steps 5–10 are **optional** (failure is logged and the pipeline continues with partial results).

| Step | Module | Description | Critical? |
|------|--------|-------------|-----------|
| 1 | monitor | Fetch HTML + screenshot | ✅ Yes |
| 2 | change_detect | Diff vs baseline (visual + HTML) | ✅ Yes |
| 3 | — | Change score quick filter | ✅ Yes |
| 4 | ai_classify | Google Gemini threat classification | ✅ Yes |
| 5 | ioc_extract | Extract IPs, domains, URLs, hashes | No |
| 6 | threat_intel | VirusTotal / AbuseIPDB enrichment | No |
| 7 | attribution | Signature + AI attribution | No |
| 8 | database | Persist incident + IOCs to SQLite | No |
| 9 | alerts | Dispatch Telegram / Email alerts | No |
| 10 | report_gen | Generate HTML forensic report | No |

**CLI commands:**

```bash
# Establish baseline (first scan)
python main.py scan --url https://example.com --baseline

# Full scan + report
python main.py scan --url https://example.com

# Continuous monitoring from YAML config
python main.py monitor --config sites.yaml

# Regenerate a report
python main.py report --incident-id 5

# Test alert delivery
python main.py test --channel telegram
python main.py test --channel email
```

**`PipelineError`** — raised when a critical step (1–4) fails, carrying `url`, `step` and `cause`.

---

### 4.2 `dashboard.py` — Web Dashboard

**Purpose:** A Flask web server providing a browser-based UI for non-technical users. Exposes the same pipeline as the CLI through a clean interface with real-time progress streaming.

**Technology:** Flask 3 + Server-Sent Events (SSE) — no WebSocket, no frontend framework required.

**Routes:**

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Serves the full dashboard HTML (single-page app) |
| `/api/scan` | POST | Starts a scan. Body: `{"url": "https://..."}`. Returns `{"scan_id": "..."}` |
| `/api/scan/<id>/stream` | GET | SSE stream — emits `status`, `progress`, `done`, `error` events |
| `/api/scans` | GET | Returns last 50 scan records from the DB as JSON |
| `/report/<report_id>` | GET | Serves the HTML report file for a given report ID |

**SSE event types:**

| Event | Data fields | Meaning |
|-------|-------------|---------|
| `status` | `step`, `message` | Current pipeline step name |
| `progress` | `pct` | Progress percentage (0–100) |
| `done` | `status`, `incident_id`, `duration`, `report_url`, `stages_completed`, `stages_failed` | Scan finished successfully |
| `error` | `message` | Pipeline failed |
| `ping` | — | Keepalive (sent every 30s) |

**Dashboard UI features:**
- Dark theme, GitHub-style design
- URL input with Enter-key support
- Animated 10-step progress list with pulsing active indicator
- Toast notification in bottom-right corner on completion
- "View Report" button linking directly to the HTML report
- Scan History table with severity badges, risk score, and per-row report links

---

### 4.3 `config.py` — Configuration

**Purpose:** Loads all settings from the `.env` file via Pydantic-Settings. Provides a cached singleton `get_settings()`.

**Key settings:**

| Variable | Default | Description |
|----------|---------|-------------|
| `GOOGLE_API_KEY` | — | Google Gemini API key (required for AI steps) |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal v3 API key |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB API key (optional) |
| `TELEGRAM_BOT_TOKEN` | — | Telegram bot token (optional) |
| `TELEGRAM_CHAT_IDS` | — | Comma-separated chat IDs |
| `SMTP_HOST` | — | SMTP server for email alerts |
| `SENDGRID_API_KEY` | — | SendGrid key (used if SMTP not set) |
| `SNAPSHOT_DIR` | `data/snapshots` | Where page captures are stored |
| `REPORT_DIR` | `data/reports` | Where reports are saved |
| `DB_PATH` | `data/db/widirs.db` | SQLite database path |
| `MIN_CHANGE_SCORE` | `0.10` | Threshold to trigger full analysis |
| `SCAN_INTERVAL` | `300` | Default scan interval in seconds |

**Convenience properties:**
- `is_telegram_configured` — True when token + at least one chat ID is set
- `is_email_configured` — True when transport + recipient is configured
- `telegram_chat_id_list` / `alert_email_to_list` — parsed CSV fields as `List[str]`

---

### 4.4 `database.py` — Persistence Layer

**Purpose:** Async SQLite wrapper using `aiosqlite`. Manages the full database schema and provides typed methods for all data operations.

**Tables:**

| Table | Purpose |
|-------|---------|
| `sites` | Monitored URLs with scan interval and alert threshold |
| `snapshots` | Each captured HTML/screenshot per site, with hash |
| `incidents` | Detected incidents with risk score, threat type, severity |
| `iocs` | Individual IOCs linked to an incident |
| `ti_cache` | Threat-intel cache with TTL expiry (avoids redundant API calls) |
| `reports` | Generated report paths and SHA-256 hashes |
| `alerts` | Alert delivery status per channel |

**Key methods:**

```python
await db.upsert_site(url, name, scan_interval, alert_threshold) -> int
await db.insert_snapshot(site_id, html_hash, screenshot_path, html_path) -> int
await db.insert_incident(site_id, report_id, risk_score, threat_type, severity) -> int
await db.insert_iocs(incident_id, iocs_list) -> int
await db.ti_cache_get(key) -> dict | None
await db.ti_cache_set(key, data, ttl_hours)
await db.insert_report(incident_id, html_path, pdf_path, sha256) -> int
```

---

### 4.5 `models.py` — Data Models

**Purpose:** All shared dataclasses used across every module. Every model inherits `SerializableMixin` which provides a `to_dict()` method returning a JSON-serializable dictionary.

**Enums:**

| Enum | Values |
|------|--------|
| `Severity` | `info`, `low`, `medium`, `high`, `critical` |
| `ThreatType` | `hacktivist_defacement`, `malware_injection`, `phishing_overlay`, `seo_spam_injection`, `ransomware_notice`, `nation_state_op`, `script_kiddie`, `false_positive`, `unknown` |
| `IOCType` | `ip`, `domain`, `url`, `hash_md5`, `hash_sha1`, `hash_sha256`, `email`, `handle`, `wallet`, `file_path` |
| `AlertChannel` | `telegram`, `email` |

**Core dataclasses:**

| Class | Description |
|-------|-------------|
| `ScanResult` | Output of one website capture (URL, hash, paths, status code) |
| `ChangeReport` | Diff output: change score, visual similarity, DOM changes, injections |
| `ThreatClassification` | AI output: threat type, severity, risk score, IOC hints, recommended actions |
| `IOC` | Single indicator of compromise (value, type, confidence, context) |
| `IOCBundle` | All IOCs for one incident |
| `EnrichedIOC` | An IOC with VT/AbuseIPDB scores attached |
| `AttributionReport` | Best-effort threat actor attribution |
| `Incident` | Aggregates all pipeline outputs for one detection event |
| `IncidentResult` | Pipeline return value: status, report ID, stages completed/failed |
| `ReportResult` | Report generation outcome: HTML path, PDF path, SHA-256 |

---

## 5. Modules

### 5.1 `modules/monitor.py` — Website Scanner

**Class:** `WebsiteMonitor`

**Purpose:** Captures a website's HTML and full-page screenshot, normalizes content, computes a hash, and compares it to the stored baseline to detect changes.

**Key methods:**

| Method | Description |
|--------|-------------|
| `fetch_page(url)` | HTTP GET with random user-agent rotation, 3 retries, redirect following |
| `screenshot_page(url)` | Headless Chromium screenshot (1280×800), ad/tracker domains blocked |
| `compute_html_hash(html)` | Normalised SHA-256: strips script/style content, sorts attributes, collapses whitespace |
| `save_snapshot(url, html, screenshot, metadata)` | Saves `page.html`, `screenshot.png`, `metadata.json` under `data/snapshots/{domain}/{timestamp}/` |
| `load_baseline(url)` | Loads most recent snapshot from DB + disk |
| `run_scan(url)` | Full pipeline: fetch + screenshot concurrently → hash → compare → save → return `ScanResult` |

**Design notes:**
- Uses 10 rotating user-agent strings (Chrome, Firefox, Safari, Edge, mobile)
- Blocks 14 ad/tracking domains during screenshots for stable visual diffs
- `is_baseline=True` on first scan; `has_changes=True` when hash differs from baseline

---

### 5.2 `modules/change_detect.py` — Change Detection

**Class:** `ChangeDetector`

**Purpose:** Compares two snapshots using visual metrics and HTML structural analysis. Produces a weighted 0.0–1.0 change score.

**Methods:**

| Method | Description |
|--------|-------------|
| `compare_screenshots(old, new)` | pHash + SSIM + pixel diff → `VisualDiff` with bounding boxes and red-overlay diff image |
| `compare_html(old, new)` | Extracts and compares titles, scripts, iframes, links, text → `HTMLDiff` with unified diff |
| `detect_injections(html)` | Scans for `base64_in_script`, `eval_encoded`, `hidden_iframe`, `external_script_non_cdn`, `phishing_form`, `crypto_miner` |
| `compute_change_score(visual, html_diff, injections)` | Weighted formula → score 0.0–1.0 |
| `build_change_report(...)` | Assembles `ChangeReport` from all sub-results |

**Change score formula:**
```
score = (1 - ssim) × 0.25
      + min(changed_area × 5, 1) × 0.15
      + text_diff_ratio × 0.20
      + min(added_scripts × 0.1, 0.2)
      + min(injections × 0.15, 0.30)
      + 0.10 if title changed
```

---

### 5.3 `modules/ai_classify.py` — AI Threat Classification

**Class:** `ThreatClassifier`

**Purpose:** Sends the change report to Google Gemini 3.1 Flash-Lite and classifies it into one of 9 threat types with severity, confidence, IOC hints, and recommended actions.

**Model:** `gemini-3.1-flash-lite` (free tier: 15 req/min, 1M tokens/day)

**Threat taxonomy:**

| Type | Description |
|------|-------------|
| `hacktivist_defacement` | Political/ideological graffiti with "Hacked by" banners |
| `malware_injection` | Obfuscated scripts, hidden iframes, cryptominers |
| `phishing_overlay` | Credential-harvesting forms posting to foreign domains |
| `seo_spam_injection` | Hidden links and keyword stuffing for SEO abuse |
| `ransomware_notice` | Extortion messages with wallet addresses and deadlines |
| `nation_state_op` | Surgical, stealthy modifications targeting high-value sites |
| `script_kiddie` | Generic boilerplate defacements from mass-scanning tools |
| `false_positive` | Legitimate CMS updates, A/B tests, CDN asset rotation |
| `unknown` | Cannot be classified |

**Risk score formula:**
```
risk = severity_score × 0.50
     + confidence × 30
     + (1 - false_positive_probability) × 20
```

**Key methods:**
- `classify(change_report, new_html)` → `ThreatClassification`
- `compute_risk_score(tc)` → `int` (0–100)
- `build_classification_prompt(report, html)` → formatted prompt string

---

### 5.4 `modules/ioc_extract.py` — IOC Extraction

**Class:** `IOCExtractor`

**Purpose:** Scans raw HTML and HTTP response headers for indicators of compromise using vetted regular expressions. Filters out private IPs, the site's own domain, and common CDN hosts.

**Extracted IOC types:**

| IOC Type | Pattern |
|----------|---------|
| IPv4 addresses | `\b(\d{1,3}\.){3}\d{1,3}\b` (non-private only) |
| URLs | `https?://...` (non-CDN, non-self) |
| Domains | Common TLDs (`.com`, `.ru`, `.io`, `.onion`, etc.) |
| MD5 hashes | 32 hex chars |
| SHA-1 hashes | 40 hex chars |
| SHA-256 hashes | 64 hex chars |
| Email addresses | Standard email pattern |
| Bitcoin wallets | Legacy (`1`/`3` prefix) and bech32 (`bc1`) |
| Ethereum wallets | `0x` + 40 hex chars |
| Attacker handles | "Hacked by X", "by ~X~" patterns in visible text |

**Key method:**
```python
extractor.extract_all(html, url, headers) -> IOCBundle
```

---

### 5.5 `modules/threat_intel.py` — Threat Intelligence

**Class:** `ThreatIntelligenceEngine`

**Purpose:** Enriches extracted IOCs against three external threat-intelligence sources. Results are cached in SQLite to avoid redundant API calls.

**Sources:**

| Source | IOC Types | Key metric |
|--------|-----------|------------|
| VirusTotal v3 | IP, domain, URL, hash | `malicious_count` from 70+ antivirus engines |
| AbuseIPDB | IP only | `abuse_confidence_score` (0–100) |
| URLhaus (abuse.ch) | URL, domain, hash | `query_status`: `is_malware` / `no_results` |

**TI risk score formula (0.0–1.0):**
```
ti_risk = min(vt_malicious / 10, 1.0) × 0.50
        + (abuse_score / 100) × 0.30
        + 0.20 if urlhaus status == "is_malware"
```

**Verdict tiers:** `malicious` (≥0.5), `suspicious` (0.2–0.5), `clean`, `unknown`

**Caching:** Each source result cached under key `{source}:{ioc_type}:{value}` with configurable TTL (default 24h).

**Key methods:**
```python
await engine.enrich_bundle(ioc_bundle) -> EnrichedBundle
engine.generate_ti_summary(bundle) -> TISummary
```

---

### 5.6 `modules/attribution.py` — Threat Attribution

**Class:** `AttributionEngine`

**Purpose:** Attributes a defacement to a known threat group by combining offline signature matching (from `data/signatures.yaml`) with Google Gemini AI analysis.

**Two-stage process:**

**Stage 1 — Signature matching (offline):**
- Scans HTML for text patterns, wallet address prefixes, known domains, handle regex patterns
- Each match adds to a per-group score (capped per category)
- Groups with score > 0.05 are returned sorted by confidence

**Stage 2 — AI analysis (Gemini):**
- Sends HTML snippet + IOCs + prior classification to Gemini
- Returns: origin region, motivation, sophistication level (1–5), language detected, supporting/dissenting evidence

**Confidence fusion:**
```
if signature match found:
    confidence = sig_score × 0.60 + ai_confidence × 0.40
else:
    confidence = ai_confidence × 0.60
```

**Key methods:**
```python
engine.match_signatures(iocs, html) -> List[SignatureMatch]
await engine.ai_attribution_analysis(html, iocs, classification) -> dict
engine.generate_final_report(sig_matches, ai_analysis, iocs) -> AttributionReport
```

---

### 5.7 `modules/alerts.py` — Alert System

**Class:** `AlertManager`

**Purpose:** Routes and delivers incident alerts across Telegram and email based on severity. Includes per-URL deduplication cooldown (30 minutes) and a low-severity hourly email digest.

**Severity routing:**

| Severity | Channels |
|----------|---------|
| Critical / High | Telegram + Email (immediate) |
| Medium | Telegram only (immediate) |
| Low | Email digest (batched hourly) |
| Info | Log only |

**Telegram features:**
- MarkdownV2 formatted message with threat summary and IOC counts
- Diff screenshot attached as photo when available
- 3-button inline keyboard: "Full Report", "False Positive", "Escalate"
- 3 retries with 5s backoff on timeout

**Email features:**
- Fully inline-styled mobile-responsive HTML email
- Incident summary table, top-10 IOC table with risk badges, recommended actions
- Inline diff image attachment
- Supports both SMTP (STARTTLS port 587) and SendGrid REST API

**Key methods:**
```python
await manager.dispatch_alert(incident) -> AlertResult
await manager.send_telegram_alert(incident) -> bool
await manager.send_email_alert(incident) -> bool
await manager.flush_digest() -> bool
```

---

### 5.8 `modules/report_gen.py` — Report Generation

**Class:** `ForensicReportGenerator`

**Purpose:** Renders a professional HTML forensic report from an incident using a Jinja2 template. Optionally converts to PDF with WeasyPrint. Computes SHA-256 for chain-of-custody.

**Report sections:**
1. Cover page (incident ID, severity banner, risk score metrics)
2. Executive summary (3-sentence AI-generated CISO brief)
3. Incident timeline (6 forensic events with timestamps)
4. Visual evidence (before/after screenshots + red-overlay diff)
5. IOC inventory (defanged values, types, TI risk scores)
6. Threat intelligence (per-IOC VT/AbuseIPDB/URLhaus verdicts)
7. Attribution (suspected actor, motivation, TTPs)
8. Recommended actions
9. Appendix (unified diff, HTTP headers, hashes, scan duration)

**Report ID format:**
```
WIDIRS-{YYYYMMDD}-{domain}-{4-hex-chars}
e.g. WIDIRS-20260616-quietude-one.vercel.app-E164
```

**File output:**
```
data/reports/WIDIRS-20260616-{domain}-XXXX/
    report.html    ← always generated
    report.pdf     ← generated if WeasyPrint + libgobject available
```

**Key methods:**
```python
await gen.generate_report(incident) -> ReportResult
await gen.generate_executive_summary(incident) -> str
generate_report_id(url) -> str
defang(value) -> str  # hxxps://evil[.]com
```

---

## 6. Pipeline Flow

```
User submits URL
        │
        ▼
Step 1 ── SCAN ─────────────────────────────────────────── CRITICAL
        Fetch HTML (aiohttp) + Screenshot (Playwright) concurrently
        Compute normalized SHA-256 hash of HTML
        Compare hash against stored baseline
        Save snapshot to data/snapshots/{domain}/{timestamp}/
        │
        ├── is_baseline=True → return "baseline_set" (still generate report)
        │
        ▼
Step 2 ── CHANGE DETECTION ──────────────────────────────── CRITICAL
        pHash distance + SSIM + pixel diff on screenshots
        HTML structural diff (title, scripts, iframes, links, text)
        Injection pattern scan (base64, eval, hidden iframes, etc.)
        Compute weighted change_score (0.0–1.0)
        │
        ▼
Step 3 ── QUICK FILTER ──────────────────────────────────── CRITICAL
        If change_score < MIN_CHANGE_SCORE (0.10):
            mark as "below_threshold" — continue to report anyway
        │
        ▼
Step 4 ── AI CLASSIFICATION ─────────────────────────────── CRITICAL
        If real changes detected:
            → Call Google Gemini 3.1 Flash-Lite
            → Parse JSON response → ThreatClassification
            → Compute risk_score (0–100)
        Else:
            → Use FALSE_POSITIVE classification, skip API call
        │
        ├── All statuses continue to step 5+ (report always generated)
        │
        ▼
Step 5 ── IOC EXTRACTION ─────────────────────────────────── optional
        Regex scan of HTML + response headers
        Extract IPs, domains, URLs, hashes, emails, wallets, handles
        Filter private IPs, self-domain, CDN hosts
        │
        ▼
Step 6 ── THREAT INTELLIGENCE ────────────────────────────── optional
        For each IOC (up to 4 concurrent):
            IP   → VirusTotal + AbuseIPDB
            URL  → VirusTotal + URLhaus
            Hash → VirusTotal + URLhaus
        Cache results in SQLite (TTL 24h)
        Compute ti_risk_score per IOC
        │
        ▼
Step 7 ── ATTRIBUTION ────────────────────────────────────── optional
        Match signatures.yaml patterns against HTML + IOCs
        Call Gemini for AI attribution analysis
        Fuse: confidence = sig×0.60 + ai×0.40
        │
        ▼
Step 8 ── BUILD INCIDENT ─────────────────────────────────── optional
        Aggregate all outputs into Incident dataclass
        Insert incident row + IOCs into SQLite
        │
        ▼
Step 9 ── ALERT ──────────────────────────────────────────── optional
        Route by severity:
            critical/high → Telegram + Email
            medium        → Telegram
            low           → Email digest queue
            info          → log only
        │
        ▼
Step 10 ── REPORT ────────────────────────────────────────── optional
        Render Jinja2 template with all incident data
        Embed screenshots as base64 data URIs
        Generate AI executive summary (3-sentence CISO brief)
        Write report.html to data/reports/{report_id}/
        Attempt WeasyPrint PDF + SHA-256 chain-of-custody
        │
        ▼
     Return IncidentResult
     (incident_id, status, stages_completed, stages_failed, duration_seconds)
```

---

## 7. API Keys Required

| Key | Required | Free Tier | Where to get |
|-----|----------|-----------|--------------|
| `GOOGLE_API_KEY` | **Yes** (AI steps) | 15 req/min, 1M tokens/day, no card | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) |
| `VIRUSTOTAL_API_KEY` | Recommended | 4 lookups/min, 500/day | [virustotal.com](https://www.virustotal.com) → API key |
| `ABUSEIPDB_API_KEY` | Optional | 1,000 checks/day | [abuseipdb.com](https://www.abuseipdb.com) |
| `SHODAN_API_KEY` | Optional | Paid plan required | [shodan.io](https://www.shodan.io) |
| `TELEGRAM_BOT_TOKEN` | Optional | Free | BotFather on Telegram |
| `SENDGRID_API_KEY` | Optional | 100 emails/day | [sendgrid.com](https://sendgrid.com) |

> **Minimum to run the full system:** `GOOGLE_API_KEY` + `VIRUSTOTAL_API_KEY`

---

## 8. Setup & Running

### Prerequisites
- Python 3.11+
- Virtual environment

### Installation

```bash
# 1. Clone / navigate to project
cd widirs

# 2. Create .env from template
copy .env.example .env
# Edit .env and add your API keys

# 3. Activate virtual environment
.venv\Scripts\activate.ps1        # Windows PowerShell
# source .venv/bin/activate        # Linux/macOS

# 4. Install dependencies
pip install -r requirements.txt

# 5. Install Playwright browser
playwright install chromium
```

### Running the Web Dashboard (recommended)

```bash
python dashboard.py
# Open http://localhost:5000 in your browser
```

### Running the CLI

```bash
# First scan (establishes baseline)
python main.py scan --url https://example.com --baseline

# Subsequent scans (generates report)
python main.py scan --url https://example.com

# Continuous monitoring
python main.py monitor --config sites.yaml
```

### `sites.yaml` format for monitoring

```yaml
sites:
  - url: https://example.com
    scan_interval: 300    # seconds
  - url: https://another.com
    scan_interval: 600
```

---

## 9. Data Storage

### SQLite Database (`data/db/widirs.db`)

All incident data persists in a local SQLite database. No external database server required.

### Snapshot Storage (`data/snapshots/`)

```
data/snapshots/
└── {domain}/
    └── {YYYYMMDD_HHMMSS}/
        ├── page.html        ← raw HTML at time of scan
        ├── screenshot.png   ← full-page screenshot
        └── metadata.json    ← url, hash, status_code, timing
```

### Report Storage (`data/reports/`)

```
data/reports/
└── WIDIRS-{YYYYMMDD}-{domain}-{XXXX}/
    ├── report.html    ← full forensic report (always generated)
    └── report.pdf     ← PDF with embedded SHA-256 (if WeasyPrint available)
```

### Diff Images (`data/diffs/`)

Red-overlay visual diff PNGs generated during screenshot comparison:
```
data/diffs/diff_{YYYYMMDD_HHMMSS_microseconds}.png
```

---

*Documentation generated for WIDIRS v1.0.0 — June 2026*
