"""WIDIRS Web Dashboard — Flask server with real-time scan progress via SSE."""

from __future__ import annotations

import asyncio
import json
import queue
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, Response, jsonify, render_template_string, request, send_file

# ── project imports ─────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent))

from config import get_settings
from database import Database
from main import run_full_incident_pipeline, PipelineError

app = Flask(__name__)
app.config["SECRET_KEY"] = "widirs-dashboard"

# ── active scan registry ─────────────────────────────────────────────────────
# scan_id -> {"queue": Queue, "status": str, "result": dict|None}
_scans: Dict[str, Dict[str, Any]] = {}
_scans_lock = threading.Lock()


# ── helpers ───────────────────────────────────────────────────────────────────

def _run_pipeline_in_thread(scan_id: str, url: str) -> None:
    """Run the async pipeline in a background thread, posting SSE events."""
    q = _scans[scan_id]["queue"]

    def _emit(event: str, data: dict) -> None:
        q.put({"event": event, "data": data})

    _emit("status", {"step": "starting", "message": f"Starting scan for {url}…"})

    async def _run() -> None:
        settings = get_settings()
        settings.ensure_directories()

        # Patch Progress so pipeline steps emit SSE events instead of rich bars
        step_names = {
            "scan":            "Scanning website",
            "change-detection":"Detecting changes",
            "quick-filter":    "Applying filters",
            "ai-classification":"AI threat classification",
            "ioc-extraction":  "Extracting IOCs",
            "threat-intel":    "Threat intelligence lookup",
            "attribution":     "Attribution analysis",
            "build-incident":  "Building incident record",
            "alert":           "Dispatching alerts",
            "report":          "Generating report",
        }
        completed = 0
        total_steps = len(step_names)

        class FakeTask:
            pass

        class FakeProgress:
            def add_task(self, desc, total=10):
                return FakeTask()
            def update(self, task, description="", completed=None):
                label = description.split("·")[-1].strip() if "·" in description else description
                key = label.lower().replace(" ", "-")
                msg = step_names.get(key, label)
                _emit("status", {"step": key, "message": msg})
            def advance(self, task):
                nonlocal completed
                completed += 1
                pct = int((completed / total_steps) * 100)
                _emit("progress", {"pct": pct})

        try:
            async with Database(settings.db_path) as db:
                result = await run_full_incident_pipeline(
                    url, settings, db, progress=FakeProgress()
                )
            _emit("done", {
                "status": result.status,
                "incident_id": result.incident_id,
                "duration": round(result.duration_seconds, 1),
                "stages_completed": result.stages_completed,
                "stages_failed": result.stages_failed,
                "report_url": f"/report/{result.incident_id}" if result.incident_id else "",
            })
        except PipelineError as exc:
            _emit("error", {"message": f"Pipeline failed at step '{exc.step}': {exc.cause}"})
        except Exception as exc:
            _emit("error", {"message": str(exc)})

    asyncio.run(_run())
    with _scans_lock:
        _scans[scan_id]["running"] = False


# ── API routes ─────────────────────────────────────────────────────────────────

@app.post("/api/scan")
def api_scan():
    """Start a new scan. Returns scan_id immediately."""
    data = request.get_json(force=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    import secrets
    scan_id = secrets.token_hex(8)
    with _scans_lock:
        _scans[scan_id] = {"queue": queue.Queue(), "running": True}

    t = threading.Thread(target=_run_pipeline_in_thread, args=(scan_id, url), daemon=True)
    t.start()
    return jsonify({"scan_id": scan_id})


@app.get("/api/scan/<scan_id>/stream")
def api_scan_stream(scan_id: str):
    """SSE stream for a running scan."""
    if scan_id not in _scans:
        return jsonify({"error": "unknown scan_id"}), 404

    def _generate():
        scan = _scans[scan_id]
        q = scan["queue"]
        while True:
            try:
                msg = q.get(timeout=30)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("event") in ("done", "error"):
                    break
            except queue.Empty:
                yield "data: {\"event\":\"ping\"}\n\n"
                if not scan.get("running"):
                    break

    return Response(_generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/scans")
def api_list_scans():
    """Return all past incidents from the DB."""
    async def _fetch():
        settings = get_settings()
        async with Database(settings.db_path) as db:
            cur = await db.conn.execute(
                """SELECT i.id, i.report_id, i.risk_score, i.threat_type,
                          i.severity, i.created_at, s.url,
                          r.html_path
                   FROM incidents i
                   JOIN sites s ON s.id = i.site_id
                   LEFT JOIN reports r ON r.incident_id = i.id
                   ORDER BY i.created_at DESC LIMIT 50"""
            )
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    rows = asyncio.run(_fetch())
    # add a usable report link
    for r in rows:
        rid = r.get("report_id", "")
        r["report_url"] = f"/report/{rid}" if rid else ""
    return jsonify(rows)


@app.get("/report/<report_id>")
def view_report(report_id: str):
    """Serve the HTML report for a given report_id."""
    settings = get_settings()
    # Sanitise: report_id must not contain path traversal chars
    safe = "".join(c for c in report_id if c.isalnum() or c in "-_.")
    path = Path(settings.report_dir) / safe / "report.html"
    if not path.exists():
        return "Report not found.", 404
    return send_file(str(path))


# ── dashboard HTML ─────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WIDIRS Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;700;800&family=Fira+Code:wght@400;500&display=swap');

  :root {
    --bg: #070a13;
    --surface: rgba(15, 23, 42, 0.65);
    --surface-hover: rgba(30, 41, 59, 0.8);
    --surface-solid: #0f172a;
    --border: rgba(59, 130, 246, 0.15);
    --border-focus: #3b82f6;
    --text: #f8fafc;
    --muted: #94a3b8;
    --accent: #3b82f6;
    --accent-glow: rgba(59, 130, 246, 0.4);
    --green: #10b981;
    --yellow: #f59e0b;
    --red: #ef4444;
    --purple: #8b5cf6;
    --orange: #f97316;
  }
  
  * { box-sizing: border-box; margin: 0; padding: 0; }
  
  body {
    background: var(--bg);
    background-image: radial-gradient(circle at 50% -20%, rgba(59, 130, 246, 0.15) 0%, transparent 60%);
    color: var(--text);
    font-family: 'Inter', sans-serif;
    font-size: 14px;
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
  }

  /* ── layout ── */
  .layout { display: grid; grid-template-columns: 260px 1fr;
             grid-template-rows: 64px 1fr; min-height: 100vh; }
  
  .topbar { grid-column: 1/-1; background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border);
            display: flex; align-items: center; padding: 0 24px; gap: 12px; z-index: 100; }
  
  .topbar .logo-wrap { display: flex; align-items: center; gap: 10px; }
  
  .topbar .logo { font-family: 'Outfit', sans-serif; font-size: 20px; font-weight: 800;
                  background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
                  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
                  letter-spacing: .5px; }
  
  .topbar .subtitle { color: var(--muted); font-size: 12px; border-left: 1px solid var(--border);
                      padding-left: 12px; margin-left: 4px; }
  
  .sidebar { background: rgba(15, 23, 42, 0.4); border-right: 1px solid var(--border);
             padding: 24px 0; display: flex; flex-direction: column; gap: 8px; }
  
  .sidebar-label { padding: 0 20px 8px; font-size: 11px; font-weight: 700;
                   color: var(--muted); text-transform: uppercase; letter-spacing: 1.5px; }
  
  .sidebar-item { display: flex; align-items: center; gap: 12px;
                  padding: 12px 20px; cursor: pointer; color: var(--muted);
                  font-weight: 500; border-left: 3px solid transparent;
                  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); }
  
  .sidebar-item:hover { color: var(--text); background: rgba(30, 41, 59, 0.4); }
  
  .sidebar-item.active { color: var(--text); background: rgba(59, 130, 246, 0.1);
                         border-left-color: var(--accent); text-shadow: 0 0 10px rgba(59, 130, 246, 0.2); }
  
  .sidebar-icon { flex-shrink: 0; }
  
  .main { padding: 40px 48px; overflow-y: auto; }

  /* ── scan card ── */
  .scan-card { background: var(--surface); backdrop-filter: blur(12px);
               border: 1px solid var(--border); border-radius: 12px;
               padding: 32px 40px; max-width: 800px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
               margin-bottom: 32px; transition: border-color 0.3s; }
  
  .scan-card h2 { font-family: 'Outfit', sans-serif; font-size: 22px; font-weight: 700; margin-bottom: 8px; }
  
  .scan-card p  { color: var(--muted); font-size: 14px; margin-bottom: 24px; line-height: 1.6; }
  
  .input-row { display: flex; gap: 12px; }
  
  .url-input { flex: 1; background: rgba(15, 23, 42, 0.8); border: 1px solid var(--border);
               border-radius: 8px; color: var(--text); font-family: 'Fira Code', monospace;
               font-size: 14px; padding: 12px 16px; outline: none; transition: all 0.2s; }
  
  .url-input:focus { border-color: var(--border-focus); box-shadow: 0 0 12px var(--accent-glow); }
  
  .btn { padding: 12px 28px; border-radius: 8px; border: none; cursor: pointer;
         font-size: 14px; font-weight: 600; font-family: 'Inter', sans-serif;
         transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
         display: inline-flex; align-items: center; justify-content: center; gap: 8px; }
  
  .btn:hover { opacity: .9; }
  
  .btn-primary { background: linear-gradient(135deg, #3b82f6 0%, #6366f1 100%); color: #ffffff;
                 box-shadow: 0 4px 14px rgba(99, 102, 241, 0.3); }
  
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(99, 102, 241, 0.5); }
  
  .btn-primary:active { transform: translateY(0); }
  
  .btn-sm { padding: 8px 16px; font-size: 12px; }
  
  .btn-ghost { background: rgba(30, 41, 59, 0.5); color: var(--text); border: 1px solid var(--border); }
  
  .btn-ghost:hover { background: rgba(30, 41, 59, 0.8); border-color: var(--border-focus); }

  /* ── progress panel ── */
  .progress-panel { display: none; margin-top: 32px; border-top: 1px solid var(--border); padding-top: 24px; }
  
  .progress-panel.show { display: block; animation: fadeIn 0.4s ease-out; }
  
  .prog-bar-wrap { background: rgba(30, 41, 59, 0.5); border-radius: 6px;
                   height: 8px; margin-bottom: 24px; overflow: hidden; }
  
  .prog-bar { height: 100%; background: linear-gradient(90deg, #3b82f6 0%, #8b5cf6 100%);
              border-radius: 6px; transition: width .4s cubic-bezier(0.4, 0, 0.2, 1); width: 0%; }
  
  .steps-list { list-style: none; display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
  
  .step { display: flex; align-items: center; gap: 12px; color: var(--muted);
          font-size: 13.5px; font-weight: 500; transition: color 0.3s; }
  
  .step.active { color: var(--text); }
  
  .step.done   { color: var(--green); }
  
  .step.error  { color: var(--red); }
  
  .dot { width: 10px; height: 10px; border-radius: 50%; background: rgba(148, 163, 184, 0.2);
         flex-shrink: 0; transition: all 0.3s; }
  
  .step.active .dot { background: var(--accent); box-shadow: 0 0 10px var(--accent); animation: pulse 1.5s infinite; }
  
  .step.done   .dot { background: var(--green); box-shadow: 0 0 8px rgba(16, 185, 129, 0.4); }
  
  .step.error  .dot { background: var(--red); box-shadow: 0 0 8px rgba(239, 68, 68, 0.4); }
  
  @keyframes pulse { 0%,100%{transform:scale(1);opacity:1} 50%{transform:scale(1.3);opacity:.5} }
  @keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }

  /* ── result toast ── */
  .toast { display: none; position: fixed; bottom: 32px; right: 32px;
           background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(16px);
           border: 1px solid var(--border); border-radius: 12px;
           padding: 20px 24px; min-width: 340px; max-width: 440px;
           box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5); z-index: 9999; }
  
  .toast.show { display: block; animation: slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
  
  @keyframes slideUp { from{transform:translateY(24px) scale(0.96);opacity:0} to{transform:translateY(0) scale(1);opacity:1} }
  
  .toast-header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  
  .toast-icon { font-size: 20px; }
  
  .toast-title { font-family: 'Outfit', sans-serif; font-weight: 700; font-size: 15px; }
  
  .toast-body { color: var(--muted); font-size: 13px; line-height: 1.6; }
  
  .toast-actions { margin-top: 16px; display: flex; gap: 8px; }
  
  .toast-close { position: absolute; top: 12px; right: 16px;
                 cursor: pointer; color: var(--muted); font-size: 20px; transition: color 0.2s; }
  
  .toast-close:hover { color: var(--text); }

  /* ── table ── */
  .section-title { font-family: 'Outfit', sans-serif; font-size: 20px; font-weight: 700; margin-bottom: 24px; color: var(--text); }
  
  .table-wrap { background: var(--surface); backdrop-filter: blur(12px);
                border: 1px solid var(--border); border-radius: 12px; overflow: hidden;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2); }
  
  table { width: 100%; border-collapse: collapse; }
  
  th { background: rgba(15, 23, 42, 0.8); color: var(--muted); font-size: 11px;
       font-weight: 700; text-transform: uppercase; letter-spacing: 1px;
       padding: 14px 20px; text-align: left; border-bottom: 1px solid var(--border); }
  
  td { padding: 16px 20px; border-bottom: 1px solid rgba(59, 130, 246, 0.08);
       font-size: 13.5px; vertical-align: middle; }
  
  tr:last-child td { border-bottom: none; }
  
  tr:hover td { background: rgba(30, 41, 59, 0.2); }
  
  .badge { display: inline-flex; align-items: center; padding: 3px 10px;
           border-radius: 20px; font-size: 11px; font-weight: 700;
           text-transform: uppercase; letter-spacing: .5px; }
  
  .badge-critical { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.3); }
  
  .badge-high     { background: rgba(249, 115, 22, 0.15); color: var(--orange); border: 1px solid rgba(249, 115, 22, 0.3); }
  
  .badge-medium   { background: rgba(245, 158, 11, 0.15); color: var(--yellow); border: 1px solid rgba(245, 158, 11, 0.3); }
  
  .badge-low, .badge-info { background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); }
  
  .badge-unknown  { background: rgba(148, 163, 184, 0.15); color: var(--muted); border: 1px solid rgba(148, 163, 184, 0.3); }
  
  .url-cell { max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: 'Fira Code', monospace; color: #cbd5e1; }
  
  .empty-state { text-align: center; padding: 64px 24px; color: var(--muted); }
  
  .empty-state .icon { font-size: 48px; margin-bottom: 16px; opacity: 0.6; }

  /* ── pages ── */
  .page { display: none; }
  
  .page.active { display: block; }
</style>
</head>
<body>
<div class="layout">

  <!-- topbar -->
  <header class="topbar">
    <div class="logo-wrap">
      <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #3b82f6;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
      <span class="logo">WIDIRS</span>
    </div>
    <span class="subtitle">Web Defacement Investigation & Response System</span>
  </header>

  <!-- sidebar -->
  <nav class="sidebar">
    <div class="sidebar-label">Navigation</div>
    <div class="sidebar-item active" onclick="showPage('scan',this)">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="sidebar-icon"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      <span>New Scan</span>
    </div>
    <div class="sidebar-item" onclick="showPage('history',this)">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="sidebar-icon"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>
      <span>Scan History</span>
    </div>
  </nav>

  <!-- main -->
  <main class="main">

    <!-- scan page -->
    <div id="page-scan" class="page active">
      <div class="scan-card">
        <h2>Scan a Website</h2>
        <p>Enter a URL to start a full defacement analysis. The WIDIRS automated incident pipeline will scan, analyze, extract IOCs, enrich them, and generate a forensic report.</p>
        <div class="input-row">
          <input id="urlInput" class="url-input" type="url"
                 placeholder="https://example.com"
                 onkeydown="if(event.key==='Enter') startScan()">
          <button class="btn btn-primary" onclick="startScan()" id="scanBtn">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <span>Scan</span>
          </button>
        </div>
        <div class="progress-panel" id="progressPanel">
          <div class="prog-bar-wrap"><div class="prog-bar" id="progBar"></div></div>
          <ul class="steps-list" id="stepsList"></ul>
        </div>
      </div>
    </div>

    <!-- history page -->
    <div id="page-history" class="page">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px">
        <div class="section-title" style="margin:0">Scan History</div>
        <button class="btn btn-ghost btn-sm" onclick="loadHistory()">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px;"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path></svg>
          <span>Refresh</span>
        </button>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>URL</th><th>Threat Type</th><th>Severity</th>
              <th>Risk</th><th>Date</th><th>Report</th>
            </tr>
          </thead>
          <tbody id="historyBody">
            <tr><td colspan="6" class="empty-state">
              <div class="icon">📭</div>Loading…
            </td></tr>
          </tbody>
        </table>
      </div>
    </div>

  </main>
</div>

<!-- result toast -->
<div class="toast" id="toast">
  <span class="toast-close" onclick="closeToast()">×</span>
  <div class="toast-header">
    <span class="toast-icon" id="toastIcon"></span>
    <span class="toast-title" id="toastTitle"></span>
  </div>
  <div class="toast-body" id="toastBody"></div>
  <div class="toast-actions" id="toastActions"></div>
</div>

<script>
// ── page routing ──────────────────────────────────────────────────────────────
function showPage(name, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar-item').forEach(s => s.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  if (el) el.classList.add('active');
  if (name === 'history') loadHistory();
}

// ── scan ──────────────────────────────────────────────────────────────────────
const STEPS = [
  {key:'scan',            label:'Scanning website'},
  {key:'change-detection',label:'Detecting changes'},
  {key:'quick-filter',    label:'Applying filters'},
  {key:'ai-classification',label:'AI threat classification'},
  {key:'ioc-extraction',  label:'Extracting IOCs'},
  {key:'threat-intel',    label:'Threat intelligence lookup'},
  {key:'attribution',     label:'Attribution analysis'},
  {key:'build-incident',  label:'Building incident record'},
  {key:'alert',           label:'Dispatching alerts'},
  {key:'report',          label:'Generating report'},
];

let currentStepIndex = -1;

function renderSteps() {
  const list = document.getElementById('stepsList');
  list.innerHTML = STEPS.map((s,i) =>
    `<li class="step" id="step-${s.key}">
       <span class="dot"></span>${s.label}
     </li>`).join('');
}

function setStep(key) {
  const idx = STEPS.findIndex(s => s.key === key);
  // mark previous steps done
  STEPS.forEach((s, i) => {
    const el = document.getElementById('step-' + s.key);
    if (!el) return;
    el.className = 'step' + (i < idx ? ' done' : i === idx ? ' active' : '');
  });
  currentStepIndex = idx;
}

function startScan() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) { alert('Please enter a URL'); return; }

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('scanBtn').textContent = 'Scanning…';
  document.getElementById('progBar').style.width = '0%';
  currentStepIndex = -1;
  renderSteps();
  document.getElementById('progressPanel').classList.add('show');
  closeToast();

  fetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({url})
  })
  .then(r => r.json())
  .then(({scan_id, error}) => {
    if (error) { showError(error); return; }
    listenToScan(scan_id);
  })
  .catch(e => showError(e.message));
}

function listenToScan(scanId) {
  const es = new EventSource('/api/scan/' + scanId + '/stream');
  es.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.event === 'ping') return;

    if (msg.event === 'status') {
      setStep(msg.data.step);
    }
    if (msg.event === 'progress') {
      document.getElementById('progBar').style.width = msg.data.pct + '%';
    }
    if (msg.event === 'done') {
      es.close();
      document.getElementById('progBar').style.width = '100%';
      // mark all steps done
      STEPS.forEach(s => {
        const el = document.getElementById('step-' + s.key);
        if (el) el.className = 'step done';
      });
      document.getElementById('scanBtn').disabled = false;
      document.getElementById('scanBtn').textContent = 'Scan';
      showDone(msg.data);
    }
    if (msg.event === 'error') {
      es.close();
      document.getElementById('scanBtn').disabled = false;
      document.getElementById('scanBtn').textContent = 'Scan';
      showError(msg.data.message);
    }
  };
  es.onerror = () => { es.close(); };
}

// ── toast ─────────────────────────────────────────────────────────────────────
function showDone(data) {
  const isIncident = data.status === 'incident_processed';
  const icon = isIncident ? '🚨' : '✅';
  const title = isIncident ? 'Incident Detected!' : 'Scan Complete';
  const statusLabels = {
    no_change: 'No changes detected',
    below_threshold: 'Changes below threshold',
    false_positive: 'False positive',
    baseline_set: 'Baseline established',
    incident_processed: 'Defacement detected',
  };
  const body = `${statusLabels[data.status] || data.status} · ${data.duration}s`;

  document.getElementById('toastIcon').textContent = icon;
  document.getElementById('toastTitle').textContent = title;
  document.getElementById('toastBody').textContent = body;

  const actions = document.getElementById('toastActions');
  actions.innerHTML = '';
  if (data.report_url) {
    const btn = document.createElement('a');
    btn.href = data.report_url;
    btn.target = '_blank';
    btn.className = 'btn btn-primary btn-sm';
    btn.textContent = '📄 View Report';
    actions.appendChild(btn);
  }
  document.getElementById('toast').classList.add('show');
}

function showError(msg) {
  document.getElementById('toastIcon').textContent = '❌';
  document.getElementById('toastTitle').textContent = 'Scan Failed';
  document.getElementById('toastBody').textContent = msg;
  document.getElementById('toastActions').innerHTML = '';
  document.getElementById('toast').classList.add('show');
}

function closeToast() {
  document.getElementById('toast').classList.remove('show');
}

// ── history ───────────────────────────────────────────────────────────────────
function loadHistory() {
  fetch('/api/scans').then(r=>r.json()).then(rows => {
    const tbody = document.getElementById('historyBody');
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state">
        <div class="icon">📭</div>No scans yet. Run your first scan above.</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.map(r => {
      const sev = r.severity || 'unknown';
      const tt  = (r.threat_type||'unknown').replace(/_/g,' ');
      const date = r.created_at ? r.created_at.slice(0,16).replace('T',' ') : '—';
      const risk = r.risk_score != null ? Math.round(r.risk_score) : '—';
      const reportBtn = r.report_url
        ? `<a href="${r.report_url}" target="_blank"
              class="btn btn-ghost btn-sm">📄 View</a>`
        : `<span style="color:var(--muted)">—</span>`;
      return `<tr>
        <td><div class="url-cell" title="${r.url}">${r.url}</div></td>
        <td style="text-transform:capitalize">${tt}</td>
        <td><span class="badge badge-${sev}">${sev}</span></td>
        <td>${risk}</td>
        <td style="color:var(--muted)">${date}</td>
        <td>${reportBtn}</td>
      </tr>`;
    }).join('');
  });
}
</script>
</body>
</html>"""


@app.get("/")
def index():
    return render_template_string(DASHBOARD_HTML)


if __name__ == "__main__":
    print("\n  WIDIRS Dashboard  ->  http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
