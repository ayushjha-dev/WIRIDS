"""WIDIRS Interactive Telegram Bot.

Provides general chatbot support via Google Gemini and triggers WIDIRS scan pipeline
when sent a website URL.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import structlog
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# Insert root path to resolve project imports
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import get_settings
from database import Database
from main import run_full_incident_pipeline, PipelineError
from google import genai
from google.genai import types as genai_types

# Set up logging
logger = structlog.get_logger("telegram_bot")

# In-memory chatbot sessions: user_id -> genai Chat
_chat_sessions: Dict[int, Any] = {}
_chat_lock = asyncio.Lock()


def get_latest_diff_image() -> Optional[str]:
    """Find the most recently modified diff image in data/diffs/ (within last 60s)."""
    diff_dir = Path("data/diffs")
    if not diff_dir.is_dir():
        return None
    png_files = list(diff_dir.glob("diff_*.png"))
    if not png_files:
        return None
    png_files.sort(key=os.path.getmtime, reverse=True)
    latest_file = png_files[0]
    # Check if modified in the last 60 seconds
    if time.time() - os.path.getmtime(latest_file) < 60:
        return str(latest_file)
    return None


class TelegramProgress:
    """Mock Progress interface matching rich.progress.Progress for run_full_incident_pipeline."""

    def __init__(self, callback) -> None:
        self.callback = callback
        self.completed = 0
        self.current_step = "Starting scan..."

    def add_task(self, desc, total=10) -> int:
        return 1

    def update(self, task, description="", completed=None) -> None:
        label = description.split("·")[-1].strip() if "·" in description else description
        clean_label = re.sub(r'\[.*?\]', '', label)
        self.current_step = clean_label
        asyncio.create_task(self.callback(self.current_step, self.completed))

    def advance(self, task) -> None:
        self.completed += 1
        asyncio.create_task(self.callback(self.current_step, self.completed))


# ==================================================================
# Commands
# ==================================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send welcome message to the user."""
    welcome = (
        r"🛡️ *Welcome to WIDIRS Security Agent\!*" + "\n\n"
        r"I am your automated incident response and threat intelligence bot\." + "\n\n"
        r"*What I can do for you:*" + "\n"
        r"1️⃣ *Security Scan:* Send me any website URL \(starting with `http://` or `https://`\)\. "
        r"I will trigger the automated incident response pipeline, compare the site against its baseline, "
        r"extract IOCs, analyze threats, and deliver a full forensic report directly to you\." + "\n"
        r"2️⃣ *Security Chat:* Chat with me\! Ask general security questions, defacement queries, "
        r"malware topics, or CVE lookups, and I will answer as your personal security AI assistant\." + "\n\n"
        r"Send `/help` to see available commands\."
    )
    await update.message.reply_text(welcome, parse_mode="MarkdownV2")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send help instructions."""
    help_text = (
        r"🤖 *WIDIRS Bot Commands:*" + "\n\n"
        r"• *Send a URL* \(e\.g\. `https://example.com`\) to run an incident detection scan\." + "\n"
        r"• *Send any text message* to ask questions and chat with the security AI\." + "\n"
        r"• `/start` \- Display welcome banner" + "\n"
        r"• `/help` \- Display this help instruction manual"
    )
    await update.message.reply_text(help_text, parse_mode="MarkdownV2")


# ==================================================================
# Chat / Scan Handler
# ==================================================================

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Process incoming text message (either URL to scan or chat query)."""
    text = update.message.text.strip()
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id

    # 1. Check if the input contains a URL
    url_match = re.search(r'(https?://[^\s]+)', text)
    if url_match:
        url = url_match.group(1)
        await run_telegram_scan(url, update, context)
        return

    # 2. General Cybersecurity Chatbot Mode
    settings = get_settings()
    if not settings.google_api_key:
        await update.message.reply_text(
            "⚠️ *Gemini Chat is disabled:* GOOGLE_API_KEY is not configured in settings."
        )
        return

    # Send typing status
    await context.bot.send_chat_action(chat_id=chat_id, action="typing")

    async with _chat_lock:
        if user_id not in _chat_sessions:
            try:
                client = genai.Client(api_key=settings.google_api_key)
                _chat_sessions[user_id] = client.aio.chats.create(
                    model="gemini-3.1-flash-lite",
                    config=genai_types.GenerateContentConfig(
                        system_instruction=(
                            "You are WIDIRS-Bot, an advanced cybersecurity assistant specialized in "
                            "web defacement, malware analysis, incident response, and threat hunting. "
                            "Reply concisely, clearly, and helpful in Markdown formatting. Frame "
                            "responses from a professional cybersecurity operations center perspective."
                        )
                    )
                )
            except Exception as exc:
                logger.error("chat_session_create_failed", error=str(exc))
                await update.message.reply_text("❌ Failed to initialize AI chat session.")
                return
        chat_session = _chat_sessions[user_id]

    try:
        response = await chat_session.send_message(text)
        try:
            await update.message.reply_text(response.text, parse_mode="Markdown")
        except Exception as parse_exc:
            logger.warning("chat_markdown_parse_failed_trying_plaintext", error=str(parse_exc))
            await update.message.reply_text(response.text)
    except Exception as exc:
        logger.error("chat_send_message_failed", error=str(exc))
        async with _chat_lock:
            _chat_sessions.pop(user_id, None)
        
        err_msg = str(exc)
        if "429" in err_msg or "RESOURCE_EXHAUSTED" in err_msg or "quota" in err_msg.lower():
            await update.message.reply_text(
                "⚠️ *Gemini API Quota Exceeded:* The configured Google Gemini API key has exceeded its rate limit or daily quota (RESOURCE_EXHAUSTED). Please check/update the `GOOGLE_API_KEY` in your `.env` file."
            )
        else:
            await update.message.reply_text(
                "⚠️ *Chat Error:* Failed to get response from Gemini API. Session refreshed. Please try again."
            )


# ==================================================================
# Scan Pipeline Execution
# ==================================================================

async def run_telegram_scan(url: str, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Run WIDIRS incident response pipeline and send results."""
    chat_id = update.effective_chat.id
    settings = get_settings()
    settings.ensure_directories()

    status_msg = await update.message.reply_text(
        f"🤖 *WIDIRS Scan Pipeline* initiated...\n🌐 *Target:* `{url}`\n\n"
        f"🌐 Starting web capture... [0%]",
        parse_mode="Markdown"
    )

    async def update_progress(step_name: str, completed_value: int) -> None:
        total_steps = 10
        pct = min(int((completed_value / total_steps) * 100), 100)
        filled = int(completed_value)
        empty = total_steps - filled
        bar = "▓" * filled + "░" * empty

        step_descriptions = {
            "scan":            "🌐 Capturing HTML & screenshot...",
            "change-detection":"🔍 Running change detection...",
            "quick-filter":    "⚡ Applying thresholds...",
            "ai-classification":"🧠 Classifying threat category via Gemini...",
            "ioc-extraction":  "📋 Extracting Indicators of Compromise (IOCs)...",
            "threat-intel":    "📡 Querying VirusTotal / AbuseIPDB / URLhaus...",
            "attribution":     "🎯 Identifying threat actor attribution...",
            "build-incident":  "💾 Saving details to SQLite database...",
            "alert":           "📢 Dispatching alerts...",
            "report":          "📄 Rendering PDF & HTML forensic reports...",
        }

        msg = step_descriptions.get(step_name.lower().replace(" ", "-"), step_name)
        progress_text = (
            f"🤖 *WIDIRS Scan Pipeline* in progress...\n"
            f"🌐 *Target:* `{url}`\n\n"
            f"{msg}\n"
            f"`[{bar}]` *{pct}%*\n"
        )
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=status_msg.message_id,
                text=progress_text,
                parse_mode="Markdown"
            )
        except Exception:
            pass

    progress_handler = TelegramProgress(update_progress)

    try:
        async with Database(settings.db_path) as db:
            result = await run_full_incident_pipeline(url, settings, db, progress=progress_handler)

        # Update progress to completed
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=status_msg.message_id,
                text=fr"✅ *Scan Complete for* `{url}`\!",
                parse_mode="MarkdownV2"
            )
        except Exception:
            pass

        # Build final report summary
        summary_lines = []
        if result.status == "baseline_set":
            summary_lines.append(f"🟢 *Baseline Established Successfully*")
            summary_lines.append(f"WIDIRS has captured and stored a secure baseline snapshot for `{url}`. Subsequent scans will be compared against this baseline to check for defacements.")
        elif result.status == "no_change":
            summary_lines.append(f"🟢 *Scan Complete: No Changes Detected*")
            summary_lines.append(f"The website at `{url}` is identical to the baseline snapshot. No threat detected.")
        elif result.status == "below_threshold":
            summary_lines.append(f"ℹ️ *Scan Complete: Minor Changes (Below Alert Threshold)*")
            summary_lines.append(f"Minor changes were detected, but they fall below the configured alert sensitivity threshold.")
        elif result.status == "incident_processed":
            # Threat was detected, query detailed fields
            summary_lines.append(r"🚨 *CRITICAL ALERT: Threat/Defacement Detected\!*")
            async with Database(settings.db_path) as db:
                incident = await db.get_incident(result.db_row_id)
                iocs = await db.get_iocs_for_incident(result.db_row_id)
                
            if incident:
                summary_lines.append(f"\n*Incident Details:*")
                summary_lines.append(f"• *Threat Category:* `{incident['threat_type']}`")
                summary_lines.append(f"• *Severity:* `{incident['severity'].upper()}`")
                summary_lines.append(f"• *Risk Score:* `{int(round(incident['risk_score']))}/100`")
                summary_lines.append(f"• *IOC Count:* `{len(iocs)}`")
                summary_lines.append(f"• *Report ID:* `{incident['report_id']}`")
        else:
            summary_lines.append(f"ℹ️ *Scan Complete*")
            summary_lines.append(f"Scan status: `{result.status}`")

        summary_lines.append(f"\n⚡ *Duration:* `{result.duration_seconds}s`")
        try:
            await update.message.reply_text("\n".join(summary_lines), parse_mode="Markdown")
        except Exception as parse_exc:
            logger.warning("scan_summary_markdown_failed_trying_plaintext", error=str(parse_exc))
            await update.message.reply_text("\n".join(summary_lines))

        # Send Visual Diff Screenshot if incident processed
        if result.status == "incident_processed":
            diff_img = get_latest_diff_image()
            if diff_img and os.path.isfile(diff_img):
                try:
                    with open(diff_img, "rb") as fh:
                        await update.message.reply_photo(
                            photo=fh,
                            caption="🖼️ Bounding box diff highlights compared to baseline."
                        )
                except Exception as exc:
                    logger.warning("failed_to_send_diff_photo", error=str(exc))

        # Send reports as document attachments
        html_path, pdf_path = None, None
        if result.db_row_id:
            async with Database(settings.db_path) as db:
                cur = await db.conn.execute(
                    "SELECT html_path, pdf_path FROM reports WHERE incident_id = ?",
                    (result.db_row_id,)
                )
                row = await cur.fetchone()
                if row:
                    html_path = row["html_path"]
                    pdf_path = row["pdf_path"]

        if html_path and os.path.isfile(html_path):
            try:
                with open(html_path, "rb") as fh:
                    await update.message.reply_document(
                        document=fh,
                        filename=f"Forensic_Report_{result.incident_id}.html",
                        caption="📄 WIDIRS HTML Forensic Report with chain-of-custody signatures."
                    )
            except Exception as exc:
                logger.error("failed_to_send_html_report", error=str(exc))

        if pdf_path and os.path.isfile(pdf_path):
            try:
                with open(pdf_path, "rb") as fh:
                    await update.message.reply_document(
                        document=fh,
                        filename=f"Forensic_Report_{result.incident_id}.pdf",
                        caption="📕 WIDIRS PDF Forensic Report."
                    )
            except Exception as exc:
                logger.error("failed_to_send_pdf_report", error=str(exc))

    except PipelineError as exc:
        logger.error("telegram_scan_pipeline_error", error=str(exc))
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=status_msg.message_id,
                text=fr"❌ *Scan Pipeline Failed\!*\nFailed at step `{exc.step}`\nError: `{exc.cause}`",
                parse_mode="Markdown"
            )
        except Exception:
            pass
    except Exception as exc:
        logger.error("telegram_scan_unknown_error", error=str(exc))
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=status_msg.message_id,
                text=fr"❌ *Scan Failed\!* \nError: `{exc}`",
                parse_mode="Markdown"
            )
        except Exception:
            pass


# ==================================================================
# Application Entry Point
# ==================================================================

def run_bot() -> None:
    """Start the Telegram chatbot listener."""
    settings = get_settings()
    if not settings.telegram_bot_token:
        print("CRITICAL ERROR: TELEGRAM_BOT_TOKEN is not configured in your settings/.env file.")
        sys.exit(1)

    print("[*] Launching WIDIRS Telegram Bot...")
    print("Press Ctrl+C to stop.")

    app = ApplicationBuilder().token(settings.telegram_bot_token).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    app.run_polling()


if __name__ == "__main__":
    run_bot()
