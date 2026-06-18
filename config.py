"""WIDIRS configuration.

Loads settings from environment variables / .env via pydantic-settings.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application settings. Field names map 1:1 to .env variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---------------- AI / LLM ----------------
    # Free tier: 15 requests/min, 1 million tokens/day
    # Get a key at: https://aistudio.google.com/app/apikey
    google_api_key: str = Field(default="", alias="GOOGLE_API_KEY")

    # ---------------- Threat Intelligence ----------------
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    shodan_api_key: str = Field(default="", alias="SHODAN_API_KEY")
    misp_url: str = Field(default="", alias="MISP_URL")
    misp_key: str = Field(default="", alias="MISP_KEY")

    # ---------------- Alerting: Telegram ----------------
    telegram_bot_token: str = Field(default="", alias="TELEGRAM_BOT_TOKEN")
    telegram_chat_ids: str = Field(default="", alias="TELEGRAM_CHAT_IDS")

    # ---------------- Alerting: Email ----------------
    smtp_host: str = Field(default="", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_user: str = Field(default="", alias="SMTP_USER")
    smtp_pass: str = Field(default="", alias="SMTP_PASS")
    sendgrid_api_key: str = Field(default="", alias="SENDGRID_API_KEY")
    alert_email_from: str = Field(default="", alias="ALERT_EMAIL_FROM")
    alert_email_to: str = Field(default="", alias="ALERT_EMAIL_TO")

    # ---------------- System ----------------
    snapshot_dir: Path = Field(default=Path("data/snapshots"), alias="SNAPSHOT_DIR")
    report_dir: Path = Field(default=Path("data/reports"), alias="REPORT_DIR")
    db_path: Path = Field(default=Path("data/db/widirs.db"), alias="DB_PATH")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    concurrent_scans: int = Field(default=5, ge=1, alias="CONCURRENT_SCANS")
    scan_interval: int = Field(default=300, ge=10, alias="SCAN_INTERVAL")
    ti_cache_ttl_hours: int = Field(default=24, ge=1, alias="TI_CACHE_TTL_HOURS")
    min_change_score: float = Field(default=0.10, ge=0.0, le=1.0, alias="MIN_CHANGE_SCORE")
    min_severity_to_alert: str = Field(default="medium", alias="MIN_SEVERITY_TO_ALERT")

    # ---------------- Validators ----------------
    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(allowed)}")
        return upper

    @field_validator("min_severity_to_alert")
    @classmethod
    def _validate_severity(cls, value: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        lower = value.lower()
        if lower not in allowed:
            raise ValueError(f"MIN_SEVERITY_TO_ALERT must be one of {sorted(allowed)}")
        return lower

    # ---------------- Helpers ----------------
    @staticmethod
    def _csv_to_list(value: str) -> List[str]:
        """Split a comma-separated string into a clean list, ignoring blanks."""
        if not value or not value.strip():
            return []
        return [item.strip() for item in value.split(",") if item.strip()]

    @property
    def telegram_chat_id_list(self) -> List[str]:
        return self._csv_to_list(self.telegram_chat_ids)

    @property
    def alert_email_to_list(self) -> List[str]:
        return self._csv_to_list(self.alert_email_to)

    # ---------------- Convenience properties ----------------
    @property
    def is_telegram_configured(self) -> bool:
        """True when both a bot token and at least one chat ID are set."""
        return bool(self.telegram_bot_token and self.telegram_chat_id_list)

    @property
    def is_email_configured(self) -> bool:
        """True when a transport (SMTP host or SendGrid) and a recipient are set."""
        return bool(
            (self.smtp_host or self.sendgrid_api_key) and self.alert_email_to_list
        )

    def ensure_directories(self) -> None:
        """Create data directories if they do not exist."""
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()
