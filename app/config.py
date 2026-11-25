from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


class ProductionConfigurationError(RuntimeError):
    """Raised when unsafe development/mock settings are active in a production environment."""


class OutboundNetworkBlockedError(RuntimeError):
    """Raised when an outbound network request is attempted while running in mock mode."""


def _parse_bool(val: str, default: bool = False) -> bool:
    if val is None or val.strip() == "":
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    project_root: Path
    db_path: Path
    app_env: str
    provider_mode: str
    connector_mode: str
    enable_dev_key_issuance: bool
    enable_test_fixtures: bool
    block_outbound_in_mock: bool
    gemini_api_key: str
    gemini_model: str
    max_tool_calls_per_investigation: int
    tool_timeout_seconds: float
    max_retries: int
    max_input_chars: int
    max_request_body_bytes: int
    max_requests_per_tenant_per_minute: int
    max_analyses_per_tenant: int

    @property
    def is_production(self) -> bool:
        return self.app_env.lower().strip() in ("production", "prod")

    @property
    def is_development_or_test(self) -> bool:
        return self.app_env.lower().strip() in ("development", "dev", "test", "testing", "local")

    @property
    def active_provider(self) -> str:
        mode = self.provider_mode.lower().strip()
        if mode == "mock":
            return "mock"
        if mode == "gemini":
            return "gemini" if bool(self.gemini_api_key.strip()) else "mock"
        # auto mode
        return "gemini" if bool(self.gemini_api_key.strip()) else "mock"

    @property
    def has_gemini_key(self) -> bool:
        return bool(self.gemini_api_key.strip())


def validate_environment_safety(settings: Settings) -> None:
    """
    Enforces strict environment boundaries:
    Refuses to start or operate in production if development-key issuance,
    test fixtures, mock connector mode, or mock provider mode are enabled.
    """
    if not settings.is_production:
        return

    violations = []
    if settings.enable_dev_key_issuance:
        violations.append("MLOPS_ENABLE_DEV_KEY_ISSUANCE=true (development API key mode enabled)")
    if settings.enable_test_fixtures:
        violations.append("MLOPS_ENABLE_TEST_FIXTURES=true (test fixture credentials enabled)")
    if settings.connector_mode.lower().strip() == "mock":
        violations.append("MLOPS_CONNECTOR_MODE=mock (mock telemetry connectors enabled)")
    if settings.active_provider == "mock":
        violations.append("active_provider=mock (mock reasoning provider enabled without live credentials)")

    if violations:
        raise ProductionConfigurationError(
            "PRODUCTION_SAFETY_BLOCK: Refusing to run in production environment with unsafe development/mock settings: "
            + "; ".join(violations)
        )


def assert_no_outbound_network_in_mock(target_description: str = "external service") -> None:
    """Fails clearly and safely if an outbound network call is attempted while in mock mode."""
    settings = get_settings()
    if settings.block_outbound_in_mock and (
        settings.active_provider == "mock" or settings.connector_mode == "mock"
    ):
        raise OutboundNetworkBlockedError(
            f"OUTBOUND_NETWORK_BLOCKED_IN_MOCK_MODE: Attempted outbound network call to {target_description} "
            "while mock mode is active. No external network calls are permitted."
        )


def get_settings() -> Settings:
    raw_db = os.getenv("MLOPS_DB_PATH", "data/mlops_sandbox.db")
    db_path = Path(raw_db)
    if not db_path.is_absolute():
        db_path = PROJECT_ROOT / db_path

    app_env = os.getenv("MLOPS_ENV", "development").strip().lower()
    default_dev_keys = app_env in ("development", "dev", "test", "testing", "local")

    settings = Settings(
        project_root=PROJECT_ROOT,
        db_path=db_path,
        app_env=app_env,
        provider_mode=os.getenv("MLOPS_PROVIDER_MODE", "auto"),
        connector_mode=os.getenv("MLOPS_CONNECTOR_MODE", "mock"),
        enable_dev_key_issuance=_parse_bool(
            os.getenv("MLOPS_ENABLE_DEV_KEY_ISSUANCE", ""), default=default_dev_keys
        ),
        enable_test_fixtures=_parse_bool(
            os.getenv("MLOPS_ENABLE_TEST_FIXTURES", ""), default=False
        ),
        block_outbound_in_mock=_parse_bool(
            os.getenv("MLOPS_BLOCK_OUTBOUND_IN_MOCK", ""), default=True
        ),
        gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        max_tool_calls_per_investigation=int(
            os.getenv("MLOPS_MAX_TOOL_CALLS_PER_INVESTIGATION", "12")
        ),
        tool_timeout_seconds=float(os.getenv("MLOPS_TOOL_TIMEOUT_SECONDS", "5.0")),
        max_retries=int(os.getenv("MLOPS_MAX_RETRIES", "2")),
        max_input_chars=int(os.getenv("MLOPS_MAX_INPUT_CHARS", "4000")),
        max_request_body_bytes=int(os.getenv("MLOPS_MAX_REQUEST_BODY_BYTES", "32768")),
        max_requests_per_tenant_per_minute=int(
            os.getenv("MLOPS_MAX_REQUESTS_PER_TENANT_PER_MINUTE", "120")
        ),
        max_analyses_per_tenant=int(os.getenv("MLOPS_MAX_ANALYSES_PER_TENANT", "50")),
    )
    validate_environment_safety(settings)
    return settings
