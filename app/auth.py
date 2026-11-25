from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence

from fastapi import Depends, Header, HTTPException, status

from app.config import ProductionConfigurationError, get_settings
from app.db import (
     get_connection,
    record_audit_event,
    seed_tenant_environment,
    utc_now_iso,
)
from app.schemas import ApiKeyMetadata, ApiScope, CreateDevTenantResponse

PBKDF2_ITERATIONS = 120_000


@dataclass(frozen=True)
class AuthenticatedCaller:
    tenant_id: str
    tenant_name: str
    key_id: str
    key_name: str
    key_prefix: str
    scopes: frozenset[str]
    is_test_fixture: bool


def _hash_api_key(raw_key: str, salt_hex: str) -> str:
    salt_bytes = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac(
        "sha256", raw_key.encode("utf-8"), salt_bytes, PBKDF2_ITERATIONS
    )
    return digest.hex()


def _extract_prefix(raw_key: str) -> Optional[str]:
    """
    Keys are formatted as:
      - Normal dev key: `mlops_dev_<8hex>.<random_secret>`
      - Test-only fixture key: `mlops_test_only_fixture_<8hex>.<deterministic_suffix>`
    Returns the prefix before the '.' separator.
    """
    if not raw_key or "." not in raw_key:
        return None
    prefix, _ = raw_key.split(".", 1)
    if not (
        prefix.startswith("mlops_dev_")
        or prefix.startswith("mlops_test_only_fixture_")
    ):
        return None
    return prefix


def create_demo_tenant_and_key(
    *,
    tenant_name: str,
    key_name: str,
    scopes: Sequence[ApiScope | str],
    db_path: Optional[Path] = None,
) -> CreateDevTenantResponse:
    settings = get_settings()
    if settings.is_production or not settings.enable_dev_key_issuance:
        raise PermissionError(
            "DEV_KEY_ISSUANCE_DISABLED: Local development tenant/key creation is disabled in this environment."
        )

    tenant_id = f"tenant_{secrets.token_hex(6)}"
    conn = get_connection(db_path)
    try:
        seeded_incidents = seed_tenant_environment(
            conn,
            tenant_id=tenant_id,
            tenant_name=tenant_name.strip(),
            environment=settings.app_env,
        )
    finally:
        conn.close()

    raw_key, metadata = issue_api_key(
        tenant_id=tenant_id,
        key_name=key_name,
        scopes=scopes,
        db_path=db_path,
    )

    record_audit_event(
        event_type="DEV_TENANT_CREATED",
        actor=f"tenant-admin@{tenant_id}",
        tenant_id=tenant_id,
        summary=f"Created local demo tenant `{tenant_id}` ({tenant_name}) and issued initial key `{metadata.key_id}` (prefix `{metadata.key_prefix}`).",
        details={
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "key_id": metadata.key_id,
            "key_prefix": metadata.key_prefix,
            "scopes": metadata.scopes,
            "seeded_incidents_count": len(seeded_incidents),
        },
        db_path=db_path,
    )

    return CreateDevTenantResponse(
        tenant_id=tenant_id,
        tenant_name=tenant_name.strip(),
        environment=settings.app_env,
        api_key=raw_key,
        key_metadata=metadata,
        seeded_incidents=seeded_incidents,
    )


def issue_api_key(
    *,
    tenant_id: str,
    key_name: str,
    scopes: Sequence[ApiScope | str],
    db_path: Optional[Path] = None,
) -> tuple[str, ApiKeyMetadata]:
    settings = get_settings()
    if settings.is_production or not settings.enable_dev_key_issuance:
        raise PermissionError(
            "DEV_KEY_ISSUANCE_DISABLED: Development API key issuance is not permitted in this environment."
        )

    key_id = f"key_{secrets.token_hex(6)}"
    prefix_token = secrets.token_hex(4)
    key_prefix = f"mlops_dev_{prefix_token}"
    secret_part = secrets.token_urlsafe(32)
    raw_key = f"{key_prefix}.{secret_part}"

    salt_hex = secrets.token_hex(16)
    key_hash = _hash_api_key(raw_key, salt_hex)
    scope_list = sorted({s.value if isinstance(s, ApiScope) else str(s) for s in scopes})
    now = utc_now_iso()

    conn = get_connection(db_path)
    try:
        tenant_row = conn.execute(
            "SELECT tenant_id FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        if not tenant_row:
            raise ValueError(f"Tenant `{tenant_id}` does not exist.")

        conn.execute(
            """INSERT INTO api_keys
               (key_id, tenant_id, key_name, key_prefix, key_salt, key_hash, scopes_json,
                is_test_fixture, status, created_at, revoked_at, last_used_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'ACTIVE', ?, NULL, NULL)""",
            (
                key_id,
                tenant_id,
                key_name.strip(),
                key_prefix,
                salt_hex,
                key_hash,
                json.dumps(scope_list),
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    metadata = ApiKeyMetadata(
        key_id=key_id,
        tenant_id=tenant_id,
        key_name=key_name.strip(),
        key_prefix=key_prefix,
        scopes=scope_list,
        status="ACTIVE",
        is_test_fixture=False,
        created_at=now,
    )
    return raw_key, metadata


def provision_test_only_fixture_key(
    *,
    fixture_tag: str,
    tenant_id: str,
    tenant_name: str = "Automated Test Fixture Tenant",
    scopes: Sequence[ApiScope | str] = (
        ApiScope.ANALYSES_READ,
        ApiScope.ANALYSES_WRITE,
        ApiScope.ACTIONS_APPROVE,
        ApiScope.AUDIT_READ,
        ApiScope.KEYS_MANAGE,
    ),
    db_path: Optional[Path] = None,
) -> tuple[str, ApiKeyMetadata]:
    """
    Deterministic fixture credential helper strictly for automated tests.
    Refuses to run unless MLOPS_ENV=test and MLOPS_ENABLE_TEST_FIXTURES=true.
    """
    settings = get_settings()
    if settings.is_production or settings.app_env != "test" or not settings.enable_test_fixtures:
        raise PermissionError(
            "TEST_FIXTURES_FORBIDDEN: Deterministic test fixture credentials are only allowed when "
            "MLOPS_ENV=test and MLOPS_ENABLE_TEST_FIXTURES=true."
        )

    tag_clean = "".join(c for c in fixture_tag.lower() if c.isalnum())[:8].ljust(8, "0")
    key_id = f"key_test_fixture_{tag_clean}"
    key_prefix = f"mlops_test_only_fixture_{tag_clean}"
    # Unmistakably test-only deterministic token derived from fixture_tag
    deterministic_suffix = hashlib.sha256(
        f"TEST_ONLY_DO_NOT_USE_IN_PROD:{tenant_id}:{fixture_tag}".encode("utf-8")
    ).hexdigest()[:32]
    raw_key = f"{key_prefix}.TEST_ONLY_{deterministic_suffix}"

    salt_hex = hashlib.sha256(f"salt:{key_prefix}".encode("utf-8")).hexdigest()[:32]
    key_hash = _hash_api_key(raw_key, salt_hex)
    scope_list = sorted({s.value if isinstance(s, ApiScope) else str(s) for s in scopes})
    now = utc_now_iso()

    conn = get_connection(db_path)
    try:
        seed_tenant_environment(
            conn, tenant_id=tenant_id, tenant_name=tenant_name, environment="test"
        )
        conn.execute(
            """INSERT OR REPLACE INTO api_keys
               (key_id, tenant_id, key_name, key_prefix, key_salt, key_hash, scopes_json,
                is_test_fixture, status, created_at, revoked_at, last_used_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'ACTIVE', ?, NULL, NULL)""",
            (
                key_id,
                tenant_id,
                f"TEST_ONLY_FIXTURE ({fixture_tag})",
                key_prefix,
                salt_hex,
                key_hash,
                json.dumps(scope_list),
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return raw_key, ApiKeyMetadata(
        key_id=key_id,
        tenant_id=tenant_id,
        key_name=f"TEST_ONLY_FIXTURE ({fixture_tag})",
        key_prefix=key_prefix,
        scopes=scope_list,
        status="ACTIVE",
        is_test_fixture=True,
        created_at=now,
    )


def revoke_api_key(
    *,
    tenant_id: str,
    key_id: str,
    actor: str,
    db_path: Optional[Path] = None,
) -> ApiKeyMetadata:
    now = utc_now_iso()
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        if not row:
            raise LookupError(f"API key `{key_id}` not found.")
        if row["tenant_id"] != tenant_id:
            raise PermissionError(
                f"TENANT_ISOLATION_VIOLATION: Key `{key_id}` does not belong to caller tenant."
            )
        conn.execute(
            "UPDATE api_keys SET status = 'REVOKED', revoked_at = ? WHERE key_id = ? AND tenant_id = ?",
            (now, key_id, tenant_id),
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM api_keys WHERE key_id = ?", (key_id,)
        ).fetchone()
    finally:
        conn.close()

    record_audit_event(
        event_type="API_KEY_REVOKED",
        actor=actor,
        tenant_id=tenant_id,
        summary=f"Revoked API key `{key_id}` (prefix `{updated['key_prefix']}`).",
        details={"key_id": key_id, "key_prefix": updated["key_prefix"]},
        db_path=db_path,
    )

    return ApiKeyMetadata(
        key_id=updated["key_id"],
        tenant_id=updated["tenant_id"],
        key_name=updated["key_name"],
        key_prefix=updated["key_prefix"],
        scopes=json.loads(updated["scopes_json"]),
        status=updated["status"],
        is_test_fixture=bool(updated["is_test_fixture"]),
        created_at=updated["created_at"],
        revoked_at=updated["revoked_at"],
        last_used_at=updated["last_used_at"],
    )


def list_tenant_api_keys(
    tenant_id: str, db_path: Optional[Path] = None
) -> List[ApiKeyMetadata]:
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
        return [
            ApiKeyMetadata(
                key_id=r["key_id"],
                tenant_id=r["tenant_id"],
                key_name=r["key_name"],
                key_prefix=r["key_prefix"],
                scopes=json.loads(r["scopes_json"]),
                status=r["status"],
                is_test_fixture=bool(r["is_test_fixture"]),
                created_at=r["created_at"],
                revoked_at=r["revoked_at"],
                last_used_at=r["last_used_at"],
            )
            for r in rows
        ]
    finally:
        conn.close()


def authenticate_raw_api_key(
    raw_key: str, db_path: Optional[Path] = None
) -> AuthenticatedCaller:
    settings = get_settings()
    if settings.is_production:
        raise PermissionError(
            "PRODUCTION_AUTH_BLOCK: Local development API keys are rejected in production."
        )

    prefix = _extract_prefix(raw_key)
    if not prefix:
        raise PermissionError("INVALID_API_KEY_FORMAT: Malformed or unrecognized API key.")

    if prefix.startswith("mlops_test_only_fixture_") and (
        settings.app_env != "test" or not settings.enable_test_fixtures
    ):
        raise PermissionError(
            "TEST_FIXTURE_KEY_REJECTED: Test-only fixture credentials are rejected outside test mode."
        )

    conn = get_connection(db_path)
    try:
        row = conn.execute(
            """SELECT k.*, t.name as tenant_name, t.status as tenant_status,
                      t.rate_limit_per_minute as rate_limit
               FROM api_keys k
               JOIN tenants t ON k.tenant_id = t.tenant_id
               WHERE k.key_prefix = ?""",
            (prefix,),
        ).fetchone()
        if not row:
            raise PermissionError("INVALID_API_KEY: Unknown API key.")

        expected_hash = row["key_hash"]
        computed_hash = _hash_api_key(raw_key, row["key_salt"])
        if not hmac.compare_digest(expected_hash, computed_hash):
            raise PermissionError("INVALID_API_KEY: Key verification failed.")

        if row["status"] != "ACTIVE":
            raise PermissionError(
                f"API_KEY_REVOKED: Key `{row['key_id']}` (prefix `{prefix}`) has been revoked."
            )

        if row["tenant_status"] != "ACTIVE":
            raise PermissionError(f"TENANT_SUSPENDED: Tenant `{row['tenant_id']}` is not active.")

        # Enforce per-tenant rate limit per minute
        minute_bucket = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
        conn.execute(
            """INSERT INTO tenant_rate_windows (tenant_id, minute_bucket, request_count)
               VALUES (?, ?, 1)
               ON CONFLICT(tenant_id, minute_bucket)
               DO UPDATE SET request_count = request_count + 1""",
            (row["tenant_id"], minute_bucket),
        )
        rate_row = conn.execute(
            "SELECT request_count FROM tenant_rate_windows WHERE tenant_id = ? AND minute_bucket = ?",
            (row["tenant_id"], minute_bucket),
        ).fetchone()
        if rate_row and rate_row["request_count"] > row["rate_limit"]:
            conn.commit()
            raise BufferError(
                f"RATE_LIMIT_EXCEEDED: Tenant `{row['tenant_id']}` exceeded {row['rate_limit']} requests/minute."
            )

        now = utc_now_iso()
        conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?",
            (now, row["key_id"]),
        )
        conn.commit()

        scopes = frozenset(json.loads(row["scopes_json"]))
        return AuthenticatedCaller(
            tenant_id=row["tenant_id"],
            tenant_name=row["tenant_name"],
            key_id=row["key_id"],
            key_name=row["key_name"],
            key_prefix=row["key_prefix"],
            scopes=scopes,
            is_test_fixture=bool(row["is_test_fixture"]),
        )
    finally:
        conn.close()


def _extract_header_token(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    if authorization:
        parts = authorization.strip().split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
    if x_api_key:
        return x_api_key.strip()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing development API key. Supply `Authorization: Bearer <DEV_API_KEY>` or `X-API-Key: <DEV_API_KEY>`.",
    )


def require_scopes(*required_scopes: ApiScope | str) -> Callable[..., AuthenticatedCaller]:
    req_set = {s.value if isinstance(s, ApiScope) else str(s) for s in required_scopes}

    def dependency(raw_token: str = Depends(_extract_header_token)) -> AuthenticatedCaller:
        try:
            caller = authenticate_raw_api_key(raw_token)
        except ProductionConfigurationError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            ) from exc
        except BufferError as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)
            ) from exc
        except PermissionError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
            ) from exc

        missing = req_set - caller.scopes
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"INSUFFICIENT_SCOPE: Key `{caller.key_prefix}` lacks required scope(s): {sorted(missing)}.",
            )
        return caller

    return dependency

