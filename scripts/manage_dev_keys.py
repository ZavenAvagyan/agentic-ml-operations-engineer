#!/usr/bin/env python3
"""
Local Development Tenant & Fake API Key CLI
===========================================
Creates isolated demo tenants, issues cryptographically random fake development
API keys (shown once, stored as PBKDF2-HMAC-SHA256 hashes), lists key metadata,
and revokes keys.

Refuses to run if MLOPS_ENV=production.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.auth import (
    create_demo_tenant_and_key,
    issue_api_key,
    list_tenant_api_keys,
    revoke_api_key,
)
from app.db import init_db
from app.schemas import DEFAULT_DEV_SCOPES, ApiScope


def _parse_scopes(raw_scopes: str) -> list[ApiScope]:
    if not raw_scopes.strip():
        return list(DEFAULT_DEV_SCOPES)
    scopes: list[ApiScope] = []
    for item in raw_scopes.split(","):
        cleaned = item.strip()
        if cleaned:
            scopes.append(ApiScope(cleaned))
    return scopes


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage local development tenants and fake API keys for the Agentic MLOps sandbox."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create-tenant
    create_p = subparsers.add_parser(
        "create-tenant",
        help="Create a new isolated local demo tenant and issue an initial fake development API key.",
    )
    create_p.add_argument(
        "--tenant-name",
        default="Local Developer Demo Tenant",
        help="Human-readable name for the demo tenant.",
    )
    create_p.add_argument(
        "--key-name",
        default="default-dev-cli-key",
        help="Name/label for the issued development API key.",
    )
    create_p.add_argument(
        "--scopes",
        default=",".join(s.value for s in DEFAULT_DEV_SCOPES),
        help="Comma-separated scopes (e.g. analyses:read,analyses:write,actions:approve).",
    )
    create_p.add_argument(
        "--json",
        action="store_true",
        help="Emit output as JSON.",
    )

    # issue-key
    issue_p = subparsers.add_parser(
        "issue-key",
        help="Issue an additional scoped development API key for an existing tenant.",
    )
    issue_p.add_argument("--tenant-id", required=True, help="Target tenant_id.")
    issue_p.add_argument("--key-name", default="secondary-dev-key", help="Key name/label.")
    issue_p.add_argument(
        "--scopes",
        default="analyses:read,analyses:write",
        help="Comma-separated scopes.",
    )
    issue_p.add_argument("--json", action="store_true", help="Emit output as JSON.")

    # list-keys
    list_p = subparsers.add_parser(
        "list-keys",
        help="List API key metadata for a tenant (never displays raw keys or hashes).",
    )
    list_p.add_argument("--tenant-id", required=True, help="Target tenant_id.")

    # revoke-key
    revoke_p = subparsers.add_parser(
        "revoke-key",
        help="Revoke an API key within a tenant.",
    )
    revoke_p.add_argument("--tenant-id", required=True, help="Target tenant_id.")
    revoke_p.add_argument("--key-id", required=True, help="Key ID to revoke (e.g. key_...).")
    revoke_p.add_argument("--actor", default="cli-operator@sandbox.local", help="Actor identity for audit log.")

    args = parser.parse_args()
    init_db(reset=False)

    if args.command == "create-tenant":
        scopes = _parse_scopes(args.scopes)
        res = create_demo_tenant_and_key(
            tenant_name=args.tenant_name,
            key_name=args.key_name,
            scopes=scopes,
        )
        if args.json:
            print(json.dumps(res.model_dump(), indent=2))
            return
        print("=" * 78)
        print("LOCAL DEMO TENANT & FAKE DEVELOPMENT API KEY CREATED")
        print("=" * 78)
        print(f"Tenant ID    : {res.tenant_id}")
        print(f"Tenant Name  : {res.tenant_name}")
        print(f"Environment  : {res.environment}")
        print(f"Key ID       : {res.key_metadata.key_id}")
        print(f"Key Prefix   : {res.key_metadata.key_prefix}")
        print(f"Scopes       : {', '.join(res.key_metadata.scopes)}")
        print("-" * 78)
        print("ONE-TIME RAW API KEY (Save now; only PBKDF2-HMAC-SHA256 hash stored at rest):")
        print(f"\n  {res.api_key}\n")
        print("-" * 78)
        print("Notice:", res.notice)
        print("=" * 78)

    elif args.command == "issue-key":
        scopes = _parse_scopes(args.scopes)
        raw_key, meta = issue_api_key(
            tenant_id=args.tenant_id,
            key_name=args.key_name,
            scopes=scopes,
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "tenant_id": args.tenant_id,
                        "api_key": raw_key,
                        "key_metadata": meta.model_dump(),
                    },
                    indent=2,
                )
            )
            return
        print("=" * 78)
        print(f"Issued Key ID: {meta.key_id} (Tenant: {args.tenant_id})")
        print(f"Scopes       : {', '.join(meta.scopes)}")
        print(f"One-Time Key : {raw_key}")
        print("=" * 78)

    elif args.command == "list-keys":
        keys = list_tenant_api_keys(args.tenant_id)
        print(json.dumps({"tenant_id": args.tenant_id, "keys": [k.model_dump() for k in keys]}, indent=2))

    elif args.command == "revoke-key":
        meta = revoke_api_key(
            tenant_id=args.tenant_id,
            key_id=args.key_id,
            actor=args.actor,
        )
        print(json.dumps({"revoked": True, "key_metadata": meta.model_dump()}, indent=2))


if __name__ == "__main__":
    main()
