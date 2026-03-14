"""Health validation API endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from defensewatch.config import AppConfig

router = APIRouter(tags=["health"])

_config: AppConfig | None = None


def set_validate_config(config: AppConfig) -> None:
    global _config
    _config = config


@router.get("/api/health/validate")
async def validate():
    """Run all configuration and environment checks."""
    from defensewatch.validate import validate_config
    from defensewatch.config import load_config

    config = _config if _config is not None else load_config()
    results = await validate_config(config)

    errors = sum(1 for r in results if r["status"] == "error")
    warnings = sum(1 for r in results if r["status"] == "warning")
    ok = len(results) - errors - warnings

    overall = "error" if errors else ("warning" if warnings else "ok")

    return {
        "status": overall,
        "summary": {"total": len(results), "ok": ok, "warnings": warnings, "errors": errors},
        "checks": results,
    }
