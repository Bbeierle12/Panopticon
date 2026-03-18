"""Configuration API — read and write platform settings."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body

import tomli_w

from netsec.core.config import get_settings, load_settings, _deep_merge

logger = logging.getLogger(__name__)

router = APIRouter()

_CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"
_SENSITIVE_PATTERN = re.compile(r"(key|secret|password|token)", re.IGNORECASE)


def _mask_sensitive(data: dict, path: str = "") -> dict:
    """Recursively mask sensitive values like API keys."""
    masked = {}
    for k, v in data.items():
        full_key = f"{path}.{k}" if path else k
        if isinstance(v, dict):
            masked[k] = _mask_sensitive(v, full_key)
        elif _SENSITIVE_PATTERN.search(k) and isinstance(v, str) and v:
            masked[k] = "***"
        else:
            masked[k] = v
    return masked


@router.get("/")
async def get_config() -> dict:
    """Return current settings with sensitive fields masked."""
    logger.info("Configuration read requested")
    settings = get_settings()
    data = settings.model_dump()
    return {
        "config": _mask_sensitive(data),
        "source": {
            "default": str(_CONFIG_DIR / "default.toml"),
            "local": str(_CONFIG_DIR / "local.toml"),
            "local_exists": (_CONFIG_DIR / "local.toml").exists(),
        },
    }


@router.get("/raw")
async def get_config_raw() -> dict:
    """Return raw TOML text of both config files."""
    logger.info("Raw configuration read requested")
    default_text = ""
    local_text = ""

    default_path = _CONFIG_DIR / "default.toml"
    if default_path.exists():
        default_text = default_path.read_text()

    local_path = _CONFIG_DIR / "local.toml"
    if local_path.exists():
        local_text = local_path.read_text()

    return {
        "default_toml": default_text,
        "local_toml": local_text,
    }


@router.put("/")
async def update_config(overrides: dict[str, Any] = Body(...)) -> dict:
    """Write overrides to local.toml (deep-merged). Restart required for some settings."""
    logger.warning("Configuration update requested: %s", list(overrides.keys()))

    local_path = _CONFIG_DIR / "local.toml"
    existing: dict[str, Any] = {}

    if local_path.exists():
        import tomllib
        with open(local_path, "rb") as f:
            existing = tomllib.load(f)

    merged = _deep_merge(existing, overrides)

    # Validate by loading through Pydantic
    from netsec.core.config import Settings
    import tomllib
    default_path = _CONFIG_DIR / "default.toml"
    base: dict[str, Any] = {}
    if default_path.exists():
        with open(default_path, "rb") as f:
            base = tomllib.load(f)
    full = _deep_merge(base, merged)
    Settings.model_validate(full)  # raises on invalid

    with open(local_path, "wb") as f:
        tomli_w.dump(merged, f)

    logger.info("Configuration saved to %s", local_path)

    return {
        "status": "saved",
        "path": str(local_path),
        "note": "Server restart required for server/database changes to take effect.",
    }
