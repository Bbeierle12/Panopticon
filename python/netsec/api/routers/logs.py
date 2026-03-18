"""Logs API — tail the server log file and stream events."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)

router = APIRouter()

_LOG_FILE = Path(__file__).resolve().parents[3] / "panopticon.log"


def _tail_file(path: Path, lines: int, offset: int = 0) -> list[str]:
    """Read the last N lines from a file efficiently, with optional offset."""
    if not path.exists():
        return []

    # Read from end of file
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        if file_size == 0:
            return []

        # Read in chunks from the end
        chunk_size = 8192
        buf = b""
        pos = file_size
        all_lines: list[str] = []

        while pos > 0 and len(all_lines) < lines + offset + 1:
            read_size = min(chunk_size, pos)
            pos -= read_size
            f.seek(pos)
            buf = f.read(read_size) + buf
            all_lines = buf.decode("utf-8", errors="replace").splitlines()

    # Apply offset and limit
    if offset > 0:
        return all_lines[-(lines + offset):-offset]
    return all_lines[-lines:]


@router.get("/file")
async def get_log_file(
    lines: int = Query(default=100, ge=1, le=5000, description="Number of lines to return"),
    offset: int = Query(default=0, ge=0, description="Skip this many lines from the end"),
) -> dict:
    """Tail the panopticon.log file."""
    logger.debug("Log file tail requested: lines=%d offset=%d", lines, offset)

    log_lines = _tail_file(_LOG_FILE, lines, offset)

    return {
        "file": str(_LOG_FILE),
        "exists": _LOG_FILE.exists(),
        "total_lines": len(log_lines),
        "lines": log_lines,
    }


@router.get("/file/info")
async def get_log_info() -> dict:
    """Get log file metadata."""
    if not _LOG_FILE.exists():
        return {"exists": False, "path": str(_LOG_FILE)}

    stat = _LOG_FILE.stat()
    return {
        "exists": True,
        "path": str(_LOG_FILE),
        "size_bytes": stat.st_size,
        "modified": stat.st_mtime,
    }
