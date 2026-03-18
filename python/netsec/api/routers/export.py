"""Export API — download alerts, devices, scans, vulns as CSV or JSON."""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.models.alert import Alert
from netsec.models.device import Device
from netsec.models.scan import Scan
from netsec.models.vulnerability import Vulnerability
from netsec.db.session import get_session

logger = logging.getLogger(__name__)

router = APIRouter()

_RESOURCE_MAP = {
    "alerts": Alert,
    "devices": Device,
    "scans": Scan,
    "vulnerabilities": Vulnerability,
}


def _row_to_dict(row) -> dict:
    """Convert a SQLAlchemy model instance to a flat dict."""
    d = {}
    for col in row.__table__.columns:
        val = getattr(row, col.name)
        if isinstance(val, datetime):
            val = val.isoformat()
        elif isinstance(val, (dict, list)):
            val = json.dumps(val)
        d[col.name] = val
    return d


@router.get("/{resource}")
async def export_resource(
    resource: Literal["alerts", "devices", "scans", "vulnerabilities"],
    request: Request,
    fmt: Literal["csv", "json"] = Query(default="csv", description="Export format"),
    limit: int = Query(default=10000, ge=1, le=100000),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    """Export a resource as CSV or JSON."""
    logger.info("Export requested: resource=%s format=%s limit=%d", resource, fmt, limit)

    model = _RESOURCE_MAP[resource]
    result = await session.execute(select(model).limit(limit))
    rows = result.scalars().all()
    dicts = [_row_to_dict(r) for r in rows]

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"panopticon_{resource}_{timestamp}.{fmt}"

    logger.info("Export serving %d rows for %s as %s", len(dicts), resource, fmt)

    if fmt == "json":
        content = json.dumps(dicts, indent=2, default=str)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # CSV
    if not dicts:
        return StreamingResponse(
            iter([""]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=dicts[0].keys())
    writer.writeheader()
    writer.writerows(dicts)

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
