"""Hub aggregation — single endpoint powering the navigation dashboard."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsec import __version__
from netsec.models.alert import Alert
from netsec.models.device import Device
from netsec.models.scan import Scan
from netsec.models.vulnerability import Vulnerability
from netsec.db.session import get_session

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/status")
async def get_hub_status(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Aggregated status for the hub dashboard — one fetch powers all 8 cards."""
    logger.info("Hub status requested")

    event_bus = request.app.state.event_bus
    registry = request.app.state.adapter_registry
    scheduler = request.app.state.scheduler

    # Count queries
    async def count_table(model):
        result = await session.execute(select(func.count()).select_from(model))
        return result.scalar() or 0

    # Run all queries concurrently
    (
        alert_count,
        device_count,
        scan_count,
        vuln_count,
        tools_health,
    ) = await asyncio.gather(
        count_table(Alert),
        count_table(Device),
        count_table(Scan),
        count_table(Vulnerability),
        registry.health_check_all(),
    )

    # Scheduler jobs
    jobs = []
    if scheduler and hasattr(scheduler, 'list_jobs'):
        jobs = scheduler.list_jobs()

    # Adapter summary
    adapters = []
    for name, adapter in registry._adapters.items():
        adapters.append({
            "name": name,
            "display_name": getattr(adapter, 'display_name', name),
            "status": tools_health.get(name, 'unknown')
            if not hasattr(tools_health.get(name), 'value')
            else tools_health[name].value,
        })

    logger.info(
        "Hub status served: alerts=%d devices=%d scans=%d vulns=%d tools=%d jobs=%d",
        alert_count, device_count, scan_count, vuln_count, len(adapters), len(jobs),
    )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "health": {
            "status": "healthy",
            "version": __version__,
        },
        "counts": {
            "alerts": alert_count,
            "devices": device_count,
            "scans": scan_count,
            "vulnerabilities": vuln_count,
        },
        "tools": [
            {"name": name, "status": status.value if hasattr(status, 'value') else str(status)}
            for name, status in tools_health.items()
        ],
        "adapters": adapters,
        "scheduler_jobs": jobs,
        "ws_clients": getattr(event_bus, '_ws_client_count', 0),
    }
