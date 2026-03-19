"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from netsec.core.config import get_settings
from netsec.core.events import Event, EventBus, EventType
from netsec.core.logging import setup_logging
from netsec.core.scheduler import Scheduler
from netsec.db.session import init_db, close_db, get_session_context
from netsec.adapters.registry import AdapterRegistry
from netsec.api.websocket import register_ws_forwarding
from netsec.services.monitoring_service import MonitoringService
from netsec.services.browsing_service import BrowsingService
from netsec.sentinel.alerts import ingest_raw_alerts
from netsec.adapters.base import ToolStatus

_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown."""
    settings = get_settings()
    setup_logging(level=settings.logging.level, fmt=settings.logging.format)

    # Initialize database
    await init_db()

    # Start event bus
    event_bus = EventBus()
    await event_bus.start()
    app.state.event_bus = event_bus

    # Register WebSocket forwarding
    register_ws_forwarding(event_bus)

    # Discover and initialize adapters
    registry = AdapterRegistry()
    await registry.discover()
    await registry.init_all()
    app.state.adapter_registry = registry

    # Start scheduler with task handler
    scheduler = Scheduler()

    # Create shared monitoring service state for tool health tracking
    _tool_status_cache: dict[str, str] = {}

    async def task_handler(task_type: str, task_params: dict) -> None:
        """Handle scheduled tasks."""
        async with get_session_context() as session:
            if task_type == "device_availability_check":
                service = MonitoringService(session, event_bus, registry)
                service._previous_tool_status = {}  # Device check doesn't need tool state
                await service.check_device_availability(
                    offline_threshold_minutes=task_params.get("offline_threshold_minutes", 15)
                )
            elif task_type == "tool_health_check":
                service = MonitoringService(session, event_bus, registry)
                # Restore previous state for delta detection
                service._previous_tool_status = {
                    k: ToolStatus(v) for k, v in _tool_status_cache.items()
                }
                await service.check_tool_health()
                # Save current state
                _tool_status_cache.clear()
                _tool_status_cache.update({
                    k: v.value for k, v in service._previous_tool_status.items()
                })
            elif task_type == "scan":
                # For future scheduled scans
                pass
            elif task_type == "sentinel_collect":
                adapter = registry.get("sentinel")
                if adapter is not None:
                    await adapter.execute("collect", {})
            elif task_type == "sentinel_feeds":
                adapter = registry.get("sentinel")
                if adapter is not None:
                    await adapter.execute("feeds_update", {"force": False})
            elif task_type == "sentinel_vuln_scan":
                adapter = registry.get("sentinel")
                if adapter is not None:
                    await adapter.execute("vuln_scan", {"force": False, "refresh_feeds": True})
            elif task_type == "sentinel_correlate":
                adapter = registry.get("sentinel")
                if adapter is not None:
                    result = await adapter.execute(
                        "correlate",
                        {"refresh_feeds": True, "scan_vulns": True},
                    )
                    await ingest_raw_alerts(
                        session=session,
                        event_bus=event_bus,
                        alerts=list(result.get("alerts", [])),
                        source_tool="sentinel",
                    )

    scheduler.set_task_handler(task_handler)
    await scheduler.start()
    app.state.scheduler = scheduler

    # Register default monitoring jobs
    scheduler.add_job(
        name="Device Availability Monitor",
        trigger_type="interval",
        trigger_args={"minutes": 5},
        task_type="device_availability_check",
        task_params={"offline_threshold_minutes": 15},
    )
    scheduler.add_job(
        name="Tool Health Monitor",
        trigger_type="interval",
        trigger_args={"minutes": 2},
        task_type="tool_health_check",
        task_params={},
    )
    if settings.sentinel.enabled:
        scheduler.add_job(
            name="Sentinel Collection",
            trigger_type="interval",
            trigger_args={"seconds": max(settings.sentinel.collect_interval_secs, 60)},
            task_type="sentinel_collect",
            task_params={},
        )
        scheduler.add_job(
            name="Sentinel Feeds",
            trigger_type="interval",
            trigger_args={"hours": max(settings.sentinel.osint.feed_refresh_hours, 1)},
            task_type="sentinel_feeds",
            task_params={},
        )
        scheduler.add_job(
            name="Sentinel Vulnerability Scan",
            trigger_type="cron",
            trigger_args={"hour": 4, "minute": 0},
            task_type="sentinel_vuln_scan",
            task_params={},
        )
        scheduler.add_job(
            name="Sentinel Correlate",
            trigger_type="interval",
            trigger_args={"minutes": 10},
            task_type="sentinel_correlate",
            task_params={},
        )

    # Start browsing metrics service (tails Suricata eve.json)
    browsing_service = BrowsingService(event_bus)
    await browsing_service.start()
    app.state.browsing_service = browsing_service

    # Publish system startup event
    await event_bus.publish(Event(
        type=EventType.SYSTEM_STARTUP,
        source="app",
        data={"version": "0.1.0"},
    ))

    yield

    # Publish system shutdown event
    await event_bus.publish(Event(
        type=EventType.SYSTEM_SHUTDOWN,
        source="app",
        data={},
    ))

    # Shutdown
    await browsing_service.stop()
    await scheduler.stop()
    await registry.shutdown_all()
    await event_bus.stop()
    await close_db()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="NetSec Orchestrator",
        description="Security orchestration backend for network monitoring tools",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API key auth middleware (only active when auth.enabled=true)
    if settings.auth.enabled:
        from netsec.api.middleware import ApiKeyMiddleware
        app.add_middleware(ApiKeyMiddleware)

    # Register routers
    from netsec.api.routers import (
        system, tools, scans, devices, alerts,
        scheduler, vulnerabilities, traffic, ws, terminal, sentinel,
        overview, metadata, hub, config_api, logs, export, browsing,
    )
    app.include_router(hub.router, prefix="/api/hub", tags=["hub"])
    app.include_router(overview.router, prefix="/api/overview", tags=["overview"])
    app.include_router(system.router, prefix="/api/system", tags=["system"])
    app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
    app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
    app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
    app.include_router(scheduler.router, prefix="/api/scheduler", tags=["scheduler"])
    app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
    app.include_router(traffic.router, prefix="/api/traffic", tags=["traffic"])
    app.include_router(terminal.router, prefix="/api/terminal", tags=["terminal"])
    app.include_router(sentinel.router, prefix="/api/sentinel", tags=["sentinel"])
    app.include_router(metadata.router, prefix="/api/metadata", tags=["metadata"])
    app.include_router(config_api.router, prefix="/api/config", tags=["config"])
    app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
    app.include_router(export.router, prefix="/api/export", tags=["export"])
    app.include_router(browsing.router, prefix="/api/browsing", tags=["browsing"])
    app.include_router(ws.router)

    # Serve frontend SPA (must be after API routers)
    if _FRONTEND_DIR.is_dir():
        app.mount("/assets", StaticFiles(directory=_FRONTEND_DIR / "assets"), name="static")

        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request as StarletteRequest
        from starlette.responses import Response

        _API_PREFIXES = ("/api/", "/ws", "/docs", "/openapi", "/redoc")
        _index_html = _FRONTEND_DIR / "index.html"

        class SPAFallbackMiddleware(BaseHTTPMiddleware):
            """Serve index.html for non-API GET requests that don't match a route."""

            async def dispatch(self, request: StarletteRequest, call_next) -> Response:
                response = await call_next(request)
                # Only intercept 404s for GET requests to non-API paths
                if (
                    response.status_code == 404
                    and request.method == "GET"
                    and not any(request.url.path.startswith(p) for p in _API_PREFIXES)
                ):
                    return FileResponse(_index_html)
                return response

        app.add_middleware(SPAFallbackMiddleware)

    return app
