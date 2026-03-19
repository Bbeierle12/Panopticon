"""In-process async event bus using asyncio.Queue."""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable, Coroutine
from uuid import uuid4

logger = logging.getLogger(__name__)

EventHandler = Callable[["Event"], Coroutine[Any, Any, None]]


class EventType(StrEnum):
    # Scan events
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    # Device events
    DEVICE_DISCOVERED = "device.discovered"
    DEVICE_UPDATED = "device.updated"
    DEVICE_OFFLINE = "device.offline"
    # Alert events
    ALERT_CREATED = "alert.created"
    ALERT_UPDATED = "alert.updated"
    ALERT_RESOLVED = "alert.resolved"
    # Tool events
    TOOL_ONLINE = "tool.online"
    TOOL_OFFLINE = "tool.offline"
    # Metadata events
    METADATA_EXTRACTED = "metadata.extracted"
    # Browsing metrics events
    BROWSING_DNS_QUERY = "browsing.dns_query"
    BROWSING_TLS_HANDSHAKE = "browsing.tls_handshake"
    BROWSING_SUSPICIOUS_DOMAIN = "browsing.suspicious_domain"
    BROWSING_BEACON_DETECTED = "browsing.beacon_detected"
    BROWSING_METRICS_UPDATE = "browsing.metrics_update"
    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"


@dataclass
class Event:
    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""


class EventBus:
    """Simple in-process async event bus."""

    def __init__(self, max_queue_size: int = 10_000) -> None:
        self._subscribers: dict[EventType, list[EventHandler]] = defaultdict(list)
        self._wildcard_subscribers: list[EventHandler] = []
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue_size)
        self._running = False
        self._task: asyncio.Task[None] | None = None

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Subscribe to a specific event type."""
        self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe to all events (for WebSocket forwarding, logging, etc.)."""
        self._wildcard_subscribers.append(handler)

    async def publish(self, event: Event) -> None:
        """Publish an event to the bus."""
        await self._queue.put(event)

    def publish_nowait(self, event: Event) -> None:
        """Non-blocking publish (drops if queue full)."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("Event queue full, dropping event: %s", event.type)

    async def start(self) -> None:
        """Start processing events."""
        self._running = True
        self._task = asyncio.create_task(self._process_loop())
        logger.info("EventBus started")

    async def stop(self) -> None:
        """Stop processing events."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("EventBus stopped")

    async def _process_loop(self) -> None:
        """Main event processing loop."""
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            # Dispatch to specific subscribers
            for handler in self._subscribers.get(event.type, []):
                try:
                    await handler(event)
                except Exception:
                    logger.exception("Error in event handler for %s", event.type)

            # Dispatch to wildcard subscribers
            for handler in self._wildcard_subscribers:
                try:
                    await handler(event)
                except Exception:
                    logger.exception("Error in wildcard handler for %s", event.type)
