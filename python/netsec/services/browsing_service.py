"""Browsing metrics service — tails Suricata eve.json, aggregates DNS/TLS/HTTP/flow data."""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import math
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netsec.core.config import get_settings
from netsec.core.events import Event, EventBus, EventType

logger = logging.getLogger(__name__)

EVE_LOG_PATH = Path("/var/log/suricata/eve.json")
MAX_RECENT_EVENTS = 200
METRICS_PUSH_INTERVAL = 5.0  # seconds
WS_THROTTLE_PER_SEC = 10
HOURLY_FLUSH_INTERVAL = 3600
BEACON_MIN_CONNECTIONS = 10
BEACON_JITTER_THRESHOLD = 0.15  # std_dev/mean < this = beacon
ENTROPY_THRESHOLD = 3.5


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _extract_sld(domain: str) -> str:
    """Extract second-level domain label for entropy scoring."""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain


class BrowsingMetrics:
    """In-memory rolling aggregates for browsing data."""

    def __init__(self) -> None:
        # Real-time counters
        self.dns_query_timestamps: collections.deque[float] = collections.deque(maxlen=600)
        self.active_connections = 0
        self.bandwidth_up = 0
        self.bandwidth_down = 0

        # DNS
        self.top_domains: collections.Counter[str] = collections.Counter()
        self.query_type_counts: collections.Counter[str] = collections.Counter()
        self.nxdomain_count = 0
        self.total_dns_queries = 0
        self.domain_first_seen: dict[str, str] = {}  # domain -> ISO timestamp
        self.suspicious_domains: dict[str, dict[str, Any]] = {}  # domain -> details

        # TLS
        self.tls_versions: collections.Counter[str] = collections.Counter()
        self.ja3_fingerprints: collections.Counter[str] = collections.Counter()
        self.tls_count = 0

        # Traffic
        self.top_destinations: collections.Counter[str] = collections.Counter()  # "ip:port" -> bytes
        self.protocol_distribution: collections.Counter[str] = collections.Counter()  # proto -> bytes
        self.device_upload: collections.Counter[str] = collections.Counter()  # src_ip -> bytes
        self.device_download: collections.Counter[str] = collections.Counter()  # dst_ip -> bytes
        self.http_count = 0

        # Beacon detection
        self.connection_times: dict[str, list[float]] = {}  # "src>dst:port" -> timestamps
        self.detected_beacons: list[dict[str, Any]] = []

        # Recent events for live feed
        self.recent_events: collections.deque[dict[str, Any]] = collections.deque(maxlen=MAX_RECENT_EVENTS)

        # Hourly accumulator
        self.hourly_dns = 0
        self.hourly_unique_domains: set[str] = set()
        self.hourly_nxdomain = 0
        self.hourly_bytes_up = 0
        self.hourly_bytes_down = 0
        self.hourly_tls = 0
        self.hourly_http = 0
        self.hourly_suspicious = 0

    @property
    def dns_qps(self) -> float:
        """DNS queries per second over the last 60s."""
        now = time.time()
        cutoff = now - 60.0
        count = sum(1 for t in self.dns_query_timestamps if t > cutoff)
        return count / 60.0

    def realtime_snapshot(self) -> dict[str, Any]:
        return {
            "dns_qps": round(self.dns_qps, 2),
            "active_connections": self.active_connections,
            "bandwidth_up": self.bandwidth_up,
            "bandwidth_down": self.bandwidth_down,
            "total_dns_queries": self.total_dns_queries,
            "total_tls": self.tls_count,
            "total_http": self.http_count,
        }

    def flush_hourly(self) -> dict[str, Any]:
        """Return hourly summary and reset accumulators."""
        summary = {
            "hour": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00:00"),
            "dns_queries": self.hourly_dns,
            "unique_domains": len(self.hourly_unique_domains),
            "nxdomain_count": self.hourly_nxdomain,
            "bytes_up": self.hourly_bytes_up,
            "bytes_down": self.hourly_bytes_down,
            "tls_connections": self.hourly_tls,
            "http_connections": self.hourly_http,
            "suspicious_domains": self.hourly_suspicious,
            "top_domains_json": json.dumps(dict(self.top_domains.most_common(50))),
            "protocol_dist_json": json.dumps(dict(self.protocol_distribution.most_common(20))),
            "tls_version_dist_json": json.dumps(dict(self.tls_versions)),
        }
        self.hourly_dns = 0
        self.hourly_unique_domains.clear()
        self.hourly_nxdomain = 0
        self.hourly_bytes_up = 0
        self.hourly_bytes_down = 0
        self.hourly_tls = 0
        self.hourly_http = 0
        self.hourly_suspicious = 0
        return summary


class BrowsingService:
    """Tails Suricata eve.json and maintains browsing metrics."""

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self.metrics = BrowsingMetrics()
        self._task: asyncio.Task | None = None
        self._metrics_task: asyncio.Task | None = None
        self._flush_task: asyncio.Task | None = None
        self._running = False
        self._ws_event_count = 0
        self._ws_event_reset = 0.0
        # Sentinel IOC lookup (loaded lazily)
        self._ioc_domains: set[str] | None = None
        self._ioc_ips: set[str] | None = None

    async def start(self) -> None:
        """Start tailing eve.json."""
        if self._running:
            return
        self._running = True
        self._load_ioc_data()
        self._task = asyncio.create_task(self._tail_eve())
        self._metrics_task = asyncio.create_task(self._push_metrics_loop())
        self._flush_task = asyncio.create_task(self._hourly_flush_loop())
        logger.info("BrowsingService started, tailing %s", EVE_LOG_PATH)

    async def stop(self) -> None:
        """Stop tailing."""
        self._running = False
        for task in (self._task, self._metrics_task, self._flush_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        logger.info("BrowsingService stopped")

    def _load_ioc_data(self) -> None:
        """Load Sentinel IOC domains and IPs for fast lookup."""
        try:
            settings = get_settings()
            db_path = Path(settings.sentinel.osint.cache_dir) / "sentinel.db"
            if not db_path.exists():
                # Try relative to project root
                db_path = Path(__file__).resolve().parents[2] / settings.sentinel.osint.cache_dir / "sentinel.db"
            if db_path.exists():
                import sqlite3
                conn = sqlite3.connect(str(db_path))
                try:
                    self._ioc_domains = {
                        row[0] for row in conn.execute(
                            "SELECT DISTINCT domain FROM sentinel_ioc_domains"
                        ).fetchall()
                    }
                    self._ioc_ips = {
                        row[0] for row in conn.execute(
                            "SELECT DISTINCT ip FROM sentinel_ioc_ips"
                        ).fetchall()
                    }
                    logger.info(
                        "Loaded %d IOC domains, %d IOC IPs from Sentinel",
                        len(self._ioc_domains), len(self._ioc_ips),
                    )
                except Exception:
                    self._ioc_domains = set()
                    self._ioc_ips = set()
                finally:
                    conn.close()
            else:
                self._ioc_domains = set()
                self._ioc_ips = set()
                logger.info("Sentinel DB not found at %s, IOC lookups disabled", db_path)
        except Exception as e:
            self._ioc_domains = set()
            self._ioc_ips = set()
            logger.warning("Failed to load IOC data: %s", e)

    def _check_domain_ioc(self, domain: str) -> str | None:
        """Check domain against IOC list. Returns source name or None."""
        if self._ioc_domains and domain in self._ioc_domains:
            return "sentinel_feeds"
        return None

    def _check_ip_ioc(self, ip: str) -> str | None:
        """Check IP against IOC list. Returns source name or None."""
        if self._ioc_ips and ip in self._ioc_ips:
            return "sentinel_feeds"
        return None

    async def _tail_eve(self) -> None:
        """Tail eve.json continuously."""
        while self._running:
            if not EVE_LOG_PATH.exists():
                logger.warning("eve.json not found at %s, retrying in 10s", EVE_LOG_PATH)
                await asyncio.sleep(10)
                continue

            try:
                await self._tail_file(EVE_LOG_PATH)
            except Exception as e:
                logger.error("Eve tailer error: %s", e)
                await asyncio.sleep(5)

    async def _tail_file(self, path: Path) -> None:
        """Tail a file from the end, processing new lines."""
        inode = os.stat(path).st_ino
        with open(path, "r") as f:
            # Seek to end
            f.seek(0, os.SEEK_END)

            while self._running:
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        try:
                            event = json.loads(line)
                            await self._process_event(event)
                        except json.JSONDecodeError:
                            pass
                else:
                    # Check for file rotation
                    try:
                        new_inode = os.stat(path).st_ino
                        if new_inode != inode:
                            logger.info("eve.json rotated, reopening")
                            return  # Will reopen in _tail_eve loop
                    except FileNotFoundError:
                        return
                    await asyncio.sleep(0.1)

    async def _process_event(self, event: dict[str, Any]) -> None:
        """Process a single eve.json event."""
        event_type = event.get("event_type")
        timestamp = event.get("timestamp", "")

        if event_type == "dns":
            await self._handle_dns(event, timestamp)
        elif event_type == "tls":
            await self._handle_tls(event, timestamp)
        elif event_type == "http":
            await self._handle_http(event, timestamp)
        elif event_type == "flow":
            self._handle_flow(event)
        elif event_type == "stats":
            self._handle_stats(event)

    async def _handle_dns(self, event: dict[str, Any], timestamp: str) -> None:
        """Process DNS event."""
        dns = event.get("dns", {})
        dns_type = dns.get("type")

        if dns_type == "query":
            domain = dns.get("rrname", "")
            rrtype = dns.get("rrtype", "A")
            src_ip = event.get("src_ip", "")

            if not domain:
                return

            self.metrics.dns_query_timestamps.append(time.time())
            self.metrics.total_dns_queries += 1
            self.metrics.top_domains[domain] += 1
            self.metrics.query_type_counts[rrtype] += 1
            self.metrics.hourly_dns += 1
            self.metrics.hourly_unique_domains.add(domain)

            # First-seen tracking
            if domain not in self.metrics.domain_first_seen:
                self.metrics.domain_first_seen[domain] = timestamp

            # Entropy scoring
            sld = _extract_sld(domain)
            entropy = _shannon_entropy(sld)
            is_suspicious = False
            threat_source = ""

            # IOC check
            ioc_hit = self._check_domain_ioc(domain)
            if ioc_hit:
                is_suspicious = True
                threat_source = ioc_hit

            # Entropy check
            if entropy > ENTROPY_THRESHOLD and len(sld) > 8:
                is_suspicious = True
                threat_source = threat_source or "high_entropy"

            if is_suspicious:
                self.metrics.suspicious_domains[domain] = {
                    "domain": domain,
                    "entropy": round(entropy, 2),
                    "threat_source": threat_source,
                    "first_seen": self.metrics.domain_first_seen.get(domain, timestamp),
                    "query_count": self.metrics.top_domains[domain],
                }
                self.metrics.hourly_suspicious += 1

                await self._publish_throttled(EventType.BROWSING_SUSPICIOUS_DOMAIN, {
                    "domain": domain,
                    "entropy": round(entropy, 2),
                    "threat_source": threat_source,
                    "src_ip": src_ip,
                })

            # Add to recent events
            self.metrics.recent_events.append({
                "timestamp": timestamp,
                "event_type": "dns",
                "summary": f"DNS {rrtype} {domain}" + (f" [from {src_ip}]" if src_ip else ""),
                "is_suspicious": is_suspicious,
            })

        elif dns_type == "answer":
            rcode = dns.get("rcode", "")
            if rcode == "NXDOMAIN":
                self.metrics.nxdomain_count += 1
                self.metrics.hourly_nxdomain += 1

    async def _handle_tls(self, event: dict[str, Any], timestamp: str) -> None:
        """Process TLS event."""
        tls = event.get("tls", {})
        sni = tls.get("sni", "")
        version = tls.get("version", "")
        ja3 = tls.get("ja3", {}).get("hash", "") if isinstance(tls.get("ja3"), dict) else ""
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dest_ip", "")
        dst_port = event.get("dest_port", 0)

        self.metrics.tls_count += 1
        self.metrics.hourly_tls += 1

        if version:
            self.metrics.tls_versions[version] += 1
        if ja3:
            self.metrics.ja3_fingerprints[ja3] += 1

        # Beacon tracking
        if dst_ip:
            key = f"{src_ip}>{dst_ip}:{dst_port}"
            if key not in self.metrics.connection_times:
                self.metrics.connection_times[key] = []
            self.metrics.connection_times[key].append(time.time())
            self._check_beacon(key, src_ip, dst_ip, dst_port)

        # IOC check on destination
        ip_ioc = self._check_ip_ioc(dst_ip)
        is_suspicious = bool(ip_ioc)

        self.metrics.recent_events.append({
            "timestamp": timestamp,
            "event_type": "tls",
            "summary": f"TLS {version} → {sni or dst_ip}:{dst_port}",
            "is_suspicious": is_suspicious,
        })

    async def _handle_http(self, event: dict[str, Any], timestamp: str) -> None:
        """Process HTTP event."""
        http = event.get("http", {})
        hostname = http.get("hostname", "")
        method = http.get("http_method", "")
        url = http.get("url", "")
        status = http.get("status", "")

        self.metrics.http_count += 1
        self.metrics.hourly_http += 1

        if hostname:
            self.metrics.top_domains[hostname] += 1

        self.metrics.recent_events.append({
            "timestamp": timestamp,
            "event_type": "http",
            "summary": f"HTTP {method} {hostname}{url[:60]}" + (f" → {status}" if status else ""),
            "is_suspicious": False,
        })

    def _handle_flow(self, event: dict[str, Any]) -> None:
        """Process flow event."""
        flow = event.get("flow", {})
        app_proto = event.get("app_proto", "unknown")
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dest_ip", "")
        dst_port = event.get("dest_port", 0)

        bytes_up = flow.get("bytes_toserver", 0)
        bytes_down = flow.get("bytes_toclient", 0)

        self.metrics.bandwidth_up += bytes_up
        self.metrics.bandwidth_down += bytes_down
        self.metrics.hourly_bytes_up += bytes_up
        self.metrics.hourly_bytes_down += bytes_down

        dest_key = f"{dst_ip}:{dst_port}"
        self.metrics.top_destinations[dest_key] += bytes_up + bytes_down
        self.metrics.protocol_distribution[app_proto] += bytes_up + bytes_down
        self.metrics.device_upload[src_ip] += bytes_up
        self.metrics.device_download[src_ip] += bytes_down

    def _handle_stats(self, event: dict[str, Any]) -> None:
        """Process stats event for connection count."""
        stats = event.get("stats", {})
        flow_stats = stats.get("flow", {})
        self.metrics.active_connections = flow_stats.get("active", 0)

    def _check_beacon(self, key: str, src_ip: str, dst_ip: str, dst_port: int) -> None:
        """Check connection pattern for beaconing behavior."""
        timestamps = self.metrics.connection_times[key]
        if len(timestamps) < BEACON_MIN_CONNECTIONS:
            return

        # Only check last N connections
        recent = timestamps[-50:]
        intervals = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]

        if not intervals:
            return

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 1.0:
            return  # Too fast, likely normal traffic

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        jitter = std_dev / mean_interval if mean_interval > 0 else 1.0

        if jitter < BEACON_JITTER_THRESHOLD:
            # Check if already detected
            existing = any(
                b["src_ip"] == src_ip and b["dst_ip"] == dst_ip and b["dst_port"] == dst_port
                for b in self.metrics.detected_beacons
            )
            if not existing:
                beacon = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "interval_secs": round(mean_interval, 2),
                    "jitter": round(jitter, 4),
                    "connection_count": len(timestamps),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "still_active": True,
                }
                self.metrics.detected_beacons.append(beacon)
                logger.warning(
                    "Beacon detected: %s -> %s:%d interval=%.1fs jitter=%.4f",
                    src_ip, dst_ip, dst_port, mean_interval, jitter,
                )
                # Fire-and-forget publish
                asyncio.create_task(self.event_bus.publish(Event(
                    type=EventType.BROWSING_BEACON_DETECTED,
                    source="browsing_service",
                    data=beacon,
                )))

    async def _publish_throttled(self, event_type: EventType, data: dict[str, Any]) -> None:
        """Publish an event, throttled to max N per second to WS."""
        now = time.time()
        if now - self._ws_event_reset > 1.0:
            self._ws_event_count = 0
            self._ws_event_reset = now
        if self._ws_event_count < WS_THROTTLE_PER_SEC:
            self._ws_event_count += 1
            await self.event_bus.publish(Event(
                type=event_type,
                source="browsing_service",
                data=data,
            ))

    async def _push_metrics_loop(self) -> None:
        """Push realtime metrics via EventBus every N seconds."""
        while self._running:
            await asyncio.sleep(METRICS_PUSH_INTERVAL)
            try:
                await self.event_bus.publish(Event(
                    type=EventType.BROWSING_METRICS_UPDATE,
                    source="browsing_service",
                    data=self.metrics.realtime_snapshot(),
                ))
            except Exception:
                pass

    async def _hourly_flush_loop(self) -> None:
        """Flush hourly summaries to log (SQLite storage deferred)."""
        while self._running:
            await asyncio.sleep(HOURLY_FLUSH_INTERVAL)
            summary = self.metrics.flush_hourly()
            logger.info("Hourly browsing summary: %s", json.dumps(summary))
