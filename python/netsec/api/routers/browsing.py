"""Browsing metrics API — real-time and historical web traffic analytics."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Query, Request

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_service(request: Request):
    """Get the browsing service from app state."""
    return request.app.state.browsing_service


# ── Real-time ──

@router.get("/realtime")
async def get_realtime(request: Request) -> dict[str, Any]:
    """Current real-time counters."""
    svc = _get_service(request)
    return svc.metrics.realtime_snapshot()


@router.get("/events/recent")
async def get_recent_events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    """Recent browsing events for live feed."""
    svc = _get_service(request)
    events = list(svc.metrics.recent_events)
    return events[-limit:]


# ── DNS Analytics ──

@router.get("/dns/top-domains")
async def get_top_domains(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    """Top resolved domains by query count."""
    svc = _get_service(request)
    suspicious = svc.metrics.suspicious_domains
    return [
        {
            "domain": domain,
            "count": count,
            "is_suspicious": domain in suspicious,
            "threat_source": suspicious.get(domain, {}).get("threat_source"),
        }
        for domain, count in svc.metrics.top_domains.most_common(limit)
    ]


@router.get("/dns/suspicious")
async def get_suspicious_domains(request: Request) -> list[dict[str, Any]]:
    """Domains flagged by threat feeds or high entropy."""
    svc = _get_service(request)
    return sorted(
        svc.metrics.suspicious_domains.values(),
        key=lambda d: d.get("query_count", 0),
        reverse=True,
    )


@router.get("/dns/query-types")
async def get_query_types(request: Request) -> list[dict[str, Any]]:
    """DNS query type breakdown."""
    svc = _get_service(request)
    return [
        {"rrtype": rrtype, "count": count}
        for rrtype, count in svc.metrics.query_type_counts.most_common(20)
    ]


@router.get("/dns/nxdomain-rate")
async def get_nxdomain_rate(request: Request) -> dict[str, Any]:
    """NXDOMAIN rate and potential DGA indicator."""
    svc = _get_service(request)
    total = svc.metrics.total_dns_queries
    nx = svc.metrics.nxdomain_count
    return {
        "total_queries": total,
        "nxdomain_count": nx,
        "nxdomain_rate": round(nx / max(total, 1), 4),
    }


@router.get("/dns/first-seen")
async def get_first_seen_domains(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    """Recently first-seen domains."""
    svc = _get_service(request)
    # Sort by timestamp descending
    items = sorted(
        svc.metrics.domain_first_seen.items(),
        key=lambda kv: kv[1],
        reverse=True,
    )[:limit]
    return [
        {
            "domain": domain,
            "first_seen": ts,
            "query_count": svc.metrics.top_domains.get(domain, 0),
        }
        for domain, ts in items
    ]


# ── Traffic Analysis ──

@router.get("/traffic/top-destinations")
async def get_top_destinations(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    """Top destinations by bandwidth."""
    svc = _get_service(request)
    return [
        {
            "destination": dest,
            "bytes_total": bytes_total,
        }
        for dest, bytes_total in svc.metrics.top_destinations.most_common(limit)
    ]


@router.get("/traffic/protocols")
async def get_protocol_distribution(request: Request) -> list[dict[str, Any]]:
    """Protocol distribution by bytes."""
    svc = _get_service(request)
    total = sum(svc.metrics.protocol_distribution.values()) or 1
    return [
        {
            "protocol": proto,
            "bytes_total": bytes_total,
            "percentage": round(bytes_total / total * 100, 1),
        }
        for proto, bytes_total in svc.metrics.protocol_distribution.most_common(20)
    ]


@router.get("/traffic/tls-versions")
async def get_tls_versions(request: Request) -> list[dict[str, Any]]:
    """TLS version distribution."""
    svc = _get_service(request)
    return [
        {"version": version, "count": count}
        for version, count in svc.metrics.tls_versions.most_common(10)
    ]


@router.get("/traffic/ja3")
async def get_ja3_fingerprints(
    request: Request,
    limit: int = Query(default=25, ge=1, le=100),
) -> list[dict[str, Any]]:
    """JA3 fingerprint tracking."""
    svc = _get_service(request)
    return [
        {"ja3_hash": hash_val, "count": count}
        for hash_val, count in svc.metrics.ja3_fingerprints.most_common(limit)
    ]


# ── Security Indicators ──

@router.get("/security/beacons")
async def get_beacons(request: Request) -> list[dict[str, Any]]:
    """Detected beacon patterns."""
    svc = _get_service(request)
    return svc.metrics.detected_beacons


@router.get("/security/high-entropy")
async def get_high_entropy(request: Request) -> list[dict[str, Any]]:
    """High-entropy domain alerts (potential DGA/tunneling)."""
    svc = _get_service(request)
    return [
        d for d in svc.metrics.suspicious_domains.values()
        if d.get("threat_source") == "high_entropy"
    ]


@router.get("/security/bad-ips")
async def get_bad_ips(request: Request) -> list[dict[str, Any]]:
    """Connections to known-bad IPs from Sentinel feeds."""
    svc = _get_service(request)
    return [
        d for d in svc.metrics.suspicious_domains.values()
        if d.get("threat_source") == "sentinel_feeds"
    ]
