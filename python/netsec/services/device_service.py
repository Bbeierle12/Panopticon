"""Device management service."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netsec.core.events import Event, EventBus, EventType
from netsec.models.device import Device, Port

logger = logging.getLogger(__name__)


class DeviceService:
    """Manages network devices and their ports."""

    def __init__(self, session: AsyncSession, event_bus: EventBus) -> None:
        self.session = session
        self.event_bus = event_bus

    async def upsert_from_scan(self, host_data: dict[str, Any]) -> Device:
        """Create or update a device from scan results.

        Merges data if device already exists (matched by IP or MAC).
        """
        addresses = host_data.get("addresses", {})
        ip = addresses.get("ipv4", "")
        mac = addresses.get("mac")
        vendor = addresses.get("vendor")
        hostnames = host_data.get("hostnames", [])
        hostname = hostnames[0]["name"] if hostnames else None

        # Try to find existing device
        device = await self._find_device(ip, mac)
        now = datetime.now(timezone.utc)

        if device is None:
            device = Device(
                id=uuid4().hex,
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                vendor=vendor,
                status=host_data.get("status", "online"),
                first_seen=now,
                last_seen=now,
            )
            self.session.add(device)
            event_type = EventType.DEVICE_DISCOVERED
        else:
            # Merge data
            if mac and not device.mac_address:
                device.mac_address = mac
            if hostname and not device.hostname:
                device.hostname = hostname
            if vendor and not device.vendor:
                device.vendor = vendor
            device.last_seen = now
            device.status = host_data.get("status", device.status)
            event_type = EventType.DEVICE_UPDATED

        # Update OS info
        os_info = host_data.get("os", {})
        if os_info.get("name"):
            device.os_family = os_info["name"]

        # Update ports
        for port_data in host_data.get("ports", []):
            await self._upsert_port(device, port_data)

        # Infer device_type if not already set
        if not device.device_type:
            device.device_type = _infer_device_type(
                ip=device.ip_address,
                hostname=device.hostname,
                vendor=device.vendor,
                os_family=device.os_family,
                ports=host_data.get("ports", []),
            )
            if device.device_type:
                logger.info(
                    "Inferred device_type=%s for %s (%s)",
                    device.device_type, device.ip_address, device.hostname,
                )

        await self.session.flush()

        await self.event_bus.publish(Event(
            type=event_type,
            source="device_service",
            data={
                "device_id": device.id,
                "ip": device.ip_address,
                "hostname": device.hostname,
            },
        ))

        return device

    async def get_device(self, device_id: str) -> Device | None:
        stmt = select(Device).options(selectinload(Device.ports)).where(Device.id == device_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_devices(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        status: str | None = None,
    ) -> list[Device]:
        stmt = (
            select(Device)
            .options(selectinload(Device.ports))
            .order_by(Device.last_seen.desc())
            .offset(offset)
            .limit(limit)
        )
        if status:
            stmt = stmt.where(Device.status == status)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_device(self, device_id: str, **kwargs: Any) -> Device | None:
        device = await self.get_device(device_id)
        if device is None:
            return None
        for key, value in kwargs.items():
            if value is not None and hasattr(device, key):
                setattr(device, key, value)
        await self.session.flush()
        return device

    async def delete_device(self, device_id: str) -> bool:
        device = await self.get_device(device_id)
        if device is None:
            return False
        await self.session.delete(device)
        await self.session.flush()
        return True

    async def _find_device(self, ip: str, mac: str | None) -> Device | None:
        conditions = [Device.ip_address == ip]
        if mac:
            conditions.append(Device.mac_address == mac)
        stmt = (
            select(Device)
            .options(selectinload(Device.ports))
            .where(or_(*conditions))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def reclassify_all(self) -> int:
        """Re-run device type inference on all devices with no type set."""
        devices = await self.list_devices(limit=1000)
        updated = 0
        for device in devices:
            if not device.device_type:
                ports = [
                    {"port": p.port_number, "service": p.service_name}
                    for p in device.ports
                ]
                device.device_type = _infer_device_type(
                    ip=device.ip_address,
                    hostname=device.hostname,
                    vendor=device.vendor,
                    os_family=device.os_family,
                    ports=ports,
                )
                if device.device_type:
                    updated += 1
        await self.session.flush()
        logger.info("Reclassified %d devices", updated)
        return updated

    async def _upsert_port(self, device: Device, port_data: dict[str, Any]) -> Port:
        port_num = port_data.get("port", 0)
        protocol = port_data.get("protocol", "tcp")

        # Find existing port
        existing = None
        for p in device.ports:
            if p.port_number == port_num and p.protocol == protocol:
                existing = p
                break

        if existing is None:
            port = Port(
                id=uuid4().hex,
                device_id=device.id,
                port_number=port_num,
                protocol=protocol,
                state=port_data.get("state", "open"),
                service_name=port_data.get("service"),
                service_version=port_data.get("version"),
                banner=port_data.get("product"),
            )
            self.session.add(port)
            device.ports.append(port)
            return port
        else:
            existing.state = port_data.get("state", existing.state)
            if port_data.get("service"):
                existing.service_name = port_data["service"]
            if port_data.get("version"):
                existing.service_version = port_data["version"]
            return existing


def _infer_device_type(
    ip: str,
    hostname: str | None,
    vendor: str | None,
    os_family: str | None,
    ports: list[dict[str, Any]],
) -> str | None:
    """Infer device type from IP, hostname, vendor, OS, and open ports."""
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    os_f = (os_family or "").lower()
    open_ports = {p.get("port", 0) for p in ports if p.get("state", "open") == "open"}
    services = {(p.get("service") or "").lower() for p in ports}

    # ── Gateway: .1 or .254 ──
    if ip.rsplit(".", 1)[-1] in ("1", "254"):
        return "router"

    # ── Router / mesh / gateway patterns ──
    if any(kw in h for kw in ("gateway", "router", "orbi", "rbe9", "rbs", "rbr")):
        return "router"
    if any(kw in v for kw in ("netgear", "orbi", "arris", "asus rt", "linksys", "ubiquiti")):
        if ip.rsplit(".", 1)[-1] in ("1", "254"):
            return "router"
        return "router"  # mesh nodes are routers too

    # ── Extender / access point ──
    if any(kw in h for kw in ("extender", "repeater", "tl-wa", "tl-wr", "re505", "re450", "eap")):
        return "extender"
    if any(kw in v for kw in ("tp-link",)):
        return "extender"

    # ── IoT / cameras / smart home ──
    if any(kw in h for kw in (
        "ring", "cam", "nest", "hue", "echo", "alexa", "sonos", "roku",
        "chromecast", "firestick", "doorbell", "thermostat", "arlo",
        "wemo", "smartthings", "tuya", "wyze",
    )):
        return "iot"

    # ── Mobile ──
    if any(kw in h for kw in ("ipad", "iphone", "pixel", "galaxy", "samsung", "android")):
        return "mobile"
    if "apple" in v and any(kw in h for kw in ("ipad", "iphone")):
        return "mobile"

    # ── Workstation / laptop ──
    if any(kw in h for kw in (
        "thinkpad", "macbook", "imac", "desktop", "laptop", "dell", "lenovo",
        "surface", "hp-", "acer", "asus-",
    )):
        return "workstation"
    if any(kw in os_f for kw in ("windows", "linux", "macos", "ubuntu", "debian", "fedora")):
        return "workstation"

    # ── Server (by ports) ──
    server_ports = {22, 80, 443, 3306, 5432, 8080, 8443, 3000, 5000, 9090}
    if len(open_ports & server_ports) >= 3:
        return "server"
    if any(kw in h for kw in ("server", "nas", "plex", "proxmox", "esxi", "truenas", "unraid")):
        return "server"

    # ── Printer ──
    if any(kw in h for kw in ("printer", "hp-", "epson", "canon", "brother")):
        return "iot"
    if 631 in open_ports or 9100 in open_ports or "ipp" in services:
        return "iot"

    return None
