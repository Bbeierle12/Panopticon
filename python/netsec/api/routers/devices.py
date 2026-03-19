"""Devices router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.db.session import get_session
from netsec.schemas.device import DeviceOut, DeviceUpdate
from netsec.services.device_service import DeviceService

router = APIRouter()


def _get_device_service(request: Request, session: AsyncSession = Depends(get_session)) -> DeviceService:
    return DeviceService(session=session, event_bus=request.app.state.event_bus)


@router.get("/", response_model=list[DeviceOut])
async def list_devices(
    offset: int = 0,
    limit: int = 100,
    status: str | None = None,
    service: DeviceService = Depends(_get_device_service),
) -> list[DeviceOut]:
    """List all discovered devices."""
    devices = await service.list_devices(offset=offset, limit=limit, status=status)
    return [DeviceOut.model_validate(d) for d in devices]


@router.post("/reclassify")
async def reclassify_devices(
    service: DeviceService = Depends(_get_device_service),
) -> dict:
    """Re-run device type inference on all unclassified devices."""
    count = await service.reclassify_all()
    return {"reclassified": count}


@router.get("/{device_id}", response_model=DeviceOut)
async def get_device(
    device_id: str,
    service: DeviceService = Depends(_get_device_service),
) -> DeviceOut:
    """Get device details with ports."""
    device = await service.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return DeviceOut.model_validate(device)


@router.patch("/{device_id}", response_model=DeviceOut)
async def update_device(
    device_id: str,
    body: DeviceUpdate,
    service: DeviceService = Depends(_get_device_service),
) -> DeviceOut:
    """Update device info."""
    device = await service.update_device(device_id, **body.model_dump(exclude_unset=True))
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return DeviceOut.model_validate(device)


@router.delete("/{device_id}", status_code=204)
async def delete_device(
    device_id: str,
    service: DeviceService = Depends(_get_device_service),
) -> None:
    """Delete a device."""
    deleted = await service.delete_device(device_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Device not found")
