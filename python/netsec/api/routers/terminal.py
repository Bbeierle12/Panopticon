"""Terminal router with WebSocket support for interactive PTY sessions."""
from __future__ import annotations

import asyncio
import base64
import logging

from datetime import datetime

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from netsec.core.terminal import get_terminal_manager, PING_INTERVAL

logger = logging.getLogger(__name__)

router = APIRouter()


# ============================================================================
# Pydantic Schemas
# ============================================================================

class TerminalCreateRequest(BaseModel):
    """Request to create a new terminal session."""
    shell: str | None = None
    cols: int = 120
    rows: int = 30


class TerminalResizeRequest(BaseModel):
    """Request to resize a terminal."""
    cols: int
    rows: int


class TerminalSessionOut(BaseModel):
    """Terminal session response."""
    session_id: str
    shell: str
    cols: int
    rows: int
    created_at: datetime


class ShellInfo(BaseModel):
    """Information about an available shell."""
    id: str
    name: str
    path: str


class AvailableShellsResponse(BaseModel):
    """Response containing available shells."""
    shells: list[ShellInfo]


# ============================================================================
# REST Endpoints
# ============================================================================

@router.get("/shells", response_model=AvailableShellsResponse)
async def list_available_shells() -> AvailableShellsResponse:
    """List available shells for the current platform."""
    manager = get_terminal_manager()
    shells = manager.get_available_shells()
    return AvailableShellsResponse(
        shells=[ShellInfo(**s) for s in shells]
    )


@router.post("/", response_model=TerminalSessionOut)
async def create_terminal(body: TerminalCreateRequest) -> TerminalSessionOut:
    """Create a new terminal session."""
    manager = get_terminal_manager()
    logger.info("Creating terminal: shell=%s cols=%d rows=%d", body.shell, body.cols, body.rows)

    try:
        session = await manager.create_session(
            shell=body.shell,
            cols=body.cols,
            rows=body.rows,
        )
        return TerminalSessionOut(
            session_id=session.session_id,
            shell=session.shell,
            cols=session.cols,
            rows=session.rows,
            created_at=session.created_at,
        )
    except RuntimeError as e:
        logger.error("Failed to create terminal: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=list[TerminalSessionOut])
async def list_terminals() -> list[TerminalSessionOut]:
    """List all active terminal sessions."""
    manager = get_terminal_manager()
    sessions = await manager.list_sessions()
    return [
        TerminalSessionOut(
            session_id=s.session_id,
            shell=s.shell,
            cols=s.cols,
            rows=s.rows,
            created_at=s.created_at,
        )
        for s in sessions
    ]


@router.get("/{session_id}", response_model=TerminalSessionOut)
async def get_terminal(session_id: str) -> TerminalSessionOut:
    """Get terminal session info."""
    manager = get_terminal_manager()
    session = await manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Terminal session not found")
    return TerminalSessionOut(
        session_id=session.session_id,
        shell=session.shell,
        cols=session.cols,
        rows=session.rows,
        created_at=session.created_at,
    )


@router.post("/{session_id}/resize")
async def resize_terminal(session_id: str, body: TerminalResizeRequest) -> dict:
    """Resize a terminal session."""
    manager = get_terminal_manager()
    success = await manager.resize(session_id, body.cols, body.rows)
    if not success:
        raise HTTPException(status_code=404, detail="Terminal session not found")
    return {"status": "ok"}


@router.delete("/{session_id}")
async def delete_terminal(session_id: str) -> dict:
    """Close a terminal session."""
    logger.info("Deleting terminal session %s", session_id)
    manager = get_terminal_manager()
    success = await manager.close_session(session_id)
    if not success:
        raise HTTPException(status_code=404, detail="Terminal session not found")
    return {"status": "ok"}


# ============================================================================
# WebSocket Endpoint
# ============================================================================

@router.websocket("/ws/{session_id}")
async def terminal_websocket(websocket: WebSocket, session_id: str) -> None:
    """WebSocket endpoint for bidirectional terminal communication.

    Client -> Server messages:
        {"type": "input", "data": "<base64-encoded-input>"}
        {"type": "resize", "cols": 120, "rows": 30}
        {"type": "ping"}

    Server -> Client messages:
        {"type": "output", "data": "<base64-encoded-output>"}
        {"type": "buffered_output", "data": "<base64-encoded-output>"}
        {"type": "exit", "code": 0}
        {"type": "error", "message": "..."}
        {"type": "pong"}
        {"type": "ping"}
    """
    await websocket.accept()
    logger.info("WebSocket connected for session %s", session_id)

    manager = get_terminal_manager()
    session = await manager.get_session(session_id)

    # If no existing session, create one
    if not session:
        try:
            output_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=4096)

            def on_output(data: bytes) -> None:
                try:
                    output_queue.put_nowait(data)
                except asyncio.QueueFull:
                    pass

            exit_event = asyncio.Event()
            exit_code_holder = [0]

            def on_exit(code: int) -> None:
                exit_code_holder[0] = code
                exit_event.set()

            session = await manager.create_session(
                output_callback=on_output,
                exit_callback=on_exit,
            )
            logger.info("Created new session %s via WebSocket", session.session_id)
        except RuntimeError as e:
            logger.error("Failed to create session via WebSocket: %s", e)
            await websocket.send_json({"type": "error", "message": str(e)})
            await websocket.close()
            return
    else:
        # Reattach callbacks for existing session
        output_queue = asyncio.Queue(maxsize=4096)

        def on_output(data: bytes) -> None:
            try:
                output_queue.put_nowait(data)
            except asyncio.QueueFull:
                pass

        exit_event = asyncio.Event()
        exit_code_holder = [0]

        def on_exit(code: int) -> None:
            exit_code_holder[0] = code
            exit_event.set()

        session._output_callback = on_output
        session._exit_callback = on_exit

        # Replay buffered output for reconnection
        buffer = manager.get_output_buffer(session_id)
        if buffer:
            logger.info("Replaying %d buffered chunks for session %s", len(buffer), session_id)
            for chunk in buffer:
                try:
                    encoded = base64.b64encode(chunk).decode("ascii")
                    await websocket.send_json({"type": "buffered_output", "data": encoded})
                except Exception:
                    break

    async def send_output() -> None:
        """Forward PTY output to WebSocket."""
        try:
            while True:
                try:
                    data = await asyncio.wait_for(output_queue.get(), timeout=0.1)
                    encoded = base64.b64encode(data).decode("ascii")
                    await websocket.send_json({"type": "output", "data": encoded})
                except asyncio.TimeoutError:
                    if exit_event.is_set():
                        await websocket.send_json({"type": "exit", "code": exit_code_holder[0]})
                        break
        except Exception:
            pass

    async def receive_input() -> None:
        """Receive input from WebSocket and forward to PTY."""
        try:
            while True:
                try:
                    msg = await websocket.receive_json()
                except WebSocketDisconnect:
                    logger.info("WebSocket disconnected for session %s", session_id)
                    break

                msg_type = msg.get("type")

                if msg_type == "input":
                    data = base64.b64decode(msg.get("data", ""))
                    await manager.write_input(session.session_id, data)

                elif msg_type == "resize":
                    cols = msg.get("cols", 120)
                    rows = msg.get("rows", 30)
                    await manager.resize(session.session_id, cols, rows)

                elif msg_type == "ping":
                    await websocket.send_json({"type": "pong"})

        except Exception:
            pass

    async def server_ping() -> None:
        """Server-side keep-alive ping to prevent proxy/LB timeout."""
        try:
            while True:
                await asyncio.sleep(PING_INTERVAL)
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
        except asyncio.CancelledError:
            pass

    # Run all tasks concurrently
    output_task = asyncio.create_task(send_output())
    input_task = asyncio.create_task(receive_input())
    ping_task = asyncio.create_task(server_ping())

    try:
        await asyncio.gather(output_task, input_task, return_exceptions=True)
    finally:
        output_task.cancel()
        input_task.cancel()
        ping_task.cancel()
        logger.info("WebSocket closed for session %s", session_id)
