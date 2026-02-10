"""WebSocket interactive terminal endpoint.

Provides a real-time bidirectional terminal session inside a cell.
In production, this proxies between the WebSocket client and a PTY
inside the MicroVM via vsock.
"""

import asyncio
import uuid

import structlog
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.db.base import get_db
from aijailer.engine.microvm import get_microvm_engine

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["Terminal"])


@router.websocket("/v1/cells/{cell_id}/terminal")
async def interactive_terminal(
    websocket: WebSocket,
    cell_id: uuid.UUID,
):
    """Interactive terminal session via WebSocket.

    Protocol:
    Client → Server:
        {"type": "input", "data": "ls -la\\n"}
        {"type": "resize", "cols": 120, "rows": 40}
        {"type": "ping"}

    Server → Client:
        {"type": "output", "data": "total 24\\ndrwxr-xr-x ..."}
        {"type": "exit", "code": 0}
        {"type": "error", "message": "Cell is not running"}
        {"type": "pong"}
    """
    # Authenticate via query param or header
    token = websocket.query_params.get("token")
    if not token:
        # Check Authorization header from protocol
        auth_header = websocket.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if auth_header else None

    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return

    await websocket.accept()

    logger.info("terminal.connected", cell_id=str(cell_id))

    engine = get_microvm_engine()

    try:
        # Verify cell exists and is running
        vm_info = await engine.get_vm_info(cell_id)
        if vm_info.status.value != "running":
            await websocket.send_json(
                {"type": "error", "message": f"Cell is not running (status: {vm_info.status.value})"}
            )
            await websocket.close()
            return

        await websocket.send_json(
            {"type": "output", "data": f"Connected to cell {cell_id}\r\n$ "}
        )

        while True:
            message = await websocket.receive_json()
            msg_type = message.get("type")

            if msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            elif msg_type == "resize":
                cols = message.get("cols", 80)
                rows = message.get("rows", 24)
                logger.debug("terminal.resize", cell_id=str(cell_id), cols=cols, rows=rows)
                # In production: send resize signal to PTY via vsock

            elif msg_type == "input":
                data = message.get("data", "")
                # In production: forward input to PTY via vsock and stream back output
                # For MVP: echo the command and simulate output
                command = data.strip()
                if command:
                    result = await engine.exec_command(cell_id, command)
                    await websocket.send_json(
                        {"type": "output", "data": f"{result.stdout}$ "}
                    )
                else:
                    await websocket.send_json({"type": "output", "data": "$ "})

    except WebSocketDisconnect:
        logger.info("terminal.disconnected", cell_id=str(cell_id))
    except Exception as e:
        logger.error("terminal.error", cell_id=str(cell_id), error=str(e))
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
            await websocket.close()
        except Exception:
            pass


@router.websocket("/v1/cells/{cell_id}/logs")
async def live_log_stream(
    websocket: WebSocket,
    cell_id: uuid.UUID,
):
    """Live audit log streaming via WebSocket.

    Streams audit events for a cell in real-time.

    Query Parameters:
        event_types: Comma-separated list of event types to stream
        severity_min: Minimum severity level
    """
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return

    await websocket.accept()

    event_types = websocket.query_params.get("event_types", "").split(",")
    event_types = [e.strip() for e in event_types if e.strip()]
    severity_min = websocket.query_params.get("severity_min", "info")

    logger.info(
        "logs.stream.connected",
        cell_id=str(cell_id),
        event_types=event_types,
    )

    try:
        # In production: subscribe to Kafka topic for this cell's events
        # and forward matching events to the WebSocket client
        # For MVP: send a connected confirmation and wait
        await websocket.send_json({
            "type": "connected",
            "cell_id": str(cell_id),
            "filters": {"event_types": event_types, "severity_min": severity_min},
        })

        while True:
            # Keep connection alive; production would push events here
            message = await asyncio.wait_for(
                websocket.receive_json(),
                timeout=30.0,
            )
            if message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})

    except asyncio.TimeoutError:
        # Send keepalive
        try:
            await websocket.send_json({"type": "keepalive"})
        except Exception:
            pass
    except WebSocketDisconnect:
        logger.info("logs.stream.disconnected", cell_id=str(cell_id))
    except Exception as e:
        logger.error("logs.stream.error", cell_id=str(cell_id), error=str(e))
