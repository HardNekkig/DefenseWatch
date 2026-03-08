from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from defensewatch.broadcast import ConnectionManager

router = APIRouter()

_manager: ConnectionManager | None = None


def set_manager(manager: ConnectionManager):
    global _manager
    _manager = manager


@router.websocket("/ws/live")
async def websocket_endpoint(ws: WebSocket):
    if _manager is None:
        await ws.close()
        return
    await _manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _manager.disconnect(ws)
