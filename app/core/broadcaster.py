from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket


class TelemetryBroadcaster:
    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        if not self.active_connections:
            return
        payload = json.dumps(message, default=str)
        dead_sockets: set[WebSocket] = set()

        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                dead_sockets.add(connection)

        for dead in dead_sockets:
            self.active_connections.discard(dead)

    def broadcast_sync(self, message: dict[str, Any]) -> None:
        if not self.active_connections:
            return
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast(message), loop)
            else:
                loop.run_until_complete(self.broadcast(message))
        except Exception:
            pass


broadcaster = TelemetryBroadcaster()
