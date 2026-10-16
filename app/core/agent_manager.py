from __future__ import annotations

import socket
import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import Any


class MultiHostAgentManager:
    def __init__(self) -> None:
        self._lock = Lock()
        self.agents: dict[str, dict[str, Any]] = {}
        # Auto-register local host node as primary agent
        local_hostname = socket.gethostname()
        self.register_agent(hostname=local_hostname, os_platform=socket.getplatform() if hasattr(socket, 'getplatform') else 'local', ip_address="127.0.0.1", is_local=True)

    def register_agent(
        self,
        hostname: str,
        os_platform: str,
        ip_address: str,
        is_local: bool = False,
    ) -> dict[str, Any]:
        with self._lock:
            agent_id = f"agent-{uuid.uuid4().hex[:8]}"
            now = datetime.now(timezone.utc).isoformat()
            agent = {
                "id": agent_id,
                "hostname": hostname,
                "os_platform": os_platform,
                "ip_address": ip_address,
                "status": "online",
                "is_local": is_local,
                "registered_at": now,
                "last_heartbeat": now,
                "events_ingested": 0,
            }
            self.agents[agent_id] = agent
            return agent

    def heartbeat(self, agent_id: str, events_count: int = 0) -> dict[str, Any]:
        with self._lock:
            agent = self.agents.get(agent_id)
            if not agent:
                return {"status": "error", "message": f"Agent '{agent_id}' not found."}
            agent["last_heartbeat"] = datetime.now(timezone.utc).isoformat()
            agent["status"] = "online"
            agent["events_ingested"] += events_count
            return agent

    def get_agents(self) -> list[dict[str, Any]]:
        now_dt = datetime.now(timezone.utc)
        with self._lock:
            result = []
            for agent in self.agents.values():
                node = dict(agent)
                last_hb = datetime.fromisoformat(node["last_heartbeat"])
                # Mark offline if no heartbeat for 60 seconds (unless local)
                if not node.get("is_local") and (now_dt - last_hb).total_seconds() > 60:
                    node["status"] = "offline"
                result.append(node)
            return result
