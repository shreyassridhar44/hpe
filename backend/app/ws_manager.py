"""
ws_manager.py — WebSocket connection managers for simulation and admin streams.
"""

"""
ws_manager.py — WebSocket connection managers with Redis pub/sub.
All backend pods subscribe to Redis so any pod can broadcast to
all connected browsers regardless of which pod they connected to.
"""

import json
import logging
import asyncio
import os
import threading
from fastapi import WebSocket
from typing import List, Optional

logger = logging.getLogger("hpe.ws")

# Redis pub/sub channels
SIMULATION_CHANNEL = "hpe:simulation"
ADMIN_CHANNEL = "hpe:admin"

_redis_client = None
_redis_available = False


def _connect_redis():
    """Try to connect to Redis. Falls back gracefully if not available."""
    global _redis_client, _redis_available
    try:
        import redis
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
        _redis_client = redis.from_url(redis_url, decode_responses=True)
        _redis_client.ping()
        _redis_available = True
        logger.info(f"[WS] Redis connected at {redis_url}")
    except Exception as e:
        logger.warning(f"[WS] Redis not available ({e}) — falling back to local broadcast only")
        _redis_available = False


class ConnectionManager:
    """
    Manages WebSocket connections with Redis pub/sub broadcasting.
    When Redis is available: events published by ANY pod reach ALL browsers.
    When Redis is unavailable: falls back to local-only broadcast (single pod mode).
    """

    def __init__(self, name: str = "default", channel: str = "hpe:default"):
        self.name = name
        self.channel = channel
        self.connections: List[WebSocket] = []
        self._pubsub_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def start_redis_listener(self, loop: asyncio.AbstractEventLoop):
        """Start background thread listening to Redis channel."""
        self._loop = loop  # Store loop reference for sync broadcast support
        if not _redis_available:
            logger.info(f"[WS:{self.name}] Redis unavailable — local mode only")
            return

        def listen():
            try:
                import redis
                redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
                r = redis.from_url(redis_url, decode_responses=True)
                ps = r.pubsub()
                ps.subscribe(self.channel)
                logger.info(f"[WS:{self.name}] Subscribed to Redis channel: {self.channel}")

                for message in ps.listen():
                    if message["type"] != "message":
                        continue
                    try:
                        data = json.loads(message["data"])
                        # Schedule broadcast on the event loop
                        asyncio.run_coroutine_threadsafe(
                            self._local_broadcast(data), loop
                        )
                    except Exception as e:
                        logger.error(f"[WS:{self.name}] Redis message error: {e}")
            except Exception as e:
                logger.error(f"[WS:{self.name}] Redis listener crashed: {e}")

        self._pubsub_thread = threading.Thread(
            target=listen,
            name=f"redis-listener-{self.name}",
            daemon=True
        )
        self._pubsub_thread.start()

    def add(self, ws: WebSocket):
        self.connections.append(ws)
        logger.info(f"[WS:{self.name}] Client connected ({len(self.connections)} active)")

    def remove(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)
        logger.info(f"[WS:{self.name}] Client disconnected ({len(self.connections)} active)")

    async def broadcast(self, data: dict):
        """
        Publish to Redis (reaches ALL pods) if available.
        Falls back to local broadcast if Redis is down.
        """
        if _redis_available and _redis_client:
            try:
                _redis_client.publish(self.channel, json.dumps(data, default=str))
                return
            except Exception as e:
                logger.warning(f"[WS:{self.name}] Redis publish failed: {e} — using local broadcast")

        # Fallback: local broadcast only
        await self._local_broadcast(data)

    async def _local_broadcast(self, data: dict):
        """Send directly to all WebSockets connected to THIS pod."""
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.remove(ws)

    def broadcast_sync(self, data: dict):
        """
        Schedule a broadcast from a synchronous (non-async) context.
        Used by sync FastAPI endpoints running in worker threads.
        """
        if self._loop is None:
            logger.warning(f"[WS:{self.name}] No event loop stored — cannot broadcast from sync context")
            return
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(data), self._loop)
        except Exception as e:
            logger.warning(f"[WS:{self.name}] Sync broadcast failed: {e}")

    @property
    def active_count(self) -> int:
        return len(self.connections)


# Initialise Redis connection
_connect_redis()

# Simulation stream (globe + pipeline)
manager = ConnectionManager("simulation", SIMULATION_CHANNEL)

# Admin alert stream
admin_manager = ConnectionManager("admin", ADMIN_CHANNEL)