"""
node_client.py
Drop-in client SDK for IWSN nodes.

Usage on each field node:
    from node_client import SDNNodeClient

    client = SDNNodeClient(
        controller_url="ws://192.168.1.100:8765",
        node_id="node-rpi-01",
        ip="192.168.1.10",
        capabilities=["dpi", "mqtt", "live_capture"],
    )

    # In your async main:
    await client.connect()          # registers + syncs policies
    await client.send_flow(stats)   # from your DPI engine
    await client.send_alert(alert)  # from your rule engine
    await client.send_sensor(data)  # from your MQTT parser
    await client.send_heartbeat()

    # Incoming from controller:
    client.on_flow_rule   = my_enforce_fn    # DROP/RATE_LIMIT etc.
    client.on_quarantine  = my_quarantine_fn
    client.on_policy_update = my_policy_fn
    client.on_alert_broadcast = my_preblock_fn
"""

from __future__ import annotations
import asyncio
import json
import time
from typing import Callable, Optional, Any, Awaitable
import websockets
from loguru import logger


HandlerFn = Callable[[dict], Awaitable[None]]


class SDNNodeClient:
    def __init__(
        self,
        controller_url: str,
        node_id: str,
        ip: str,
        version: str = "1.0",
        capabilities: list[str] | None = None,
        reconnect_delay: float = 5.0,
    ):
        self.url = f"{controller_url}/ws/{node_id}"
        self.node_id = node_id
        self.ip = ip
        self.version = version
        self.capabilities = capabilities or []
        self.reconnect_delay = reconnect_delay

        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._connected = False
        self._send_lock = asyncio.Lock()

        # Callbacks – set these before connect()
        self.on_flow_rule: Optional[HandlerFn] = None
        self.on_quarantine: Optional[HandlerFn] = None
        self.on_policy_update: Optional[HandlerFn] = None
        self.on_alert_broadcast: Optional[HandlerFn] = None
        self.on_controller_ready: Optional[HandlerFn] = None

    # ── Public API ───────────────────────────────────────────────

    async def connect(self):
        """Connect and run the receive loop. Reconnects on disconnect."""
        while True:
            try:
                async with websockets.connect(self.url) as ws:
                    self._ws = ws
                    self._connected = True
                    logger.info(f"[client] Connected to controller at {self.url}")
                    await self._register()
                    await self._receive_loop()
            except (websockets.ConnectionClosed, OSError) as exc:
                logger.warning(f"[client] Disconnected: {exc}. Reconnecting in {self.reconnect_delay}s")
                self._connected = False
            except Exception as exc:
                logger.error(f"[client] Unexpected error: {exc}")
                self._connected = False
            await asyncio.sleep(self.reconnect_delay)

    async def send_flow(self, stats: dict):
        """Send nDPI flow stats to the controller."""
        stats.setdefault("node_id", self.node_id)
        await self._send("flow_stats", stats)

    async def send_alert(self, alert: dict):
        """Send an attack alert from the rule engine."""
        alert.setdefault("node_id", self.node_id)
        await self._send("attack_alert", alert)

    async def send_sensor(self, data: dict):
        """Send MQTT-parsed sensor value."""
        data.setdefault("node_id", self.node_id)
        await self._send("mqtt_sensor", data)

    async def send_heartbeat(self, load_pct: float = 0.0, flows_active: int = 0, alerts_pending: int = 0):
        await self._send("heartbeat", {
            "node_id": self.node_id,
            "status": "active",
            "load_pct": load_pct,
            "flows_active": flows_active,
            "alerts_pending": alerts_pending,
        })

    async def ack_rule(self, rule_id: int, status: str = "applied", detail: str = ""):
        await self._send("rule_ack", {
            "node_id": self.node_id,
            "rule_id": rule_id,
            "status": status,
            "detail": detail,
        })

    # ── Private ──────────────────────────────────────────────────

    async def _register(self):
        await self._send("register", {
            "node_id": self.node_id,
            "ip": self.ip,
            "version": self.version,
            "capabilities": self.capabilities,
        })

    async def _send(self, msg_type: str, payload: dict):
        if not self._ws or not self._connected:
            logger.warning(f"[client] Not connected – dropping {msg_type}")
            return
        msg = json.dumps({"type": msg_type, "payload": payload, "ts": time.time()})
        async with self._send_lock:
            try:
                await self._ws.send(msg)
            except Exception as exc:
                logger.warning(f"[client] Send failed ({msg_type}): {exc}")

    async def _receive_loop(self):
        async for raw in self._ws:
            try:
                data = json.loads(raw)
                await self._dispatch_incoming(data)
            except Exception as exc:
                logger.warning(f"[client] Bad message from controller: {exc}")

    async def _dispatch_incoming(self, data: dict):
        msg_type = data.get("type", "")
        payload = data.get("payload", {})

        if msg_type == "controller_ready":
            logger.info(f"[client] Controller ready: {payload.get('message', '')}")
            if self.on_controller_ready:
                await self.on_controller_ready(payload)

        elif msg_type == "flow_rule":
            logger.info(f"[client] Flow rule received: {payload.get('rule_type')} rule_id={payload.get('rule_id')}")
            if self.on_flow_rule:
                await self.on_flow_rule(payload)
            # Auto-ack
            await self.ack_rule(payload.get("rule_id", 0), "applied")

        elif msg_type == "quarantine_command":
            logger.warning(f"[client] Quarantine: mac={payload.get('mac')} ip={payload.get('ip')}")
            if self.on_quarantine:
                await self.on_quarantine(payload)

        elif msg_type == "policy_update":
            policies = payload.get("policies", [])
            logger.info(f"[client] Policy update: {len(policies)} policies received")
            if self.on_policy_update:
                await self.on_policy_update(payload)

        elif msg_type == "alert_broadcast":
            logger.warning(
                f"[client] Alert broadcast from {payload.get('origin_node')}: "
                f"{payload.get('alert_type')} src={payload.get('src_ip')}"
            )
            if self.on_alert_broadcast:
                await self.on_alert_broadcast(payload)

        elif msg_type == "controller_ack":
            logger.debug(f"[client] Controller ACK: {payload.get('status')} for {payload.get('ref_type')}")

        else:
            logger.debug(f"[client] Unknown message from controller: {msg_type}")
