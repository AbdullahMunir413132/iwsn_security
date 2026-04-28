"""
node_client.py
Drop-in client SDK for IWSN nodes WITH OpenDaylight/OVS integration.
DEPLOYMENT MODES:
1. LIVE CAPTURE: Packets flow through OVS bridge, DPI engine reads from bridge
2. PCAP ANALYSIS: DPI engine reads from .pcap files, no real-time enforcement

Usage on each field node:
    from node_client import SDNNodeClient

    client = SDNNodeClient(
        # controller_url="ws://192.168.1.100:8765",
        controller_url = "ws://localhost:8765",
        node_id="node-1",
        ip="192.168.1.10",
        capabilities=["dpi", "mqtt", "live_capture"],
        mode="live",  # or "pcap"
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

INTEGRATION WITH OVS (for LIVE CAPTURE mode):
    When OVS is installed and configured on the node:
    - All packets flow through br0 (OVS bridge)
    - DPI engine captures from br0 (not eth0/wlan0)
    - When controller pushes DROP flow_rule:
      → ODL pushes OpenFlow rule to OVS (kernel enforcement)
      → AND/OR node applies iptables rule (application enforcement)
    - Both layers work together for defense-in-depth

PCAP ANALYSIS MODE:
    - OVS is NOT required
    - DPI engine reads from .pcap files
    - No real-time enforcement (analysis only)
    - Still sends alerts/flows to controller for logging
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
        metadata: dict[str, Any] | None = None,
        reconnect_delay: float = 5.0,
        mode: str = "live",  # "live" or "pcap"
    ):
        self.url = f"{controller_url}/ws/{node_id}"
        self.node_id = node_id
        self.ip = ip
        self.version = version
        self.capabilities = capabilities or []
        self.metadata = metadata or {}
        self.reconnect_delay = reconnect_delay
        self.mode = mode  # live capture or pcap analysis

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
                    logger.info(f"[client] Connected to controller at {self.url} (mode={self.mode})")
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
        caps = self.capabilities.copy()
        if self.mode == "live":
            caps.append("ovs_enabled")  # signal that OVS is available for enforcement
        elif self.mode == "pcap":
            caps.append("pcap_analysis")

        metadata = self.metadata.copy()
        metadata.setdefault("mode", self.mode)
        
        await self._send("register", {
            "node_id": self.node_id,
            "ip": self.ip,
            "version": self.version,
            "capabilities": caps,
            "metadata": metadata,
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


# ─────────────────────────────────────────────────────────────────
# Example enforcement handlers for LIVE CAPTURE mode
# ─────────────────────────────────────────────────────────────────

async def enforce_flow_rule_live(rule: dict):
    """
    Enforce a flow rule on the node using iptables (application-layer enforcement).
    This is a FALLBACK if ODL/OVS kernel enforcement fails.
    
    In LIVE CAPTURE mode:
    - ODL pushes OpenFlow rule to OVS (kernel-level, happens first)
    - This function adds iptables rule as backup (application-level)
    
    In PCAP mode:
    - This function does nothing (no real-time enforcement)
    """
    import subprocess
    
    rule_type = rule.get("rule_type")
    match = rule.get("match", {})
    src_ip = match.get("src_ip")
    
    if rule_type == "DROP" and src_ip:
        # Add iptables DROP rule
        cmd = ["iptables", "-I", "INPUT", "-s", src_ip, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            logger.success(f"[enforce] iptables DROP rule added for {src_ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"[enforce] iptables failed: {e.stderr.decode()}")
    
    elif rule_type == "RATE_LIMIT" and src_ip:
        # Use tc (traffic control) for rate limiting
        # This requires more complex setup - example skeleton:
        logger.info(f"[enforce] Rate limit for {src_ip} would be applied via tc")
        # tc qdisc add dev br0 root handle 1: htb default 10
        # tc class add dev br0 parent 1: classid 1:1 htb rate 128kbit
        # tc filter add dev br0 protocol ip parent 1:0 prio 1 u32 match ip src {src_ip} flowid 1:1


async def enforce_quarantine_live(cmd: dict):
    """
    Quarantine a MAC/IP at the node level.
    
    Options:
    1. ebtables to drop all traffic from MAC address
    2. iptables to drop all traffic from IP address
    3. Both for defense-in-depth
    """
    import subprocess
    
    mac = cmd.get("mac")
    ip = cmd.get("ip")
    
    if mac:
        # Block MAC address using ebtables
        ecmd = ["ebtables", "-I", "INPUT", "-s", mac, "-j", "DROP"]
        try:
            subprocess.run(ecmd, check=True, capture_output=True)
            logger.success(f"[enforce] ebtables DROP for MAC {mac}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"[enforce] ebtables failed (may not be installed): {e}")
    
    if ip:
        # Block IP address using iptables
        icmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(icmd, check=True, capture_output=True)
            logger.success(f"[enforce] iptables DROP for IP {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"[enforce] iptables failed: {e}")
