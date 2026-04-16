#!/usr/bin/env python3
"""
Minimal wireless client test for IWSN SDN Controller.

Runs from /home/saad-kashif/test and imports SDK from ./files/node_client.py.
"""

from __future__ import annotations

import argparse
import asyncio

from node_client import SDNNodeClient  # noqa: E402


async def run_once(controller_url: str, node_id: str, ip: str) -> None:
    received: list[dict] = []

    async def on_flow_rule(payload: dict) -> None:
        print("[NODE] <- FLOW RULE:", payload)
        received.append({"type": "flow_rule", **payload})

    async def on_quarantine(payload: dict) -> None:
        print("[NODE] <- QUARANTINE:", payload)
        received.append({"type": "quarantine", **payload})

    async def on_policy_update(payload: dict) -> None:
        policies = payload.get("policies", [])
        print(f"[NODE] <- POLICY UPDATE: {len(policies)} policies")

    async def on_alert_broadcast(payload: dict) -> None:
        print("[NODE] <- ALERT BROADCAST:", payload)
        received.append({"type": "alert_broadcast", **payload})

    client = SDNNodeClient(
        controller_url=controller_url,
        node_id=node_id,
        ip=ip,
        capabilities=["dpi", "mqtt", "live_capture"],
        reconnect_delay=3.0,
    )
    client.on_flow_rule = on_flow_rule
    client.on_quarantine = on_quarantine
    client.on_policy_update = on_policy_update
    client.on_alert_broadcast = on_alert_broadcast

    connect_task = asyncio.create_task(client.connect())
    await asyncio.sleep(2.0)

    # Send one flow message
    await client.send_flow(
        {
            "flow_key": f"{ip}:50000->10.0.0.1:1883",
            "protocol": "TCP",
            "l7_protocol": "MQTT",
            "src_ip": ip,
            "src_port": 50000,
            "dst_ip": "10.0.0.1",
            "dst_port": 1883,
            "src_mac": "AA:BB:CC:DD:EE:50",
            "bytes_in": 1200,
            "bytes_out": 800,
            "packets_in": 12,
            "packets_out": 8,
            "duration_ms": 500,
        }
    )
    print("[NODE] -> flow_stats sent")

    # Send one critical alert
    await client.send_alert(
        {
            "alert_type": "port_scan",
            "severity": "critical",
            "src_ip": "192.168.1.200",
            "src_mac": "DE:AD:BE:EF:00:01",
            "dst_ip": "10.0.0.1",
            "flow_key": "test-scan-flow",
            "description": "test alert from wireless client",
            "extra": {"ports": 20, "window_sec": 3},
        }
    )
    print("[NODE] -> attack_alert sent")

    # Send one sensor value
    await client.send_sensor(
        {
            "device_id": "sensor-01",
            "topic": "iwsn/temp/zone-a",
            "sensor_type": "temperature",
            "value": 24.1,
            "unit": "C",
            "quality": "good",
            "raw": {"source": "run_client_test.py"},
        }
    )
    print("[NODE] -> mqtt_sensor sent")

    # Send heartbeat
    await client.send_heartbeat(load_pct=20.0, flows_active=1, alerts_pending=0)
    print("[NODE] -> heartbeat sent")

    await asyncio.sleep(4.0)
    connect_task.cancel()
    print(f"Done. Received {len(received)} controller command(s).")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IWSN SDN client test runner")
    parser.add_argument(
        "--controller-url",
        default="ws://127.0.0.1:8765",
        help="Controller base URL (example: ws://192.168.1.40:8765)",
    )
    parser.add_argument("--node-id", default="client-node-01", help="Unique node ID")
    parser.add_argument("--ip", default="192.168.1.50", help="Client device IP")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asyncio.run(run_once(args.controller_url, args.node_id, args.ip))


if __name__ == "__main__":
    main()
