#!/usr/bin/env python3
"""
ovs_telemetry_bridge.py
──────────────────────────────────────────────────────────────────────────────
Sidecar telemetry bridge:  OVS/ODL OpenFlow statistics  →  InfluxDB + SDN Controller

Runs on the IWSN node (or on the controller host).  Every --interval seconds:

  1. Polls ODL RESTCONF for port (connector) statistics for each OpenFlow node.
  2. Writes the stats to InfluxDB (same bucket used by Grafana) so live dashboards
     see OVS data alongside DPI/IDS data.
  3. Pushes a summary flow_stats + heartbeat to the SDN controller via WebSocket
     so the controller DB also has network-level counters.

Usage:
    # With ODL + InfluxDB running:
    python3 ovs_telemetry_bridge.py \
        --odl-url http://127.0.0.1:8181 \
        --controller-url ws://127.0.0.1:8765 \
        --influx-url http://127.0.0.1:8086 \
        --influx-token <your-token> \
        --influx-org iwsn \
        --influx-bucket iwsn_metrics \
        --node-id ovs-telemetry-bridge \
        --interval 5

    # Without InfluxDB (ODL→controller only):
    python3 ovs_telemetry_bridge.py \
        --odl-url http://127.0.0.1:8181 \
        --controller-url ws://127.0.0.1:8765 \
        --node-id ovs-telemetry-bridge \
        --interval 5

Requirements:  httpx, websockets, loguru  (all in venv)
    pip install httpx websockets loguru influxdb-client
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx
from loguru import logger

# ── Optional InfluxDB ──────────────────────────────────────────────────────
try:
    from influxdb_client import InfluxDBClient, WriteOptions
    from influxdb_client.client.write_api import SYNCHRONOUS
    from influxdb_client.domain.write_precision import WritePrecision
    INFLUX_AVAILABLE = True
except ImportError:
    INFLUX_AVAILABLE = False
    logger.warning("influxdb-client not installed – InfluxDB writes disabled")

# ── Path setup for node_client ─────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
_CANDIDATES = [_HERE, _HERE.parent / "server" / "iwsn_controller", _HERE.parent]
for _c in _CANDIDATES:
    if (_c / "node_client.py").exists():
        sys.path.insert(0, str(_c))
        break


# ══════════════════════════════════════════════════════════════════════════════
#  ODL RESTCONF poller
# ══════════════════════════════════════════════════════════════════════════════

class ODLPoller:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.headers = {"Accept": "application/json"}

    async def get_openflow_nodes(self) -> list[str]:
        """Return list of connected OpenFlow node IDs, e.g. ['openflow:12345']."""
        url = f"{self.base_url}/restconf/operational/opendaylight-inventory:nodes"
        try:
            async with httpx.AsyncClient(timeout=8.0) as c:
                r = await c.get(url, auth=self.auth, headers=self.headers)
                r.raise_for_status()
                data = r.json()
                nodes = data.get("nodes", {}).get("node", [])
                return [n["id"] for n in nodes if isinstance(n.get("id"), str)
                        and n["id"].startswith("openflow:")]
        except Exception as exc:
            logger.warning(f"[odl] get_openflow_nodes: {exc}")
            return []

    async def get_node_connector_stats(self, node_id: str) -> list[dict[str, Any]]:
        """
        Fetch per-port statistics for a specific OVS switch.
        Returns list of connector dicts with rx/tx counters.
        """
        url = (
            f"{self.base_url}/restconf/operational/opendaylight-inventory:nodes"
            f"/node/{node_id}"
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(url, auth=self.auth, headers=self.headers)
                r.raise_for_status()
                node_data = r.json().get("node", [{}])[0]
                connectors = node_data.get("node-connector", [])
                result = []
                for conn in connectors:
                    conn_id = conn.get("id", "")
                    # Skip LOCAL (internal OVS port) and controller port
                    if "LOCAL" in conn_id.upper():
                        continue
                    stats = conn.get(
                        "opendaylight-port-statistics:flow-capable-node-connector-statistics", {}
                    )
                    if not stats:
                        continue
                    rx = stats.get("bytes", {}).get("received", 0)
                    tx = stats.get("bytes", {}).get("transmitted", 0)
                    rx_pkts = stats.get("packets", {}).get("received", 0)
                    tx_pkts = stats.get("packets", {}).get("transmitted", 0)
                    rx_drop = stats.get("receive-drops", 0)
                    tx_drop = stats.get("transmit-drops", 0)
                    rx_err  = stats.get("receive-errors", 0)
                    result.append({
                        "connector_id": conn_id,
                        "node_id":      node_id,
                        "rx_bytes":     int(rx),
                        "tx_bytes":     int(tx),
                        "rx_packets":   int(rx_pkts),
                        "tx_packets":   int(tx_pkts),
                        "rx_drops":     int(rx_drop),
                        "tx_drops":     int(tx_drop),
                        "rx_errors":    int(rx_err),
                    })
                return result
        except Exception as exc:
            logger.warning(f"[odl] get_connector_stats({node_id}): {exc}")
            return []

    async def get_flow_stats_summary(self, node_id: str) -> dict[str, Any]:
        """Get aggregate flow table statistics for the node."""
        url = (
            f"{self.base_url}/restconf/operational/opendaylight-inventory:nodes"
            f"/node/{node_id}/table/0"
        )
        try:
            async with httpx.AsyncClient(timeout=8.0) as c:
                r = await c.get(url, auth=self.auth, headers=self.headers)
                r.raise_for_status()
                table_data = r.json().get("flow-node-inventory:table", [{}])[0]
                tbl_stats = table_data.get(
                    "opendaylight-flow-table-statistics:flow-table-statistics", {}
                )
                return {
                    "active_flows":     int(tbl_stats.get("active-flows",     0)),
                    "packets_looked_up": int(tbl_stats.get("packets-looked-up", 0)),
                    "packets_matched":  int(tbl_stats.get("packets-matched",  0)),
                }
        except Exception as exc:
            logger.debug(f"[odl] flow_stats_summary({node_id}): {exc}")
            return {"active_flows": 0, "packets_looked_up": 0, "packets_matched": 0}


# ══════════════════════════════════════════════════════════════════════════════
#  InfluxDB writer
# ══════════════════════════════════════════════════════════════════════════════

class InfluxWriter:
    def __init__(self, url: str, token: str, org: str, bucket: str):
        self._client = InfluxDBClient(url=url, token=token, org=org)
        self._write  = self._client.write_api(write_options=SYNCHRONOUS)
        self._bucket = bucket
        self._org    = org

    def write_connector_stats(self, stats_list: list[dict[str, Any]]):
        """Write OVS port counters to InfluxDB measurement 'ovs_port_stats'."""
        points = []
        ts = int(time.time_ns())
        for s in stats_list:
            p = (
                f"ovs_port_stats,"
                f"node_id={s['node_id'].replace(':','_')},"
                f"connector={s['connector_id'].replace(':','_').replace('/','_')} "
                f"rx_bytes={s['rx_bytes']}i,"
                f"tx_bytes={s['tx_bytes']}i,"
                f"rx_packets={s['rx_packets']}i,"
                f"tx_packets={s['tx_packets']}i,"
                f"rx_drops={s['rx_drops']}i,"
                f"tx_drops={s['tx_drops']}i,"
                f"rx_errors={s['rx_errors']}i "
                f"{ts}"
            )
            points.append(p)
        if points:
            self._write.write(bucket=self._bucket, org=self._org,
                              record="\n".join(points),
                              write_precision=WritePrecision.NANOSECONDS)

    def write_flow_table_stats(self, node_id: str, stats: dict[str, Any]):
        """Write OVS flow table counters to InfluxDB measurement 'ovs_flow_table'."""
        ts = int(time.time_ns())
        p = (
            f"ovs_flow_table,"
            f"node_id={node_id.replace(':','_')} "
            f"active_flows={stats['active_flows']}i,"
            f"packets_looked_up={stats['packets_looked_up']}i,"
            f"packets_matched={stats['packets_matched']}i "
            f"{ts}"
        )
        self._write.write(bucket=self._bucket, org=self._org, record=p,
                          write_precision=WritePrecision.NANOSECONDS)

    def close(self):
        self._client.close()


# ══════════════════════════════════════════════════════════════════════════════
#  Main polling loop
# ══════════════════════════════════════════════════════════════════════════════

async def run(args: argparse.Namespace):
    odl = ODLPoller(args.odl_url, args.odl_user, args.odl_password)

    # InfluxDB (optional)
    influx: InfluxWriter | None = None
    if INFLUX_AVAILABLE and args.influx_url and args.influx_token:
        influx = InfluxWriter(
            url=args.influx_url,
            token=args.influx_token,
            org=args.influx_org,
            bucket=args.influx_bucket,
        )
        logger.info(f"[influx] Writing to {args.influx_url} bucket={args.influx_bucket}")
    else:
        logger.info("[influx] InfluxDB disabled (no --influx-url / --influx-token)")

    # SDN Controller WebSocket (optional)
    sdn_client = None
    if args.controller_url:
        try:
            from node_client import SDNNodeClient  # type: ignore
            sdn_client = SDNNodeClient(
                controller_url=args.controller_url,
                node_id=args.node_id,
                ip="127.0.0.1",
                capabilities=["ovs_telemetry", "restconf_poller"],
                mode="live",
                reconnect_delay=5.0,
            )
            asyncio.create_task(sdn_client.connect())
            await asyncio.sleep(2.0)
            logger.info(f"[sdn] Connected to controller at {args.controller_url}")
        except Exception as exc:
            logger.warning(f"[sdn] Could not connect: {exc}")

    logger.info(f"[ovs-bridge] Polling ODL every {args.interval}s …")

    iteration = 0
    while True:
        iteration += 1
        try:
            node_ids = await odl.get_openflow_nodes()
            if not node_ids:
                logger.debug("[odl] No OpenFlow nodes visible yet")
            else:
                logger.info(f"[odl] Polling {len(node_ids)} node(s): {node_ids}")

            for nid in node_ids:
                connectors = await odl.get_node_connector_stats(nid)
                flow_stats = await odl.get_flow_stats_summary(nid)

                # Aggregate totals for WebSocket push
                total_rx_bytes   = sum(c["rx_bytes"]   for c in connectors)
                total_tx_bytes   = sum(c["tx_bytes"]   for c in connectors)
                total_rx_packets = sum(c["rx_packets"] for c in connectors)
                total_tx_packets = sum(c["tx_packets"] for c in connectors)

                logger.info(
                    f"[odl] {nid}: ports={len(connectors)} "
                    f"rx={total_rx_bytes}B tx={total_tx_bytes}B "
                    f"active_flows={flow_stats['active_flows']}"
                )

                # Write to InfluxDB
                if influx and connectors:
                    influx.write_connector_stats(connectors)
                    influx.write_flow_table_stats(nid, flow_stats)

                # Push to SDN controller via WebSocket
                if sdn_client:
                    await sdn_client.send_flow({
                        "flow_key":   f"ovs:{nid}:aggregate:{iteration}",
                        "protocol":   "ANY",
                        "l7_protocol": "OVS_STATS",
                        "src_ip":     "ovs",
                        "src_port":   0,
                        "dst_ip":     "odl",
                        "dst_port":   6653,
                        "src_mac":    "",
                        "bytes_in":   total_rx_bytes,
                        "bytes_out":  total_tx_bytes,
                        "packets_in": total_rx_packets,
                        "packets_out": total_tx_packets,
                        "duration_ms": int(args.interval * 1000),
                        "raw_stats": {
                            "source":       "ovs_telemetry_bridge",
                            "openflow_node": nid,
                            "active_flows": flow_stats["active_flows"],
                            "pkts_matched": flow_stats["packets_matched"],
                            "connectors":   len(connectors),
                        },
                    })

                    await sdn_client.send_heartbeat(
                        load_pct=0.0,
                        flows_active=flow_stats["active_flows"],
                        alerts_pending=0,
                    )

        except Exception as exc:
            logger.error(f"[loop] Unhandled error: {exc}")

        await asyncio.sleep(args.interval)


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description="OVS/ODL telemetry bridge for IWSN")
    p.add_argument("--odl-url",        default="http://127.0.0.1:8181",  help="ODL RESTCONF base URL")
    p.add_argument("--odl-user",       default="admin")
    p.add_argument("--odl-password",   default="admin")
    p.add_argument("--controller-url", default="ws://127.0.0.1:8765",    help="IWSN SDN controller WS URL (blank to disable)")
    p.add_argument("--node-id",        default="ovs-telemetry-bridge",   help="Node ID registered with controller")
    p.add_argument("--influx-url",     default="",                        help="InfluxDB v2 URL (blank to disable)")
    p.add_argument("--influx-token",   default="",                        help="InfluxDB API token")
    p.add_argument("--influx-org",     default="iwsn")
    p.add_argument("--influx-bucket",  default="iwsn_metrics")
    p.add_argument("--interval",       type=float, default=5.0,           help="Poll interval in seconds")
    args = p.parse_args()

    logger.info("=== IWSN OVS Telemetry Bridge starting ===")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
