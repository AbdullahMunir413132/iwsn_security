#!/bin/bash
# ============================================================
# IWSN Node OVS Setup — Physical Multi-Node Deployment
# ============================================================
# Sets up an Open vSwitch bridge (br0) with a deterministic
# OpenFlow Datapath ID (DPID) so the ODL controller sees each
# physical device as a predictable openflow:N node.
#
# DPID ↔ ODL node-id mapping:
#   node_num=1 → DPID=0000000000000001 → openflow:1
#   node_num=2 → DPID=0000000000000002 → openflow:2
#   node_num=3 → DPID=0000000000000003 → openflow:3
#   node_num=4 → DPID=0000000000000004 → openflow:4
#
# Usage (run as root or with sudo bash):
#   sudo bash setup_node_ovs.sh <server_ip> <of_port> <iface> <node_num>
#
# Example — Node 2, server at 192.168.1.10, OVS port 6653, iface wlan0:
#   sudo bash setup_node_ovs.sh 192.168.1.10 6653 wlan0 2
#
# After running, OVS reports telemetry to ODL natively via OpenFlow on port 6653.
# Use ovs_telemetry_bridge.py to push OVS port stats to InfluxDB + the FastAPI controller.

set -euo pipefail

# ── Argument parsing ─────────────────────────────────────────
if [[ $# -lt 4 ]]; then
    echo "Usage: sudo bash $0 <server_ip> <of_port> <iface> <node_num>"
    echo "  server_ip  – IP of the IWSN controller / ODL server"
    echo "  of_port    – OpenFlow port (usually 6653)"
    echo "  iface      – Physical network interface (e.g. wlan0 wlp2s0 eth0)"
    echo "  node_num   – Node number 1–4 (sets deterministic OpenFlow DPID)"
    echo ""
    echo "  Example: sudo bash $0 192.168.1.10 6653 wlan0 2"
    exit 1
fi

SERVER_IP="$1"
OF_PORT="$2"
IFACE="$3"
NODE_NUM="$4"

# ── Validate inputs ──────────────────────────────────────────
if [[ ! "$NODE_NUM" =~ ^[1-4]$ ]]; then
    echo "[ERROR] node_num must be 1, 2, 3, or 4.  Got: $NODE_NUM"
    exit 1
fi

if ! ip link show "$IFACE" &>/dev/null; then
    echo "[ERROR] Interface '$IFACE' not found. Available interfaces:"
    ip -br link show
    exit 1
fi

# Zero-padded 16-hex DPID: node 2 → 0000000000000002
DPID=$(printf "%016d" "$NODE_NUM")
DPID_HEX=$(printf "%016x" "$NODE_NUM")
NODE_ID="iwsn-node-0${NODE_NUM}"
OPENFLOW_ID="openflow:${NODE_NUM}"

echo "============================================================"
echo " IWSN Node OVS Setup"
echo "  Node number  : $NODE_NUM  ($NODE_ID)"
echo "  OpenFlow ID  : $OPENFLOW_ID"
echo "  DPID (hex)   : $DPID_HEX"
echo "  Interface    : $IFACE"
echo "  ODL server   : tcp:$SERVER_IP:$OF_PORT"
echo "============================================================"

# ── Check prerequisites ──────────────────────────────────────
if ! command -v ovs-vsctl &>/dev/null; then
    echo "[*] Installing Open vSwitch..."
    apt-get update -qq && apt-get install -y openvswitch-switch openvswitch-common
fi

if ! systemctl is-active --quiet ovsdb-server 2>/dev/null; then
    echo "[*] Starting OVS services..."
    systemctl start openvswitch-switch || service openvswitch-switch start || true
fi

# ── Remove existing bridge if present ───────────────────────
if ovs-vsctl br-exists br0 2>/dev/null; then
    echo "[*] Removing existing br0..."
    ovs-vsctl del-br br0 || true
fi

# ── Migrate IP from physical interface to br0 ────────────────
# Read current IP (if any) before adding to bridge
CURRENT_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet )\S+' | head -1 || true)
CURRENT_GW=$(ip route show default | grep "$IFACE" | grep -oP '(?<=via )\S+' | head -1 || true)

echo "[*] Creating OVS bridge br0..."
ovs-vsctl add-br br0

# ── Set deterministic Datapath ID ────────────────────────────
echo "[*] Setting DPID = $DPID_HEX  (→ $OPENFLOW_ID in ODL)"
ovs-vsctl set bridge br0 other-config:datapath-id="$DPID_HEX"

# ── Add physical interface as uplink port ────────────────────
echo "[*] Adding $IFACE to br0..."
ovs-vsctl add-port br0 "$IFACE"

# ── Configure OpenFlow protocol ──────────────────────────────
ovs-vsctl set bridge br0 protocols=OpenFlow13
ovs-vsctl set bridge br0 fail-mode=standalone   # forward normally if ODL is down

# ── Connect to ODL controller ────────────────────────────────
echo "[*] Connecting to ODL at tcp:$SERVER_IP:$OF_PORT ..."
ovs-vsctl set-controller br0 "tcp:$SERVER_IP:$OF_PORT"

# ── Restore IP on br0 if the physical iface had one ──────────
if [[ -n "$CURRENT_IP" ]]; then
    echo "[*] Migrating IP $CURRENT_IP from $IFACE → br0..."
    ip addr del "$CURRENT_IP" dev "$IFACE" 2>/dev/null || true
    ip addr add "$CURRENT_IP" dev br0
    ip link set br0 up
    if [[ -n "$CURRENT_GW" ]]; then
        ip route replace default via "$CURRENT_GW" dev br0 2>/dev/null || true
    fi
else
    ip link set br0 up
fi

# ── Verify ───────────────────────────────────────────────────
echo ""
echo "[+] OVS bridge status:"
ovs-vsctl show
echo ""
echo "[+] Bridge DPID:"
ovs-vsctl get bridge br0 datapath-id 2>/dev/null || echo "  (run: ovs-vsctl get bridge br0 datapath-id)"

# ── Install systemd service ──────────────────────────────────
echo "[*] Installing systemd service: ovs-iwsn-node${NODE_NUM}.service"
cat > "/etc/systemd/system/ovs-iwsn-node${NODE_NUM}.service" << EOF
[Unit]
Description=IWSN OVS Bridge Node ${NODE_NUM} (DPID=${DPID_HEX}, controller=${SERVER_IP}:${OF_PORT})
After=network.target openvswitch-switch.service
Wants=openvswitch-switch.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash -c " \\
    ovs-vsctl br-exists br0 || ovs-vsctl add-br br0; \\
    ovs-vsctl set bridge br0 other-config:datapath-id=${DPID_HEX}; \\
    ovs-vsctl set bridge br0 protocols=OpenFlow13; \\
    ovs-vsctl set bridge br0 fail-mode=standalone; \\
    ovs-vsctl set-controller br0 tcp:${SERVER_IP}:${OF_PORT}; \\
    ip link set br0 up"
ExecStop=/usr/bin/ovs-vsctl del-br br0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "ovs-iwsn-node${NODE_NUM}.service"

echo ""
echo "============================================================"
echo " Setup complete!"
echo ""
echo "  OpenFlow node ID : $OPENFLOW_ID"
echo "  DPID             : $DPID_HEX"
echo "  Controller target: tcp:$SERVER_IP:$OF_PORT"
echo ""
echo "  Verify connection (after ODL starts):"
echo "    ovs-vsctl show"
echo "    ovs-ofctl dump-flows br0"
echo ""
echo "  OVS is now reporting telemetry to ODL via OpenFlow on port 6653."
echo "  To start the full node daemon pipeline:"
echo "    cd ~/test/iwsn_security"
echo "    source ~/test/.venv/bin/activate"
echo "    ./bin/iwsn node-start --server-ip $SERVER_IP --node-num $NODE_NUM --iface $IFACE"
echo "============================================================"
