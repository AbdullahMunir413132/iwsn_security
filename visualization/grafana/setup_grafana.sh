#!/bin/bash
#
# IWSN Security - Grafana Real-Time Monitoring Setup
# Starts InfluxDB + Grafana via Docker Compose, then pushes metrics.
#
# Usage:
#   ./setup_grafana.sh                    # Start stack only
#   ./setup_grafana.sh ../c_dpi_engine    # Start stack + push existing metrics
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     IWSN Security - Grafana Real-Time Monitoring Setup      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Check Docker ──────────────────────────────────────────────────
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed."
    echo ""
    echo "  Install Docker:"
    echo "    curl -fsSL https://get.docker.com | sh"
    echo "    sudo usermod -aG docker \$USER"
    echo "    # Log out and back in, then re-run this script"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not installed."
    echo ""
    echo "  Install Docker Compose:"
    echo "    sudo apt install docker-compose-plugin"
    exit 1
fi

print_success "Docker and Docker Compose found"

# ── Determine compose command ─────────────────────────────────────
if docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

# ── Start the stack ───────────────────────────────────────────────
print_info "Starting InfluxDB + Grafana containers..."
cd "$SCRIPT_DIR"
$COMPOSE_CMD up -d

if [ $? -ne 0 ]; then
    print_error "Failed to start Docker containers."
    echo "  Try: sudo $COMPOSE_CMD up -d"
    exit 1
fi

print_success "Containers started"

# ── Helper: check service health ──────────────────────────────────
check_health() {
    local url="$1" pattern="$2"
    if command -v curl &> /dev/null; then
        curl -s "$url" 2>/dev/null | grep -q "$pattern" 2>/dev/null
    elif command -v wget &> /dev/null; then
        wget -qO- "$url" 2>/dev/null | grep -q "$pattern" 2>/dev/null
    else
        # Fallback: use docker exec to check from inside the container
        if [ "$url" = "http://localhost:8086/health" ]; then
            docker exec iwsn_influxdb influx ping &> /dev/null
        elif [ "$url" = "http://localhost:3000/api/health" ]; then
            docker exec iwsn_grafana wget -qO- http://localhost:3000/api/health 2>/dev/null | grep -q "$pattern" 2>/dev/null
        else
            return 1
        fi
    fi
}

# ── Wait for InfluxDB to be ready ─────────────────────────────────
print_info "Waiting for InfluxDB to initialize..."
for i in $(seq 1 30); do
    if check_health "http://localhost:8086/health" '"status":"pass"'; then
        print_success "InfluxDB is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        print_warn "InfluxDB may still be starting. Continuing anyway..."
    fi
    sleep 1
done

# ── Wait for Grafana to be ready ──────────────────────────────────
print_info "Waiting for Grafana to initialize..."
for i in $(seq 1 30); do
    if check_health "http://localhost:3000/api/health" '"database"'; then
        print_success "Grafana is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        print_warn "Grafana may still be starting. Continuing anyway..."
    fi
    sleep 1
done

# ── Install Python dependency ─────────────────────────────────────
print_info "Checking Python influxdb-client package..."
if python3 -c "import influxdb_client" 2>/dev/null; then
    print_success "influxdb-client already installed"
else
    print_info "Installing influxdb-client..."
    # Try multiple install methods (newer Python requires --break-system-packages)
    INSTALLED=0
    pip3 install influxdb-client 2>/dev/null && INSTALLED=1
    if [ $INSTALLED -eq 0 ]; then
        pip3 install --break-system-packages influxdb-client 2>/dev/null && INSTALLED=1
    fi
    if [ $INSTALLED -eq 0 ]; then
        python3 -m pip install influxdb-client 2>/dev/null && INSTALLED=1
    fi
    if [ $INSTALLED -eq 0 ]; then
        python3 -m pip install --break-system-packages influxdb-client 2>/dev/null && INSTALLED=1
    fi
    if [ $INSTALLED -eq 1 ]; then
        print_success "influxdb-client installed"
    else
        print_warn "Could not auto-install influxdb-client."
        echo "  Try one of these manually:"
        echo "    pip3 install --break-system-packages influxdb-client"
        echo "    sudo pip3 install influxdb-client"
        echo "    python3 -m pip install influxdb-client"
    fi
fi

# ── Push existing metrics if directory provided ───────────────────
BASE_DIR="${1:-$PROJECT_ROOT/c_dpi_engine}"
if [ -d "$BASE_DIR" ] && [ -f "$BASE_DIR/performance_metrics.txt" ]; then
    echo ""
    print_info "Pushing existing metrics from: $BASE_DIR"
    python3 "$SCRIPT_DIR/push_metrics.py" "$BASE_DIR"
fi

# ── Print summary ─────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            Grafana Real-Time Dashboard Ready!               ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                             ║"
echo "║  Grafana:   http://localhost:3000                           ║"
echo "║  Login:     admin / iwsn_security                           ║"
echo "║  InfluxDB:  http://localhost:8086                           ║"
echo "║                                                             ║"
echo "║  Push metrics after analysis:                               ║"
echo "║    python3 push_metrics.py ../c_dpi_engine                  ║"
echo "║                                                             ║"
echo "║  Watch mode (auto-push on file change):                     ║"
echo "║    python3 push_metrics.py ../c_dpi_engine --watch          ║"
echo "║                                                             ║"
echo "║  Stop:  docker compose down                                 ║"
echo "║  Logs:  docker compose logs -f                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
