#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENGINE_BIN="$PROJECT_ROOT/c_dpi_engine/bin/dpi_mqtt_analyzer"

if [[ ! -x "$ENGINE_BIN" ]]; then
  echo "[ERROR] Missing analyzer binary: $ENGINE_BIN"
  echo "Run: ./bin/iwsn build"
  exit 1
fi

IFACE="${1:-${IWSN_LIVE_INTERFACE:-any}}"
DURATION="${2:-${IWSN_BENCH_DURATION_SECONDS:-20}}"
FILTER="${3:-${IWSN_LIVE_BPF_FILTER:-}}"

USE_SUDO="${IWSN_BENCH_USE_SUDO:-0}"
if [[ "$USE_SUDO" == "1" && ${EUID:-0} -ne 0 ]]; then
  exec sudo "$0" "$@"
fi

if [[ ${EUID:-0} -ne 0 ]]; then
  echo "[WARN] Running without root. Live capture may fail on some interfaces."
  echo "[WARN] To force sudo: IWSN_BENCH_USE_SUDO=1 ./bin/iwsn benchmark-live ..."
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]]; then
  echo "[ERROR] Duration must be an integer number of seconds"
  exit 1
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$PROJECT_ROOT/visualization/reports/live_bench_$timestamp"
mkdir -p "$OUT_DIR"

profiles=(
  "baseline:1:1:4096"
  "balanced:2:4:8192"
  "high-throughput:4:8:16384"
)

run_profile() {
  local name="$1"
  local ids="$2"
  local mqtt="$3"
  local queue="$4"
  local log_file="$OUT_DIR/${name}.log"

  echo "[RUN] $name (IDS=$ids MQTT=$mqtt QUEUE=$queue)"

  if env \
    IWSN_CAPTURE_MODE=live \
    IWSN_AUTOMATED_LIVE_CONFIG=1 \
    IWSN_LIVE_INTERFACE="$IFACE" \
    IWSN_LIVE_DURATION_SECONDS="$DURATION" \
    IWSN_LIVE_MAX_PACKETS=0 \
    IWSN_LIVE_PROMISCUOUS=1 \
    IWSN_IDS_WORKERS="$ids" \
    IWSN_MQTT_WORKERS="$mqtt" \
    IWSN_PIPELINE_QUEUE_CAPACITY="$queue" \
    IWSN_LIVE_BPF_FILTER="$FILTER" \
    "$ENGINE_BIN" >"$log_file" 2>&1; then
    status="ok"
  else
    status="failed"
  fi

  local packets captured_pps ids_processed mqtt_processed drops_ids drops_mqtt hwm_ids hwm_mqtt
  packets="$(grep -E "Packets Captured:" "$log_file" | tail -n1 | awk '{print $3}')"
  captured_pps="$(grep -E "Packets/sec:" "$log_file" | tail -n1 | awk '{print $2}')"
  ids_processed="$(grep -E "Pipeline processed:" "$log_file" | tail -n1 | sed -E 's/.*IDS=([0-9]+).*/\1/')"
  mqtt_processed="$(grep -E "Pipeline processed:" "$log_file" | tail -n1 | sed -E 's/.*MQTT=([0-9]+).*/\1/')"
  drops_ids="$(grep -E "Queue drops:" "$log_file" | tail -n1 | sed -E 's/.*IDS=([0-9]+).*/\1/' || true)"
  drops_mqtt="$(grep -E "Queue drops:" "$log_file" | tail -n1 | sed -E 's/.*MQTT=([0-9]+).*/\1/' || true)"
  hwm_ids="$(grep -E "Queue high watermark:" "$log_file" | tail -n1 | sed -E 's/.*IDS=([0-9]+).*/\1/' || true)"
  hwm_mqtt="$(grep -E "Queue high watermark:" "$log_file" | tail -n1 | sed -E 's/.*MQTT=([0-9]+).*/\1/' || true)"

  packets="${packets:-0}"
  captured_pps="${captured_pps:-0}"
  ids_processed="${ids_processed:-0}"
  mqtt_processed="${mqtt_processed:-0}"
  drops_ids="${drops_ids:-0}"
  drops_mqtt="${drops_mqtt:-0}"
  hwm_ids="${hwm_ids:-0}"
  hwm_mqtt="${hwm_mqtt:-0}"

  echo "$name,$ids,$mqtt,$queue,$packets,$captured_pps,$ids_processed,$mqtt_processed,$drops_ids,$drops_mqtt,$hwm_ids,$hwm_mqtt,$status,$log_file" >>"$OUT_DIR/summary.csv"
}

generate_recommendation() {
  local rec_file="$OUT_DIR/recommendation.txt"

  awk -F',' '
    BEGIN {
      best_score = -1.0
      best_name = ""
      best_ids = 0
      best_mqtt = 0
      best_queue = 0
      ok_count = 0
      print "profile,ids_workers,mqtt_workers,queue_capacity,packets_captured,packets_per_sec,ids_processed,mqtt_processed,queue_drops_ids,queue_drops_mqtt,queue_hwm_ids,queue_hwm_mqtt,status,score"
    }
    NR == 1 { next }
    {
      profile = $1
      ids = $2 + 0
      mqtt = $3 + 0
      queue = $4 + 0
      packets = $5 + 0
      pps = $6 + 0
      ids_processed = $7 + 0
      mqtt_processed = $8 + 0
      drop_ids = $9 + 0
      drop_mqtt = $10 + 0
      hwm_ids = $11 + 0
      hwm_mqtt = $12 + 0
      status = $13

      score = 0.0
      if (status == "ok") {
        ok_count++
        # Reward throughput, penalize drops heavily and high queue pressure lightly.
        score = pps - ((drop_ids + drop_mqtt) * 250.0) - (((hwm_ids + hwm_mqtt) / 2.0) * 0.05)
        if (score > best_score) {
          best_score = score
          best_name = profile
          best_ids = ids
          best_mqtt = mqtt
          best_queue = queue
        }
      } else {
        score = -1.0
      }

      printf "%s,%d,%d,%d,%d,%.3f,%d,%d,%d,%d,%d,%d,%s,%.3f\n", \
             profile, ids, mqtt, queue, packets, pps, ids_processed, mqtt_processed, \
             drop_ids, drop_mqtt, hwm_ids, hwm_mqtt, status, score
    }
    END {
      if (ok_count > 0) {
        printf "BEST,%s,%d,%d,%d,score=%.3f\n", best_name, best_ids, best_mqtt, best_queue, best_score > "/dev/stderr"
      } else {
        printf "BEST,NONE,0,0,0,score=-1\n" > "/dev/stderr"
      }
    }
  ' "$OUT_DIR/summary.csv" >"$OUT_DIR/scored_summary.csv" 2>"$OUT_DIR/.best.tmp"

  {
    echo "Live Benchmark Recommendation"
    echo "============================="
    echo ""
    if grep -q "^BEST,NONE" "$OUT_DIR/.best.tmp"; then
      echo "No successful profile run was detected."
      echo ""
      echo "Suggested next run:"
      echo "  IWSN_BENCH_USE_SUDO=1 ./bin/iwsn benchmark-live ${IFACE} ${DURATION} \"${FILTER}\""
    else
      local best_line
      best_line="$(grep '^BEST,' "$OUT_DIR/.best.tmp")"
      local best_profile best_ids best_mqtt best_queue best_score
      IFS=',' read -r _ best_profile best_ids best_mqtt best_queue best_score <<<"$best_line"
      echo "Recommended profile: ${best_profile}"
      echo "IDS workers: ${best_ids}"
      echo "MQTT workers: ${best_mqtt}"
      echo "Queue capacity: ${best_queue}"
      echo "${best_score}"
      echo ""
      echo "Recommended live command:"
      echo "  IWSN_IDS_WORKERS=${best_ids} IWSN_MQTT_WORKERS=${best_mqtt} IWSN_PIPELINE_QUEUE_CAPACITY=${best_queue} ./bin/iwsn live"
    fi
  } >"$rec_file"

  rm -f "$OUT_DIR/.best.tmp"
}

echo "profile,ids_workers,mqtt_workers,queue_capacity,packets_captured,packets_per_sec,ids_processed,mqtt_processed,queue_drops_ids,queue_drops_mqtt,queue_hwm_ids,queue_hwm_mqtt,status,log" >"$OUT_DIR/summary.csv"

for p in "${profiles[@]}"; do
  IFS=':' read -r name ids mqtt queue <<<"$p"
  run_profile "$name" "$ids" "$mqtt" "$queue"
  echo "[DONE] $name"
  echo ""
done

generate_recommendation

echo "========================================"
echo "Live benchmark finished"
echo "Interface: $IFACE"
echo "Duration per profile: ${DURATION}s"
echo "Summary: $OUT_DIR/summary.csv"
echo "Scored summary: $OUT_DIR/scored_summary.csv"
echo "Recommendation: $OUT_DIR/recommendation.txt"
echo "Logs: $OUT_DIR/*.log"
echo "========================================"

column -s, -t "$OUT_DIR/summary.csv" | sed 's/^/  /'
echo ""
column -s, -t "$OUT_DIR/scored_summary.csv" | sed 's/^/  /'
