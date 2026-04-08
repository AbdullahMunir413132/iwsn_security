#!/usr/bin/env python3

import json
import sys
from datetime import datetime
from pathlib import Path


def pct(value):
    return f"{value * 100:.1f}%"


def load_results(results_path: Path):
    with results_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_rows(results):
    rows = []
    for item in results.get("per_attack_results", []):
        status = item.get("result_type", "unknown")
        icon = "✅" if status in {"true_positive", "true_negative"} else "❌"
        rows.append(
            """
            <tr>
                <td>{name}</td>
                <td>{attack_type}</td>
                <td>{status_icon} {status}</td>
                <td>{detections}</td>
                <td>{mqtt_flows}</td>
                <td>{mqtt_messages}</td>
                <td>{elapsed:.3f}s</td>
            </tr>
            """.format(
                name=item.get("name", "-"),
                attack_type=item.get("attack_type", "-"),
                status_icon=icon,
                status=status,
                detections=item.get("detections", 0),
                mqtt_flows=item.get("mqtt_flows", 0),
                mqtt_messages=item.get("mqtt_messages", 0),
                elapsed=float(item.get("elapsed_seconds", 0.0)),
            ).strip()
        )
    return "\n".join(rows)


def build_html(data, generated_at):
    summary = data.get("summary", {})
    mqtt = data.get("mqtt_summary", {})
    rows = build_rows(data)

    tp = int(summary.get("true_positives", 0))
    tn = int(summary.get("true_negatives", 0))
    fp = int(summary.get("false_positives", 0))
    fn = int(summary.get("false_negatives", 0))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>IWSN Robustness Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; background: #f4f6f8; color: #1f2937; }}
    .wrap {{ max-width: 1200px; margin: 24px auto; padding: 0 16px; }}
    .card {{ background: white; border-radius: 12px; padding: 20px; margin-bottom: 16px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }}
    h1, h2 {{ margin: 0 0 12px 0; }}
    .meta {{ color: #6b7280; font-size: 14px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
    .metric {{ background: #f9fafb; border-radius: 10px; padding: 14px; }}
    .metric .k {{ color: #6b7280; font-size: 13px; }}
    .metric .v {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #e5e7eb; text-align: left; }}
    th {{ background: #f8fafc; }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: repeat(2, 1fr); }} }}
    @media (max-width: 560px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>IWSN Robustness Test Dashboard</h1>
      <div class="meta">Generated: {generated_at} | Difficulty: {data.get('difficulty', 'unknown')} | Engine: {data.get('engine', 'unknown')}</div>
    </div>

    <div class="card">
      <h2>Summary</h2>
      <div class="grid">
        <div class="metric"><div class="k">Total Tests</div><div class="v">{summary.get('total_tests', 0)}</div></div>
        <div class="metric"><div class="k">Accuracy</div><div class="v">{pct(float(summary.get('accuracy', 0)))}</div></div>
        <div class="metric"><div class="k">F1 Score</div><div class="v">{pct(float(summary.get('f1_score', 0)))}</div></div>
        <div class="metric"><div class="k">Throughput</div><div class="v">{float(summary.get('throughput_pps', 0)):.1f}</div></div>
      </div>
    </div>

    <div class="card">
      <h2>Detection Matrix</h2>
      <canvas id="matrixChart" height="120"></canvas>
    </div>

    <div class="card">
      <h2>MQTT Coverage</h2>
      <div class="grid">
        <div class="metric"><div class="k">MQTT Flows Detected</div><div class="v">{mqtt.get('total_mqtt_flows_detected', 0)}</div></div>
        <div class="metric"><div class="k">MQTT Messages Parsed</div><div class="v">{mqtt.get('total_mqtt_messages_parsed', 0)}</div></div>
        <div class="metric"><div class="k">MQTT Packets in PCAPs</div><div class="v">{mqtt.get('total_mqtt_packets_in_pcaps', 0)}</div></div>
        <div class="metric"><div class="k">Avg Detection Time</div><div class="v">{float(summary.get('avg_detection_time_sec', 0)):.3f}s</div></div>
      </div>
    </div>

    <div class="card">
      <h2>Per-Attack Results</h2>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Attack Type</th>
            <th>Result</th>
            <th>Detections</th>
            <th>MQTT Flows</th>
            <th>MQTT Messages</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    const matrixCtx = document.getElementById('matrixChart');
    new Chart(matrixCtx, {{
      type: 'bar',
      data: {{
        labels: ['True Positives', 'True Negatives', 'False Positives', 'False Negatives'],
        datasets: [{{
          data: [{tp}, {tn}, {fp}, {fn}],
          backgroundColor: ['#16a34a', '#22c55e', '#ef4444', '#dc2626']
        }}]
      }},
      options: {{
        plugins: {{ legend: {{ display: false }} }},
        scales: {{ y: {{ beginAtZero: true }} }}
      }}
    }});
  </script>
</body>
</html>
"""


def main():
    default_json = Path(__file__).parent / "robustness_test_output" / "reports" / "robustness_results.json"
    results_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else default_json.resolve()

    if not results_path.exists():
        print(f"[ERROR] Results file not found: {results_path}")
        sys.exit(1)

    data = load_results(results_path)
    output_path = results_path.parent / "robustness_dashboard.html"
    html = build_html(data, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    output_path.write_text(html, encoding="utf-8")

    print(f"[OK] Robustness dashboard generated: {output_path}")


if __name__ == "__main__":
    main()
