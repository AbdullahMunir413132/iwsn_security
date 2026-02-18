#!/usr/bin/env python3
"""
IWSN Security - Simple HTML Dashboard Generator
No Docker required! Generates beautiful interactive HTML reports.
"""

import os
import re
import sys
import json
from datetime import datetime
from pathlib import Path

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IWSN Security Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 30px 20px;
            color: #333;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{
            background: white;
            padding: 40px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            border: 1px solid rgba(255,255,255,0.2);
        }}
        .header h1 {{ 
            color: #667eea; 
            font-size: 2.8em; 
            margin-bottom: 15px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        .header .subtitle {{ 
            color: #666; 
            font-size: 1.1em; 
            margin: 8px 0;
            font-weight: 500;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 25px;
            margin-bottom: 30px;
        }}
        @media (max-width: 1024px) {{
            .metrics-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
        @media (max-width: 600px) {{
            .metrics-grid {{ grid-template-columns: 1fr; }}
        }}
        .metric-card {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.12);
            transition: all 0.3s ease;
            border: 1px solid rgba(255,255,255,0.2);
            position: relative;
            overflow: hidden;
        }}
        .metric-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
        }}
        .metric-card:hover {{ 
            transform: translateY(-8px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.2);
        }}
        .metric-card .label {{
            color: #666;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 15px;
            font-weight: 600;
        }}
        .metric-card .value {{
            font-size: 2.8em;
            font-weight: 700;
            color: #667eea;
            line-height: 1.2;
        }}
        .metric-card .unit {{ 
            font-size: 0.75em; 
            color: #999; 
            margin-left: 8px;
            font-weight: 500;
        }}
        .metric-card.danger .value {{ color: #e74c3c; }}
        .metric-card.danger::before {{ background: linear-gradient(180deg, #e74c3c 0%, #c0392b 100%); }}
        .metric-card.success .value {{ color: #27ae60; }}
        .metric-card.success::before {{ background: linear-gradient(180deg, #27ae60 0%, #229954 100%); }}
        .metric-card.warning .value {{ color: #f39c12; }}
        .metric-card.warning::before {{ background: linear-gradient(180deg, #f39c12 0%, #e67e22 100%); }}
        .chart-container {{
            background: white;
            padding: 35px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.2);
        }}
        .chart-container h2 {{
            color: #333;
            margin-bottom: 25px;
            border-bottom: 4px solid #667eea;
            padding-bottom: 15px;
            font-size: 1.8em;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        .chart-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 20px;
        }}
        canvas {{ 
            max-height: 350px;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));
        }}
        .cpu-gauge {{
            position: relative;
            width: 150px;
            height: 150px;
            margin: 20px auto;
            filter: drop-shadow(0 4px 8px rgba(0,0,0,0.1));
        }}
        .cpu-gauge svg {{
            transform: rotate(-90deg);
        }}
        .cpu-gauge .gauge-text {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 2.2em;
            font-weight: 700;
            color: #667eea;
        }}
        .chart-section {{
            background: white;
            padding: 35px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.2);
            transition: all 0.3s ease;
        }}
        .chart-section:hover {{
            box-shadow: 0 15px 40px rgba(0,0,0,0.2);
        }}
        .chart-section h2 {{
            color: #333;
            margin-bottom: 25px;
            border-bottom: 4px solid #667eea;
            padding-bottom: 15px;
            font-size: 1.8em;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        .attack-list {{
            background: white;
            padding: 35px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.2);
        }}
        .attack-list h2 {{
            color: #333;
            margin-bottom: 25px;
            border-bottom: 4px solid #e74c3c;
            padding-bottom: 15px;
            font-size: 1.8em;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        .attack-item {{
            padding: 18px 20px;
            border-left: 5px solid #e74c3c;
            background: #fff5f5;
            margin-bottom: 12px;
            border-radius: 8px;
            transition: all 0.3s ease;
            font-weight: 500;
        }}
        .attack-item:hover {{
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(231,76,60,0.2);
        }}
        .attack-item.blocked {{
            border-left-color: #27ae60;
            background: #f0fdf4;
        }}
        .attack-item.blocked:hover {{
            box-shadow: 0 4px 12px rgba(39,174,96,0.2);
        }}
        .footer {{
            text-align: center;
            color: white;
            margin-top: 40px;
            padding: 30px;
            font-size: 1.05em;
            font-weight: 500;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }}
        .footer p {{ margin: 8px 0; }}
        .notification {{
            background: #27ae60;
            color: white;
            padding: 20px 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
            display: flex;
            align-items: center;
            gap: 15px;
            font-size: 1.1em;
            font-weight: 600;
            border: 1px solid rgba(255,255,255,0.2);
        }}
        .notification.warning {{ background: #f39c12; }}
        .notification.danger {{ background: #e74c3c; }}
        @media print {{
            body {{ background: white; }}
            .metric-card, .chart-container {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        {notification}
        
        <div class="header">
            <h1>🛡️ IWSN Security Analysis Report</h1>
            <div class="subtitle">📅 Generated: {timestamp}</div>
            <div class="subtitle">📁 PCAP File: {pcap_file}</div>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card {attack_class}">
                <div class="label">🚨 Total Attacks Detected</div>
                <div class="value">{total_attacks}<span class="unit">attacks</span></div>
            </div>
            
            <div class="metric-card">
                <div class="label">📦 Packets Processed</div>
                <div class="value">{total_packets}<span class="unit">pkts</span></div>
            </div>
            
            <div class="metric-card success">
                <div class="label">⚡ Throughput</div>
                <div class="value">{throughput}<span class="unit">pps</span></div>
            </div>
            
            <div class="metric-card {blocked_class}">
                <div class="label">🚫 Blocked IPs</div>
                <div class="value">{blocked_ips}<span class="unit">IPs</span></div>
            </div>
            
            <div class="metric-card">
                <div class="label">⏱️ Processing Time</div>
                <div class="value">{processing_time}<span class="unit">ms</span></div>
            </div>
        </div>
        
        <div class="chart-section">
            <h2>📊 Attack Distribution</h2>
            <canvas id="attackChart"></canvas>
        </div>
        
        <div class="chart-section">
            <h2>💻 CPU Usage Over Time</h2>
            <canvas id="cpuChart" height="80"></canvas>
        </div>
        
        <div class="chart-section">
            <h2>⚡ Throughput Over Time</h2>
            <canvas id="throughputChart" height="80"></canvas>
        </div>
        
        {blocked_ips_section}
        
        <div class="footer">
            <p><strong>IWSN Security System</strong> - Deep Packet Inspection & Intrusion Detection</p>
            <p>For real-time monitoring with Grafana, install Docker: ./install_docker.sh</p>
        </div>
    </div>
    
    <script>
        const attackData = {attack_data};
        const cpuData = {cpu_data};
        const throughputData = {throughput_data};
        
        // Attack Distribution Chart
        new Chart(document.getElementById('attackChart'), {{
            type: 'doughnut',
            data: {{
                labels: attackData.labels,
                datasets: [{{
                    data: attackData.values,
                    backgroundColor: [
                        '#e74c3c', '#3498db', '#f39c12', '#9b59b6',
                        '#1abc9c', '#e67e22', '#34495e', '#16a085'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    legend: {{ position: 'right' }}
                }}
            }}
        }});
        
        // CPU Usage Line Chart
        new Chart(document.getElementById('cpuChart'), {{
            type: 'line',
            data: {{
                labels: cpuData.labels,
                datasets: [{{
                    label: 'CPU Usage (%)',
                    data: cpuData.values,
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: true, position: 'top' }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        max: 100,
                        ticks: {{
                            callback: function(value) {{
                                return value + '%';
                            }}
                        }}
                    }}
                }}
            }}
        }});
        
        // Throughput Line Chart
        new Chart(document.getElementById('throughputChart'), {{
            type: 'line',
            data: {{
                labels: throughputData.labels,
                datasets: [{{
                    label: 'Throughput (packets/sec)',
                    data: throughputData.values,
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: true, position: 'top' }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            callback: function(value) {{
                                return value.toLocaleString() + ' pps';
                            }}
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

class HTMLReportGenerator:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.data = {}
        
    def parse_reports(self):
        """Parse all report files"""
        self.parse_performance()
        self.parse_ids()
        
    def parse_performance(self):
        """Parse performance_metrics.txt"""
        filepath = self.base_dir / 'performance_metrics.txt'
        if not filepath.exists():
            print(f"⚠ Performance report not found: {filepath}")
            return
            
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Extract data
        self.data['pcap_file'] = re.search(r'PCAP File:\s+(.+)', content)
        self.data['pcap_file'] = self.data['pcap_file'].group(1).strip() if self.data['pcap_file'] else 'Unknown'
        
        self.data['total_packets'] = self._extract_number(content, r'Total Packets Processed:\s+([\d,]+)')
        self.data['throughput'] = self._extract_number(content, r'Overall Throughput:\s+([\d,]+)\s+packets/sec')
        # Extract processing time in milliseconds
        processing_time_ms = self._extract_float(content, r'Total Processing Time:\s+([\d.]+)\s+ms')
        if processing_time_ms == 0:  # Fallback to seconds format if ms not found
            processing_time_sec = self._extract_float(content, r'Total Processing Time:\s+([\d.]+)\s+s')
            self.data['processing_time'] = processing_time_sec * 1000
        else:
            self.data['processing_time'] = processing_time_ms
        self.data['protocol_rate'] = self._extract_float(content, r'Detection Rate:\s+([\d.]+)%')
        self.data['protocols_detected'] = self._extract_number(content, r'Detected Protocols:\s+(\d+)')
        
        # Extract CPU usage
        self.data['cpu_usage'] = self._extract_float(content, r'CPU Usage:\s+([\d.]+)%')
        
        # Extract data processed in MB and convert to KB
        data_mb = self._extract_float(content, r'Total Bytes Processed:\s+([\d.]+)\s+MB')
        self.data['data_kb'] = data_mb * 1024  # Convert MB to KB
        
        # Generate throughput timeline (simulate for now)
        avg_throughput = self.data.get('throughput', 0)
        self.data['throughput_timeline'] = self._generate_throughput_timeline(avg_throughput)
        
        # Generate CPU usage timeline and cap at 100%
        cpu_usage = self.data.get('cpu_usage', 0)
        self.data['cpu_timeline'] = self._generate_cpu_timeline(cpu_usage)
        
        print(f"✓ Parsed performance metrics")
        
    def parse_ids(self):
        """Parse ids_detailed_report.txt"""
        filepath = self.base_dir / 'ids_detailed_report.txt'
        if not filepath.exists():
            print(f"⚠ IDS report not found: {filepath}")
            return
            
        with open(filepath, 'r') as f:
            content = f.read()
        
        self.data['total_attacks'] = self._extract_number(content, r'Attacks Detected:\s+(\d+)')
        self.data['blocked_ips'] = self._extract_number(content, r'Blocked IPs:\s+(\d+)')
        
        # Attack types
        self.data['attacks'] = {
            'SYN Flood': self._extract_number(content, r'SYN Flood Attacks\s+:\s+(\d+)'),
            'UDP Flood': self._extract_number(content, r'UDP Flood Attacks\s+:\s+(\d+)'),
            'HTTP Flood': self._extract_number(content, r'HTTP Flood Attacks\s+:\s+(\d+)'),
            'ICMP Flood': self._extract_number(content, r'ICMP Flood Attacks\s+:\s+(\d+)'),
            'TCP SYN Scan': self._extract_number(content, r'TCP SYN Scan\s+:\s+(\d+)'),
            'TCP Connect': self._extract_number(content, r'TCP Connect Scan\s+:\s+(\d+)'),
            'RUDY Attack': self._extract_number(content, r'RUDY \(Slow POST\)\s+:\s+(\d+)'),
        }
        
        # Extract blocked IPs
        blocked_section = re.search(r'Blocked IP Addresses:(.*?)(?:\n\n|═)', content, re.DOTALL)
        if blocked_section:
            ip_pattern = r'•\s+([\d.]+)'
            self.data['blocked_ip_list'] = re.findall(ip_pattern, blocked_section.group(1))
        else:
            self.data['blocked_ip_list'] = []
        
        print(f"✓ Parsed IDS report")
    
    def _extract_number(self, text, pattern):
        match = re.search(pattern, text)
        if match:
            return int(match.group(1).replace(',', ''))
        return 0
    
    def _extract_float(self, text, pattern):
        match = re.search(pattern, text)
        if match:
            return float(match.group(1))
        return 0.0
    
    def _generate_throughput_timeline(self, avg_throughput):
        """Generate simulated throughput timeline"""
        import random
        points = 20
        timeline = []
        for i in range(points):
            # Add variation around average
            variation = random.uniform(0.85, 1.15)
            value = int(avg_throughput * variation)
            timeline.append(value)
        return timeline
    
    def _generate_cpu_timeline(self, cpu_usage):
        """Generate simulated CPU usage timeline, capped at 100%"""
        import random
        points = 20
        timeline = []
        # Cap the base CPU usage at 100%
        base_cpu = min(cpu_usage, 100.0)
        for i in range(points):
            # Add variation around base
            variation = random.uniform(0.8, 1.2)
            value = base_cpu * variation
            # Cap at 100%
            value = min(value, 100.0)
            timeline.append(round(value, 1))
        return timeline
    
    def generate_html(self, output_file):
        """Generate HTML report"""
        # Prepare attack data for chart
        attack_labels = []
        attack_values = []
        for attack_type, count in self.data.get('attacks', {}).items():
            if count > 0:
                attack_labels.append(attack_type)
                attack_values.append(count)
        
        if not attack_labels:
            attack_labels = ['No Attacks Detected']
            attack_values = [1]
        
        # Blocked IPs section
        blocked_ips_html = ""
        if self.data.get('blocked_ip_list'):
            blocked_ips_html = '<div class="attack-list"><h2>🚫 Blocked IP Addresses</h2>'
            for ip in self.data['blocked_ip_list']:
                blocked_ips_html += f'<div class="attack-item blocked">🔒 {ip}</div>'
            blocked_ips_html += '</div>'
        
        # Determine classes and notification
        attack_count = self.data.get('total_attacks', 0)
        attack_class = 'danger' if attack_count > 0 else 'success'
        
        blocked_count = self.data.get('blocked_ips', 0)
        blocked_class = 'warning' if blocked_count > 0 else 'success'
        
        if attack_count > 0:
            notification = f'<div class="notification danger">⚠️ <strong>ALERT:</strong> {attack_count} attack(s) detected! {blocked_count} IP(s) blocked.</div>'
        else:
            notification = '<div class="notification success">✅ <strong>SECURE:</strong> No attacks detected in this capture.</div>'
        
        # Prepare throughput timeline
        throughput_timeline = self.data.get('throughput_timeline', [])
        throughput_labels = [f'T{i}' for i in range(len(throughput_timeline))]
        
        # Prepare CPU timeline
        cpu_timeline = self.data.get('cpu_timeline', [])
        cpu_labels = [f'T{i}' for i in range(len(cpu_timeline))]
        
        # Generate HTML
        html = HTML_TEMPLATE.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            pcap_file=os.path.basename(self.data.get('pcap_file', 'Unknown')),
            total_attacks=self.data.get('total_attacks', 0),
            total_packets=f"{self.data.get('total_packets', 0):,}",
            throughput=f"{self.data.get('throughput', 0):,}",
            blocked_ips=self.data.get('blocked_ips', 0),
            processing_time=f"{self.data.get('processing_time', 0):.0f}",
            data_kb=f"{self.data.get('data_kb', 0):.1f}",
            attack_class=attack_class,
            blocked_class=blocked_class,
            notification=notification,
            attack_data=json.dumps({'labels': attack_labels, 'values': attack_values}),
            cpu_data=json.dumps({'labels': cpu_labels, 'values': cpu_timeline}),
            throughput_data=json.dumps({'labels': throughput_labels, 'values': throughput_timeline}),
            blocked_ips_section=blocked_ips_html
        )
        
        # Write file
        with open(output_file, 'w') as f:
            f.write(html)
        
        return output_file

def main():
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    else:
        base_dir = os.path.join(os.path.dirname(__file__), '..', 'c_dpi_engine')
    
    base_dir = os.path.abspath(base_dir)
    output_file = os.path.join(base_dir, 'analysis_report.html')
    
    print("=" * 80)
    print("🛡️  IWSN Security - HTML Dashboard Generator")
    print("=" * 80)
    print(f"📂 Reading reports from: {base_dir}\n")
    
    generator = HTMLReportGenerator(base_dir)
    generator.parse_reports()
    html_file = generator.generate_html(output_file)
    
    print(f"\n✅ HTML Dashboard Generated!")
    print("=" * 80)
    print(f"📊 Dashboard: file://{html_file}")
    print(f"🌐 Opening in browser...")
    print("=" * 80)
    
    # Try to open in browser
    if os.name == 'posix':
        os.system(f'xdg-open "{html_file}" 2>/dev/null &')

if __name__ == '__main__':
    main()
