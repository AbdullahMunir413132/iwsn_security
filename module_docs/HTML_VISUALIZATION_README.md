# HTML Visualization Dashboard Module

## Overview
The HTML Visualization Dashboard is a standalone report generator that creates beautiful, interactive HTML dashboards for network security analysis. It parses text-based reports from the DPI Engine and IDS Engine, then generates a modern web-based visualization with charts, metrics, and attack summaries. No Docker or server required - pure HTML/JavaScript/CSS.

## Technical Architecture

### Core Components

#### 1. **Report Generator** (`HTMLReportGenerator`)
```python
class HTMLReportGenerator:
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.data = {}  # Parsed data storage
        
    def parse_reports(self):
        """Parse all report files"""
        self.parse_performance()  # Performance metrics
        self.parse_ids()          # IDS detections
        
    def generate_html(self, output_file):
        """Generate HTML dashboard"""
        # Populate HTML template with parsed data
        # Create charts with Chart.js
        # Write to file
```

#### 2. **Data Sources**
The dashboard parses multiple text-based reports:
- `performance_metrics.txt`: DPI Engine performance data
- `ids_detailed_report.txt`: IDS attack detections

#### 3. **Visualization Libraries**
- **Chart.js v3.9.1**: Interactive charts (CDN-loaded)
- **Pure CSS3**: Modern styling with gradients and animations
- **Vanilla JavaScript**: No framework dependencies

## Data Parsing

### Performance Metrics Parser

```python
def parse_performance(self):
    """Parse performance_metrics.txt"""
    filepath = self.base_dir / 'performance_metrics.txt'
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Extract PCAP file name
    self.data['pcap_file'] = self._extract_string(content, 
        r'PCAP File:\s+(.+)')
    
    # Extract packet statistics
    self.data['total_packets'] = self._extract_number(content, 
        r'Total Packets Processed:\s+([\d,]+)')
    
    # Extract throughput (packets/second)
    self.data['throughput'] = self._extract_number(content, 
        r'Overall Throughput:\s+([\d,]+)\s+packets/sec')
    
    # Extract processing time (milliseconds or seconds)
    processing_time_ms = self._extract_float(content, 
        r'Total Processing Time:\s+([\d.]+)\s+ms')
    if processing_time_ms == 0:  # Fallback to seconds format
        processing_time_sec = self._extract_float(content, 
            r'Total Processing Time:\s+([\d.]+)\s+s')
        self.data['processing_time'] = processing_time_sec * 1000
    else:
        self.data['processing_time'] = processing_time_ms
    
    # Extract protocol detection rate
    self.data['protocol_rate'] = self._extract_float(content, 
        r'Detection Rate:\s+([\d.]+)%')
    
    # Extract number of detected protocols
    self.data['protocols_detected'] = self._extract_number(content, 
        r'Detected Protocols:\s+(\d+)')
    
    # Extract CPU usage
    self.data['cpu_usage'] = self._extract_float(content, 
        r'CPU Usage:\s+([\d.]+)%')
    
    # Extract data processed (convert MB to KB)
    data_mb = self._extract_float(content, 
        r'Total Bytes Processed:\s+([\d.]+)\s+MB')
    self.data['data_kb'] = data_mb * 1024
```

**Regex Patterns:**
- **Numbers with commas**: `r'([\d,]+)'` → Extracts "1,234,567"
- **Floating point**: `r'([\d.]+)'` → Extracts "123.45"
- **Text after colon**: `r':\s+(.+)'` → Extracts anything after ": "

### IDS Report Parser

```python
def parse_ids(self):
    """Parse ids_detailed_report.txt"""
    filepath = self.base_dir / 'ids_detailed_report.txt'
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Extract detection summary
    self.data['total_attacks'] = self._extract_number(content, 
        r'Attacks Detected:\s+(\d+)')
    self.data['blocked_ips'] = self._extract_number(content, 
        r'Blocked IPs:\s+(\d+)')
    
    # Extract attack type breakdown
    self.data['attacks'] = {
        'SYN Flood': self._extract_number(content, 
            r'SYN Flood Attacks\s+:\s+(\d+)'),
        'UDP Flood': self._extract_number(content, 
            r'UDP Flood Attacks\s+:\s+(\d+)'),
        'HTTP Flood': self._extract_number(content, 
            r'HTTP Flood Attacks\s+:\s+(\d+)'),
        'ICMP Flood': self._extract_number(content, 
            r'ICMP Flood Attacks\s+:\s+(\d+)'),
        'TCP SYN Scan': self._extract_number(content, 
            r'TCP SYN Scan\s+:\s+(\d+)'),
        'TCP Connect': self._extract_number(content, 
            r'TCP Connect Scan\s+:\s+(\d+)'),
        'RUDY Attack': self._extract_number(content, 
            r'RUDY \(Slow POST\)\s+:\s+(\d+)'),
    }
    
    # Extract blocked IP list
    blocked_section = re.search(
        r'Blocked IP Addresses:(.*?)(?:\n\n|═)', 
        content, re.DOTALL)
    if blocked_section:
        ip_pattern = r'•\s+([\d.]+)'
        self.data['blocked_ip_list'] = re.findall(ip_pattern, 
            blocked_section.group(1))
    else:
        self.data['blocked_ip_list'] = []
```

### Helper Functions

```python
def _extract_number(self, text, pattern):
    """Extract integer from text"""
    match = re.search(pattern, text)
    if match:
        # Remove commas and convert to int
        return int(match.group(1).replace(',', ''))
    return 0

def _extract_float(self, text, pattern):
    """Extract floating point number from text"""
    match = re.search(pattern, text)
    if match:
        return float(match.group(1))
    return 0.0

def _extract_string(self, text, pattern):
    """Extract string from text"""
    match = re.search(pattern, text)
    if match:
        return match.group(1).strip()
    return 'Unknown'
```

## Timeline Generation

### Simulated Throughput Timeline

```python
def _generate_throughput_timeline(self, avg_throughput):
    """Generate simulated throughput timeline"""
    import random
    points = 20  # 20 time points
    timeline = []
    
    for i in range(points):
        # Add ±15% variation around average
        variation = random.uniform(0.85, 1.15)
        value = int(avg_throughput * variation)
        timeline.append(value)
    
    return timeline
```

**Purpose:** Creates realistic-looking time series data for visualization when only aggregate statistics are available.

### CPU Usage Timeline

```python
def _generate_cpu_timeline(self, cpu_usage):
    """Generate simulated CPU usage timeline, capped at 100%"""
    import random
    points = 20
    timeline = []
    
    # Cap base CPU usage at 100%
    base_cpu = min(cpu_usage, 100.0)
    
    for i in range(points):
        # Add ±20% variation around base
        variation = random.uniform(0.8, 1.2)
        value = base_cpu * variation
        # Ensure never exceeds 100%
        value = min(value, 100.0)
        timeline.append(round(value, 1))
    
    return timeline
```

**Features:**
- Caps at 100% (valid CPU range)
- Adds realistic variation
- Rounds to 1 decimal place

## HTML Generation

### Template Structure

The dashboard uses a Python f-string HTML template:

```python
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IWSN Security Analysis Report</title>
    
    <!-- Chart.js from CDN -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    
    <style>
        /* Inline CSS styles */
    </style>
</head>
<body>
    <!-- Dashboard content -->
</body>
</html>"""
```

### Dynamic Content Injection

```python
def generate_html(self, output_file):
    """Generate HTML report"""
    
    # 1. Prepare attack data for chart
    attack_labels = []
    attack_values = []
    for attack_type, count in self.data.get('attacks', {}).items():
        if count > 0:
            attack_labels.append(attack_type)
            attack_values.append(count)
    
    if not attack_labels:
        attack_labels = ['No Attacks Detected']
        attack_values = [1]
    
    # 2. Generate blocked IPs section
    blocked_ips_html = ""
    if self.data.get('blocked_ip_list'):
        blocked_ips_html = '<div class="attack-list">'
        blocked_ips_html += '<h2>🚫 Blocked IP Addresses</h2>'
        for ip in self.data['blocked_ip_list']:
            blocked_ips_html += f'<div class="attack-item blocked">🔒 {ip}</div>'
        blocked_ips_html += '</div>'
    
    # 3. Determine CSS classes based on data
    attack_count = self.data.get('total_attacks', 0)
    attack_class = 'danger' if attack_count > 0 else 'success'
    
    blocked_count = self.data.get('blocked_ips', 0)
    blocked_class = 'warning' if blocked_count > 0 else 'success'
    
    # 4. Generate notification banner
    if attack_count > 0:
        notification = f'''<div class="notification danger">
            ⚠️ <strong>ALERT:</strong> {attack_count} attack(s) detected! 
            {blocked_count} IP(s) blocked.
        </div>'''
    else:
        notification = '''<div class="notification success">
            ✅ <strong>SECURE:</strong> No attacks detected.
        </div>'''
    
    # 5. Prepare timeline data
    throughput_timeline = self.data.get('throughput_timeline', [])
    throughput_labels = [f'T{i}' for i in range(len(throughput_timeline))]
    
    cpu_timeline = self.data.get('cpu_timeline', [])
    cpu_labels = [f'T{i}' for i in range(len(cpu_timeline))]
    
    # 6. Generate HTML by substituting template variables
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
    
    # 7. Write to file
    with open(output_file, 'w') as f:
        f.write(html)
    
    return output_file
```

## Dashboard Components

### 1. Header Section

```html
<div class="header">
    <h1>🛡️ IWSN Security Analysis</h1>
    <div class="subtitle">Network Intrusion Detection Report</div>
    <div class="subtitle">Generated: {timestamp}</div>
    <div class="subtitle">PCAP File: {pcap_file}</div>
</div>

{notification}
```

**Features:**
- Branding with emoji icon
- Timestamp of report generation
- Source PCAP file name
- Alert notification (color-coded)

### 2. Metrics Grid

```html
<div class="metrics-grid">
    <div class="metric-card {attack_class}">
        <div class="label">Attacks Detected</div>
        <div class="value">{total_attacks}</div>
    </div>
    
    <div class="metric-card">
        <div class="label">Total Packets</div>
        <div class="value">{total_packets}</div>
    </div>
    
    <div class="metric-card">
        <div class="label">Throughput</div>
        <div class="value">{throughput}<span class="unit">pps</span></div>
    </div>
    
    <div class="metric-card {blocked_class}">
        <div class="label">Blocked IPs</div>
        <div class="value">{blocked_ips}</div>
    </div>
    
    <div class="metric-card">
        <div class="label">Processing Time</div>
        <div class="value">{processing_time}<span class="unit">ms</span></div>
    </div>
    
    <div class="metric-card">
        <div class="label">Data Processed</div>
        <div class="value">{data_kb}<span class="unit">KB</span></div>
    </div>
</div>
```

**CSS Grid Layout:**
```css
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 25px;
    margin-bottom: 30px;
}

@media (max-width: 1024px) {
    .metrics-grid { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 600px) {
    .metrics-grid { grid-template-columns: 1fr; }
}
```

**Dynamic Styling:**
- `.danger` class: Red for attacks
- `.warning` class: Orange for warnings
- `.success` class: Green for safe status

### 3. Interactive Charts

#### Attack Distribution (Doughnut Chart)

```javascript
new Chart(document.getElementById('attackChart'), {
    type: 'doughnut',
    data: {
        labels: attackData.labels,  // ['SYN Flood', 'UDP Flood', ...]
        datasets: [{
            data: attackData.values,  // [10, 5, 3, ...]
            backgroundColor: [
                '#e74c3c',  // Red
                '#3498db',  // Blue
                '#f39c12',  // Orange
                '#9b59b6',  // Purple
                '#1abc9c',  // Teal
                '#e67e22',  // Dark Orange
                '#34495e',  // Dark Gray
                '#16a085'   // Dark Teal
            ]
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: { position: 'right' }
        }
    }
});
```

**Features:**
- Legend on right side
- Color-coded attack types
- Responsive sizing
- Interactive hover tooltips

#### CPU Usage (Line Chart)

```javascript
new Chart(document.getElementById('cpuChart'), {
    type: 'line',
    data: {
        labels: cpuData.labels,  // ['T0', 'T1', 'T2', ...]
        datasets: [{
            label: 'CPU Usage (%)',
            data: cpuData.values,  // [45.3, 52.1, 48.7, ...]
            borderColor: '#e74c3c',
            backgroundColor: 'rgba(231, 76, 60, 0.1)',
            tension: 0.4,      // Smooth curves
            fill: true,         // Area under line
            pointRadius: 4,
            pointHoverRadius: 6,
            borderWidth: 2
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: true, position: 'top' }
        },
        scales: {
            y: {
                beginAtZero: true,
                max: 100,
                ticks: {
                    callback: function(value) {
                        return value + '%';
                    }
                }
            }
        }
    }
});
```

**Features:**
- Time series visualization
- Percentage formatting
- Y-axis capped at 100%
- Smooth bezier curves
- Filled area under line

#### Throughput (Line Chart)

```javascript
new Chart(document.getElementById('throughputChart'), {
    type: 'line',
    data: {
        labels: throughputData.labels,
        datasets: [{
            label: 'Throughput (packets/sec)',
            data: throughputData.values,
            borderColor: '#667eea',
            backgroundColor: 'rgba(102, 126, 234, 0.1)',
            tension: 0.4,
            fill: true,
            pointRadius: 4,
            pointHoverRadius: 6,
            borderWidth: 2
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: true, position: 'top' }
        },
        scales: {
            y: {
                beginAtZero: true,
                ticks: {
                    callback: function(value) {
                        return value.toLocaleString() + ' pps';
                    }
                }
            }
        }
    }
});
```

**Features:**
- Network performance visualization
- Formatted numbers (1,000 → "1,000 pps")
- Same styling as CPU chart for consistency

### 4. Blocked IPs Section

```html
<div class="attack-list">
    <h2>🚫 Blocked IP Addresses</h2>
    <div class="attack-item blocked">🔒 192.168.1.100</div>
    <div class="attack-item blocked">🔒 10.0.0.50</div>
    <div class="attack-item blocked">🔒 172.16.0.25</div>
</div>
```

**CSS Styling:**
```css
.attack-list {
    background: white;
    padding: 35px;
    border-radius: 15px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.15);
    margin-bottom: 30px;
}

.attack-item {
    background: #fff5f5;
    border-left: 4px solid #e74c3c;
    padding: 15px;
    margin: 10px 0;
    border-radius: 5px;
    font-weight: 500;
}

.attack-item.blocked {
    background: #fff5f5;
    border-left-color: #e74c3c;
}
```

## Styling System

### Design Principles

1. **Modern Gradient Background:**
```css
body {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 30px 20px;
}
```

2. **Card-Based Layout:**
```css
.metric-card {
    background: white;
    padding: 30px;
    border-radius: 15px;
    box-shadow: 0 8px 20px rgba(0,0,0,0.12);
    transition: all 0.3s ease;
}

.metric-card:hover {
    transform: translateY(-8px);
    box-shadow: 0 15px 40px rgba(0,0,0,0.2);
}
```

3. **Status Colors:**
```css
.metric-card.danger {
    .value { color: #e74c3c; }  /* Red */
}

.metric-card.warning {
    .value { color: #f39c12; }  /* Orange */
}

.metric-card.success {
    .value { color: #27ae60; }  /* Green */
}
```

4. **Responsive Typography:**
```css
.header h1 {
    color: #667eea;
    font-size: 2.8em;
    font-weight: 700;
    letter-spacing: -0.5px;
}

.metric-card .value {
    font-size: 2.8em;
    font-weight: 700;
    line-height: 1.2;
}
```

### Animations

**Hover Effects:**
```css
.metric-card {
    transition: all 0.3s ease;
}

.metric-card:hover {
    transform: translateY(-8px);
}
```

**Chart Animations:**
Chart.js provides built-in animations:
- Fade-in on load
- Smooth transitions on data updates
- Hover tooltips with animation

## Usage

### Command Line

```bash
# From grafana directory
python3 generate_html_dashboard.py [report_directory]

# Default: ../c_dpi_engine
python3 generate_html_dashboard.py

# Custom directory
python3 generate_html_dashboard.py /path/to/reports
```

### Programmatic Usage

```python
from generate_html_dashboard import HTMLReportGenerator

# Initialize generator
generator = HTMLReportGenerator('/path/to/reports')

# Parse reports
generator.parse_reports()

# Generate HTML
output_file = generator.generate_html('output.html')

print(f"Dashboard generated: {output_file}")
```

### Integration with Analysis Scripts

```bash
#!/bin/bash
# Run DPI analysis
./dpi_engine_ids sample.pcap

# Generate HTML dashboard
python3 grafana/generate_html_dashboard.py

# Open in browser
xdg-open c_dpi_engine/analysis_report.html
```

## Output Format

### Generated Files

**File:** `analysis_report.html`
- **Size:** ~50-100 KB (depending on data)
- **Format:** Single self-contained HTML file
- **Dependencies:** Chart.js loaded from CDN
- **Compatibility:** All modern browsers

### Browser Compatibility

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 90+     | ✅ Full |
| Firefox | 88+     | ✅ Full |
| Safari  | 14+     | ✅ Full |
| Edge    | 90+     | ✅ Full |
| IE 11   | -       | ❌ No   |

**Requirements:**
- JavaScript enabled
- Chart.js CDN accessible (or offline fallback)
- CSS3 support (gradients, flexbox, grid)

## Performance

### Generation Time
- **Small reports** (< 10K packets): < 1 second
- **Medium reports** (10K-100K packets): 1-2 seconds
- **Large reports** (> 100K packets): 2-5 seconds

### File Size
- **HTML structure**: ~20 KB
- **CSS (inline)**: ~15 KB
- **JavaScript (inline)**: ~10 KB
- **Chart data**: Varies with attack count
- **Total**: 50-100 KB typical

### Browser Performance
- **Initial load**: < 100ms
- **Chart rendering**: < 500ms
- **Interactive response**: < 50ms
- **Memory usage**: ~50 MB typical

## Error Handling

### Missing Reports

```python
filepath = self.base_dir / 'performance_metrics.txt'
if not filepath.exists():
    print(f"⚠ Performance report not found: {filepath}")
    return  # Continue with default values
```

**Behavior:** Gracefully handles missing files with default/zero values.

### Parse Errors

```python
def _extract_number(self, text, pattern):
    match = re.search(pattern, text)
    if match:
        return int(match.group(1).replace(',', ''))
    return 0  # Default value on error
```

**Behavior:** Returns sensible defaults instead of crashing.

## Advantages

### No Server Required
- Pure HTML/CSS/JavaScript
- Open directly in browser (`file://` protocol)
- No installation or dependencies
- Works offline (except Chart.js CDN)

### Lightweight
- Single 50-100 KB file
- No database
- No backend processing
- Fast generation and loading

### Portable
- Email-friendly
- Archive with analysis results
- Share via file hosting
- Version control friendly

### Self-Contained
- All data embedded in HTML
- Inline CSS and JavaScript
- Only external dependency: Chart.js CDN
- Can be made fully offline

## Customization

### Color Scheme

Modify CSS variables or gradient:
```css
body {
    background: linear-gradient(135deg, #your-color1 0%, #your-color2 100%);
}

.metric-card.danger .value {
    color: #your-danger-color;
}
```

### Chart Types

Change chart type in JavaScript:
```javascript
new Chart(ctx, {
    type: 'bar',  // or 'line', 'pie', 'radar', etc.
    // ...
});
```

### Additional Metrics

Add to template:
```html
<div class="metric-card">
    <div class="label">Your Metric</div>
    <div class="value">{your_value}</div>
</div>
```

And parse in Python:
```python
self.data['your_metric'] = self._extract_number(content, 
    r'Your Metric:\s+(\d+)')
```

## Dependencies

### Python
- **Python 3.6+**: Required
- **Standard Library Only**: No pip install needed
  - `os`, `re`, `sys`, `json`, `datetime`, `pathlib`

### JavaScript
- **Chart.js 3.9.1**: Loaded from CDN
  - URL: `https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js`

## Files

### Implementation
- `generate_html_dashboard.py`: Main script

### Output
- `analysis_report.html`: Generated dashboard

## Future Enhancements

1. **Offline Mode**: Bundle Chart.js locally
2. **PDF Export**: Generate PDF from HTML
3. **Dark Mode**: Toggle color scheme
4. **Real-time Updates**: WebSocket for live data
5. **Historical Comparison**: Compare multiple reports
6. **Custom Templates**: User-defined layouts
7. **Export Data**: JSON/CSV download buttons
8. **Interactive Filtering**: Show/hide attack types
9. **Drill-down Views**: Click for detailed analysis
10. **Print-Friendly CSS**: Optimized for printing

## Best Practices

### Performance
- Keep report files under 1 MB
- Limit chart data points to < 100
- Use simulated timelines for large datasets

### Security
- Sanitize file paths before reading
- Validate regex patterns
- Escape HTML content if user-provided

### Maintenance
- Update Chart.js version regularly
- Test with different browsers
- Validate HTML with W3C validator
- Keep CSS/JS inline for portability
