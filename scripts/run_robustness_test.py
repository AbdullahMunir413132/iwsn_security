#!/usr/bin/env python3
"""
IWSN Security — Robustness Test Harness v3.0
Automated pipeline: Simulator → Rule Engine + MQTT Parser → Accuracy Report

Uses dpi_mqtt_analyzer to get full IDS + MQTT parsing output.
"""

import os, sys, json, subprocess, time, re
from datetime import datetime

# ────────────────────── CONFIGURATION ──────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
# Use the full MQTT-capable analyzer binary
DPI_ENGINE = os.path.join(PROJECT_DIR, "c_dpi_engine", "bin", "dpi_mqtt_analyzer")
# Fallback to IDS-only if MQTT analyzer not built
DPI_ENGINE_FALLBACK = os.path.join(PROJECT_DIR, "c_dpi_engine", "bin", "dpi_engine_ids")
SIMULATOR = os.path.join(SCRIPT_DIR, "attack_simulator.py")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "robustness_test_output")
PCAP_DIR = os.path.join(OUTPUT_DIR, "pcaps")
REPORT_DIR = os.path.join(OUTPUT_DIR, "reports")

# Legacy broad keyword mapping (kept for before/after transparency)
ATTACK_KEYWORDS = {
    "SYN Flood": ["syn flood", "distributed syn", "ddos"],
    "UDP Flood": ["udp flood", "udp flood attack"],
    "ICMP Flood": ["icmp flood"],
    "HTTP Flood": ["http flood"],
    "Ping of Death": ["ping of death", "icmp flood", "oversized icmp"],
    "Land Attack": ["land attack", "land"],
    "Smurf Attack": ["smurf", "icmp.*broadcast"],
    "Fraggle Attack": ["fraggle", "udp.*broadcast"],
    "Teardrop Attack": ["teardrop", "fragment"],
    "TCP SYN Scan": ["syn scan", "network scan", "port scan", "tcp syn scan", "connect scan"],
    "TCP Connect Scan": ["connect scan", "network scan", "port scan"],
    "UDP Scan": ["udp scan", "port scan"],
    "Xmas Tree Scan": ["xmas", "christmas"],
    "NULL Scan": ["null scan"],
    "FIN Scan": ["fin scan"],
    "RUDY (Slow POST)": ["rudy", "slow post"],
    "Slowloris": ["slowloris", "slow header"],
    "DNS Amplification": ["dns amplification", "dns amp"],
    "NTP Amplification": ["ntp amplification", "ntp amp"],
    "ARP Spoofing": ["arp spoofing", "arp spoof"],
    "IP Spoofing": ["ip spoofing", "ip spoof", "spoofing indicator"],
    "MQTT Traffic": [],  # Not an attack — just sensor traffic
    "None": [],
}

# ────────────────────── HELPERS ──────────────────────

def run_cmd(cmd, timeout=120):
    """Run a command and return stdout."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"

def check_detection_legacy(output, attack_type):
    """Legacy broad keyword scoring retained for comparison purposes."""
    if attack_type in ("None", "MQTT Traffic"):
        # For normal/MQTT traffic: any detection with >0 counts is a false positive
        m = re.search(r"Total Attacks Detected:\s+(\d+)", output)
        if not m:
            m = re.search(r"Attacks Detected:\s+(\d+)", output)
        detections = int(m.group(1)) if m else 0
        if detections == 0:
            return True, "true_negative"
        else:
            return False, "false_positive"
    
    keywords = ATTACK_KEYWORDS.get(attack_type, [attack_type.lower()])
    output_lower = output.lower()
    for kw in keywords:
        if re.search(kw, output_lower):
            return True, "true_positive"
    return False, "false_negative"


def extract_total_attacks(output):
    """Extract total attacks detected from combined engine output/report text."""
    m = re.search(r"Total Attacks Detected:\s+(\d+)", output)
    if not m:
        m = re.search(r"Attacks Detected:\s+(\d+)", output)
    return int(m.group(1)) if m else 0


def extract_detected_attack_types(report_text):
    """Extract attack type labels from IDS detailed report records."""
    matches = re.findall(r"Attack Type:\s+(.+)", report_text)
    cleaned = []
    for label in matches:
        value = label.strip()
        if value and value not in cleaned:
            cleaned.append(value)
    return cleaned


def normalize_label(label):
    return re.sub(r"\s+", " ", str(label).strip().lower())


CANONICAL_CLASS_MAP = {
    "syn flood": "SYN Flood",
    "distributed syn flood": "SYN Flood",
    "udp flood": "UDP Flood",
    "udp flood attack": "UDP Flood",
    "icmp flood": "ICMP Flood",
    "icmp flood attack": "ICMP Flood",
    "http flood": "HTTP Flood",
    "http flood attack": "HTTP Flood",
    "ping of death": "Ping of Death",
    "land attack": "Land Attack",
    "smurf attack": "Smurf Attack",
    "fraggle attack": "Fraggle Attack",
    "teardrop attack": "Teardrop Attack",
    "tcp syn scan": "TCP SYN Scan",
    "tcp connect scan": "TCP Connect Scan",
    "udp scan": "UDP Scan",
    "xmas tree scan": "Xmas Tree Scan",
    "xmas scan": "Xmas Tree Scan",
    "fin scan": "FIN Scan",
    "null scan": "NULL Scan",
    "rudy (slow post)": "RUDY (Slow POST)",
    "rudy (slow post) attack": "RUDY (Slow POST)",
    "slowloris": "Slowloris",
    "slowloris attack": "Slowloris",
    "dns amplification": "DNS Amplification",
    "dns amplification attack": "DNS Amplification",
    "ntp amplification": "NTP Amplification",
    "ntp amplification attack": "NTP Amplification",
    "arp spoofing": "ARP Spoofing",
    "ip spoofing": "IP Spoofing",
    "ip spoofing indicator": "IP Spoofing",
    "mqtt traffic": "MQTT Traffic",
    "none": "None",
}

CANONICAL_FAMILY_MAP = {
    "SYN Flood": "Flood",
    "UDP Flood": "Flood",
    "ICMP Flood": "Flood",
    "HTTP Flood": "Flood",
    "Ping of Death": "ICMP Abuse",
    "Land Attack": "Spoofing",
    "Smurf Attack": "Amplification",
    "Fraggle Attack": "Amplification",
    "Teardrop Attack": "Fragmentation",
    "TCP SYN Scan": "Scan",
    "TCP Connect Scan": "Scan",
    "UDP Scan": "Scan",
    "Xmas Tree Scan": "Scan",
    "FIN Scan": "Scan",
    "NULL Scan": "Scan",
    "RUDY (Slow POST)": "Slow HTTP",
    "Slowloris": "Slow HTTP",
    "DNS Amplification": "Amplification",
    "NTP Amplification": "Amplification",
    "ARP Spoofing": "Spoofing",
    "IP Spoofing": "Spoofing",
    "MQTT Traffic": "Benign",
    "None": "Benign",
}


def to_canonical(label):
    normalized = normalize_label(label)
    if normalized in CANONICAL_CLASS_MAP:
        return CANONICAL_CLASS_MAP[normalized]

    # fallback: contains match (handles small wording variations)
    for key, value in CANONICAL_CLASS_MAP.items():
        if key in normalized:
            return value

    return str(label).strip()


def to_family(label):
    canonical = to_canonical(label)
    return CANONICAL_FAMILY_MAP.get(canonical, "Other")


def check_detection_strict(total_attacks, attack_type):
    """Strict detection scoring based only on attack count, not keyword hints."""
    is_attack_case = attack_type not in ("None", "MQTT Traffic")

    if is_attack_case:
        if total_attacks > 0:
            return True, "true_positive"
        return False, "false_negative"

    if total_attacks == 0:
        return True, "true_negative"
    return False, "false_positive"


def check_exact_type_match(expected_attack_type, detected_attack_types):
    """Exact class-name match (harsh): expected label must appear exactly in detected labels."""
    expected = normalize_label(expected_attack_type)
    detected_norm = {normalize_label(item) for item in detected_attack_types}
    return expected in detected_norm


def check_semantic_type_match(expected_attack_type, detected_attack_types):
    """Semantic class-name match using canonical label mapping."""
    expected = to_canonical(expected_attack_type)
    detected = {to_canonical(item) for item in detected_attack_types}
    return expected in detected


def compute_per_class_metrics(results):
    """Compute one-vs-rest macro metrics over canonical attack classes."""
    attack_rows = [r for r in results if r["attack_type"] not in ("None", "MQTT Traffic")]
    classes = sorted({to_canonical(r["attack_type"]) for r in attack_rows})
    per_class = {}

    for cls in classes:
        tp = fp = fn = tn = 0
        for row in attack_rows:
            expected = to_canonical(row["attack_type"])
            predicted_set = set(row.get("detected_attack_types_canonical", []))

            is_expected = expected == cls
            is_predicted = cls in predicted_set

            if is_expected and is_predicted:
                tp += 1
            elif (not is_expected) and is_predicted:
                fp += 1
            elif is_expected and (not is_predicted):
                fn += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        per_class[cls] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    macro_precision = sum(v["precision"] for v in per_class.values()) / len(per_class) if per_class else 0.0
    macro_recall = sum(v["recall"] for v in per_class.values()) / len(per_class) if per_class else 0.0
    macro_f1 = sum(v["f1"] for v in per_class.values()) / len(per_class) if per_class else 0.0

    return per_class, round(macro_precision, 4), round(macro_recall, 4), round(macro_f1, 4)


def compute_per_family_metrics(results):
    """Compute one-vs-rest macro metrics over attack families."""
    attack_rows = [r for r in results if r["attack_type"] not in ("None", "MQTT Traffic")]
    families = sorted({to_family(r["attack_type"]) for r in attack_rows})
    per_family = {}

    for fam in families:
        tp = fp = fn = tn = 0
        for row in attack_rows:
            expected_family = to_family(row["attack_type"])
            predicted_families = set(row.get("detected_attack_families", []))

            is_expected = expected_family == fam
            is_predicted = fam in predicted_families

            if is_expected and is_predicted:
                tp += 1
            elif (not is_expected) and is_predicted:
                fp += 1
            elif is_expected and (not is_predicted):
                fn += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        per_family[fam] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    macro_precision = sum(v["precision"] for v in per_family.values()) / len(per_family) if per_family else 0.0
    macro_recall = sum(v["recall"] for v in per_family.values()) / len(per_family) if per_family else 0.0
    macro_f1 = sum(v["f1"] for v in per_family.values()) / len(per_family) if per_family else 0.0

    return per_family, round(macro_precision, 4), round(macro_recall, 4), round(macro_f1, 4)

def extract_metrics(output):
    """Extract detection count and MQTT metrics from engine output."""
    metrics = {"detections": 0, "packets": 0, "flows": 0, "blocked_ips": 0,
               "mqtt_flows": 0, "mqtt_messages": 0, "mqtt_parse_rate": 0}
    
    m = re.search(r"Total Attacks Detected:\s+(\d+)", output)
    if not m:
        m = re.search(r"Attacks Detected:\s+(\d+)", output)
    if m: metrics["detections"] = int(m.group(1))
    
    m = re.search(r"Total Packets.*?:\s+(\d+)", output)
    if not m:
        m = re.search(r"Total Packets:\s+(\d+)", output)
    if m: metrics["packets"] = int(m.group(1))
    
    m = re.search(r"Total Flows:\s+(\d+)", output)
    if not m:
        m = re.search(r"Total flows:\s+(\d+)", output)
    if m: metrics["flows"] = int(m.group(1))
    
    m = re.search(r"Blocked (\d+) attacker IPs", output)
    if m: metrics["blocked_ips"] = int(m.group(1))
    
    # MQTT metrics
    m = re.search(r"MQTT Flows:\s+(\d+)", output)
    if m: metrics["mqtt_flows"] = int(m.group(1))
    
    m = re.search(r"(\d+)\s+messages\s+\((\d+)\s+successful\)", output)
    if m:
        metrics["mqtt_messages"] = int(m.group(1))
        metrics["mqtt_parse_rate"] = int(m.group(2))
    
    m = re.search(r"Parse:(\d+)%", output)
    if m: metrics["mqtt_parse_rate"] = int(m.group(1))
    
    return metrics

# ────────────────────── MAIN PIPELINE ──────────────────────

def main():
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                                                              ║")
    print("║     IWSN Security — Robustness Test Harness v3.0             ║")
    print("║     Attack Detection + MQTT Parsing + Performance Metrics    ║")
    print("║                                                              ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    # Check prerequisites — prefer MQTT analyzer, fall back to IDS-only
    engine_binary = DPI_ENGINE
    engine_type = "dpi_mqtt_analyzer (IDS + MQTT)"
    if not os.path.exists(DPI_ENGINE):
        if os.path.exists(DPI_ENGINE_FALLBACK):
            engine_binary = DPI_ENGINE_FALLBACK
            engine_type = "dpi_engine_ids (IDS only, no MQTT)"
            print(f"  ⚠ MQTT analyzer not found, using: {engine_type}")
        else:
            print(f"[!] No engine binary found!")
            print("    Run: cd c_dpi_engine && make all")
            sys.exit(1)
    
    print(f"  Engine: {engine_type}")

    os.makedirs(PCAP_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)

    # ──── STEP 1: Generate attack PCAPs ────
    print("\n═══════════════════════════════════════════════════════════════")
    print("  STEP 1: Generating Attack + MQTT PCAPs via Simulator")
    print("═══════════════════════════════════════════════════════════════\n")

    sim_cmd = f"python3 {SIMULATOR} --preset all --difficulty easy --seed 42 --output {PCAP_DIR}"
    print(f"  $ {sim_cmd}\n")
    sim_output = run_cmd(sim_cmd, timeout=120)
    print(sim_output)

    manifest_path = os.path.join(PCAP_DIR, "manifest.json")
    if not os.path.exists(manifest_path):
        print("[!] Manifest not found. Simulator may have failed.")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    # ──── STEP 2: Run each PCAP through Rule Engine + MQTT Parser ────
    print("\n═══════════════════════════════════════════════════════════════")
    print("  STEP 2: Running PCAPs Through IDS + MQTT Parser")
    print("═══════════════════════════════════════════════════════════════\n")

    results = []
    total_mqtt_flows_all = 0
    total_mqtt_msgs_all = 0
    
    for entry in manifest["attacks"]:
        pcap_file = entry["file"]
        attack_name = entry["name"]
        attack_type = entry["attack_type"]
        
        if not os.path.exists(pcap_file):
            print(f"  ✗ {attack_name}: PCAP not found")
            continue

        print(f"  Testing: {attack_name:25s} ... ", end="", flush=True)
        
        # Create a working dir for each test to isolate report files
        test_dir = os.path.join(REPORT_DIR, attack_name)
        os.makedirs(test_dir, exist_ok=True)
        
        # Run engine (dpi_mqtt_analyzer takes only 1 arg)
        start = time.time()
        if engine_binary == DPI_ENGINE:
            cmd = f"cd {test_dir} && {engine_binary} {pcap_file}"
        else:
            report_file = os.path.join(test_dir, "ids_report.txt")
            cmd = f"{engine_binary} {pcap_file} {report_file}"
        output = run_cmd(cmd, timeout=60)
        elapsed = time.time() - start
        
        # Also read any generated report files
        report_text = ""
        for rfile in ["ids_detailed_report.txt", "mqtt_packets_detailed.txt", "performance_metrics.txt", "ids_report.txt"]:
            rpath = os.path.join(test_dir, rfile)
            if os.path.exists(rpath):
                try:
                    with open(rpath) as rf:
                        report_text += rf.read() + "\n"
                except:
                    pass
        combined_output = output + "\n" + report_text
        
        legacy_detected, legacy_result_type = check_detection_legacy(combined_output, attack_type)
        total_attacks_detected = extract_total_attacks(combined_output)
        detected_attack_types = extract_detected_attack_types(report_text)
        detected_attack_types_canonical = [to_canonical(item) for item in detected_attack_types]
        detected_attack_families = [to_family(item) for item in detected_attack_types]

        detected, result_type = check_detection_strict(total_attacks_detected, attack_type)
        exact_type_match = None
        semantic_type_match = None
        family_match = None
        if attack_type not in ("None", "MQTT Traffic"):
            exact_type_match = check_exact_type_match(attack_type, detected_attack_types)
            semantic_type_match = check_semantic_type_match(attack_type, detected_attack_types)
            expected_family = to_family(attack_type)
            family_match = expected_family in set(detected_attack_families)

        metrics = extract_metrics(combined_output)
        
        total_mqtt_flows_all += metrics["mqtt_flows"]
        total_mqtt_msgs_all += metrics["mqtt_messages"]
        
        status = "✓" if (result_type in ["true_positive", "true_negative"]) else "✗"
        mqtt_info = f", MQTT:{metrics['mqtt_flows']}f/{metrics['mqtt_messages']}m" if metrics["mqtt_flows"] > 0 else ""
        print(f"{status} {result_type:20s} ({metrics['detections']} det, {elapsed:.2f}s{mqtt_info})")
        
        results.append({
            "name": attack_name,
            "attack_type": attack_type,
            "rfc_reference": entry["rfc_reference"],
            "detected": detected,
            "result_type": result_type,
            "legacy_detected": legacy_detected,
            "legacy_result_type": legacy_result_type,
            "exact_type_match": exact_type_match,
            "semantic_type_match": semantic_type_match,
            "family_match": family_match,
            "detected_attack_types": detected_attack_types,
            "detected_attack_types_canonical": detected_attack_types_canonical,
            "detected_attack_families": detected_attack_families,
            "total_attacks_detected": total_attacks_detected,
            "detections": metrics["detections"],
            "packets_analyzed": metrics["packets"],
            "flows": metrics["flows"],
            "blocked_ips": metrics["blocked_ips"],
            "mqtt_flows": metrics["mqtt_flows"],
            "mqtt_messages": metrics["mqtt_messages"],
            "mqtt_packets_in_pcap": entry.get("mqtt_packets", 0),
            "elapsed_seconds": round(elapsed, 3),
            "attack_packets": entry["attack_packets"],
            "total_packets": entry["total_packets"],
        })

    # ──── STEP 3: Compute Metrics ────
    print("\n═══════════════════════════════════════════════════════════════")
    print("  STEP 3: Computing Performance Metrics")
    print("═══════════════════════════════════════════════════════════════\n")

    tp = sum(1 for r in results if r["result_type"] == "true_positive")
    fp = sum(1 for r in results if r["result_type"] == "false_positive")
    tn = sum(1 for r in results if r["result_type"] == "true_negative")
    fn = sum(1 for r in results if r["result_type"] == "false_negative")
    total = len(results)

    legacy_tp = sum(1 for r in results if r["legacy_result_type"] == "true_positive")
    legacy_fp = sum(1 for r in results if r["legacy_result_type"] == "false_positive")
    legacy_tn = sum(1 for r in results if r["legacy_result_type"] == "true_negative")
    legacy_fn = sum(1 for r in results if r["legacy_result_type"] == "false_negative")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2*(precision*recall)/(precision+recall) if (precision+recall) > 0 else 0
    accuracy = (tp + tn) / total if total > 0 else 0

    legacy_precision = legacy_tp / (legacy_tp + legacy_fp) if (legacy_tp + legacy_fp) > 0 else 0
    legacy_recall = legacy_tp / (legacy_tp + legacy_fn) if (legacy_tp + legacy_fn) > 0 else 0
    legacy_f1 = 2*(legacy_precision*legacy_recall)/(legacy_precision+legacy_recall) if (legacy_precision+legacy_recall) > 0 else 0
    legacy_accuracy = (legacy_tp + legacy_tn) / total if total > 0 else 0

    attack_rows = [r for r in results if r["attack_type"] not in ("None", "MQTT Traffic")]
    exact_type_matches = sum(1 for r in attack_rows if r.get("exact_type_match") is True)
    exact_type_total = len(attack_rows)
    exact_type_accuracy = (exact_type_matches / exact_type_total) if exact_type_total > 0 else 0
    semantic_type_matches = sum(1 for r in attack_rows if r.get("semantic_type_match") is True)
    semantic_type_accuracy = (semantic_type_matches / exact_type_total) if exact_type_total > 0 else 0
    family_matches = sum(1 for r in attack_rows if r.get("family_match") is True)
    family_accuracy = (family_matches / exact_type_total) if exact_type_total > 0 else 0
    per_class_metrics, macro_precision, macro_recall, macro_f1 = compute_per_class_metrics(results)
    per_family_metrics, family_macro_precision, family_macro_recall, family_macro_f1 = compute_per_family_metrics(results)

    print(f"  ── IDS Detection Metrics ──")
    print(f"  True Positives:   {tp}")
    print(f"  False Positives:  {fp}")
    print(f"  True Negatives:   {tn}")
    print(f"  False Negatives:  {fn}")
    print(f"  ────────────────────────")
    print(f"  Precision:        {precision*100:.1f}%")
    print(f"  Recall:           {recall*100:.1f}%")
    print(f"  F1-Score:         {f1*100:.1f}%")
    print(f"  Accuracy:         {accuracy*100:.1f}%")
    print(f"  Exact Type Match: {exact_type_matches}/{exact_type_total} ({exact_type_accuracy*100:.1f}%)")
    print(f"  Semantic Match:   {semantic_type_matches}/{exact_type_total} ({semantic_type_accuracy*100:.1f}%)")
    print(f"  Family Match:     {family_matches}/{exact_type_total} ({family_accuracy*100:.1f}%)")
    print(f"  Macro Precision:  {macro_precision*100:.1f}%")
    print(f"  Macro Recall:     {macro_recall*100:.1f}%")
    print(f"  Macro F1:         {macro_f1*100:.1f}%")
    print(f"  Family Macro P/R/F1: {family_macro_precision*100:.1f}% / {family_macro_recall*100:.1f}% / {family_macro_f1*100:.1f}%")

    print(f"\n  ── Legacy (Broad Keyword) Metrics ──")
    print(f"  Precision:        {legacy_precision*100:.1f}%")
    print(f"  Recall:           {legacy_recall*100:.1f}%")
    print(f"  F1-Score:         {legacy_f1*100:.1f}%")
    print(f"  Accuracy:         {legacy_accuracy*100:.1f}%")

    print(f"\n  ── MQTT Parser Metrics ──")
    print(f"  Total MQTT Flows:    {total_mqtt_flows_all}")
    print(f"  Total MQTT Messages: {total_mqtt_msgs_all}")
    total_mqtt_in_pcap = sum(r.get("mqtt_packets_in_pcap", 0) for r in results)
    print(f"  MQTT Pkts in PCAPs:  {total_mqtt_in_pcap}")

    avg_time = sum(r["elapsed_seconds"] for r in results) / len(results) if results else 0
    total_pkts = sum(r["packets_analyzed"] for r in results)
    total_time = sum(r["elapsed_seconds"] for r in results)
    pps = total_pkts / total_time if total_time > 0 else 0

    # ──── STEP 4: Generate Report ────
    report_md = os.path.join(REPORT_DIR, "robustness_report.md")
    report_json = os.path.join(REPORT_DIR, "robustness_results.json")

    report_data = {
        "timestamp": datetime.now().isoformat(),
        "difficulty": manifest.get("difficulty", "easy"),
        "engine": engine_type,
        "summary": {
            "total_tests": total, "true_positives": tp, "false_positives": fp,
            "true_negatives": tn, "false_negatives": fn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1_score": round(f1, 4), "accuracy": round(accuracy, 4),
            "exact_type_matches": exact_type_matches,
            "exact_type_total": exact_type_total,
            "exact_type_accuracy": round(exact_type_accuracy, 4),
            "semantic_type_matches": semantic_type_matches,
            "semantic_type_accuracy": round(semantic_type_accuracy, 4),
            "family_matches": family_matches,
            "family_accuracy": round(family_accuracy, 4),
            "macro_precision": macro_precision,
            "macro_recall": macro_recall,
            "macro_f1": macro_f1,
            "family_macro_precision": family_macro_precision,
            "family_macro_recall": family_macro_recall,
            "family_macro_f1": family_macro_f1,
            "avg_detection_time_sec": round(avg_time, 3),
            "total_packets_analyzed": total_pkts,
            "throughput_pps": round(pps, 1),
        },
        "legacy_summary": {
            "true_positives": legacy_tp,
            "false_positives": legacy_fp,
            "true_negatives": legacy_tn,
            "false_negatives": legacy_fn,
            "precision": round(legacy_precision, 4),
            "recall": round(legacy_recall, 4),
            "f1_score": round(legacy_f1, 4),
            "accuracy": round(legacy_accuracy, 4),
        },
        "mqtt_summary": {
            "total_mqtt_flows_detected": total_mqtt_flows_all,
            "total_mqtt_messages_parsed": total_mqtt_msgs_all,
            "total_mqtt_packets_in_pcaps": total_mqtt_in_pcap,
        },
        "per_class_metrics": per_class_metrics,
        "per_family_metrics": per_family_metrics,
        "per_attack_results": results,
    }

    with open(report_json, "w") as f:
        json.dump(report_data, f, indent=2)

    # Generate Markdown report
    with open(report_md, "w") as f:
        f.write("# IWSN Security — Robustness Test Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Difficulty:** {manifest.get('difficulty', 'easy').upper()}  \n")
        f.write(f"**Engine:** {engine_type}  \n")
        f.write(f"**Rule Engine:** RFC-Compliant IDS v4.0 (21 attack types)  \n\n")
        
        f.write("## IDS Detection Performance (Strict)\n\n")
        f.write("| Metric | Value |\n|---|---|\n")
        f.write(f"| Total Tests | {total} |\n")
        f.write(f"| True Positives | {tp} |\n")
        f.write(f"| False Positives | {fp} |\n")
        f.write(f"| True Negatives | {tn} |\n")
        f.write(f"| False Negatives | {fn} |\n")
        f.write(f"| **Precision** | **{precision*100:.1f}%** |\n")
        f.write(f"| **Recall** | **{recall*100:.1f}%** |\n")
        f.write(f"| **F1-Score** | **{f1*100:.1f}%** |\n")
        f.write(f"| **Accuracy** | **{accuracy*100:.1f}%** |\n")
        f.write(f"| **Exact Type Match** | **{exact_type_matches}/{exact_type_total} ({exact_type_accuracy*100:.1f}%)** |\n")
        f.write(f"| **Semantic Type Match** | **{semantic_type_matches}/{exact_type_total} ({semantic_type_accuracy*100:.1f}%)** |\n")
        f.write(f"| **Family Match** | **{family_matches}/{exact_type_total} ({family_accuracy*100:.1f}%)** |\n")
        f.write(f"| **Macro Precision (Class)** | **{macro_precision*100:.1f}%** |\n")
        f.write(f"| **Macro Recall (Class)** | **{macro_recall*100:.1f}%** |\n")
        f.write(f"| **Macro F1 (Class)** | **{macro_f1*100:.1f}%** |\n")
        f.write(f"| **Macro Precision (Family)** | **{family_macro_precision*100:.1f}%** |\n")
        f.write(f"| **Macro Recall (Family)** | **{family_macro_recall*100:.1f}%** |\n")
        f.write(f"| **Macro F1 (Family)** | **{family_macro_f1*100:.1f}%** |\n")
        f.write(f"| Avg Detection Time | {avg_time:.3f}s |\n")
        f.write(f"| Total Packets | {total_pkts:,} |\n")
        f.write(f"| Throughput | {pps:,.0f} pkt/s |\n\n")

        f.write("## Legacy Detection Performance (Broad Keyword)\n\n")
        f.write("| Metric | Value |\n|---|---|\n")
        f.write(f"| True Positives | {legacy_tp} |\n")
        f.write(f"| False Positives | {legacy_fp} |\n")
        f.write(f"| True Negatives | {legacy_tn} |\n")
        f.write(f"| False Negatives | {legacy_fn} |\n")
        f.write(f"| **Precision** | **{legacy_precision*100:.1f}%** |\n")
        f.write(f"| **Recall** | **{legacy_recall*100:.1f}%** |\n")
        f.write(f"| **F1-Score** | **{legacy_f1*100:.1f}%** |\n")
        f.write(f"| **Accuracy** | **{legacy_accuracy*100:.1f}%** |\n\n")
        
        f.write("## MQTT Parser Performance\n\n")
        f.write("| Metric | Value |\n|---|---|\n")
        f.write(f"| MQTT Packets in PCAPs | {total_mqtt_in_pcap} |\n")
        f.write(f"| MQTT Flows Detected | {total_mqtt_flows_all} |\n")
        f.write(f"| MQTT Messages Parsed | {total_mqtt_msgs_all} |\n\n")

        f.write("## Per-Attack Results\n\n")
        f.write("| Attack | RFC | Result | Exact | Semantic | Family | Detected Types | Detections | MQTT Flows | Time |\n")
        f.write("|---|---|---|---|---|---|---|---|---|---|\n")
        for r in results:
            icon = "✅" if r["result_type"] in ["true_positive","true_negative"] else "❌"
            if r["attack_type"] in ["None", "MQTT Traffic"]:
                exact_match = "N/A"
                semantic_match = "N/A"
                family_match_md = "N/A"
            else:
                exact_match = "✅" if r.get("exact_type_match") else "❌"
                semantic_match = "✅" if r.get("semantic_type_match") else "❌"
                family_match_md = "✅" if r.get("family_match") else "❌"
            detected_types_str = ", ".join(r.get("detected_attack_types", [])) if r.get("detected_attack_types") else "-"
            f.write(f"| {r['attack_type']} | {r['rfc_reference']} | {icon} {r['result_type']} | {exact_match} | {semantic_match} | {family_match_md} | {detected_types_str} | {r['detections']} | {r['mqtt_flows']} | {r['elapsed_seconds']:.2f}s |\n")

        f.write("\n## Per-Class Metrics (Canonical Labels)\n\n")
        f.write("| Class | TP | FP | FN | Precision | Recall | F1 |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|\n")
        for cls, stats in sorted(per_class_metrics.items()):
            f.write(
                f"| {cls} | {stats['tp']} | {stats['fp']} | {stats['fn']} | "
                f"{stats['precision']*100:.1f}% | {stats['recall']*100:.1f}% | {stats['f1']*100:.1f}% |\n"
            )

        f.write("\n## Per-Family Metrics\n\n")
        f.write("| Family | TP | FP | FN | Precision | Recall | F1 |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|\n")
        for fam, stats in sorted(per_family_metrics.items()):
            f.write(
                f"| {fam} | {stats['tp']} | {stats['fp']} | {stats['fn']} | "
                f"{stats['precision']*100:.1f}% | {stats['recall']*100:.1f}% | {stats['f1']*100:.1f}% |\n"
            )
        
        f.write("\n## Detection Failures\n\n")
        failures = [r for r in results if r["result_type"] in ["false_negative", "false_positive"]]
        if failures:
            for r in failures:
                f.write(f"- **{r['attack_type']}** ({r['name']}): {r['result_type']} — ")
                f.write(f"{r['attack_packets']} attack packets, {r['detections']} detections\n")
        else:
            if exact_type_matches == exact_type_total:
                f.write("*No strict detection failures and all attack labels matched exactly.*\n")
            else:
                f.write("*No strict detection failures, but some attacks were labeled as a different class.*\n")
        
        f.write("\n---\n*Report generated by IWSN Robustness Test Harness v3.0*\n")

    print(f"\n═══════════════════════════════════════════════════════════════")
    print(f"  RESULTS SUMMARY")
    print(f"═══════════════════════════════════════════════════════════════")
    print(f"  IDS Accuracy:      {accuracy*100:.1f}%")
    print(f"  IDS F1-Score:      {f1*100:.1f}%")
    print(f"  MQTT Flows Found:  {total_mqtt_flows_all}")
    print(f"  MQTT Msgs Parsed:  {total_mqtt_msgs_all}")
    print(f"  Throughput:        {pps:,.0f} packets/second")
    print(f"")
    print(f"  Reports saved:")
    print(f"    {report_md}")
    print(f"    {report_json}")
    print(f"═══════════════════════════════════════════════════════════════\n")

if __name__ == "__main__":
    main()
