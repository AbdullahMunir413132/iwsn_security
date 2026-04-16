# ============================================================================
# IWSN Security - Unified DPI + IDS + MQTT Analyzer
# Single-binary build: iwsn_analyzer
# Pipeline: DPI Engine → Rule Engine (IDS) → MQTT Parser
# Requires: nDPI library, libpcap
# ============================================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g \
          -I./include -I/usr/local/include -I/usr/include -I/usr/include/ndpi
LDFLAGS = -L/usr/local/lib -L/usr/lib -L/usr/lib/x86_64-linux-gnu \
          -lndpi -lpcap -lm

# Directories
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

# ---------------------------------------------------------------------------
# Single unified binary — consolidates DPI + IDS + MQTT analysis
# Entry point: main_new_workflow.c
# ---------------------------------------------------------------------------
SOURCES = $(SRC_DIR)/main_new_workflow.c \
          $(SRC_DIR)/dpi_engine.c \
          $(SRC_DIR)/dpi_engine_flow.c \
          $(SRC_DIR)/pcap_utils.c \
          $(SRC_DIR)/mqtt_parser.c \
          $(SRC_DIR)/mqtt_wrapper.c \
          $(SRC_DIR)/rule_engine.c \
          $(SRC_DIR)/rule_engine_attacks.c \
          $(SRC_DIR)/rule_engine_attacks_new.c \
          $(SRC_DIR)/rule_engine_report.c \
          $(SRC_DIR)/performance_metrics.c \
          $(SRC_DIR)/detailed_reports.c \
          $(SRC_DIR)/ids_reports.c \
          $(SRC_DIR)/mqtt_reports.c \
          $(SRC_DIR)/live_capture.c

OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET  = $(BIN_DIR)/iwsn_analyzer

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------

# Default: build the unified analyzer
all: directories $(TARGET)

# Create output directories
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Link
$(TARGET): $(OBJECTS)
	@echo "Linking $@..."
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "✓ Build complete: $@"

# Compile
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# ---------------------------------------------------------------------------
# Convenience targets
# ---------------------------------------------------------------------------

# Run with a pcap file
run: $(TARGET)
	@echo "Usage: sudo ./$(TARGET) <pcap_file>"
	@echo "       sudo ./$(TARGET)                (interactive/live mode)"

# Quick test with a sample pcap (override PCAP= on the command line)
PCAP ?= ../scripts/pcap_samples/mqtt_normal_traffic.pcap
test: $(TARGET)
	@echo "Running analysis on $(PCAP)..."
	./$(TARGET) $(PCAP)

# Run the full pipeline: simulate → analyze → export metrics
pipeline: $(TARGET)
	@echo "=== IWSN Full Pipeline ==="
	@echo "[1/3] Generating attack PCAPs..."
	cd ../scripts && python3 attack_simulator.py
	@echo "[2/3] Running DPI + IDS + MQTT analysis..."
	./$(TARGET) ../scripts/simulator_output/combined_attack_traffic.pcap
	@echo "[3/3] Exporting Grafana metrics..."
	cd ../visualization && python3 grafana_exporter.py --watch 0
	@echo "=== Pipeline complete ==="

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "✓ Clean complete"

# Install
install: all
	@echo "Installing to /usr/local/bin..."
	sudo cp $(TARGET) /usr/local/bin/iwsn_analyzer
	@echo "✓ Installed: /usr/local/bin/iwsn_analyzer"

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/iwsn_analyzer

# Help
help:
	@echo ""
	@echo "  IWSN Security — Unified Analyzer"
	@echo "  ─────────────────────────────────"
	@echo ""
	@echo "  Targets:"
	@echo "    all       Build iwsn_analyzer (default)"
	@echo "    test      Run with sample PCAP (override: make test PCAP=file.pcap)"
	@echo "    pipeline  Simulate → Analyze → Export (full pipeline)"
	@echo "    clean     Remove build artifacts"
	@echo "    install   Install to /usr/local/bin"
	@echo "    uninstall Remove from /usr/local/bin"
	@echo "    help      Show this message"
	@echo ""
	@echo "  Usage:"
	@echo "    make                                  # Build"
	@echo "    ./bin/iwsn_analyzer capture.pcap      # Offline PCAP analysis"
	@echo "    sudo ./bin/iwsn_analyzer              # Interactive / live capture"
	@echo "    make test PCAP=my_traffic.pcap        # Quick test"
	@echo "    make pipeline                         # Full pipeline run"
	@echo ""

.PHONY: all clean install uninstall test run pipeline help directories
