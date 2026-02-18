# Makefile for IWSN Security DPI Engine + Intrusion Detection System
# Requires: nDPI library, libpcap

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -I./include -I/usr/local/include -I/usr/include -I/usr/include/ndpi
LDFLAGS = -L/usr/local/lib -L/usr/lib -L/usr/lib/x86_64-linux-gnu -lndpi -lpcap -lm

# Directories
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

# Source files for DPI + IDS
SOURCES_IDS = $(SRC_DIR)/main_with_ids.c \
              $(SRC_DIR)/dpi_engine.c \
              $(SRC_DIR)/dpi_engine_flow.c \
              $(SRC_DIR)/pcap_utils.c \
              $(SRC_DIR)/mqtt_parser.c \
              $(SRC_DIR)/mqtt_integration.c \
              $(SRC_DIR)/rule_engine.c \
              $(SRC_DIR)/rule_engine_attacks.c \
              $(SRC_DIR)/rule_engine_report.c \
              $(SRC_DIR)/performance_metrics.c \
              $(SRC_DIR)/detailed_reports.c \
              $(SRC_DIR)/ids_reports.c

# Source files for original DPI only
SOURCES_DPI = $(SRC_DIR)/main.c \
              $(SRC_DIR)/dpi_engine.c \
              $(SRC_DIR)/dpi_engine_flow.c \
              $(SRC_DIR)/mqtt_parser.c \
              $(SRC_DIR)/mqtt_integration.c \
              $(SRC_DIR)/pcap_utils.c \
              $(SRC_DIR)/performance_metrics.c \
              $(SRC_DIR)/detailed_reports.c

# Source files for new workflow (DPI → Rule Engine → MQTT Parser)
SOURCES_NEW = $(SRC_DIR)/main_new_workflow.c \
              $(SRC_DIR)/dpi_engine.c \
              $(SRC_DIR)/dpi_engine_flow.c \
              $(SRC_DIR)/pcap_utils.c \
              $(SRC_DIR)/mqtt_parser.c \
              $(SRC_DIR)/mqtt_wrapper.c \
              $(SRC_DIR)/rule_engine.c \
              $(SRC_DIR)/rule_engine_attacks.c \
              $(SRC_DIR)/rule_engine_report.c \
              $(SRC_DIR)/performance_metrics.c \
              $(SRC_DIR)/detailed_reports.c \
              $(SRC_DIR)/ids_reports.c \
              $(SRC_DIR)/mqtt_reports.c

# Object files
OBJECTS_IDS = $(SOURCES_IDS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
OBJECTS_DPI = $(SOURCES_DPI:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
OBJECTS_NEW = $(SOURCES_NEW:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Target binaries
TARGET_IDS = $(BIN_DIR)/dpi_engine_ids
TARGET_DPI = $(BIN_DIR)/dpi_engine
TARGET_NEW = $(BIN_DIR)/dpi_mqtt_analyzer

# Default target - build all including new workflow
all: directories $(TARGET_IDS) $(TARGET_DPI) $(TARGET_NEW)

# Build only IDS version
ids: directories $(TARGET_IDS)

# Build only DPI version (original)
dpi: directories $(TARGET_DPI)

# Create directories
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Link IDS version
$(TARGET_IDS): $(OBJECTS_IDS)
	@echo "Linking $@..."
	$(CC) $(OBJECTS_IDS) -o $@ $(LDFLAGS)
	@echo "✓ Build complete: $@"

# Link DPI version
$(TARGET_DPI): $(OBJECTS_DPI)
	@echo "Linking $@..."
	$(CC) $(OBJECTS_DPI) -o $@ $(LDFLAGS)
	@echo "✓ Build complete: $@"

# Link new workflow version
$(TARGET_NEW): $(OBJECTS_NEW)
	@echo "Linking $@..."
	$(CC) $(OBJECTS_NEW) -o $@ $(LDFLAGS)
	@echo "✓ Build complete: $@"

# Compile
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	@echo "Cleaning..."
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "✓ Clean complete"

# Install both binaries
install: all
	@echo "Installing to /usr/local/bin..."
	sudo cp $(TARGET_IDS) /usr/local/bin/
	sudo cp $(TARGET_DPI) /usr/local/bin/
	@echo "✓ Installation complete"

# Run IDS version with sample
test-ids: $(TARGET_IDS)
	@echo "Running IDS test with sample PCAP..."
	$(TARGET_IDS) ../pcap_samples/sample.pcap

# Run original DPI version
test-dpi: $(TARGET_DPI)
	@echo "Running DPI test with sample PCAP..."
	$(TARGET_DPI) ../pcap_samples/sample.pcap

# Help
help:
	@echo "IWSN Security DPI Engine + IDS - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build both IDS and DPI versions (default)"
	@echo "  ids          - Build only IDS version (with attack detection)"
	@echo "  dpi          - Build only DPI version (original)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install      - Install binaries to /usr/local/bin"
	@echo "  test-ids     - Run IDS version with sample PCAP"
	@echo "  test-dpi     - Run DPI version with sample PCAP"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Binaries:"
	@echo "  $(TARGET_IDS) - DPI + Intrusion Detection System"
	@echo "  $(TARGET_DPI) - DPI only (original)"
	@echo ""
	@echo "Requirements:"
	@echo "  - nDPI library installed (/usr/local/lib/libndpi.so)"
	@echo "  - libpcap-dev package"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make                              # Build both versions"
	@echo "  make ids                          # Build IDS version only"
	@echo "  ./bin/dpi_engine_ids capture.pcap # Run with attack detection"
	@echo "  ./bin/dpi_engine capture.pcap     # Run without attack detection"

.PHONY: all ids dpi clean install test-ids test-dpi help directories
