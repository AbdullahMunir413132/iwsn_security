# 📁 COMPLETE FILE STRUCTURE & INTEGRATION GUIDE

## Final Directory Structure

After integrating all files, your project should look like this:

```
iwsn_security/
│
├── c_dpi_engine/
│   │
│   ├── include/
│   │   ├── dpi_engine.h           # Existing - DPI structures
│   │   └── rule_engine.h          # NEW - IDS structures
│   │
│   ├── src/
│   │   ├── main.c                 # Existing - Original DPI main
│   │   ├── main_with_ids.c        # NEW - DPI + IDS integrated main
│   │   ├── dpi_engine.c           # Existing - Layer 2-5 parsing
│   │   ├── dpi_engine_flow.c      # Existing - Flow tracking
│   │   ├── rule_engine.c          # NEW - IDS core engine
│   │   ├── rule_engine_attacks.c  # NEW - Attack detection logic
│   │   └── rule_engine_report.c   # NEW - Reporting functions
│   │
│   ├── obj/                       # Build artifacts (auto-generated)
│   │   └── *.o                    # Compiled object files
│   │
│   ├── bin/                       # Binaries (auto-generated)
│   │   ├── dpi_engine             # Original DPI binary
│   │   └── dpi_engine_ids         # NEW - DPI + IDS binary
│   │
│   └── Makefile                   # NEW - Updated build system
│
├── pcap_samples/                  # Sample PCAP files
│   ├── mqtt.pcap
│   ├── http.cap
│   ├── dns.cap
│   └── test_capture.pcap
│
├── attack_samples/                # NEW - Attack PCAP files
│   ├── syn_flood.pcap
│   ├── port_scan.pcap
│   └── udp_flood.pcap
│
├── reports/                       # NEW - Generated reports
│   ├── attack_report.txt
│   └── analysis_*.txt
│
└── docs/                          # NEW - Documentation
    ├── IDS_README.md
    ├── INSTALLATION_GUIDE.md
    └── ATTACK_DETECTION_REFERENCE.md
```

## Files You Need to Add/Update

### NEW FILES (9 files)

1. **include/rule_engine.h**
   - IDS data structures
   - Attack type enumerations
   - Function prototypes for attack detection
   - Detection threshold configuration

2. **src/main_with_ids.c**
   - Integrated DPI + IDS main program
   - PCAP processing with attack detection
   - Comprehensive reporting

3. **src/rule_engine.c**
   - Core IDS engine implementation
   - Initialization and configuration
   - IP statistics management
   - Per-packet analysis

4. **src/rule_engine_attacks.c**
   - Individual attack detection algorithms
   - All 9+ attack types implemented
   - Confidence scoring logic

5. **src/rule_engine_report.c**
   - Attack detection printing
   - Summary report generation
   - Detailed analysis output
   - Text file report generation

6. **Makefile** (UPDATE existing)
   - Build targets for both versions
   - Support for rule engine compilation
   - Convenience targets (test-ids, etc.)

7. **IDS_README.md** (Documentation)
   - Complete feature overview
   - Usage instructions
   - Attack detection details

8. **INSTALLATION_GUIDE.md** (Documentation)
   - Step-by-step installation
   - Troubleshooting guide
   - Verification checklist

9. **ATTACK_DETECTION_REFERENCE.md** (Documentation)
   - Quick reference for all attacks
   - Detection logic explained
   - Threshold configuration

### EXISTING FILES (Keep as-is)

- include/dpi_engine.h
- src/main.c
- src/dpi_engine.c
- src/dpi_engine_flow.c
- README.md
- BUILD_INSTRUCTIONS.md
- QUICK_START.md

## Integration Steps

### STEP 1: File Placement

```bash
cd ~/iwsn_security/c_dpi_engine

# Place header file
cp rule_engine.h include/

# Place source files
cp main_with_ids.c src/
cp rule_engine.c src/
cp rule_engine_attacks.c src/
cp rule_engine_report.c src/

# Replace Makefile
cp Makefile .

# Create documentation directory
mkdir -p ../docs
cp IDS_README.md ../docs/
cp INSTALLATION_GUIDE.md ../docs/
cp ATTACK_DETECTION_REFERENCE.md ../docs/
```

### STEP 2: Verify File Structure

```bash
# Check all header files
ls -lh include/
# Should show:
# - dpi_engine.h (existing)
# - rule_engine.h (new)

# Check all source files
ls -lh src/
# Should show:
# - main.c (existing)
# - main_with_ids.c (new)
# - dpi_engine.c (existing)
# - dpi_engine_flow.c (existing)
# - rule_engine.c (new)
# - rule_engine_attacks.c (new)
# - rule_engine_report.c (new)

# Check Makefile
ls -lh Makefile
```

### STEP 3: Build Both Versions

```bash
# Clean any old builds
make clean

# Build everything
make

# Should create two binaries:
# - bin/dpi_engine (original)
# - bin/dpi_engine_ids (with IDS)

# Verify binaries
ls -lh bin/
file bin/dpi_engine
file bin/dpi_engine_ids
```

### STEP 4: Test Execution

```bash
# Test original DPI version
./bin/dpi_engine ../pcap_samples/mqtt.pcap

# Test IDS version
./bin/dpi_engine_ids ../pcap_samples/mqtt.pcap
```

## Build Targets Explained

```bash
# Build both versions (default)
make                    # or: make all

# Build only IDS version
make ids

# Build only DPI version (original)
make dpi

# Clean build artifacts
make clean

# Install binaries to /usr/local/bin
make install

# Run tests
make test-ids           # Test IDS version
make test-dpi           # Test DPI version

# Show help
make help
```

## Key Differences Between Versions

### Original DPI (bin/dpi_engine)
```
Usage: ./bin/dpi_engine <pcap_file>

Features:
✓ Complete packet parsing (L2-L5)
✓ nDPI protocol detection (L7)
✓ Flow statistics collection
✓ Detailed packet-by-packet analysis
✗ No attack detection
✗ No intrusion alerts
```

### DPI + IDS (bin/dpi_engine_ids)
```
Usage: ./bin/dpi_engine_ids <pcap_file> [report_file]

Features:
✓ Everything from original DPI
✓ Real-time attack detection
✓ 9+ attack types supported
✓ Severity classification
✓ Confidence scoring
✓ Attack summary reports
✓ Detailed attack analysis
✓ Text report generation
```

## Memory Requirements

```
Original DPI:
  - Base: ~50 MB
  - Per flow: ~10 KB
  - 10,000 flows: ~150 MB

DPI + IDS:
  - Base: ~75 MB
  - Per flow: ~12 KB
  - Per IP tracked: ~2 KB
  - Per detection: ~1 KB
  - 10,000 flows + 1,000 IPs: ~200 MB
```

## Code Dependencies

### rule_engine.h depends on:
- dpi_engine.h (flow_stats_t, parsed_packet_t)
- Standard C libraries (stdint.h, time.h)

### rule_engine.c depends on:
- rule_engine.h
- dpi_engine.h
- Standard libraries

### rule_engine_attacks.c depends on:
- rule_engine.h
- Math library (for fmin function)

### rule_engine_report.c depends on:
- rule_engine.h
- Network libraries (arpa/inet.h)

### main_with_ids.c depends on:
- dpi_engine.h
- rule_engine.h
- pcap.h

## Compilation Order

The Makefile ensures correct compilation order:

1. **Headers** (no compilation, just included)
   - dpi_engine.h
   - rule_engine.h

2. **Object files** (compiled independently)
   - dpi_engine.o
   - dpi_engine_flow.o
   - rule_engine.o
   - rule_engine_attacks.o
   - rule_engine_report.o
   - main_with_ids.o

3. **Binary** (linked together)
   - All .o files → dpi_engine_ids

## Testing Checklist

After integration, test these scenarios:

### Basic Functionality
- [ ] Program compiles without errors
- [ ] Program runs without crashing
- [ ] PCAP file is processed successfully
- [ ] Flows are tracked correctly
- [ ] Protocols are detected (via nDPI)

### Attack Detection
- [ ] Normal traffic: No false positives
- [ ] SYN flood: Detected correctly
- [ ] UDP flood: Detected correctly
- [ ] Port scan: Detected correctly
- [ ] Multiple attacks: All detected

### Output Quality
- [ ] PCAP summary is accurate
- [ ] Attack summary is clear
- [ ] Detailed analysis is comprehensive
- [ ] Report file is generated
- [ ] Console output is readable

### Performance
- [ ] Processes 1,000 packets in < 1 second
- [ ] Handles 10,000 flows without issues
- [ ] Memory usage stays reasonable
- [ ] No memory leaks (check with valgrind)

## Common Integration Issues

### Issue: Undefined reference to rule_engine functions
```
Fix: Ensure all rule_engine*.c files are in Makefile SOURCES_IDS
Check: grep "rule_engine" Makefile
```

### Issue: Cannot find rule_engine.h
```
Fix: Verify rule_engine.h is in include/ directory
Check: ls include/rule_engine.h
```

### Issue: Conflicting definitions
```
Fix: Ensure no duplicate function/struct definitions
Check: No main() in rule_engine*.c files
```

### Issue: Wrong binary executed
```
Fix: Use full path to specify which binary
./bin/dpi_engine_ids file.pcap  # IDS version
./bin/dpi_engine file.pcap       # Original version
```

## Version Control Recommendations

If using git:

```bash
# Add new files
git add include/rule_engine.h
git add src/main_with_ids.c
git add src/rule_engine*.c
git add Makefile
git add docs/*.md

# Commit
git commit -m "Add intrusion detection system (IDS) with 9+ attack types"

# Create tag
git tag -a v3.0-ids -m "DPI Engine v3.0 with Intrusion Detection"
```

## Next Steps After Integration

1. **Customize Thresholds**
   - Edit `rule_engine_set_default_thresholds()` in src/rule_engine.c
   - Adjust based on your network characteristics
   - Rebuild and test

2. **Add More Attack Types**
   - Add enum to rule_engine.h
   - Implement detection in rule_engine_attacks.c
   - Call from rule_engine_analyze_flow()

3. **Enhance Reporting**
   - Add JSON output format
   - Create CSV export
   - Add real-time alerts

4. **Convert to Real-time**
   - Modify main_with_ids.c
   - Use pcap_open_live() instead of pcap_open_offline()
   - Add signal handling for graceful shutdown

5. **Integrate with SDN Controller**
   - Add REST API client
   - Send alerts to controller
   - Implement flow blocking

---

**Integration Complete!** 🎉

You now have a complete DPI + IDS system ready for deployment.

For questions or issues, refer to:
- INSTALLATION_GUIDE.md for setup help
- IDS_README.md for usage information
- ATTACK_DETECTION_REFERENCE.md for detection details
