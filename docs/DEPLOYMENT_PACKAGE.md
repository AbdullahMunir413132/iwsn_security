# 📦 COMPLETE DEPLOYMENT PACKAGE

## All Files Included

This package contains **ALL** files needed for your IWSN Security DPI + IDS system.

## 📁 File Organization

### **EXISTING FILES** (From your original DPI engine)

#### Header Files (1 file)
- `dpi_engine.h` - DPI structures, flow tracking, packet parsing

#### Source Files (3 files)
- `dpi_engine.c` - Layer 2-5 parsing implementation
- `dpi_engine_flow.c` - Flow tracking and nDPI integration
- `main.c` - Original main program (DPI only, no IDS)

---

### **NEW FILES** (For IDS functionality)

#### Header Files (1 file)
- `rule_engine.h` - IDS structures, attack types, detection functions

#### Source Files (4 files)
- `main_with_ids.c` - NEW integrated main (DPI + IDS)
- `rule_engine.c` - IDS core engine
- `rule_engine_attacks.c` - Attack detection algorithms
- `rule_engine_report.c` - Report generation

#### Build System (1 file)
- `Makefile` - Updated to build both versions

#### Documentation (5 files)
- `FILE_STRUCTURE_GUIDE.md` - Integration instructions
- `INSTALLATION_GUIDE.md` - Step-by-step setup
- `IDS_README.md` - Feature overview
- `ATTACK_DETECTION_REFERENCE.md` - Attack detection details
- `ORIGINAL_README.md` - Your original README (for reference)

---

## 🗂️ How to Organize Files

### On Your Ubuntu VM

```bash
# 1. Create the directory structure
mkdir -p ~/iwsn_security/c_dpi_engine/{include,src,obj,bin}
mkdir -p ~/iwsn_security/{pcap_samples,attack_samples,reports,docs}

# 2. Place HEADER files
cd ~/iwsn_security/c_dpi_engine/include
# Copy here:
#   - dpi_engine.h (existing)
#   - rule_engine.h (new)

# 3. Place SOURCE files
cd ~/iwsn_security/c_dpi_engine/src
# Copy here:
#   - main.c (existing - original DPI only)
#   - main_with_ids.c (new - DPI + IDS)
#   - dpi_engine.c (existing)
#   - dpi_engine_flow.c (existing)
#   - rule_engine.c (new)
#   - rule_engine_attacks.c (new)
#   - rule_engine_report.c (new)

# 4. Place BUILD file
cd ~/iwsn_security/c_dpi_engine
# Copy here:
#   - Makefile (new/updated)

# 5. Place DOCUMENTATION
cd ~/iwsn_security/docs
# Copy here:
#   - All .md files
```

---

## 📋 Complete File List

### Total: 15 Files

```
HEADER FILES (2):
✓ dpi_engine.h                    [Existing]
✓ rule_engine.h                   [New]

SOURCE FILES (7):
✓ main.c                          [Existing]
✓ main_with_ids.c                 [New]
✓ dpi_engine.c                    [Existing]
✓ dpi_engine_flow.c               [Existing]
✓ rule_engine.c                   [New]
✓ rule_engine_attacks.c           [New]
✓ rule_engine_report.c            [New]

BUILD FILES (1):
✓ Makefile                        [Updated]

DOCUMENTATION (5):
✓ FILE_STRUCTURE_GUIDE.md         [New]
✓ INSTALLATION_GUIDE.md           [New]
✓ IDS_README.md                   [New]
✓ ATTACK_DETECTION_REFERENCE.md   [New]
✓ ORIGINAL_README.md              [Reference]
```

---

## 🚀 Quick Deployment Script

Save this as `deploy.sh` and run it:

```bash
#!/bin/bash
# Deployment script for IWSN Security DPI + IDS

echo "=========================================="
echo "IWSN Security DPI + IDS Deployment"
echo "=========================================="

# Set base directory
BASE_DIR=~/iwsn_security
DPI_DIR=$BASE_DIR/c_dpi_engine

# Create directory structure
echo "[1/6] Creating directory structure..."
mkdir -p $DPI_DIR/{include,src,obj,bin}
mkdir -p $BASE_DIR/{pcap_samples,attack_samples,reports,docs}

# Assume all files are in current directory
CURRENT_DIR=$(pwd)

# Copy header files
echo "[2/6] Copying header files..."
cp $CURRENT_DIR/dpi_engine.h $DPI_DIR/include/
cp $CURRENT_DIR/rule_engine.h $DPI_DIR/include/

# Copy source files
echo "[3/6] Copying source files..."
cp $CURRENT_DIR/main.c $DPI_DIR/src/
cp $CURRENT_DIR/main_with_ids.c $DPI_DIR/src/
cp $CURRENT_DIR/dpi_engine.c $DPI_DIR/src/
cp $CURRENT_DIR/dpi_engine_flow.c $DPI_DIR/src/
cp $CURRENT_DIR/rule_engine.c $DPI_DIR/src/
cp $CURRENT_DIR/rule_engine_attacks.c $DPI_DIR/src/
cp $CURRENT_DIR/rule_engine_report.c $DPI_DIR/src/

# Copy Makefile
echo "[4/6] Copying Makefile..."
cp $CURRENT_DIR/Makefile $DPI_DIR/

# Copy documentation
echo "[5/6] Copying documentation..."
cp $CURRENT_DIR/*.md $BASE_DIR/docs/ 2>/dev/null

# Build the project
echo "[6/6] Building project..."
cd $DPI_DIR
make clean
make

echo ""
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
echo ""
echo "Binaries created:"
ls -lh $DPI_DIR/bin/
echo ""
echo "To run:"
echo "  DPI only:     $DPI_DIR/bin/dpi_engine <pcap_file>"
echo "  DPI + IDS:    $DPI_DIR/bin/dpi_engine_ids <pcap_file> [report.txt]"
echo ""
echo "Documentation: $BASE_DIR/docs/"
echo "=========================================="
```

---

## 🔍 File Dependencies Map

```
main_with_ids.c
├── includes: dpi_engine.h
├── includes: rule_engine.h
└── links with: all .o files

main.c
├── includes: dpi_engine.h
└── links with: dpi_engine.o, dpi_engine_flow.o

dpi_engine.c
├── includes: dpi_engine.h
└── uses: nDPI library

dpi_engine_flow.c
├── includes: dpi_engine.h
└── uses: nDPI library

rule_engine.c
├── includes: rule_engine.h
└── includes: dpi_engine.h

rule_engine_attacks.c
├── includes: rule_engine.h
└── uses: math.h (for fmin)

rule_engine_report.c
├── includes: rule_engine.h
└── uses: network libs (arpa/inet.h)
```

---

## ✅ Verification Checklist

After deploying, verify:

### File Placement
- [ ] `include/` has 2 .h files
- [ ] `src/` has 7 .c files
- [ ] `Makefile` is in project root
- [ ] Documentation is accessible

### Build Success
- [ ] `make clean` works
- [ ] `make` completes without errors
- [ ] `bin/dpi_engine` exists
- [ ] `bin/dpi_engine_ids` exists
- [ ] Both binaries are executable

### Functionality
- [ ] `./bin/dpi_engine test.pcap` runs
- [ ] `./bin/dpi_engine_ids test.pcap` runs
- [ ] Attack detection works
- [ ] Reports are generated

---

## 📊 File Sizes (Approximate)

```
Header Files:
  dpi_engine.h             ~7 KB
  rule_engine.h            ~8 KB

Source Files:
  main.c                   ~14 KB
  main_with_ids.c          ~12 KB
  dpi_engine.c             ~9 KB
  dpi_engine_flow.c        ~24 KB
  rule_engine.c            ~12 KB
  rule_engine_attacks.c    ~23 KB
  rule_engine_report.c     ~15 KB

Build System:
  Makefile                 ~4 KB

Documentation:
  FILE_STRUCTURE_GUIDE.md  ~12 KB
  INSTALLATION_GUIDE.md    ~12 KB
  IDS_README.md            ~9 KB
  ATTACK_DETECTION_REFERENCE.md ~8 KB

Total Package Size: ~150 KB (source code only)
Compiled Binaries: ~300-400 KB each
```

---

## 🎯 Two Versions Explained

### Version 1: Original DPI Engine
```
Binary: bin/dpi_engine
Source: main.c + dpi_engine.c + dpi_engine_flow.c
Features:
  ✓ Packet parsing (L2-L5)
  ✓ Protocol detection (L7 via nDPI)
  ✓ Flow statistics
  ✗ No attack detection
```

### Version 2: DPI + IDS Engine
```
Binary: bin/dpi_engine_ids
Source: main_with_ids.c + dpi_engine.c + dpi_engine_flow.c
        + rule_engine.c + rule_engine_attacks.c + rule_engine_report.c
Features:
  ✓ Everything from Version 1
  ✓ Attack detection (9+ types)
  ✓ Intrusion alerts
  ✓ Security reports
```

---

## 🔄 Migration Path

If you're upgrading from original DPI to DPI+IDS:

### Step 1: Backup
```bash
cd ~/iwsn_security/c_dpi_engine
tar -czf backup_$(date +%Y%m%d).tar.gz .
```

### Step 2: Add New Files
```bash
# Add to include/
cp rule_engine.h include/

# Add to src/
cp main_with_ids.c rule_engine*.c src/

# Update Makefile
cp Makefile .
```

### Step 3: Build
```bash
make clean
make
```

### Step 4: Test Both Versions
```bash
# Test original (should still work)
./bin/dpi_engine test.pcap

# Test new version
./bin/dpi_engine_ids test.pcap
```

---

## 📞 Support & Documentation

For detailed information, read in this order:

1. **FILE_STRUCTURE_GUIDE.md** - Understanding the project
2. **INSTALLATION_GUIDE.md** - Setting up the system
3. **IDS_README.md** - Using the IDS features
4. **ATTACK_DETECTION_REFERENCE.md** - Configuring detection

---

## 🎉 You're Ready!

This package contains everything needed to deploy a complete DPI + IDS system for Industrial Wireless Sensor Network security.

**No additional files are needed.**

All dependencies (nDPI, libpcap) should already be installed on your Ubuntu VM.

Good luck with your IWSN security project! 🚀
