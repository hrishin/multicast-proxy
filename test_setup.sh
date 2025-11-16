#!/bin/bash

# Test script for BPF multicast program setup
# Run this script to verify your Ubuntu environment is ready

set -e

echo "=== BPF Multicast Program Setup Test ==="
echo

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "✓ Running as root"
else
    echo "✗ Not running as root. Some tests may fail."
    echo "  Run with sudo for full testing."
fi

echo

# Check Ubuntu version
echo "=== System Information ==="
if command -v lsb_release >/dev/null 2>&1; then
    echo "Ubuntu Version: $(lsb_release -d | cut -f2)"
else
    echo "Ubuntu Version: Unknown (lsb_release not found)"
fi

echo "Kernel Version: $(uname -r)"
echo "Architecture: $(uname -m)"

# Check kernel version compatibility
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
if [[ $KERNEL_MAJOR -ge 5 && $KERNEL_MINOR -ge 4 ]]; then
    echo "✓ Kernel version $(uname -r) supports XDP and BPF"
else
    echo "✗ Kernel version $(uname -r) may not fully support XDP"
    echo "  Recommended: 5.4+ for full XDP support"
fi

echo

# Check required packages
echo "=== Package Dependencies ==="
PACKAGES=("clang" "llc" "gcc" "make" "bpftool")
MISSING=()

for pkg in "${PACKAGES[@]}"; do
    if command -v $pkg >/dev/null 2>&1; then
        echo "✓ $pkg found"
    else
        echo "✗ $pkg not found"
        MISSING+=($pkg)
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo
    echo "Missing packages: ${MISSING[*]}"
    echo "Install with: make install-deps"
fi

echo

# Check development headers
echo "=== Development Headers ==="
HEADERS=(
    "/usr/include/linux/bpf.h"
    "/usr/include/bpf/bpf_helpers.h"
    "/usr/include/linux/if_ether.h"
    "/usr/include/linux/ip.h"
    "/usr/include/linux/igmp.h"
)

for header in "${HEADERS[@]}"; do
    if [[ -f "$header" ]]; then
        echo "✓ $(basename $header) found"
    else
        echo "✗ $(basename $header) not found"
    fi
done

echo

# Check BPF support
echo "=== BPF Support ==="
if [[ -d "/sys/fs/bpf" ]]; then
    echo "✓ BPF filesystem mounted at /sys/fs/bpf"
else
    echo "✗ BPF filesystem not mounted"
    echo "  Mount with: sudo mount -t bpf bpf /sys/fs/bpf"
fi

if command -v bpftool >/dev/null 2>&1; then
    echo "✓ bpftool available"
    bpftool version 2>/dev/null | head -1 || true
else
    echo "✗ bpftool not found"
    echo "  Install with: sudo apt install bpftool"
fi

if mount | grep -q "debugfs on /sys/kernel/debug"; then
    echo "✓ debugfs mounted"
    if sudo test -f "/sys/kernel/debug/bpf/verifier_log" 2>/dev/null; then
        echo "✓ BPF verifier log available (BPF programs have been loaded)"
    else
        echo "ℹ BPF verifier log will be available after loading a BPF program"
    fi
    
    if sudo test -f "/sys/kernel/debug/bpf/stack_map" 2>/dev/null; then
        echo "✓ BPF stack trace support available"
    else
        echo "ℹ BPF stack trace support will be available after loading BPF programs"
    fi
else
    echo "ℹ debugfs not mounted (optional, for debugging)"
    echo "  Mount with: sudo mount -t debugfs debugfs /sys/kernel/debug"
fi

echo

# Check XDP support
echo "=== XDP Support ==="
if [[ -f "/sys/kernel/debug/bpf/xdp" ]]; then
    echo "✓ XDP debugging support available"
else
    echo "✗ XDP debugging support not available"
fi

# Check if we can compile
echo
echo "=== Compilation Test ==="
if make clean >/dev/null 2>&1; then
    echo "✓ Make clean successful"
else
    echo "✗ Make clean failed"
fi

if make >/dev/null 2>&1; then
    echo "✓ BPF program compilation successful"
    echo "  Generated: multicast.bpf.o"
else
    echo "✗ BPF program compilation failed"
    echo "  Check error messages above"
fi

echo
echo "=== Setup Test Complete ==="

if [[ ${#MISSING[@]} -eq 0 ]] && [[ -f "multicast.bpf.o" ]]; then
    echo "✓ Environment is ready for BPF development!"
    echo
    echo "Next steps:"
    echo "1. Load the program: sudo make load"
    echo "2. Attach to interfaces: see README.md"
    echo "3. Monitor events: ./multicast_user"
else
    echo "✗ Environment needs setup. See errors above."
    echo
    echo "Common fixes:"
    echo "1. Install dependencies: make install-deps"
    echo "2. Mount BPF filesystem: sudo mount -t bpf bpf /sys/fs/bpf"
    echo "3. Check kernel version compatibility"
fi
