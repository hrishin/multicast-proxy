#!/bin/bash

echo "=== Finding asm/types.h header ==="
echo

# Check common locations
COMMON_PATHS=(
    "/usr/include/x86_64-linux-gnu"
    "/usr/include/aarch64-linux-gnu"
    "/usr/include/arm-linux-gnueabihf"
    "/usr/include"
    "/usr/include/linux"
    "/usr/src/linux-headers-$(uname -r)/arch/x86/include"
    "/usr/src/linux-headers-$(uname -r)/arch/arm64/include"
)

echo "Searching for asm/types.h in common paths..."
for path in "${COMMON_PATHS[@]}"; do
    if [[ -f "$path/asm/types.h" ]]; then
        echo "✓ Found: $path/asm/types.h"
        FOUND_PATH="$path"
        break
    elif [[ -d "$path/asm" ]]; then
        echo "  asm directory exists in: $path"
        ls -la "$path/asm/" | head -5
    fi
done

echo

# Check what architecture we're on
echo "System information:"
echo "Architecture: $(uname -m)"
echo "Kernel: $(uname -r)"
echo "OS: $(lsb_release -d 2>/dev/null || echo "Unknown")"

echo

# Check if linux-libc-dev is installed
if dpkg -l | grep -q linux-libc-dev; then
    echo "✓ linux-libc-dev package is installed"
    echo "Package info:"
    dpkg -l | grep linux-libc-dev
else
    echo "✗ linux-libc-dev package is NOT installed"
    echo "Install with: sudo apt install linux-libc-dev"
fi

echo

if [[ -n "$FOUND_PATH" ]]; then
    echo "=== Solution ==="
    echo "Update your Makefile to use:"
    echo "ARCH_HEADERS := $FOUND_PATH"
else
    echo "=== No asm/types.h found ==="
    echo "Try installing missing packages:"
    echo "sudo apt install linux-libc-dev linux-headers-$(uname -r)"
fi
