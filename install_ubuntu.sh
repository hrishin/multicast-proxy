#!/bin/bash

# Ubuntu installation script for BPF multicast program
# This script will install all necessary dependencies and set up the environment

set -e

echo "=== BPF Multicast Program - Ubuntu Installation ==="
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Update package list
echo "Updating package list..."
apt update

# Install essential build tools
echo "Installing build tools..."
apt install -y build-essential

# Install LLVM and Clang
echo "Installing LLVM and Clang..."
apt install -y clang llvm

# Install BPF development libraries
echo "Installing BPF development libraries..."
apt install -y libbpf-dev libelf-dev

# Install kernel headers
echo "Installing kernel headers..."
apt install -y linux-headers-$(uname -r)

# Install architecture-specific headers
echo "Installing architecture-specific headers..."
apt install -y linux-libc-dev

# Install bpftool
echo "Installing bpftool..."
apt install -y bpftool

# Install additional useful tools
echo "Installing additional tools..."
apt install -y iproute2 net-tools tcpdump

echo
echo "=== Dependencies Installation Complete ==="
echo

# Check if BPF filesystem is mounted
if [[ ! -d "/sys/fs/bpf" ]]; then
    echo "Mounting BPF filesystem..."
    mount -t bpf bpf /sys/fs/bpf
    echo "BPF filesystem mounted at /sys/fs/bpf"
else
    echo "✓ BPF filesystem already mounted"
fi

# Make BPF filesystem mount persistent
if ! grep -q "bpf.*bpf.*/sys/fs/bpf" /etc/fstab; then
    echo "Adding BPF filesystem to /etc/fstab for persistence..."
    echo "bpf bpf /sys/fs/bpf bpf defaults 0 0" >> /etc/fstab
    echo "✓ BPF filesystem will be mounted automatically on boot"
else
    echo "✓ BPF filesystem already in /etc/fstab"
fi

echo
echo "=== Environment Setup Complete ==="
echo

# Verify installation
echo "Verifying installation..."
if command -v clang >/dev/null 2>&1; then
    echo "✓ Clang: $(clang --version | head -n1)"
else
    echo "✗ Clang not found"
fi

if command -v bpftool >/dev/null 2>&1; then
    echo "✓ bpftool: $(bpftool version | head -n1)"
else
    echo "✗ bpftool not found"
fi

if [[ -d "/sys/fs/bpf" ]]; then
    echo "✓ BPF filesystem mounted"
else
    echo "✗ BPF filesystem not mounted"
fi

echo
echo "=== Installation Summary ==="
echo "✓ Build tools installed"
echo "✓ LLVM/Clang installed"
echo "✓ BPF libraries installed"
echo "✓ Kernel headers installed"
echo "✓ bpftool installed"
echo "✓ BPF filesystem mounted"
echo
echo "You can now:"
echo "1. Compile the program: make"
echo "2. Test the setup: ./test_setup.sh"
echo "3. Load the program: sudo make load"
echo
echo "For more information, see README.md"
