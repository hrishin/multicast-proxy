# Makefile for BPF multicast program
# Tested on Ubuntu 20.04+ with kernel 5.4+

# Compiler and flags
CLANG ?= clang
LLC ?= llc
CC ?= gcc

# Kernel headers path - adjust for your Ubuntu version
KERNEL_HEADERS ?= /usr/include
BPF_HEADERS ?= /usr/include

# Set architecture-specific header paths
# For Ubuntu, use the actual kernel headers path
# We need to include the parent of the arch directory so asm symlinks work
ARCH_HEADERS := /usr/src/linux-aws-6.14-headers-6.14.0-1011/arch/x86/include
ARCH_PARENT := /usr/src/linux-aws-6.14-headers-6.14.0-1011/arch/x86
KERNEL_ARCH := /usr/src/linux-aws-6.14-headers-6.14.0-1011
KERNEL_ROOT := /usr/src/linux-aws-6.14-headers-6.14.0-1011

# Compiler flags
CFLAGS = -g -O2 -Wall -Wextra
BPF_CFLAGS = -g -O2 -target bpf -c

# Source files
BPF_SRC = multicast.bpf.c
BPF_OBJ = multicast.bpf.o

# Userspace program (if you want to create one)
USER_SRC = multicast_user.c
USER_OBJ = multicast_user
USER_DEPS = -lbpf -lelf

# Default target
all: $(BPF_OBJ)

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) \
		-I. \
		-I/usr/include \
		-I$(KERNEL_ROOT)/arch/x86/include \
		-D__KERNEL__ \
		-o $@ $<

# Compile userspace program (optional)
$(USER_OBJ): $(USER_SRC)
	$(CC) $(CFLAGS) \
		-I$(KERNEL_HEADERS) \
		-I$(BPF_HEADERS) \
		-o $@ $< $(USER_DEPS)

# Clean
clean:
	rm -f $(BPF_OBJ) $(USER_OBJ)

# Fix asm symlink for compilation
fix-asm:
	@echo "Fixing asm symlink..."
	@if [ ! -L "$(KERNEL_ROOT)/include/asm" ]; then \
		echo "Creating asm symlink..."; \
		ln -sf $(KERNEL_ROOT)/arch/x86/include/asm $(KERNEL_ROOT)/include/asm; \
	fi
	@if [ ! -L "$(KERNEL_ROOT)/include/uapi/asm" ]; then \
		echo "Creating uapi asm symlink..."; \
		ln -sf $(KERNEL_ROOT)/arch/x86/include/asm $(KERNEL_ROOT)/include/uapi/asm; \
	fi
	@echo "✓ asm symlinks ready"

# Install dependencies (Ubuntu)
install-deps:
	sudo apt update
	sudo apt install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-headers-$(shell uname -r) \
		linux-libc-dev \
		build-essential \
		libelf-dev

# Check if BPF is supported
check-bpf:
	@echo "Checking BPF support..."
	@if [ -d "/sys/fs/bpf" ]; then \
		echo "✓ BPF filesystem mounted"; \
	else \
		echo "✗ BPF filesystem not mounted. Run: sudo mount -t bpf bpf /sys/fs/bpf"; \
	fi
	@if [ -f "/sys/kernel/debug/bpf/verifier_log" ]; then \
		echo "✓ BPF verifier available"; \
	else \
		echo "✗ BPF verifier not available"; \
	fi

# Check header files
check-headers:
	@echo "Checking header files..."
	@echo "KERNEL_HEADERS: $(KERNEL_HEADERS)"
	@echo "ARCH_HEADERS: $(ARCH_HEADERS)"
	@if [ -f "$(KERNEL_HEADERS)/linux/bpf.h" ]; then \
		echo "✓ linux/bpf.h found"; \
	else \
		echo "✗ linux/bpf.h not found"; \
	fi
	@if [ -f "$(ARCH_HEADERS)/asm/types.h" ]; then \
		echo "✓ asm/types.h found"; \
	else \
		echo "✗ asm/types.h not found in $(ARCH_HEADERS)"; \
		echo "  Try: make install-deps"; \
	fi

# Load BPF program (requires root)
load: $(BPF_OBJ)
	sudo bpftool prog load $(BPF_OBJ) /sys/fs/bpf/multicast

# Unload BPF program
unload:
	sudo bpftool prog unload /sys/fs/bpf/multicast

# Show loaded programs
show:
	sudo bpftool prog list
	sudo bpftool map list

.PHONY: all clean fix-asm install-deps check-bpf check-headers load unload show
