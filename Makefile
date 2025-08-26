# Makefile for BPF multicast program
# Tested on Ubuntu 20.04+ with kernel 5.4+

# Compiler and flags
CLANG ?= clang
LLC ?= llc
CC ?= gcc

# Kernel headers path - adjust for your Ubuntu version
KERNEL_HEADERS ?= /usr/include
BPF_HEADERS ?= /usr/include

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
		-I$(KERNEL_HEADERS) \
		-I$(BPF_HEADERS) \
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

# Install dependencies (Ubuntu)
install-deps:
	sudo apt update
	sudo apt install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-headers-$(shell uname -r) \
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

.PHONY: all clean install-deps check-bpf load unload show
