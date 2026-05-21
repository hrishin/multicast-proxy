# Makefile — IGMP proxy eBPF/XDP + userspace daemon
#
# Build order:
#   1. Compile BPF program → multicast.bpf.o
#   2. Generate libbpf skeleton → multicast.bpf.skel.h
#   3. Compile userspace daemon (multicast_user.c + afxdp.c) → multicast_user
#
# Requirements:
#   clang ≥ 11, libbpf-dev ≥ 0.7, bpftool, linux-headers ≥ 5.10
#   For Tier-3 AF-XDP: libxdp-dev (or libbpf ≥ 0.7 which bundles xsk.h)
#   Kernel: 5.10+ for bpf_redirect_peer; 6.7+ for netkit; 5.0 minimum

CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

# ── Kernel header paths ────────────────────────────────────────────────────
# Adjust KERNEL_ROOT for your kernel version.
KERNEL_ROOT     ?= /usr/src/linux-headers-$(shell uname -r)
KERNEL_HEADERS  ?= /usr/include
BPF_HEADERS     ?= /usr/include

# ── Flags ──────────────────────────────────────────────────────────────────
CFLAGS      = -g -O2 -Wall -Wextra -Wno-unused-parameter

ARCH            := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

BPF_CFLAGS  = -g -O2 -target bpf -c \
              -I. \
              -I$(KERNEL_HEADERS) \
              -I$(BPF_HEADERS)

# Userspace: include libbpf + local headers; link libbpf, libelf, pthreads
USER_CFLAGS = $(CFLAGS) \
              -I. \
              -I$(KERNEL_HEADERS) \
              -I$(BPF_HEADERS)

USER_LDFLAGS = -lbpf -lxdp -lelf -lpthread -lz

# ── Source / target names ──────────────────────────────────────────────────
BPF_SRC      = multicast.bpf.c
BPF_OBJ      = multicast.bpf.o
SKELETON     = multicast.bpf.skel.h

USER_SRCS    = multicast_user.c afxdp.c
USER_BIN     = multicast_user

# ── Default target ─────────────────────────────────────────────────────────
.PHONY: all
all: $(USER_BIN)

# ── Step 1: compile BPF program ───────────────────────────────────────────
$(BPF_OBJ): $(BPF_SRC) multicast.h asm_types_workaround.h fix-asm
	$(CLANG) $(BPF_CFLAGS) -o $@ $<
	@echo "✓ BPF object: $@"

# ── Step 2: generate libbpf skeleton ──────────────────────────────────────
# The skeleton gives the userspace daemon type-safe map/program accessors
# without manual bpf_object__find_map_by_name() calls.
$(SKELETON): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@
	@echo "✓ Skeleton: $@"

# ── Step 3: compile userspace daemon ──────────────────────────────────────
$(USER_BIN): $(USER_SRCS) $(SKELETON) multicast.h afxdp.h
	$(CC) $(USER_CFLAGS) -o $@ $(USER_SRCS) $(USER_LDFLAGS)
	@echo "✓ Daemon: $@"

# ── Fix asm symlink (Ubuntu kernel header workaround) ─────────────────────
.PHONY: fix-asm
fix-asm:
	@if [ ! -L "$(KERNEL_ROOT)/include/asm" ]; then \
		echo "Creating asm symlink..."; \
		ln -sf $(KERNEL_ROOT)/arch/$(ARCH)/include/asm \
		       $(KERNEL_ROOT)/include/asm; \
	fi
	@if [ ! -L "$(KERNEL_ROOT)/include/uapi/asm" ]; then \
		ln -sf $(KERNEL_ROOT)/arch/$(ARCH)/include/uapi/asm \
		       $(KERNEL_ROOT)/include/uapi/asm 2>/dev/null || true; \
	fi

# ── Clean ──────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	rm -f $(BPF_OBJ) $(SKELETON) $(USER_BIN)

# ── Install dependencies (Ubuntu 22.04+) ─────────────────────────────────
.PHONY: install-deps
install-deps:
	sudo apt update
	sudo apt install -y \
		clang llvm \
		libbpf-dev \
		linux-headers-$(shell uname -r) \
		linux-libc-dev \
		build-essential \
		libelf-dev \
		libz-dev \
		bpftool

# ── Load / unload helpers ─────────────────────────────────────────────────
.PHONY: load
load: $(USER_BIN)
	sudo UPLINK_IFACE=eth0 ./$(USER_BIN)

.PHONY: unload
unload:
	sudo bpftool net detach xdp dev eth0 2>/dev/null || true
	sudo rm -f /sys/fs/bpf/igmp-proxy/events \
	           /sys/fs/bpf/igmp-proxy/group_map \
	           /sys/fs/bpf/igmp-proxy 2>/dev/null || true

# ── Verification helpers ───────────────────────────────────────────────────
.PHONY: show
show:
	sudo bpftool prog list
	sudo bpftool map list

.PHONY: check-bpf
check-bpf:
	@echo "Checking BPF support..."
	@[ -d /sys/fs/bpf ] && echo "✓ BPF fs mounted" || echo "✗ BPF fs not mounted"
	@grep -q CONFIG_BPF_JIT=y /boot/config-$(shell uname -r) 2>/dev/null \
		&& echo "✓ BPF JIT enabled in kernel" || echo "  BPF JIT status unknown"
	@$(BPFTOOL) version 2>/dev/null | head -1 || echo "✗ bpftool not found"

.PHONY: check-headers
check-headers:
	@echo "Checking headers..."
	@[ -f "$(KERNEL_HEADERS)/linux/bpf.h" ]  && echo "✓ linux/bpf.h"  || echo "✗ linux/bpf.h"
	@[ -f "$(BPF_HEADERS)/bpf/bpf_helpers.h" ] && echo "✓ bpf/bpf_helpers.h" || echo "✗ bpf/bpf_helpers.h"
	@[ -f "$(BPF_HEADERS)/bpf/xsk.h" ]        && echo "✓ bpf/xsk.h (AF-XDP)" || echo "✗ bpf/xsk.h (install libbpf-dev)"
