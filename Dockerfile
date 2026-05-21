# Multi-stage build for the IGMP/multicast XDP proxy daemon.
#
# Stage 1 (builder) — compiles the BPF object, generates the libbpf skeleton,
#                     and links the userspace daemon.
# Stage 2 (runtime) — copies only the binary and installs shared-library deps.
#
# Build:
#   docker build -t igmp-proxy .
#
# Run (requires host networking and elevated capabilities for BPF/XDP):
#   docker run --rm \
#       --network host \
#       --privileged \
#       -e UPLINK_IFACE=eth0 \
#       igmp-proxy
#
# Minimum capabilities if --privileged is not desired:
#   --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add BPF

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    libxdp-dev \
    linux-headers-generic \
    linux-libc-dev \
    build-essential \
    libelf-dev \
    zlib1g-dev \
    libzstd-dev \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Locate the installed generic kernel headers. The Makefile defaults to
# /usr/src/linux-headers-$(uname -r) which is the host kernel inside Docker;
# we override KERNEL_ROOT to the headers we just installed instead.
RUN set -e; \
    KROOT=$(ls -d /usr/src/linux-headers-*-generic 2>/dev/null | sort -V | tail -1); \
    echo "Building with KERNEL_ROOT=${KROOT}"; \
    make KERNEL_ROOT="${KROOT}"

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# Runtime shared libraries required by the daemon binary.
# Exact set determined by: ldd multicast_user
#   libbpf.so.1  libxdp.so.1  libelf.so.1  libz.so.1  libzstd.so.1
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 \
    libxdp1 \
    libelf1 \
    zlib1g \
    libzstd1 \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/multicast_user /usr/local/bin/multicast_user

# Uplink interface to attach xdp_upstream to. Override at runtime with -e.
ENV UPLINK_IFACE=eth0

ENTRYPOINT ["/usr/local/bin/multicast_user"]
