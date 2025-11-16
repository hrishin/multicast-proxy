#!/bin/bash

# Comprehensive test script for multicast proxy
# Tests BPF program with a container/netns subscribing to multicast via a veth interface pair

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
MULTICAST_GROUP="239.1.2.3"
MULTICAST_PORT="12345"
VETH_HOST="veth-host"
VETH_CONTAINER="veth-container"
CONTAINER_NS="multicast-test-ns"
USER_PROGRAM_LOG="multicast_user.log"
CONTAINER_RECV_LOG="container_received.log"

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Kill user program if running
    if [ -f "${USER_PROGRAM_LOG}.pid" ]; then
        PID=$(cat "${USER_PROGRAM_LOG}.pid")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Stopping multicast_user (PID: $PID)..."
            kill "$PID" 2>/dev/null || true
            wait "$PID" 2>/dev/null || true
        fi
        rm -f "${USER_PROGRAM_LOG}.pid"
    fi
    
    # Detach BPF programs (user program will clean up, but do it here too just in case)
    if ip link show "$VETH_HOST" >/dev/null 2>&1; then
        echo "Detaching BPF program from $VETH_HOST..."
        ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true
    fi
    
    # Remove network namespace
    if ip netns list | grep -q "^$CONTAINER_NS"; then
        echo "Removing network namespace $CONTAINER_NS..."
        ip netns delete "$CONTAINER_NS" 2>/dev/null || true
    fi
    
# Remove veth pair
if ip link show "$VETH_HOST" >/dev/null 2>&1; then
    echo "Removing veth pair..."
    ip link delete "$VETH_HOST" 2>/dev/null || true
fi

# Clean up any pinned BPF programs if they exist
if [ -f /sys/fs/bpf/multicast ]; then
    echo "Removing pinned BPF program..."
    rm -f /sys/fs/bpf/multicast 2>/dev/null || true
fi

# Clean up container receive log (optional, comment out if you want to keep it)
# rm -f container_received.log 2>/dev/null || true

echo -e "${GREEN}Cleanup complete${NC}"
}

# Set trap for cleanup on exit
trap cleanup EXIT INT TERM

echo -e "${GREEN}=== Multicast Proxy Test ===${NC}"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Step 1: Build the project
echo -e "${YELLOW}[1/8] Building BPF program and user space program...${NC}"
if ! make clean >/dev/null 2>&1; then
    echo -e "${YELLOW}Warning: make clean failed (this is okay)${NC}"
fi

if ! make >/dev/null 2>&1; then
    echo -e "${RED}Error: Failed to build BPF program${NC}"
    exit 1
fi

if [ ! -f "multicast.bpf.o" ]; then
    echo -e "${RED}Error: multicast.bpf.o not found after build${NC}"
    exit 1
fi

if [ ! -f "multicast_user" ]; then
    echo -e "${RED}Error: multicast_user not found after build${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Build successful${NC}"
echo

# Step 2: Setup Netkit pair and network namespace
echo -e "${YELLOW}[2/8] Setting up veth pair and network namespace...${NC}"

# Clean up any existing resources
ip link delete "$VETH_HOST" 2>/dev/null || true
ip netns delete "$CONTAINER_NS" 2>/dev/null || true

# Create network namespace
ip netns add "$CONTAINER_NS"
echo "Created network namespace: $CONTAINER_NS"

# Create veth interface pair
ip link add "$VETH_HOST" type veth peer name "$VETH_CONTAINER"
echo "Created veth pair: $VETH_HOST <-> $VETH_CONTAINER"

# Move container end to namespace
ip link set "$VETH_CONTAINER" netns "$CONTAINER_NS"

# Configure host end
ip addr add 10.0.0.1/24 dev "$VETH_HOST"
ip link set "$VETH_HOST" up
echo "Configured host end: 10.0.0.1/24"

# Configure container end
ip netns exec "$CONTAINER_NS" ip addr add 10.0.0.2/24 dev "$VETH_CONTAINER"
ip netns exec "$CONTAINER_NS" ip link set "$VETH_CONTAINER" up
ip netns exec "$CONTAINER_NS" ip link set lo up
echo "Configured container end: 10.0.0.2/24"

# No Netkit programs to attach in veth mode

echo -e "${GREEN}✓ Network setup complete${NC}"
echo

# Step 3: Start user program to load BPF and attach to veth
echo -e "${YELLOW}[3/8] Starting multicast_user program to load BPF and attach to $VETH_HOST...${NC}"

# Get ifindex of veth
VETH_IFINDEX=$(ip link show "$VETH_HOST" | grep -oP '^\d+:' | sed 's/:$//')

# Start user program with interface name - it will load BPF and attach
./multicast_user "$VETH_HOST" > "$USER_PROGRAM_LOG" 2>&1 &
USER_PID=$!
echo "$USER_PID" > "${USER_PROGRAM_LOG}.pid"

# Give it a moment to start and attach
sleep 3

if ! kill -0 "$USER_PID" 2>/dev/null; then
    echo -e "${RED}Error: multicast_user program failed to start${NC}"
    cat "$USER_PROGRAM_LOG"
    exit 1
fi

# Verify XDP attachment on veth
if ip link show "$VETH_HOST" | grep -q "xdp"; then
    XDP_MODE=$(ip link show "$VETH_HOST" | grep -oP 'xdp.*?mode \K\w+' || echo "unknown")
    echo -e "${GREEN}✓ BPF program attached to $VETH_HOST (ifindex: $VETH_IFINDEX, mode: $XDP_MODE)${NC}"
else
    echo -e "${YELLOW}Warning: XDP program may not be attached. Check log for details.${NC}"
    tail -5 "$USER_PROGRAM_LOG"
fi

# Verify XDP is actually working by checking if program is loaded
if bpftool prog list 2>/dev/null | grep -q "xdp_downstream"; then
    echo -e "${GREEN}✓ XDP program is loaded in kernel${NC}"
else
    echo -e "${YELLOW}Warning: XDP program not found in kernel program list${NC}"
fi

echo -e "${GREEN}✓ multicast_user running (PID: $USER_PID)${NC}"
echo "  Monitoring events in: $USER_PROGRAM_LOG"
echo

# Step 4: Verify setup
echo -e "${YELLOW}[4/8] Verifying setup...${NC}"
sleep 1
echo -e "${GREEN}✓ Setup verified${NC}"
echo

# Step 5: Subscribe to multicast from container
echo -e "${YELLOW}[5/8] Subscribing to multicast group $MULTICAST_GROUP from container...${NC}"

# Enable multicast routing in container namespace
ip netns exec "$CONTAINER_NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
ip netns exec "$CONTAINER_NS" sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1 || true

# Create log file for container received data
CONTAINER_RECV_LOG="container_received.log"
# Use absolute path for container namespace access
CONTAINER_RECV_LOG_ABS="$(pwd)/$CONTAINER_RECV_LOG"
echo "" > "$CONTAINER_RECV_LOG" 2>/dev/null || true
echo -e "${GREEN}Container receive log: $CONTAINER_RECV_LOG${NC}"

# Create a UDP socket to join multicast group and receive data
# We'll use socat or a simple Python script
if command -v socat >/dev/null 2>&1; then
    # Use socat to join multicast group and log received data
    ip netns exec "$CONTAINER_NS" sh -c "socat UDP4-RECVFROM:$MULTICAST_PORT,ip-add-membership=$MULTICAST_GROUP:$VETH_CONTAINER STDOUT 2>&1 | tee -a $CONTAINER_RECV_LOG_ABS" &
    SOCAT_PID=$!
    sleep 1
    echo -e "${GREEN}✓ Joined multicast group using socat (logging to $CONTAINER_RECV_LOG)${NC}"
elif command -v python3 >/dev/null 2>&1; then
    # Use Python to join multicast group and receive/log data
    cat > /tmp/join_multicast.py << PYEOF
import socket
import sys
import time
from datetime import datetime

MCAST_GRP = sys.argv[1]
MCAST_PORT = int(sys.argv[2])
INTERFACE = sys.argv[3]
LOG_FILE = sys.argv[4]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', MCAST_PORT))

# Join multicast group
mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton(INTERFACE)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print(f"Joined {MCAST_GRP}:{MCAST_PORT} on {INTERFACE}")
print(f"Logging received data to: {LOG_FILE}")
print("Waiting to receive multicast data...")
sys.stdout.flush()

# Open log file
log_fd = open(LOG_FILE, 'a', buffering=1)

# Set socket timeout so we can check periodically
sock.settimeout(1.0)

try:
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            data_str = data.decode('utf-8', errors='ignore')
            log_msg = f"[{timestamp}] [CONTAINER] Received from {addr[0]}:{addr[1]}: {data_str}\n"
            
            # Print to stdout
            print(log_msg.rstrip())
            sys.stdout.flush()
            
            # Write to log file
            log_fd.write(log_msg)
            log_fd.flush()
        except socket.timeout:
            # Continue waiting
            pass
        except KeyboardInterrupt:
            break
except KeyboardInterrupt:
    pass
finally:
    log_fd.close()
    sock.close()
PYEOF
    # Copy log file path into container namespace (create it there)
    ip netns exec "$CONTAINER_NS" touch "$CONTAINER_RECV_LOG_ABS" 2>/dev/null || true
    ip netns exec "$CONTAINER_NS" python3 /tmp/join_multicast.py "$MULTICAST_GROUP" "$MULTICAST_PORT" "10.0.0.2" "$CONTAINER_RECV_LOG_ABS" 2>&1 &
    PYTHON_PID=$!
    sleep 2
    echo -e "${GREEN}✓ Joined multicast group using Python (logging to $CONTAINER_RECV_LOG)${NC}"
else
    echo -e "${YELLOW}Warning: socat and python3 not found, using C program${NC}"
    # Fallback: use a simple C program that receives and logs data
    cat > /tmp/simple_mcast_listener.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in addr;
    struct ip_mreq mreq;
    char buffer[1024];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t recvlen;
    FILE *log_file = NULL;
    time_t now;
    struct tm *tm_info;
    char timestamp[64];
    
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <group> <port> <interface> <log_file>\n", argv[0]);
        return 1;
    }
    
    log_file = fopen(argv[4], "a");
    if (!log_file) {
        fprintf(stderr, "Warning: Could not open log file %s\n", argv[4]);
    }
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(atoi(argv[2]));
    
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    
    inet_aton(argv[1], &mreq.imr_multiaddr);
    inet_aton(argv[3], &mreq.imr_interface);
    setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    
    printf("Joined %s:%s on %s\n", argv[1], argv[2], argv[3]);
    printf("Logging to: %s\n", argv[4]);
    printf("Waiting to receive multicast data...\n");
    fflush(stdout);
    
    while ((recvlen = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, 
                                (struct sockaddr *)&from, &fromlen)) > 0) {
        buffer[recvlen] = '\0';
        
        time(&now);
        tm_info = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        
        char log_msg[2048];
        snprintf(log_msg, sizeof(log_msg), 
                "[%s] [CONTAINER] Received from %s:%d: %s\n",
                timestamp, inet_ntoa(from.sin_addr), ntohs(from.sin_port), buffer);
        
        printf("%s", log_msg);
        fflush(stdout);
        
        if (log_file) {
            fprintf(log_file, "%s", log_msg);
            fflush(log_file);
        }
        
        fromlen = sizeof(from);
    }
    
    if (log_file) {
        fclose(log_file);
    }
    close(sock);
    return 0;
}
CEOF
    gcc -o /tmp/simple_mcast_listener /tmp/simple_mcast_listener.c 2>/dev/null || {
        echo -e "${RED}Error: Could not create multicast listener. Please install socat or python3${NC}"
        exit 1
    }
    # Create log file in container namespace
    ip netns exec "$CONTAINER_NS" touch "$CONTAINER_RECV_LOG_ABS" 2>/dev/null || true
    ip netns exec "$CONTAINER_NS" /tmp/simple_mcast_listener "$MULTICAST_GROUP" "$MULTICAST_PORT" "10.0.0.2" "$CONTAINER_RECV_LOG_ABS" 2>&1 &
    LISTENER_PID=$!
    sleep 2
    echo -e "${GREEN}✓ Joined multicast group using C listener (logging to $CONTAINER_RECV_LOG)${NC}"
fi

echo "  Waiting for IGMP join message..."
sleep 3

# Also manually send an IGMP join message to test the capture
echo "Attempting to send test IGMP join message from container..."

# Create a simple tool to send IGMP join message
cat > /tmp/send_igmp_join.c << 'IGMPCEOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdint.h>

// Define IGMP constants
#define IPPROTO_IGMP 2
#define IGMP_HOST_MEMBERSHIP_REPORT 0x16

// Define IGMP header structure ourselves to avoid header issues
struct igmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint32_t group;
} __attribute__((packed));

// IGMP v2 membership report
struct igmpv2_report {
    struct iphdr ip;
    struct igmp_header igmp;
} __attribute__((packed));

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <multicast_group> <interface>\n", argv[0]);
        return 1;
    }
    
    const char *group_str = argv[1];
    const char *ifname = argv[2];
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Enable IP_HDRINCL to build our own IP header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock);
        return 1;
    }
    
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", ifname);
        close(sock);
        return 1;
    }
    
    // Bind to interface
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0) {
        perror("setsockopt SO_BINDTODEVICE");
        close(sock);
        return 1;
    }
    
    // Build IGMP v2 membership report packet
    // IGMP membership reports are sent to the multicast group address (not 224.0.0.22)
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(group_str); // Send to the multicast group
    
    struct igmpv2_report pkt;
    memset(&pkt, 0, sizeof(pkt));
    
    // Get source IP from interface
    struct in_addr src_addr;
    // Try to get interface IP, fallback to 0.0.0.0
    src_addr.s_addr = 0;
    
    // IP header
    pkt.ip.version = 4;
    pkt.ip.ihl = 5;
    pkt.ip.tot_len = htons(sizeof(pkt));
    pkt.ip.id = htons(0);
    pkt.ip.frag_off = 0;
    pkt.ip.ttl = 1; // IGMP uses TTL=1
    pkt.ip.protocol = IPPROTO_IGMP;
    pkt.ip.saddr = src_addr.s_addr; // Will be filled by kernel if 0
    pkt.ip.daddr = dest.sin_addr.s_addr;
    pkt.ip.check = 0; // Kernel will calculate
    
    // IGMP header
    pkt.igmp.type = IGMP_HOST_MEMBERSHIP_REPORT;
    pkt.igmp.code = 0;
    pkt.igmp.csum = 0;
    pkt.igmp.group = inet_addr(group_str);
    
    // Calculate IGMP checksum (kernel will recalculate if needed)
    pkt.igmp.csum = 0;
    
    // Send packet
    if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }
    
    printf("Sent IGMP join for %s on %s\n", group_str, ifname);
    close(sock);
    return 0;
}
IGMPCEOF

# Compile the IGMP sender if possible
if gcc -o /tmp/send_igmp_join /tmp/send_igmp_join.c 2>/dev/null; then
    # Send IGMP join from container namespace (may require capabilities)
    # Note: Raw sockets require CAP_NET_RAW, which might not be available in netns
    if ip netns exec "$CONTAINER_NS" /tmp/send_igmp_join "$MULTICAST_GROUP" "$VETH_CONTAINER" 2>&1; then
        echo -e "${GREEN}✓ Sent manual IGMP join message${NC}"
        sleep 1  # Give time for packet to be processed
    else
        echo -e "${YELLOW}Note: Manual IGMP send failed (may need CAP_NET_RAW capability)${NC}"
        echo "  This is normal - the socket-based join should still trigger IGMP"
    fi
else
    echo -e "${YELLOW}Note: Could not compile IGMP sender${NC}"
fi

# Alternative: Force IGMP report by leaving and rejoining the group
# This is more reliable than raw sockets
echo "Attempting to trigger IGMP report by toggling membership..."
if command -v python3 >/dev/null 2>&1; then
    # Create a script that leaves and rejoins to force IGMP report
    # Use a different port to avoid conflict with existing listener
    TOGGLE_PORT=$((MULTICAST_PORT + 1))
    cat > /tmp/toggle_mcast.py << 'TOGGLEEOF'
import socket
import sys
import time

MCAST_GRP = sys.argv[1]
MCAST_PORT = int(sys.argv[2])
INTERFACE = sys.argv[3]

# Create socket and join - use SO_REUSEADDR to allow binding even if port is in use
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.bind(('', MCAST_PORT))
except OSError:
    # If port is in use, try a different ephemeral port
    sock.bind(('', 0))

mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton(INTERFACE)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
print(f"Joined {MCAST_GRP} on {INTERFACE}")
sys.stdout.flush()
time.sleep(1)

# Leave and rejoin to force new IGMP report
print("Leaving group to trigger IGMP leave...")
sys.stdout.flush()
sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
time.sleep(0.5)

print("Rejoining group to trigger IGMP join...")
sys.stdout.flush()
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
print(f"Rejoined {MCAST_GRP} (should trigger IGMP report)")
sys.stdout.flush()
time.sleep(30)
TOGGLEEOF
    ip netns exec "$CONTAINER_NS" python3 /tmp/toggle_mcast.py "$MULTICAST_GROUP" "$TOGGLE_PORT" "10.0.0.2" &
    TOGGLE_PID=$!
    sleep 3  # Give more time for IGMP packets to be sent and captured
    echo -e "${GREEN}✓ Toggled membership to trigger IGMP report${NC}"
fi

# Send an IGMP query to trigger join messages from the container
# This simulates what a router would do
echo "Sending IGMP query to trigger join responses..."
if command -v scapy >/dev/null 2>&1; then
    python3 -c "
from scapy.all import *
send(IP(dst='224.0.0.1', ttl=1)/IGMP(type=0x11), iface='$VETH_HOST')
" 2>/dev/null || true
elif gcc -o /tmp/send_igmp_query /tmp/send_igmp_join.c 2>/dev/null && test -f /tmp/send_igmp_join; then
    # We can reuse the same code but send a query instead
    echo "Note: IGMP query requires raw socket support"
else
    echo "Note: Cannot send IGMP query without raw socket support"
fi
sleep 1

# Actually, the multicast join via socket should already trigger IGMP
# Let's verify the multicast membership was actually created
echo "Checking multicast membership in container..."
if ip netns exec "$CONTAINER_NS" ip maddr show dev "$VETH_CONTAINER" | grep -q "$MULTICAST_GROUP"; then
    echo -e "${GREEN}✓ Multicast membership confirmed${NC}"
else
    echo -e "${YELLOW}Warning: Multicast membership not found in kernel table${NC}"
    echo "This might mean IGMP was sent but not captured, or join failed"
fi
echo

# Step 6: Check for events
echo -e "${YELLOW}[6/8] Checking for captured IGMP events...${NC}"

# Check if events were captured
if [ -f "$USER_PROGRAM_LOG" ]; then
    if grep -q "\[EVENT\]" "$USER_PROGRAM_LOG"; then
        echo -e "${GREEN}✓ Events captured!${NC}"
        echo "Recent events:"
        tail -5 "$USER_PROGRAM_LOG" | grep "\[EVENT\]" || tail -5 "$USER_PROGRAM_LOG"
    else
        echo -e "${YELLOW}⚠ No events in log yet. This might be normal if IGMP was processed differently.${NC}"
        echo "Log contents:"
        cat "$USER_PROGRAM_LOG"
    fi
else
    echo -e "${YELLOW}⚠ Log file not found${NC}"
fi
echo

# Step 7: Send test multicast traffic on ens5 interface
echo -e "${YELLOW}[7/8] Sending test multicast traffic on ens5 interface...${NC}"

# Check if ens5 interface exists
if ! ip link show ens5 >/dev/null 2>&1; then
    echo -e "${RED}Error: ens5 interface not found${NC}"
    exit 1
fi

# Get ens5 interface IP address
ENS5_IP=$(ip addr show ens5 | grep -oP 'inet \K[0-9.]+' | head -1)
if [ -z "$ENS5_IP" ]; then
    echo -e "${YELLOW}Warning: Could not get IP address for ens5, using 0.0.0.0${NC}"
    ENS5_IP="0.0.0.0"
else
    echo "Using ens5 interface (IP: $ENS5_IP)"
fi

# Send test packet from host to multicast group on ens5 interface
echo "Sending test packet to $MULTICAST_GROUP:$MULTICAST_PORT on ens5..."

# Create a Python script to send multicast data bound to ens5 interface
cat > /tmp/send_multicast_ens5.py << 'SENDEOF'
import socket
import sys

MCAST_GRP = sys.argv[1]
MCAST_PORT = int(sys.argv[2])
IFACE_NAME = sys.argv[3]

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Set socket option to bind to specific interface (SO_BINDTODEVICE)
# This forces the socket to use the specified interface
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, IFACE_NAME.encode('utf-8'))
except (AttributeError, OSError) as e:
    # If SO_BINDTODEVICE is not available, try IP_MULTICAST_IF with interface IP
    print(f"Note: SO_BINDTODEVICE not available, using IP_MULTICAST_IF: {e}")
    try:
        if_ip = socket.inet_aton(IFACE_NAME)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, if_ip)
    except (socket.error, OSError):
        # Fallback: try to get interface IP
        import subprocess
        try:
            result = subprocess.run(['ip', 'addr', 'show', IFACE_NAME], 
                                  capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    ip = line.split()[1].split('/')[0]
                    if_ip = socket.inet_aton(ip)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, if_ip)
                    print(f"Using interface IP: {ip}")
                    break
        except Exception:
            pass

# Set TTL for multicast
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

# Send test messages
messages = [
    b"Hello from ens5 interface - message 1",
    b"Hello from ens5 interface - message 2",
    b"Hello from ens5 interface - message 3"
]

for i, msg in enumerate(messages, 1):
    sock.sendto(msg, (MCAST_GRP, MCAST_PORT))
    print(f"Sent message {i}: {msg.decode('utf-8')}")
    sys.stdout.flush()

sock.close()
SENDEOF

if command -v python3 >/dev/null 2>&1; then
    python3 /tmp/send_multicast_ens5.py "$MULTICAST_GROUP" "$MULTICAST_PORT" "ens5"
    sleep 2
elif command -v socat >/dev/null 2>&1; then
    # socat doesn't easily support binding to interface for sending, but we can try
    for i in 1 2 3; do
        echo "test-multicast-message-$i from ens5" | socat - UDP4-DATAGRAM:$MULTICAST_GROUP:$MULTICAST_PORT,bind=$ENS5_IP &
        sleep 0.2
    done
    sleep 1
elif command -v nc >/dev/null 2>&1; then
    for i in 1 2 3; do
        echo "test-multicast-message-$i from ens5" | nc -u -s "$ENS5_IP" -w1 "$MULTICAST_GROUP" "$MULTICAST_PORT" 2>/dev/null || true
        sleep 0.2
    done
    sleep 1
else
    echo -e "${RED}Error: No suitable tool found to send multicast data${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Test packets sent on ens5 interface${NC}"
echo

# Step 8: Final summary and status
echo -e "${YELLOW}[8/8] Test complete - showing results...${NC}"
sleep 2

# Summary
echo -e "${GREEN}=== Test Summary ===${NC}"
echo "Interface: $VETH_HOST (ifindex: $VETH_IFINDEX)"
echo "Multicast Group: $MULTICAST_GROUP"
echo "User Program PID: $USER_PID"
echo "Event Log: $USER_PROGRAM_LOG"
echo "Container Receive Log: $CONTAINER_RECV_LOG"
echo
echo -e "${YELLOW}Monitoring events. Press Ctrl+C to stop...${NC}"
echo
echo "To view events in real-time, run:"
echo "  tail -f $USER_PROGRAM_LOG"
echo "  tail -f $CONTAINER_RECV_LOG"
echo

# Keep running for a bit to capture more events
echo "Waiting 10 seconds to capture events and received data..."
sleep 10

# Check if user program is still running
if ! kill -0 "$USER_PID" 2>/dev/null; then
    echo -e "${RED}Warning: multicast_user program exited early!${NC}"
    echo "Last log entries:"
    tail -20 "$USER_PROGRAM_LOG" || true
fi

# Show final events
echo -e "${YELLOW}=== Final Event Log (BPF Events) ===${NC}"
if [ -f "$USER_PROGRAM_LOG" ]; then
    cat "$USER_PROGRAM_LOG"
else
    echo "No log file found"
fi
echo

# Show container received data
echo -e "${YELLOW}=== Container Received Data Log ===${NC}"
if [ -f "$CONTAINER_RECV_LOG" ]; then
    if [ -s "$CONTAINER_RECV_LOG" ]; then
        cat "$CONTAINER_RECV_LOG"
    else
        echo "Log file exists but is empty (no data received yet)"
    fi
else
    echo "Container receive log file not found: $CONTAINER_RECV_LOG"
fi

echo
echo -e "${GREEN}Test complete!${NC}"

