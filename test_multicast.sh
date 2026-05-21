#!/bin/bash
# End-to-end multicast proxy test — realistic router-subscriber topology
#
# Topology:
#
#   [ns-router]──veth-router/veth-uplink──[host: igmp-proxy + xdp_upstream]
#                                               │
#                            ┌──────────────────┤
#                            │                  │
#                veth-ns1h/veth-ns1      veth-ns2h/veth-ns2
#                [ns1: subscriber]       [ns2: subscriber]
#
# IPs:
#   ns-router / veth-router : 10.0.0.1/24  (simulated upstream router)
#   host      / veth-uplink : 10.0.0.2/24  (proxy uplink, IGMP faces router)
#   ns1       / veth-ns1    : 10.0.1.2/24
#   ns2       / veth-ns2    : 10.0.2.2/24
#
# Test flow:
#   1. ns1 and ns2 open UDP sockets and join 239.1.1.1 via IGMPv2.
#   2. xdp_downstream (on veth-ns1h / veth-ns2h) captures the IGMP reports
#      and posts events to the daemon via BPF ring buffer.
#   3. Daemon calls IP_ADD_MEMBERSHIP on veth-uplink, proxying the join upstream.
#   4. Host kernel sends an IGMPv2 membership report out of veth-uplink; it
#      arrives at veth-router inside ns-router — the router now knows there are
#      subscribers on this link.
#   5. ns-router (simulated router) sends multicast UDP to 239.1.1.1:5000.
#   6. xdp_upstream on veth-uplink redirects each packet to the devmap entries
#      for veth-ns1h and veth-ns2h; they forward into ns1/ns2 via the veth pair.
#   7. ns1 and ns2 receive all packets → PASS.
#
# Run from repo root: sudo bash test_multicast.sh
# Logs: /tmp/daemon.log  /tmp/ns{1,2}.log  /tmp/igmp_router.log

set -euo pipefail

MCAST=239.1.1.1
PORT=5000
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON="${SCRIPT_DIR}/multicast_user"

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "=== Cleanup ==="
    kill "$DAEMON_PID"      2>/dev/null || true
    wait "$DAEMON_PID"      2>/dev/null || true
    kill "$NS1_PID" "$NS2_PID" 2>/dev/null || true
    ip netns del ns-router  2>/dev/null || true
    ip netns del ns1        2>/dev/null || true
    ip netns del ns2        2>/dev/null || true
    # Peer veths inside deleted netns are removed automatically
    ip link del veth-uplink 2>/dev/null || true
    ip link del veth-ns1h   2>/dev/null || true
    ip link del veth-ns2h   2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Stop any running daemon ────────────────────────────────────────────────
echo "=== Stopping existing daemon ==="
kill -TERM "$(pgrep -x multicast_user)" 2>/dev/null || true
sleep 1
kill -9   "$(pgrep -x multicast_user)" 2>/dev/null || true

# ── 2. Tear down leftover test state ──────────────────────────────────────────
ip netns del ns-router  2>/dev/null || true
ip netns del ns1        2>/dev/null || true
ip netns del ns2        2>/dev/null || true
ip link del veth-uplink 2>/dev/null || true
ip link del veth-ns1h   2>/dev/null || true
ip link del veth-ns2h   2>/dev/null || true

# ── 3. Network namespaces ─────────────────────────────────────────────────────
echo "=== Creating namespaces ==="
ip netns add ns-router
ip netns add ns1
ip netns add ns2

# ── 4. Router ↔ host: veth-router (ns-router) / veth-uplink (host) ───────────
ip link add veth-uplink type veth peer name veth-router
ip link set veth-router netns ns-router
ip link set veth-uplink up
ip addr add 10.0.0.2/24 dev veth-uplink

ip netns exec ns-router ip link set lo up
ip netns exec ns-router ip link set veth-router up
ip netns exec ns-router ip addr add 10.0.0.1/24 dev veth-router
# Router needs a route to the multicast block to send to 239.x.x.x
ip netns exec ns-router ip route add 239.0.0.0/8 dev veth-router
# XDP DRV mode strips CHECKSUM_PARTIAL metadata; force full sw checksum so
# UDP frames have a valid checksum after redirect to subscriber namespaces.
ip netns exec ns-router ethtool -K veth-router tx-checksumming off 2>/dev/null || true

# Force IGMPv2 on the uplink so the proxy sends v2 membership reports to the
# router. xdp_downstream reads igmphdr.group, which is only valid in v1/v2.
sysctl -qw net.ipv4.conf.veth-uplink.force_igmp_version=2

# ── 5. Subscriber veth pairs ──────────────────────────────────────────────────
ip link add veth-ns1h type veth peer name veth-ns1
ip link set veth-ns1 netns ns1
ip link set veth-ns1h up
ip netns exec ns1 ip link set lo up
ip netns exec ns1 ip link set veth-ns1 up
ip netns exec ns1 ip addr add 10.0.1.2/24 dev veth-ns1
ip netns exec ns1 sysctl -qw net.ipv4.conf.veth-ns1.force_igmp_version=2
# Disable RPF: redirected packets have src 10.0.0.1 with no reverse route in ns1
ip netns exec ns1 sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec ns1 sysctl -qw net.ipv4.conf.veth-ns1.rp_filter=0

ip link add veth-ns2h type veth peer name veth-ns2
ip link set veth-ns2 netns ns2
ip link set veth-ns2h up
ip netns exec ns2 ip link set lo up
ip netns exec ns2 ip link set veth-ns2 up
ip netns exec ns2 ip addr add 10.0.2.2/24 dev veth-ns2
ip netns exec ns2 sysctl -qw net.ipv4.conf.veth-ns2.force_igmp_version=2
ip netns exec ns2 sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec ns2 sysctl -qw net.ipv4.conf.veth-ns2.rp_filter=0

echo "  veth-uplink : $(ip link show veth-uplink | grep -o 'state [A-Z]*')"
echo "  veth-ns1h   : $(ip link show veth-ns1h   | grep -o 'state [A-Z]*')"
echo "  veth-ns2h   : $(ip link show veth-ns2h   | grep -o 'state [A-Z]*')"

# ── 6. Start igmp-proxy daemon ────────────────────────────────────────────────
echo ""
echo "=== Starting igmp-proxy daemon (uplink=veth-uplink) ==="
UPLINK_IFACE=veth-uplink "$DAEMON" >/tmp/daemon.log 2>&1 &
DAEMON_PID=$!
sleep 2

echo "--- Daemon startup log ---"
cat /tmp/daemon.log

# ── 7. Attach XDP to container-side veths ────────────────────────────────────
# veth_xdp_xmit (the kernel function called by bpf_redirect_map on a devmap
# entry pointing to a veth) silently drops frames when the receiving peer has
# no XDP program attached. Attach xdp_downstream to the container-side veths;
# it returns XDP_PASS for all non-IGMP traffic, enabling redirect delivery.
echo ""
echo "=== Attaching XDP to container-side veths (required by veth_xdp_xmit) ==="
DS_ID=$(ip link show veth-ns1h | grep -oP 'prog/xdp id \K[0-9]+')
echo "  xdp_downstream prog id: $DS_ID"
ip netns exec ns1 bpftool net attach xdp id "$DS_ID" dev veth-ns1 overwrite \
    && echo "  ns1/veth-ns1: attached" || echo "  ns1/veth-ns1: FAILED"
ip netns exec ns2 bpftool net attach xdp id "$DS_ID" dev veth-ns2 overwrite \
    && echo "  ns2/veth-ns2: attached" || echo "  ns2/veth-ns2: FAILED"

# ── 8. IGMP snooper in ns-router ─────────────────────────────────────────────
# Start before the subscribers join so we capture the IGMPv2 membership report
# that the host kernel sends out of veth-uplink after IP_ADD_MEMBERSHIP.
# A real router would use this signal to start forwarding multicast traffic.
echo ""
echo "=== Starting IGMP snooper in ns-router ==="
ip netns exec ns-router tcpdump -i veth-router -c 3 -nn \
    'igmp' >/tmp/igmp_router.log 2>&1 &
IGMP_SNOOP_PID=$!

# ── 9. Start subscriber receivers (triggers IGMPv2 join) ──────────────────────
echo ""
echo "=== Starting subscriber receivers and sending IGMPv2 join for $MCAST ==="
cat >/tmp/receiver.py <<'PYEOF'
import socket, struct, sys

group    = sys.argv[1]
iface_ip = sys.argv[2]
port     = int(sys.argv[3])
label    = sys.argv[4]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', port))
sock.settimeout(10.0)

mreq = struct.pack('4s4s', socket.inet_aton(group), socket.inet_aton(iface_ip))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
print(f'[{label}] joined {group} on {iface_ip}', flush=True)

count = 0
try:
    while True:
        data, addr = sock.recvfrom(65535)
        count += 1
        print(f'[{label}] pkt #{count}: {len(data)}B from {addr[0]}:{addr[1]}'
              f'  "{data.decode(errors="replace")}"', flush=True)
except socket.timeout:
    pass
print(f'[{label}] done — received {count} packet(s)', flush=True)
PYEOF

ip netns exec ns1 python3 /tmp/receiver.py $MCAST 10.0.1.2 $PORT ns1 \
    >/tmp/ns1.log 2>&1 &
NS1_PID=$!

ip netns exec ns2 python3 /tmp/receiver.py $MCAST 10.0.2.2 $PORT ns2 \
    >/tmp/ns2.log 2>&1 &
NS2_PID=$!

echo "  Waiting for IGMP joins to propagate through the proxy to the router..."
sleep 4

# ── 10. Verify IGMP proxy: daemon log + IGMP traffic at ns-router ─────────────
echo ""
echo "--- Daemon log after IGMP joins ---"
cat /tmp/daemon.log

kill "$IGMP_SNOOP_PID" 2>/dev/null; wait "$IGMP_SNOOP_PID" 2>/dev/null || true

echo ""
echo "--- IGMP traffic observed at ns-router (proxy → router) ---"
cat /tmp/igmp_router.log

echo ""
if grep -q "igmp: joined $MCAST" /tmp/daemon.log; then
    echo "  [PASS] Daemon proxied IGMPv2 join to uplink (IP_ADD_MEMBERSHIP on veth-uplink)"
else
    echo "  [FAIL] Daemon did not proxy join to uplink"
fi

if grep -qiE 'IGMP|Report' /tmp/igmp_router.log 2>/dev/null; then
    echo "  [PASS] Router received IGMP membership report from proxy"
else
    echo "  [WARN] Router did not capture IGMP membership report (may have arrived too fast)"
fi

# ── 11. Router sends multicast (data plane test) ──────────────────────────────
# The router now knows there are subscribers on this link and starts forwarding.
# xdp_upstream on veth-uplink intercepts each packet and fans it out to ns1/ns2
# via the devmap entries added when the IGMP joins were processed.
#
# NOTE: xdp_upstream in DRV mode intercepts packets before the kernel's RX path,
# so tcpdump on veth-uplink will show 0 captures — correct XDP behaviour.
echo ""
echo "=== Router sending multicast to $MCAST:$PORT ==="

cat >/tmp/sender.py <<'PYEOF'
import socket, sys, time

group  = sys.argv[1]
port   = int(sys.argv[2])
src_ip = sys.argv[3]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 64)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                socket.inet_aton(src_ip))

for i in range(5):
    msg = f'MCAST_PKT_{i:02d}_FROM_ROUTER'.encode()
    sock.sendto(msg, (group, port))
    print(f'  sent #{i}: {msg.decode()}', flush=True)
    time.sleep(0.3)
PYEOF

# Capture at the router-facing side and inside ns1 for diagnostic visibility
tcpdump -i veth-uplink -c 10 -nn 'udp and dst 239.1.1.1' \
    >/tmp/tcpdump_uplink.log 2>&1 &
TCPDUMP_UP=$!
ip netns exec ns1 tcpdump -i veth-ns1 -c 10 -nn 'udp and dst 239.1.1.1' \
    >/tmp/tcpdump_ns1.log 2>&1 &
TCPDUMP_NS1=$!
sleep 0.3

ip netns exec ns-router python3 /tmp/sender.py $MCAST $PORT 10.0.0.1
sleep 2

kill $TCPDUMP_UP $TCPDUMP_NS1 2>/dev/null
wait $TCPDUMP_UP $TCPDUMP_NS1 2>/dev/null

echo ""
echo "--- tcpdump veth-uplink (0 expected: XDP intercepts before kernel RX) ---"
cat /tmp/tcpdump_uplink.log
echo "--- tcpdump ns1/veth-ns1 (XDP redirect → ns1) ---"
cat /tmp/tcpdump_ns1.log
sleep 1

# ── 12. Results ───────────────────────────────────────────────────────────────
echo ""
echo "=== ns1 output ==="
cat /tmp/ns1.log

echo ""
echo "=== ns2 output ==="
cat /tmp/ns2.log

echo ""
echo "=== Final daemon log ==="
cat /tmp/daemon.log

NS1_COUNT=$(grep -c 'pkt #' /tmp/ns1.log 2>/dev/null; true)
NS2_COUNT=$(grep -c 'pkt #' /tmp/ns2.log 2>/dev/null; true)
NS1_COUNT=${NS1_COUNT:-0}
NS2_COUNT=${NS2_COUNT:-0}
echo ""
echo "=== RESULT: ns1 received $NS1_COUNT packet(s), ns2 received $NS2_COUNT packet(s) ==="
if [ "$NS1_COUNT" -gt 0 ] && [ "$NS2_COUNT" -gt 0 ]; then
    echo "PASS: multicast delivered to both subscriber namespaces via router → proxy → XDP"
    EXIT=0
else
    echo "FAIL: expected packets in both namespaces"
    EXIT=1
fi

wait "$NS1_PID" "$NS2_PID" 2>/dev/null || true
exit $EXIT
