# BPF Multicast Program

This BPF program implements multicast packet handling using XDP (eXpress Data Path) for high-performance network packet processing.

## Features

- **Downstream XDP**: Captures IGMP join/leave messages from veth interfaces
- **Upstream XDP**: Broadcasts multicast data to subscribed interfaces
- **Ring Buffer**: Efficient event notification to userspace
- **DevMap**: Fast packet redirection to multiple interfaces

## Requirements

- Ubuntu 20.04+ (tested on Ubuntu 20.04, 22.04, 24.04)
- Linux kernel 5.4+ (for XDP and BPF features)
- Root privileges for loading BPF programs

## Installation

### 1. Install Dependencies

```bash
# Install required packages
make install-deps

# Or manually:
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential \
    libelf-dev \
    bpftool
```

### 2. Check BPF Support

```bash
make check-bpf
```

If BPF filesystem is not mounted:
```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

## Building

### Compile BPF Program

```bash
make
```

This will create `multicast.bpf.o` which contains the compiled BPF bytecode.

### Compile Userspace Program (Optional)

```bash
make multicast_user
```

## Usage

### Load BPF Program

```bash
make load
```

### Check Loaded Programs

```bash
make show
```

### Unload BPF Program

```bash
make unload
```

## Program Structure

### BPF Maps

- **`events`**: Ring buffer for IGMP join/leave events
- **`fwd_map`**: DevMap for packet redirection to veth interfaces

### XDP Programs

1. **`xdp_downstream`**: Attach to veth interfaces
   - Captures IGMP join/leave messages
   - Reports events to userspace via ring buffer
   - Drops IGMP packets after processing

2. **`xdp_upstream`**: Attach to main interface (e.g., eth0)
   - Identifies multicast packets
   - Redirects to subscribed interfaces via devmap
   - Passes through IGMP control packets

## Attaching to Interfaces

### Attach Downstream Program

```bash
# Attach to veth interface
sudo bpftool net attach xdp id <prog_id> dev <veth_name>
```

### Attach Upstream Program

```bash
# Attach to main interface
sudo bpftool net attach xdp id <prog_id> dev eth0
```

## Docker

The provided `Dockerfile` uses a two-stage build: a `builder` stage that compiles
the BPF object, generates the libbpf skeleton, and links the daemon; and a
`runtime` stage that copies only the binary with its shared-library dependencies.

### Build the image

```bash
docker build -t igmp-proxy .
```

### Run the container

The daemon needs host networking (to attach XDP to a real interface) and
elevated capabilities to load BPF programs:

```bash
docker run --rm \
    --network host \
    --privileged \
    -e UPLINK_IFACE=eth0 \
    igmp-proxy
```

If you prefer not to use `--privileged`, grant only the required capabilities:

```bash
docker run --rm \
    --network host \
    --cap-add NET_ADMIN \
    --cap-add SYS_ADMIN \
    --cap-add BPF \
    -e UPLINK_IFACE=eth0 \
    igmp-proxy
```

> **Note:** The BPF programs are embedded in the binary at compile time via the
> libbpf skeleton, so no separate `.o` file needs to be mounted at runtime.

---

## Testing

### End-to-End Test

The test script sets up an isolated veth topology entirely in network namespaces, starts the daemon, subscribes two receivers to a multicast group, sends 5 packets from a sender namespace, and verifies both receivers get all 5.

```
[ns-sender]──veth-sender/veth-uplink──[host: daemon + xdp_upstream]
                                            │
                         ┌──────────────────┤
                         │                  │
             veth-ns1h/veth-ns1      veth-ns2h/veth-ns2
             [ns1: receiver]         [ns2: receiver]
```

**Run the test:**

```bash
sudo bash test_multicast.sh
```

**Expected output:**

```
=== RESULT: ns1 received 5 packet(s), ns2 received 5 packet(s) ===
PASS: multicast delivered to both subscriber namespaces
```

### Manual Smoke Test

Start the daemon on a veth interface:

```bash
sudo UPLINK_IFACE=veth-uplink ./multicast_user
```

In another terminal, join a multicast group from a subscriber namespace:

```bash
sudo ip netns exec ns1 python3 -c "
import socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', 5000))
sock.settimeout(10)
mreq = struct.pack('4s4s', socket.inet_aton('239.1.1.1'), socket.inet_aton('10.0.1.2'))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
print('joined, waiting...')
data, addr = sock.recvfrom(65535)
print(f'received: {data} from {addr}')
"
```

Send a packet from the sender namespace:

```bash
sudo ip netns exec ns-sender python3 -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('10.0.0.2'))
sock.sendto(b'hello multicast', ('239.1.1.1', 5000))
print('sent')
"
```

### Verifying BPF Map State

After the daemon is running and subscribers have joined:

```bash
# Confirm xdp_upstream is attached to the uplink
sudo bpftool net show dev veth-uplink

# Confirm xdp_downstream is attached to subscriber veths
sudo bpftool net show dev veth-ns1h

# Inspect the group → subscriber devmap
sudo bpftool map show name inner_devmap
sudo bpftool map dump name inner_devmap

# Check subscriber count per group
sudo bpftool map dump name group_sub_count | grep -v '"value": 0'

# Inspect the group_id_map (multicast IP → group_id)
sudo bpftool map dump name group_id_map
```

---

## Viewing Logs

### Daemon Log

The daemon writes all operational events to **stderr**. When started by the test script:

```bash
cat /tmp/daemon.log
```

Useful log lines to look for:

| Line | Meaning |
|---|---|
| `xdp_upstream attached to veth-uplink` | Uplink BPF program loaded |
| `xdp_downstream attached to ifindex=N (flags=drv)` | Subscriber veth registered |
| `igmp: joined 239.1.1.1 on veth-uplink` | Upstream IGMP join issued |
| `join: group=239.1.1.1 ifindex=N subs=M` | Subscriber added to devmap |
| `leave: group=239.1.1.1 ifindex=N subs=M` | Subscriber removed |
| `afxdp: initialised on veth-uplink queue 0` | AF-XDP (Tier-3) path ready |

Tail the live daemon log while the test runs:

```bash
tail -f /tmp/daemon.log
```

### Packet Capture

Capture multicast traffic arriving at a subscriber veth (inside ns1):

```bash
sudo ip netns exec ns1 tcpdump -i veth-ns1 -nn 'udp and dst 239.1.1.1'
```

Capture on the uplink (before XDP redirect — will show 0 packets if XDP is intercepting correctly):

```bash
sudo tcpdump -i veth-uplink -nn 'udp and dst 239.1.1.1'
```

### Socket Delivery Diagnostics

If packets arrive at the interface (tcpdump shows them) but the receiver socket gets nothing:

```bash
# Check for UDP checksum errors — most common cause with XDP redirect
sudo ip netns exec ns1 nstat -az | grep UdpInCsumErrors

# Check for IP multicast routing counters
sudo ip netns exec ns1 nstat -az | grep -E '(InMcast|UdpIn)'

# Verify the multicast group is registered on the interface
sudo ip netns exec ns1 ip maddr show dev veth-ns1

# Check RPF filter (should be 0 for subscriber namespaces)
sudo ip netns exec ns1 sysctl net.ipv4.conf.all.rp_filter

# Confirm the socket is listening
sudo ip netns exec ns1 ss -lunp | grep 5000
```

> **Note:** `UdpInCsumErrors > 0` with XDP in DRV mode means the sender's veth is using partial checksum offload. Fix with:
> ```bash
> sudo ethtool -K <sender-veth> tx-checksumming off
> ```

### Kernel Tracing

```bash
# Watch IGMP events processed by the daemon (BPF ring buffer)
sudo cat /sys/kernel/debug/tracing/trace_pipe &

# Monitor XDP program decisions (requires kernel tracing support)
sudo bpftool prog tracelog
```

---

## Troubleshooting

### Common Issues

1. **Header file not found**: Ensure `linux-headers-$(uname -r)` is installed
2. **BPF verifier errors**: Check kernel version compatibility
3. **Permission denied**: Run with sudo/root privileges
4. **Interface not found**: Verify interface names exist

### Debug Commands

```bash
# Check BPF verifier log
sudo cat /sys/kernel/debug/bpf/verifier_log

# List loaded programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id <prog_id>

# Dump program bytecode
sudo bpftool prog dump xlated id <prog_id>
```

### Kernel Logs

```bash
# Monitor kernel messages
sudo dmesg -w

# Check for BPF-related errors
sudo journalctl -f -k | grep -i bpf
```

## Performance Considerations

- **Ring Buffer Size**: Adjust `max_entries` in the events map based on expected event volume
- **DevMap Size**: Set `MAX_SUBS` based on maximum expected subscribers
- **XDP Mode**: Use native mode for best performance, fallback to generic mode if needed

## Security Notes

- BPF programs run in kernel space with elevated privileges
- Validate all packet data to prevent potential exploits
- Use appropriate map permissions and access controls
- Monitor program behavior in production environments

## License

GPL v2 - See the `_license` section in the BPF program.
