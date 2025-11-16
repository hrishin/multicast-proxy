# BPF Multicast Program

This BPF program implements multicast packet handling using XDP (eXpress Data Path) for high-performance network packet processing.

## Features

- **Downstream capture (XDP on veth)**: Captures IGMP join/leave messages from downstream interfaces
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
- **`fwd_map`**: DevMap for packet redirection to downstream interfaces (veth endpoints)

### Programs

1. **`xdp_downstream`**: Attach to veth/downstream interfaces
   - Captures IGMP join/leave messages
   - Reports events to userspace via ring buffer
   - Drops IGMP packets after processing

2. **`xdp_upstream`**: Attach to main interface (e.g., eth0)
   - Identifies multicast packets
   - Redirects to subscribed interfaces via devmap
   - Passes through IGMP control packets

3. Netkit-specific programs have been removed in favor of a simpler veth/XDP flow.

## Attaching to Interfaces

### Attach Downstream Program

```bash
# For veth/XDP:
sudo bpftool net attach xdp id <prog_id> dev <downstream_ifname>
```
### Attach Upstream Program

```bash
# Attach to main interface
sudo bpftool net attach xdp id <prog_id> dev eth0
```

## Troubleshooting

### Common Issues

1. **Header file not found**: Ensure `linux-headers-$(uname -r)` is installed
2. **BPF verifier errors**: Check kernel version compatibility
3. **Permission denied**: Run with sudo/root privileges
4. **Interface not found**: Verify interface names exist
5. **BPF verifier log not available**: The verifier log at `/sys/kernel/debug/bpf/verifier_log` is created dynamically when BPF programs are loaded. This is normal if you haven't loaded any BPF programs yet.

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
