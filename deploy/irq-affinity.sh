#!/bin/sh
# Tier-1: Pin NIC receive IRQs to NUMA-local CPUs.
#
# Placing NIC IRQs and container workloads on the same NUMA node eliminates
# cross-NUMA memory accesses on the packet receive path, saving 50–150 ns
# per packet cache miss and reducing jitter.
#
# Usage: irq-affinity.sh <interface>   e.g.  irq-affinity.sh eth0

set -e

IFACE=${1:-eth0}

if [ ! -d "/sys/class/net/${IFACE}" ]; then
    echo "irq-affinity: interface ${IFACE} not found, skipping"
    exit 0
fi

# Determine NUMA node of the NIC
NUMA_NODE=0
if [ -f "/sys/class/net/${IFACE}/device/numa_node" ]; then
    node=$(cat "/sys/class/net/${IFACE}/device/numa_node")
    # -1 means non-NUMA system; treat as node 0
    [ "${node}" -ge 0 ] 2>/dev/null && NUMA_NODE="${node}"
fi
echo "irq-affinity: ${IFACE} is on NUMA node ${NUMA_NODE}"

# Get CPU list for this NUMA node
CPU_LIST=""
if [ -f "/sys/devices/system/node/node${NUMA_NODE}/cpulist" ]; then
    CPU_LIST=$(cat "/sys/devices/system/node/node${NUMA_NODE}/cpulist")
fi
if [ -z "${CPU_LIST}" ]; then
    # Non-NUMA: use all online CPUs
    CPU_LIST=$(cat /sys/devices/system/cpu/online 2>/dev/null || echo "0")
fi
echo "irq-affinity: target CPU list: ${CPU_LIST}"

# Find IRQ numbers associated with the interface
IRQS=$(grep -i "${IFACE}" /proc/interrupts 2>/dev/null \
        | awk -F: '{print $1}' | tr -d ' ')

if [ -z "${IRQS}" ]; then
    echo "irq-affinity: no IRQs found for ${IFACE}, trying MSI-X pattern"
    # Some drivers name queues as <iface>-TxRx-N or <iface>-rx-N
    IRQS=$(grep -E "${IFACE}-(TxRx|rx|tx|q)[0-9]" /proc/interrupts 2>/dev/null \
            | awk -F: '{print $1}' | tr -d ' ')
fi

if [ -z "${IRQS}" ]; then
    echo "irq-affinity: no IRQs found for ${IFACE}, skipping"
    exit 0
fi

SET_COUNT=0
for irq in ${IRQS}; do
    affinity_file="/proc/irq/${irq}/smp_affinity_list"
    if [ -f "${affinity_file}" ]; then
        echo "${CPU_LIST}" > "${affinity_file}" 2>/dev/null && SET_COUNT=$((SET_COUNT + 1)) || true
    fi
done
echo "irq-affinity: set affinity for ${SET_COUNT} IRQ(s) of ${IFACE} to CPUs ${CPU_LIST}"

# Also set RPS (Receive Packet Steering) for each RX queue
for rps in /sys/class/net/${IFACE}/queues/rx-*/rps_cpus; do
    [ -f "${rps}" ] || continue
    # Convert CPU list to hex bitmask
    python3 -c "
import sys
cpus = '${CPU_LIST}'
mask = 0
for part in cpus.split(','):
    if '-' in part:
        a, b = map(int, part.split('-'))
        for c in range(a, b+1):
            mask |= (1 << c)
    else:
        mask |= (1 << int(part))
print(format(mask, 'x'))
" > "${rps}" 2>/dev/null || true
done
echo "irq-affinity: RPS configured for ${IFACE}"
