package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"math/bits"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// event must match the struct layout in multicast.bpf.c:
// struct event { __u32 type; __be32 group; __u32 ifindex; };
type event struct {
	Type    uint32
	GroupBE uint32 // network byte order
	IfIndex uint32
}

// bpf_devmap_val layout (linux/bpf.h):
// struct { __u32 ifindex; union { int fd; __u32 id; } bpf_prog; };
type bpfDevMapVal struct {
	IfIndex   uint32
	BpfProgFd int32
}

type trackedIf struct {
	IfIndex uint32
	Key     uint32
}

const (
	maxTracked = 128
)

func ipNtoa(nbo uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nbo)
	return ip.String()
}

func main() {
	log.SetFlags(0)

	var ifname string
	flag.StringVar(&ifname, "iface", "", "Interface name to attach xdp_downstream to (optional; can also pass as first arg)")
	flag.Parse()
	if ifname == "" && flag.NArg() > 0 {
		ifname = flag.Arg(0)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to set RLIMIT_MEMLOCK: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("multicast.bpf.o")
	if err != nil {
		log.Fatalf("failed to open BPF object: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to load BPF object: %v", err)
	}
	defer coll.Close()

	xdpDown := coll.Programs["xdp_downstream"]
	if xdpDown == nil {
		log.Fatalf("xdp_downstream program not found")
	}
	xdpUp := coll.Programs["xdp_upstream"]
	if xdpUp == nil {
		log.Printf("Warning: xdp_upstream program not found")
	}

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		log.Fatalf("events ring buffer map not found")
	}
	fwdMap := coll.Maps["fwd_map"]
	if fwdMap == nil {
		log.Printf("Warning: fwd_map not found; forwarding may not work")
	}

	var downstreamLink link.Link
	if ifname != "" {
		ifidx, err := ifNameToIndex(ifname)
		if err != nil {
			log.Fatalf("failed to get ifindex for %s: %v", ifname, err)
		}
		downstreamLink, err = link.AttachXDP(link.XDPOptions{
			Program:   xdpDown,
			Interface: ifidx,
			Flags:     link.XDPDriverMode,
		})
		if err != nil {
			log.Printf("Warning: failed to attach xdp_downstream to %s: %v", ifname, err)
			log.Printf("You may need to attach manually: ip link set dev %s xdp obj multicast.bpf.o sec xdp/xdp_downstream", ifname)
		} else {
			log.Printf("Attached xdp_downstream to %s (ifindex: %d)", ifname, ifidx)
		}
	}
	defer func() {
		if downstreamLink != nil {
			_ = downstreamLink.Close()
		}
	}()

	// Attach upstream to ens5 (native first, fallback to generic)
	var upstreamLink link.Link
	const upstreamIfName = "ens5"
	if xdpUp != nil {
		upIdx, err := ifNameToIndex(upstreamIfName)
		if err != nil {
			log.Printf("Failed to get interface index for %s: %v", upstreamIfName, err)
		} else {
			upstreamLink, err = link.AttachXDP(link.XDPOptions{
				Program:   xdpUp,
				Interface: upIdx,
				Flags:     link.XDPDriverMode,
			})
			if err != nil {
				log.Printf("Warning: native XDP attach failed on %s: %v", upstreamIfName, err)
				// fallback to generic mode
				upstreamLink, err = link.AttachXDP(link.XDPOptions{
					Program:   xdpUp,
					Interface: upIdx,
					Flags:     link.XDPGenericMode,
				})
				if err != nil {
					log.Printf("Failed to attach generic XDP on %s: %v", upstreamIfName, err)
					log.Printf("You may need to attach manually:")
					log.Printf("  ip link set dev %s xdp off; ip link set dev %s xdpgeneric off", upstreamIfName, upstreamIfName)
					log.Printf("  ip link set dev %s xdp obj multicast.bpf.o sec xdp/xdp_upstream", upstreamIfName)
					log.Printf("  or: ip link set dev %s xdpgeneric obj multicast.bpf.o sec xdp/xdp_upstream", upstreamIfName)
				} else {
					log.Printf("Attached xdp_upstream to %s in generic mode", upstreamIfName)
				}
			} else {
				log.Printf("Attached xdp_upstream to %s in native mode", upstreamIfName)
			}
		}
	}
	defer func() {
		if upstreamLink != nil {
			_ = upstreamLink.Close()
		}
	}()

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("failed to create ring buffer reader: %v", err)
	}
	defer rd.Close()

	// Track ifindex->key to manage fwd_map entries
	var (
		tracked     [maxTracked]trackedIf
		nextKey     uint32
		trackedLock sync.Mutex
	)

	log.Printf("Monitoring IGMP events... Press Ctrl+C to exit")
	if ifname != "" {
		if idx, _ := ifNameToIndex(ifname); idx != 0 {
			log.Printf("XDP attached to interface: %s (ifindex: %d)", ifname, idx)
		} else {
			log.Printf("XDP intended for: %s", ifname)
		}
	}

	// Reader goroutine: this blocks on rd.Read(); closing rd unblocks it.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				log.Printf("Still monitoring...")
				continue
			default:
			}
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			var ev event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
				log.Printf("Warning: failed to parse event: %v", err)
				continue
			}

			var typeStr string
			switch ev.Type {
			case 1:
				typeStr = "JOIN"
			case 2:
				typeStr = "LEAVE"
			case 3:
				typeStr = "DATA"
			default:
				typeStr = "UNKNOWN"
			}

			// ev.GroupBE was read using LittleEndian from bytes that are in network order.
			// Reverse the bytes to get the correct network-order value, then format.
			groupHost := bits.ReverseBytes32(ev.GroupBE) // host-order numeric (also equals network-order byte pattern)
			groupIP := ipNtoa(groupHost)                 // expects network-order uint32
			log.Printf("[EVENT] type=%s (%d), group=%s (0x%08x), ifindex=%d",
				typeStr, ev.Type, groupIP, groupHost, ev.IfIndex)

			if ev.Type == 3 {
				log.Printf("[FWD] Multicast data packet for group %s received on ifindex %d, forwarding to subscribers", groupIP, ev.IfIndex)
			}

			if fwdMap != nil && (ev.Type == 1 || ev.Type == 2) {
				trackedLock.Lock()
				if ev.Type == 1 {
					// JOIN: add to devmap if not present
					found := false
					var existingKey uint32
					for i := 0; i < maxTracked; i++ {
						if tracked[i].IfIndex == ev.IfIndex {
							found = true
							existingKey = tracked[i].Key
							break
						}
					}
					if !found {
						if nextKey >= maxTracked {
							log.Printf("[FWD_MAP] Maximum subscribers reached (%d)", maxTracked)
						} else {
							key := nextKey
							nextKey++
							val := bpfDevMapVal{
								IfIndex:   ev.IfIndex,
								BpfProgFd: -1,
							}
							if err := fwdMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
								log.Printf("[FWD_MAP] Failed to add ifindex %d: %v", ev.IfIndex, err)
							} else {
								// Track
								for i := 0; i < maxTracked; i++ {
									if tracked[i].IfIndex == 0 {
										tracked[i] = trackedIf{IfIndex: ev.IfIndex, Key: key}
										break
									}
								}
								log.Printf("[FWD_MAP] Added ifindex %d to forwarding map (key: %d, group: %s)",
									ev.IfIndex, key, groupIP)
								// Verify
								var verify bpfDevMapVal
								if err := fwdMap.Lookup(&key, &verify); err == nil {
									if verify.IfIndex == ev.IfIndex {
										log.Printf("[FWD_MAP] Verified: map entry %d -> ifindex %d", key, ev.IfIndex)
									} else {
										log.Printf("[FWD_MAP] Warning: Verification mismatch: expected %d got %d", ev.IfIndex, verify.IfIndex)
									}
								}
							}
						}
					} else {
						log.Printf("[FWD_MAP] ifindex %d already in forwarding map (key: %d)", ev.IfIndex, existingKey)
					}
				} else if ev.Type == 2 {
					// LEAVE: remove from devmap
					foundIdx := -1
					var key uint32
					for i := 0; i < maxTracked; i++ {
						if tracked[i].IfIndex == ev.IfIndex {
							key = tracked[i].Key
							foundIdx = i
							break
						}
					}
					if foundIdx >= 0 {
						if err := fwdMap.Delete(&key); err != nil {
							log.Printf("[FWD_MAP] Failed to remove ifindex %d: %v", ev.IfIndex, err)
						} else {
							tracked[foundIdx] = trackedIf{}
							log.Printf("[FWD_MAP] Removed ifindex %d from forwarding map (key: %d)", ev.IfIndex, key)
						}
					} else {
						log.Printf("[FWD_MAP] ifindex %d not found in forwarding map", ev.IfIndex)
					}
				}
				trackedLock.Unlock()
			}
		}
	}()

	// Wait for SIGINT/SIGTERM and then close ring buffer to unblock reader
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill)
	<-sigCh
	log.Printf("Signal received, shutting down...")
	_ = rd.Close()
	wg.Wait()

	log.Printf("Exiting...")
}

func ifNameToIndex(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}
