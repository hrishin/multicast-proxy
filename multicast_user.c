#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include "multicast.h"

static volatile bool exiting = false;
static int fwd_map_fd = -1;
static struct bpf_link *uplink = NULL;  // Store upstream link for cleanup

// Track which ifindexes are in the map and their keys
#define MAX_TRACKED_IFINDEXES 128
static struct {
    uint32_t ifindex;
    uint32_t key;
} ifindex_map[MAX_TRACKED_IFINDEXES];
static uint32_t next_key = 0;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    const struct event *e = data;
    
    if (data_sz < sizeof(*e)) {
        fprintf(stderr, "Warning: Event data size mismatch: %zu < %zu\n", 
                data_sz, sizeof(*e));
        return 0;
    }
    
    const char *type_str;
    if (e->type == 1) {
        type_str = "JOIN";
    } else if (e->type == 2) {
        type_str = "LEAVE";
    } else if (e->type == 3) {
        type_str = "DATA";
    } else {
        type_str = "UNKNOWN";
    }
    
    // Convert network byte order to host byte order
    uint32_t group_host = ntohl(e->group);
    struct in_addr group_addr;
    group_addr.s_addr = e->group;  // Keep in network byte order for inet_ntoa
    printf("[EVENT] type=%s (%u), group=%s (0x%08x), ifindex=%u\n",
           type_str, e->type,
           inet_ntoa(group_addr), group_host,
           e->ifindex);
    fflush(stdout);
    
    // For DATA events, log that we're forwarding
    if (e->type == 3) {
        printf("[FWD] Multicast data packet for group %s received on ifindex %u, forwarding to subscribers\n",
               inet_ntoa(group_addr), e->ifindex);
        fflush(stdout);
    }
    
    // Update forwarding map for JOIN/LEAVE events
    if (fwd_map_fd >= 0 && (e->type == 1 || e->type == 2)) {
        struct bpf_devmap_val val = {0};
        val.ifindex = e->ifindex;
        val.bpf_prog.fd = -1;  // No program attached to destination (fd = -1 means no program)
        
        if (e->type == 1) {
            // JOIN: Add interface to forwarding map
            // Check if already in map
            int found = 0;
            uint32_t existing_key = 0;
            for (int i = 0; i < MAX_TRACKED_IFINDEXES; i++) {
                if (ifindex_map[i].ifindex == e->ifindex) {
                    found = 1;
                    existing_key = ifindex_map[i].key;
                    break;
                }
            }
            
            if (!found && next_key < MAX_TRACKED_IFINDEXES) {
                uint32_t key = next_key++;
                int err = bpf_map_update_elem(fwd_map_fd, &key, &val, BPF_ANY);
                if (err == 0) {
                    // Track this mapping
                    for (int i = 0; i < MAX_TRACKED_IFINDEXES; i++) {
                        if (ifindex_map[i].ifindex == 0) {
                            ifindex_map[i].ifindex = e->ifindex;
                            ifindex_map[i].key = key;
                            break;
                        }
                    }
                    printf("[FWD_MAP] Added ifindex %u to forwarding map (key: %u, group: %s)\n", 
                           e->ifindex, key, inet_ntoa(group_addr));
                    fflush(stdout);
                    
                    // Verify the entry was added correctly
                    struct bpf_devmap_val verify_val = {0};
                    if (bpf_map_lookup_elem(fwd_map_fd, &key, &verify_val) == 0) {
                        if (verify_val.ifindex == e->ifindex) {
                            printf("[FWD_MAP] Verified: map entry %u -> ifindex %u\n", key, e->ifindex);
                        } else {
                            fprintf(stderr, "[FWD_MAP] Warning: Verification failed - expected ifindex %u, got %u\n",
                                    e->ifindex, verify_val.ifindex);
                        }
                    }
                } else {
                    fprintf(stderr, "[FWD_MAP] Failed to add ifindex %u: %s (errno: %d)\n", 
                            e->ifindex, strerror(errno), errno);
                }
            } else if (found) {
                printf("[FWD_MAP] ifindex %u already in forwarding map (key: %u)\n", 
                       e->ifindex, existing_key);
            } else {
                fprintf(stderr, "[FWD_MAP] Maximum subscribers reached (%u)\n", MAX_TRACKED_IFINDEXES);
            }
        } else if (e->type == 2) {
            // LEAVE: Remove interface from forwarding map
            uint32_t key = 0;
            int found_idx = -1;
            for (int i = 0; i < MAX_TRACKED_IFINDEXES; i++) {
                if (ifindex_map[i].ifindex == e->ifindex) {
                    key = ifindex_map[i].key;
                    found_idx = i;
                    break;
                }
            }
            
            if (found_idx >= 0) {
                int err = bpf_map_delete_elem(fwd_map_fd, &key);
                if (err == 0) {
                    // Remove from tracking
                    ifindex_map[found_idx].ifindex = 0;
                    ifindex_map[found_idx].key = 0;
                    printf("[FWD_MAP] Removed ifindex %u from forwarding map (key: %u)\n", 
                           e->ifindex, key);
                    fflush(stdout);
                } else {
                    fprintf(stderr, "[FWD_MAP] Failed to remove ifindex %u: %s\n", 
                            e->ifindex, strerror(errno));
                }
            } else {
                printf("[FWD_MAP] ifindex %u not found in forwarding map\n", e->ifindex);
            }
        }
    }
    
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    if (argc > 1) {
        ifname = argv[1];
    }
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    struct bpf_link *link = NULL;
    int err, prog_fd, map_fd;
    
    // Set resource limits
    if (setrlimit(RLIMIT_MEMLOCK, &(struct rlimit){RLIM_INFINITY, RLIM_INFINITY})) {
        fprintf(stderr, "Failed to set RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }
    
    // Load BPF object
    obj = bpf_object__open_file("multicast.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }
    
    // Load BPF program
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    
    // Get program file descriptor
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_downstream"));
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    
    // Get map file descriptor
    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    
    // Get forwarding map file descriptor
    fwd_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "fwd_map"));
    if (fwd_map_fd < 0) {
        fprintf(stderr, "Warning: Failed to get fwd_map fd: %s\n", strerror(errno));
        fprintf(stderr, "Forwarding map will not be updated, multicast forwarding may not work\n");
        // Continue anyway - might still work if map is accessible
    } else {
        printf("Forwarding map file descriptor: %d\n", fwd_map_fd);
    }
    
    // Attach XDP program to interface if provided
    if (argc > 1) {
        const char *ifname = argv[1];
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_downstream");
        if (!prog) {
            fprintf(stderr, "Failed to find xdp_downstream program\n");
            bpf_object__close(obj);
            return 1;
        }
        
        int ifindex = if_nametoindex(ifname);
        if (ifindex == 0) {
            fprintf(stderr, "Failed to get interface index for %s: %s\n", ifname, strerror(errno));
            bpf_object__close(obj);
            return 1;
        }
        
        link = bpf_program__attach_xdp(prog, ifindex);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Warning: Failed to attach XDP program to %s: %s\n", ifname, strerror(errno));
            fprintf(stderr, "You may need to attach manually using: ip link set dev %s xdp obj multicast.bpf.o sec xdp/xdp_downstream\n", ifname);
            link = NULL;
        } else {
            printf("Attached XDP program to interface %s (ifindex: %d)\n", ifname, ifindex);
        }
    }
    
    // Also attach xdp_upstream program to ens5
    const char *upstream_ifname = "ens5";
    struct bpf_program *up_prog = bpf_object__find_program_by_name(obj, "xdp_upstream");
    if (!up_prog) {
        fprintf(stderr, "Failed to find xdp_upstream program\n");
        // Continue anyway, don't exit
    } else {
        int up_ifindex = if_nametoindex(upstream_ifname);
        if (up_ifindex == 0) {
            fprintf(stderr, "Failed to get interface index for %s: %s\n", upstream_ifname, strerror(errno));
            // Continue anyway, don't exit
        } else {
            // First, try to remove any existing XDP program
            // This helps if XDP is already attached in a different mode
            // Try both native and generic modes
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "ip link set dev %s xdp off 2>/dev/null", upstream_ifname);
            (void)system(cmd);  // Ignore errors - it's okay if nothing was attached
            snprintf(cmd, sizeof(cmd), "ip link set dev %s xdpgeneric off 2>/dev/null", upstream_ifname);
            (void)system(cmd);  // Also try generic mode
            
            // Wait a moment for cleanup
            usleep(100000);  // 100ms
            
            // Try to attach with native mode first (default)
            uplink = bpf_program__attach_xdp(up_prog, up_ifindex);
            if (libbpf_get_error(uplink)) {
                // If native mode failed, provide instructions for manual attachment
                int libbpf_err = libbpf_get_error(uplink);
                char err_buf[256];
                libbpf_strerror(libbpf_err, err_buf, sizeof(err_buf));
                fprintf(stderr, "Warning: Failed to attach xdp_upstream to %s in native mode: %s\n",
                        upstream_ifname, err_buf);
                fprintf(stderr, "Attempting to use generic (SKB) mode...\n");
                
                // Try using the older bpf_set_link_xdp_fd API for generic mode
                // This is more widely available than bpf_xdp_attach
                int prog_fd = bpf_program__fd(up_prog);
                if (prog_fd < 0) {
                    fprintf(stderr, "Failed to get program fd\n");
                    uplink = NULL;
                } else {
                    // Use bpf_set_link_xdp_fd with XDP_FLAGS_SKB_MODE for generic mode
                    // This function is available in older libbpf versions
                    err = bpf_set_link_xdp_fd(up_ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
                    if (err == 0) {
                        printf("Attached xdp_upstream program to interface %s (ifindex: %d) in generic mode\n",
                                upstream_ifname, up_ifindex);
                        uplink = NULL;  // Track that we attached via direct API
                    } else {
                        fprintf(stderr, "Failed to attach in generic mode: %s\n", strerror(-err));
                        fprintf(stderr, "\nYou may need to attach manually. Try:\n");
                        fprintf(stderr, "  1. First detach any existing XDP program:\n");
                        fprintf(stderr, "     ip link set dev %s xdp off\n", upstream_ifname);
                        fprintf(stderr, "     ip link set dev %s xdpgeneric off\n", upstream_ifname);
                        fprintf(stderr, "  2. Then attach in native mode:\n");
                        fprintf(stderr, "     ip link set dev %s xdp obj multicast.bpf.o sec xdp/xdp_upstream\n", upstream_ifname);
                        fprintf(stderr, "  Or in generic mode:\n");
                        fprintf(stderr, "     ip link set dev %s xdpgeneric obj multicast.bpf.o sec xdp/xdp_upstream\n", upstream_ifname);
                        fprintf(stderr, "\nNote: If you get map creation errors, the maps already exist from the first load.\n");
                        fprintf(stderr, "      This is normal - the program should still work.\n");
                        uplink = NULL;
                    }
                }
            } else {
                printf("Attached xdp_upstream program to interface %s (ifindex: %d) in native mode\n",
                        upstream_ifname, up_ifindex);
            }
        }
    }
    // Set up ring buffer
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    
    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("Monitoring IGMP events... Press Ctrl+C to exit\n");
    if (ifname) {
        printf("XDP attached to interface: %s (ifindex: %d)\n", ifname, 
               ifname ? if_nametoindex(ifname) : 0);
    }
    fflush(stdout);
    
    // Main event loop
    int poll_count = 0;
    while (!exiting) {
        err = ring_buffer__poll(rb, 100); // 100ms timeout
        if (err < 0) {
            if (err == -EINTR) {
                err = 0;
                break;
            }
            if (err != -EINTR) {
                fprintf(stderr, "Error polling ring buffer: %d (%s)\n", -err, strerror(-err));
                // Don't break on error, keep trying
                continue;
            }
        }
        // Periodically print that we're still running
        poll_count++;
        if (poll_count % 100 == 0) { // Every 10 seconds (100 * 100ms)
            printf("Still monitoring... (poll count: %d)\n", poll_count);
            fflush(stdout);
        }
    }
    
    // Cleanup
    if (link) {
        bpf_link__destroy(link);
    }
    if (uplink) {
        bpf_link__destroy(uplink);
    } else {
        // If uplink is NULL but we attached via ip command, detach manually
        // Check if ens5 has XDP attached and remove it
        const char *upstream_ifname = "ens5";
        char detach_cmd[256];
        snprintf(detach_cmd, sizeof(detach_cmd), "ip link set dev %s xdp off 2>/dev/null", upstream_ifname);
        (void)system(detach_cmd);  // Ignore return value
    }
    ring_buffer__free(rb);
    bpf_object__close(obj);
    
    printf("Exiting...\n");
    return 0;
}
