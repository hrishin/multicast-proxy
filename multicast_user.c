#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "multicast.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    
    printf("Event: type=%u, group=%u.%u.%u.%u, ifindex=%u\n",
           e->type,
           (e->group >> 24) & 0xFF,
           (e->group >> 16) & 0xFF,
           (e->group >> 8) & 0xFF,
           e->group & 0xFF,
           e->ifindex);
    
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
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
    
    // Main event loop
    while (!exiting) {
        err = ring_buffer__poll(rb, 100); // 100ms timeout
        if (err < 0) {
            if (err == -EINTR) {
                err = 0;
                break;
            }
            fprintf(stderr, "Error polling ring buffer: %s\n", strerror(-err));
            break;
        }
    }
    
    // Cleanup
    ring_buffer__free(rb);
    bpf_object__close(obj);
    
    printf("Exiting...\n");
    return 0;
}
