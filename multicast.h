#ifndef MULTICAST_H
#define MULTICAST_H

#include <stdint.h>

// Event types
#define EVENT_JOIN  1
#define EVENT_LEAVE 2

// Event structure for IGMP join/leave events
struct event {
    uint32_t type;     // 1: join, 2: leave
    uint32_t group;    // Multicast group address (network byte order)
    uint32_t ifindex;  // Interface index where event occurred
};

#endif // MULTICAST_H
