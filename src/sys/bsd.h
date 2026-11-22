#ifndef NETSOCK_BSD_H
#define NETSOCK_BSD_H
#include <stdint.h>

/* Socket identity is used only to join observations within one scan. */
struct netsock_row {
    uint64_t id;
    uint8_t local[16], remote[16];
    uint16_t local_port, remote_port;
    int32_t state;
    uint8_t ipv6, tcp;
};
#endif
