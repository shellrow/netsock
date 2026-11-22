#include "../bsd.h"
#include <arpa/inet.h>
#include <errno.h>
#include <libproc.h>
#include <string.h>
#include <sys/socket.h>

/* Returns one for an Internet socket, zero for other descriptors, or -errno. */
int netsock_fd(int pid, int fd, struct netsock_row *out) {
    struct socket_fdinfo fdinfo;
    int size = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &fdinfo, sizeof(fdinfo));
    if (size <= 0)
        return errno ? -errno : -EBADF;
    if ((size_t)size != sizeof(fdinfo))
        return -EIO;
    const struct socket_info *s = &fdinfo.psi;
    if (s->soi_family != AF_INET && s->soi_family != AF_INET6)
        return 0;

    const struct in_sockinfo *in;
    if (s->soi_kind == SOCKINFO_TCP && s->soi_protocol == IPPROTO_TCP) {
        out->tcp = 1;
        in = &s->soi_proto.pri_tcp.tcpsi_ini;
        out->state = s->soi_proto.pri_tcp.tcpsi_state;
    } else if (s->soi_kind == SOCKINFO_IN && s->soi_protocol == IPPROTO_UDP) {
        in = &s->soi_proto.pri_in;
    } else {
        return 0;
    }
    out->id = s->soi_so;
    out->ipv6 = s->soi_family == AF_INET6;
    if (out->ipv6) {
        memcpy(out->local, &in->insi_laddr.ina_6, 16);
        memcpy(out->remote, &in->insi_faddr.ina_6, 16);
    } else {
        memcpy(out->local, &in->insi_laddr.ina_46.i46a_addr4, 4);
        memcpy(out->remote, &in->insi_faddr.ina_46.i46a_addr4, 4);
    }
    out->local_port = ntohs((uint16_t)in->insi_lport);
    out->remote_port = ntohs((uint16_t)in->insi_fport);
    return 1;
}
