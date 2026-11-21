#include "../bsd.h"
#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libutil.h>
#include <stdlib.h>
#include <string.h>

static int read_table(const char *name, void **data, size_t *len) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        if (sysctlbyname(name, NULL, len, NULL, 0) == -1)
            return errno ? errno : EIO;
        void *buf = malloc(*len ? *len : 1);
        if (!buf)
            return ENOMEM;
        if (sysctlbyname(name, buf, len, NULL, 0) == 0) {
            *data = buf;
            return 0;
        }
        int error = errno ? errno : EIO;
        free(buf);
        if (error != ENOMEM)
            return error;
    }
    return EAGAIN;
}

typedef void (*row_callback)(void *, const struct netsock_row *);
int netsock_pcbs(int tcp, void *ctx, row_callback visit) {
    void *data;
    size_t len;
    int error = read_table(tcp ? "net.inet.tcp.pcblist" : "net.inet.udp.pcblist", &data, &len);
    if (error)
        return error;

    const size_t header = sizeof(struct xinpgen);
    const size_t stride = tcp ? sizeof(struct xtcpcb) : sizeof(struct xinpcb);
    if (len < 2 * header || (len - 2 * header) % stride != 0) {
        free(data);
        return EPROTO;
    }
    const char *bytes = data;
    const struct xinpgen *first = data;
    const struct xinpgen *last = (const void *)(bytes + len - header);
    if (first->xig_len != header || last->xig_len != header) {
        free(data);
        return EPROTO;
    }
    for (size_t offset = header; offset < len - header; offset += stride) {
        const void *record = bytes + offset;
        const struct xtcpcb *xt = record;
        const struct xinpcb *in = tcp ? &xt->xt_inp : record;
        if ((tcp ? xt->xt_len : in->xi_len) != stride) {
            error = EPROTO;
            break;
        }
        if (in->inp_gencnt > first->xig_gen)
            continue;
        struct netsock_row row = {0};
        row.tcp = tcp;
        row.id = in->xi_socket.xso_so;
        row.state = tcp ? xt->t_state : 0;
        row.local_port = ntohs(in->inp_lport);
        row.remote_port = ntohs(in->inp_fport);
        if (in->inp_vflag & INP_IPV6) {
            row.ipv6 = 1;
            memcpy(row.local, &in->in6p_laddr, 16);
            memcpy(row.remote, &in->in6p_faddr, 16);
        } else if (in->inp_vflag & INP_IPV4) {
            memcpy(row.local, &in->inp_laddr, 4);
            memcpy(row.remote, &in->inp_faddr, 4);
        } else {
            continue;
        }
        visit(ctx, &row);
    }
    free(data);
    return error;
}

typedef void (*owner_callback)(void *, uint64_t, uint32_t);
int netsock_owners(void *ctx, owner_callback visit) {
    void *data;
    size_t len;
    int error = read_table("kern.file", &data, &len);
    if (error)
        return error;
    const struct xfile *files = data;
    if (len % sizeof(*files) != 0)
        error = EPROTO;
    for (size_t i = 0; !error && i < len / sizeof(*files); ++i) {
        if (files[i].xf_size != sizeof(*files))
            error = EPROTO;
        else if (files[i].xf_type == DTYPE_SOCKET && files[i].xf_data && files[i].xf_pid > 0)
            visit(ctx, files[i].xf_data, files[i].xf_pid);
    }
    free(data);
    return error;
}

void netsock_process_name(int pid, char *buf, size_t size) {
    struct kinfo_proc *process = kinfo_getproc(pid);
    if (process) {
        strlcpy(buf, process->ki_comm, size);
        free(process);
    }
}
