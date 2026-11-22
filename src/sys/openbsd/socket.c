#include "../bsd.h"
#include "../bsd_sysctl.h"
#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <string.h>

typedef void (*file_callback)(void *, const struct netsock_row *, uint32_t, uint32_t, const char *);

int netsock_files(int owners, void *ctx, file_callback visit) {
    int mib[] = {CTL_KERN, KERN_FILE, owners ? KERN_FILE_BYPID : KERN_FILE_BYFILE,
                 owners ? -1 : DTYPE_SOCKET, sizeof(struct kinfo_file), INT_MAX};
    void *data;
    size_t count;
    int error = read_records(mib, 6, sizeof(struct kinfo_file), &data, &count);
    if (error)
        return error;
    const struct kinfo_file *files = data;
    for (size_t i = 0; i < count; ++i) {
        const struct kinfo_file *file = &files[i];
        if (file->f_type != DTYPE_SOCKET || (owners && (!file->p_pid || file->fd_fd < 0)))
            continue;
        if (file->so_family != AF_INET && file->so_family != AF_INET6)
            continue;
        int tcp = file->so_protocol == IPPROTO_TCP && file->so_type == SOCK_STREAM;
        if (!tcp && !(file->so_protocol == IPPROTO_UDP && file->so_type == SOCK_DGRAM))
            continue;
        struct netsock_row row = {0};
        /* Non-root callers receive the same sentinel for every PCB. */
        row.id = file->so_pcb == UINT64_MAX ? 0 : file->so_pcb;
        row.ipv6 = file->so_family == AF_INET6;
        row.tcp = tcp;
        row.state = file->t_state;
        row.local_port = ntohs(file->inp_lport);
        row.remote_port = ntohs(file->inp_fport);
        memcpy(row.local, file->inp_laddru, row.ipv6 ? 16 : 4);
        memcpy(row.remote, file->inp_faddru, row.ipv6 ? 16 : 4);
        visit(ctx, &row, file->inp_rtableid, owners ? file->p_pid : 0, file->p_comm);
    }
    free(data);
    return 0;
}
