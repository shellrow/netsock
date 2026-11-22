#include "../bsd.h"
#include "../bsd_sysctl.h"
#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <string.h>

typedef void (*row_callback)(void *, const struct netsock_row *);

static int read_pcbs(const char *name, int tcp, int ipv6, void *ctx, row_callback visit) {
    int mib[CTL_MAXNAME];
    size_t n = CTL_MAXNAME - 4;
    if (sysctlnametomib(name, mib, &n) == -1)
        return errno == ENOENT ? 0 : errno;
    mib[n++] = PCB_ALL;
    mib[n++] = 0;
    mib[n++] = sizeof(struct kinfo_pcb);
    mib[n++] = INT_MAX;

    void *data;
    size_t count;
    int error = read_records(mib, n, sizeof(struct kinfo_pcb), &data, &count);
    if (error)
        return error;
    const struct kinfo_pcb *pcbs = data;
    for (size_t i = 0; i < count; ++i) {
        const struct kinfo_pcb *pcb = &pcbs[i];
        struct netsock_row row = {0};
        row.id = pcb->ki_sockaddr;
        row.tcp = tcp;
        row.ipv6 = ipv6;
        row.state = pcb->ki_tstate;
        if (ipv6) {
            struct sockaddr_in6 local, remote;
            memcpy(&local, pcb->ki_spad, sizeof(local));
            memcpy(&remote, pcb->ki_dpad, sizeof(remote));
            memcpy(row.local, &local.sin6_addr, 16);
            memcpy(row.remote, &remote.sin6_addr, 16);
            row.local_port = ntohs(local.sin6_port);
            row.remote_port = ntohs(remote.sin6_port);
        } else {
            struct sockaddr_in local, remote;
            memcpy(&local, pcb->ki_spad, sizeof(local));
            memcpy(&remote, pcb->ki_dpad, sizeof(remote));
            memcpy(row.local, &local.sin_addr, 4);
            memcpy(row.remote, &remote.sin_addr, 4);
            row.local_port = ntohs(local.sin_port);
            row.remote_port = ntohs(remote.sin_port);
        }
        visit(ctx, &row);
    }
    free(data);
    return 0;
}

int netsock_pcbs(int tcp, int ipv4, int ipv6, void *ctx, row_callback visit) {
    if (ipv4) {
        int error = read_pcbs(tcp ? "net.inet.tcp.pcblist" : "net.inet.udp.pcblist",
                              tcp, 0, ctx, visit);
        if (error)
            return error;
    }
    if (ipv6)
        return read_pcbs(tcp ? "net.inet6.tcp6.pcblist" : "net.inet6.udp6.pcblist",
                         tcp, 1, ctx, visit);
    return 0;
}

int netsock_owners(void *ctx, void (*visit)(void *, uint64_t, uint32_t)) {
    int mib[] = {CTL_KERN, KERN_FILE2, KERN_FILE_BYPID, -1, sizeof(struct kinfo_file), INT_MAX};
    void *data;
    size_t count;
    int error = read_records(mib, 6, sizeof(struct kinfo_file), &data, &count);
    if (error)
        return error;
    const struct kinfo_file *files = data;
    for (size_t i = 0; i < count; ++i)
        if (files[i].ki_ftype == DTYPE_SOCKET && files[i].ki_pid > 0 && files[i].ki_fdata)
            visit(ctx, files[i].ki_fdata, files[i].ki_pid);
    free(data);
    return 0;
}

void netsock_process_name(int pid, char *buf, size_t size) {
    struct kinfo_proc2 proc;
    size_t len = sizeof(proc);
    int mib[] = {CTL_KERN, KERN_PROC2, KERN_PROC_PID, pid, sizeof(proc), 1};
    if (sysctl(mib, 6, &proc, &len, NULL, 0) == 0 && len == sizeof(proc) && proc.p_pid == pid)
        strlcpy(buf, proc.p_comm, size);
}
