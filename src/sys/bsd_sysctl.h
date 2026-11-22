#ifndef NETSOCK_BSD_SYSCTL_H
#define NETSOCK_BSD_SYSCTL_H

#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <stdlib.h>

/* Both kernels can grow a table between the size query and the read.
 * NetBSD can return a larger required length even when the read succeeds. */
static int read_records(const int *mib, unsigned int miblen, size_t stride,
                        void **data, size_t *count) {
    for (int attempt = 0; attempt < 8; ++attempt) {
        size_t capacity = 0;
        if (sysctl(mib, miblen, NULL, &capacity, NULL, 0) == -1)
            return errno;
        void *buf = malloc(capacity ? capacity : 1);
        if (!buf)
            return ENOMEM;
        size_t len = capacity;
        int error = sysctl(mib, miblen, buf, &len, NULL, 0) == -1 ? errno : 0;
        if (!error && len <= capacity && len % stride == 0) {
            *data = buf;
            *count = len / stride;
            return 0;
        }
        free(buf);
        if (error && error != ENOMEM)
            return error;
        if (!error && len <= capacity)
            return EPROTO;
    }
    return EAGAIN;
}
#endif
