/*
 * Open A UNIX Socket access to physical memory
 *
 * Author: Valerio G. Aimale <valerio@aimale.com>
 */

#ifndef MEMORY_ACCESS_H
#define MEMORY_ACCESS_H

#include <sys/socket.h>
#include "qemu/osdep.h"
#include "qapi/error.h"

void qmp_pmemaccess (const char *path, Error **errp);

struct pmemaccess_args {
    int socket_fd;
    struct sockaddr_un *address;
    socklen_t address_length;
    char *path;
    Error **errp;
};

#endif /* MEMORY_ACCESS_H */
