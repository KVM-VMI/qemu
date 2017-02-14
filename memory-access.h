/*
 * Mount guest physical memory using FUSE.
 *
 * Author: Valerio G. Aimale <valerio@aimale.com>
 */

#ifndef MEMORY_ACCESS_H
#define MEMORY_ACCESS_H

<<<<<<< ours
=======
#include <sys/socket.h>
>>>>>>> theirs
#include "qapi-types.h"
#include "qapi/qmp/qdict.h"
#include "qapi/error.h"

void qmp_pmemaccess (const char *path, Error **errp);

struct pmemaccess_args {
<<<<<<< ours
	char *path;
	Error **errp;
=======
    int socket_fd;
    struct sockaddr_un *address;
    socklen_t address_length;
    char *path;
    Error **errp;
>>>>>>> theirs
};

#endif /* MEMORY_ACCESS_H */
