/*
 * Mount guest physical memory using FUSE.
 *
 * Author: Valerio G. Aimale <valerio@aimale.com>
 */

#ifndef MEMORY_ACCESS_H
#define MEMORY_ACCESS_H

#include "qapi-types.h"
#include "qapi/qmp/qdict.h"
#include "qapi/error.h"

void qmp_pmemaccess (const char *path, Error **errp);

struct pmemaccess_args {
	char *path;
	Error **errp;
};

#endif /* MEMORY_ACCESS_H */
