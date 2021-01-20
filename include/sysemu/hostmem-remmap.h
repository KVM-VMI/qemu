/*
 * QEMU Remote Memory Backend
 *
 * Copyright (C) 2020 Bitdefender S.R.L.
 *
 * Authors:
 *   Mircea Cirjaliu <mcirjaliu@bitdefender.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef SYSEMU_HOSTMEM_REMMAP_H
#define SYSEMU_HOSTMEM_REMMAP_H

#include "sysemu/hostmem.h"

#define TYPE_MEMORY_BACKEND_RM "memory-backend-remote-mapping"
#define MEMORY_BACKEND_RM(obj)                                        \
    OBJECT_CHECK(HostMemoryBackendRM, (obj), TYPE_MEMORY_BACKEND_RM)

typedef struct HostMemoryBackendRM HostMemoryBackendRM;

struct HostMemoryBackendRM {
    HostMemoryBackend parent_obj;

    int fd;
    off_t offset;
    uint64_t align;
    bool replaced;

    /* full memory */
    size_t mem_size;
    void *mem_ptr;

    /* hotpluggable memory */
    size_t hotplug_size;
    void *hotplug_ptr;
};

void remote_memory_backend_remap(HostMemoryBackendRM *backend, Error **errp);

#endif /* SYSEMU_HOSTMEM_REMMAP_H */
