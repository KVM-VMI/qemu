/*
 * QEMU host fd memory backend
 *
 * Copyright (C) 2020 Bitdefender S.R.L.
 *
 * Authors:
 *   Mircea Cirjaliu <mcirjaliu@bitdefender.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/hostmem-remmap.h"
#include "sysemu/sysemu.h"
#include "qom/object_interfaces.h"
#include "qemu/memfd.h"
#include "qapi/error.h"
#include "qemu/error-report.h"

#include <linux/remote_mapping.h>
#include <sys/ioctl.h>

#define MB (1024 * 1024)

void remote_memory_backend_remap(HostMemoryBackendRM *m, Error **errp)
{
    HostMemoryBackend *backend = MEMORY_BACKEND(m);
    int result;
    void *repl;

    result = ioctl(m->fd, PIDFD_MEM_REMAP, m->hotplug_ptr);
    if (result) {
        error_setg_errno(errp, errno, "Remapping failed for %lx", m->offset);

        if (!m->replaced) {
            /* replace useful memory with anon memory */
            munmap(m->hotplug_ptr, backend->size);
            repl = mmap(m->hotplug_ptr, backend->size, PROT_READ,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
            if (repl == MAP_FAILED) {
                warn_report("%s: replacing useful memory failed", __func__);
            }
            /* no specific action taken if mmap() failed */

            m->replaced = true;
        }
    }
}

static void
rm_backend_memory_alloc(HostMemoryBackend *backend, Error **errp)
{
    HostMemoryBackendRM *m = MEMORY_BACKEND_RM(backend);
    char *name;

    if (!backend->size) {
        error_setg(errp, "can't create backend with size 0");
        return;
    }

    if (m->fd == -1) {
        error_setg(errp, "can't create backend with fd -1");
        return;
    }

    if (host_memory_backend_mr_inited(backend)) {
        return;
    }

    backend->force_prealloc = mem_prealloc;

    // remote mapping may impose certain size/alignment constraints not compatible with memory hotplug
    // the hotpluggable region must be of size 2^x, bigger than the remote mapped region
    // first the backing memory must be allocated so the region is reserved
    // then the useful memory can start at any alignment [0, 2M) depending on the source VMA
    // m->align gives the machine physical memory alignment (not related to remote mapping)

    //         |<-----------useful size------------->|
    // |-------|++++++++++++++++++++++++++++++++++++++........|-----------|
    // |<----->|    alignment imposed by remote mapping
    //         |<---------------pow2 size-------------------->|
    // |<--------------------pow2 size + 2M------------------------------>|

    m->hotplug_size = MAX(pow2ceil(backend->size), m->align);
    m->mem_size = m->hotplug_size + 2 * MB;

    /* alloc backing memory */
    m->mem_ptr = mmap(0, m->mem_size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (m->mem_ptr == MAP_FAILED) {
        error_setg_errno(errp, errno, "%s: failed mapping %ld bytes", __func__, m->mem_size);
        return;
    }

    /* map remote memory */
    m->hotplug_ptr = mmap(m->mem_ptr, backend->size, PROT_READ | PROT_WRITE,
        MAP_SHARED, m->fd, m->offset);
    if (m->hotplug_ptr == MAP_FAILED) {
        error_setg_errno(errp, errno, "%s: failed mapping %ld bytes", __func__, backend->size);
        munmap(m->mem_ptr, m->mem_size);
    }

    name = g_strdup_printf("remote-map-%p", backend);
    memory_region_init_ram_ptr(&backend->mr, OBJECT(backend), name,
                               m->hotplug_size, m->hotplug_ptr);
    backend->mr.align = m->align;
    g_free(name);
}

static void
rm_backend_get_fd(Object *obj, Visitor *v, const char *name,
                  void *opaque, Error **errp)
{
    HostMemoryBackendRM *m = MEMORY_BACKEND_RM(obj);
    uint64_t value = m->fd;

    visit_type_size(v, name, &value, errp);
}

static void
rm_backend_set_fd(Object *obj, Visitor *v, const char *name,
                  void *opaque, Error **errp)
{
    HostMemoryBackendRM *m = MEMORY_BACKEND_RM(obj);
    Error *local_err = NULL;
    uint64_t value;

    if (host_memory_backend_mr_inited(MEMORY_BACKEND(obj))) {
        error_setg(&local_err, "cannot change property value");
        goto out;
    }

    visit_type_size(v, name, &value, &local_err);
    if (local_err) {
        goto out;
    }
    if (!value) {
        error_setg(&local_err, "Property '%s.%s' doesn't take value '%"
            PRIu64 "'", object_get_typename(obj), name, value);
        goto out;
    }
    m->fd = value;

out:
    error_propagate(errp, local_err);
}

static void
rm_backend_get_offset(Object *obj, Visitor *v, const char *name,
                      void *opaque, Error **errp)
{
    HostMemoryBackendRM *m = MEMORY_BACKEND_RM(obj);
    uint64_t value = m->offset;

    visit_type_size(v, name, &value, errp);
}

static void
rm_backend_set_offset(Object *obj, Visitor *v, const char *name,
                      void *opaque, Error **errp)
{
    HostMemoryBackendRM *m = MEMORY_BACKEND_RM(obj);
    Error *local_err = NULL;
    uint64_t value;

    if (host_memory_backend_mr_inited(MEMORY_BACKEND(obj))) {
        error_setg(&local_err, "cannot change property value");
        goto out;
    }

    visit_type_size(v, name, &value, &local_err);
    if (local_err) {
        goto out;
    }
    m->offset = value;

out:
    error_propagate(errp, local_err);
}

static void
rm_backend_get_align(Object *obj, Visitor *v, const char *name,
                     void *opaque, Error **errp)
{
    HostMemoryBackendRM *m = MEMORY_BACKEND_RM(obj);
    uint64_t val = m->align;

    visit_type_size(v, name, &val, errp);
}

static void
rm_backend_set_align(Object *obj, Visitor *v, const char *name,
                     void *opaque, Error **errp)
{
    HostMemoryBackendRM *m = MEMORY_BACKEND_RM(obj);
    Error *local_err = NULL;
    uint64_t value;

    if (host_memory_backend_mr_inited(MEMORY_BACKEND(obj))) {
        error_setg(&local_err, "cannot change property value");
        goto out;
    }

    visit_type_size(v, name, &value, &local_err);
    if (local_err) {
        goto out;
    }
    if (!value) {
        error_setg(&local_err, "Property '%s.%s' doesn't take value '%"
            PRIu64 "'", object_get_typename(obj), name, value);
        goto out;
    }
    m->align = value;

out:
    error_propagate(errp, local_err);
}

static void
rm_backend_instance_init(Object *obj)
{
    HostMemoryBackendRM *m = MEMORY_BACKEND_RM(obj);

    m->fd = -1;
}

static void
rm_backend_instance_finalize(Object *obj)
{
    HostMemoryBackendRM *m = MEMORY_BACKEND_RM(obj);

    info_report("%s: fd %d, offset %lx, size %lx",
        __func__, m->fd, m->offset, MEMORY_BACKEND(obj)->size);

    if (m->mem_ptr) {
        /* munmap useful & backing memory */
        munmap(m->mem_ptr, m->mem_size);
    }
}

static void
rm_backend_class_init(ObjectClass *oc, void *data)
{
    HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);

    bc->alloc = rm_backend_memory_alloc;

    object_class_property_add(oc, "fd", "int",
        rm_backend_get_fd,
        rm_backend_set_fd,
        NULL, NULL, &error_abort);

    object_class_property_add(oc, "offset", "int",
        rm_backend_get_offset,
        rm_backend_set_offset,
        NULL, NULL, &error_abort);

    object_class_property_add(oc, "align", "int",
        rm_backend_get_align,
        rm_backend_set_align,
        NULL, NULL, &error_abort);
}

static const TypeInfo rm_backend_info = {
    .name = TYPE_MEMORY_BACKEND_RM,
    .parent = TYPE_MEMORY_BACKEND,
    .class_init = rm_backend_class_init,
    .instance_init = rm_backend_instance_init,
    .instance_finalize = rm_backend_instance_finalize,
    .instance_size = sizeof(HostMemoryBackendRM),
};

static void register_types(void)
{
    type_register_static(&rm_backend_info);
}

type_init(register_types);
