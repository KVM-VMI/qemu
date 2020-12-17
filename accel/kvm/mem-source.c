/*
 * VM Introspection
 *
 * Copyright (C) 2020 Bitdefender S.R.L.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/notify.h"
#include "qemu/thread.h"

#include "exec/memory.h"
#include "exec/address-spaces.h"

#include "qapi/error.h"

#include "qom/object.h"
#include "qom/object_interfaces.h"

#include "sysemu/sysemu.h"

#include "chardev/char.h"
#include "chardev/char-fe.h"

#include <linux/remote_mapping.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include "mem-introspection.h"

#define HANDSHAKE_TIMEOUT 5
static void mem_source_machine_ready(Notifier *notifier, void *data);

struct MemSourceState {
    /* private */
    Object parent_obj;

    /* public */
    char *chardev;
    CharBackend chr;
    Notifier machine_ready;

    /* remote mapping */
    int pidfd;
    struct rmemfds fds;

    /* handshake logic */
    GSource *timeout;
    bool handshake;
    MemSourceConnected *handshake_complete;
    void *handshake_complete_ctx;

    MemoryListener mlisten;
};

/* copied from kvm-all.c */
static hwaddr kvm_align_section(MemoryRegionSection *section, hwaddr *start)
{
    hwaddr size = int128_get64(section->size);
    hwaddr delta, aligned;

    /* kvm works in page size chunks, but the function may be called
    with sub-page size and unaligned start address. Pad the start
    address to next and truncate size to previous page boundary. */
    aligned = ROUND_UP(section->offset_within_address_space,
                       qemu_real_host_page_size);
    delta = aligned - section->offset_within_address_space;
    *start = aligned;
    if (delta > size) {
        return 0;
    }

    return (size - delta) & qemu_real_host_page_mask;
}

// memory listener
static void mlisten_region_add(MemoryListener *listener, MemoryRegionSection *section)
{
    MemSourceState *ms = container_of(listener, MemSourceState, mlisten);
    MemoryRegion *mr = section->mr;
    void *ram = NULL;
    hwaddr start_addr, size;
    struct pidfd_mem_map mreq;
    int result;

    if (!memory_region_is_ram(mr))
        return;
    if (memory_region_is_ram_device(mr))
        return;             /* only pure memory allowed */

    /* copied from kvm-all.c */
    size = kvm_align_section(section, &start_addr);
    if (!size)
        return;

    /* use aligned delta to align the ram address */
    ram = memory_region_get_ram_ptr(mr) + section->offset_within_region +
        (start_addr - section->offset_within_address_space);
    if (ram == NULL)
        return;             /* not the region we're interested in */

    //info_report("%s: useful region: phys %lx, size %lx, virt %lx, owner %s",
    //    __func__, start_addr, size, (long)ram,
    //    object_get_typename(mr->parent_obj.parent));

    mreq.address = (uint64_t)ram;
    mreq.offset = start_addr;
    mreq.size = size;

    result = ioctl(ms->fds.ctl_fd, PIDFD_MEM_MAP, &mreq);
    if (result)
        warn_report("%s: failed registering memory region", __func__);
}

// memory listener
static void mlisten_region_del(MemoryListener *listener, MemoryRegionSection *section)
{
    MemSourceState *ms = container_of(listener, MemSourceState, mlisten);
    MemoryRegion *mr = section->mr;
    void *ram = NULL;
    hwaddr start_addr, size;
    struct pidfd_mem_unmap ureq;
    int result;

    if (!memory_region_is_ram(mr))
        return;
    if (memory_region_is_ram_device(mr))
        return;             /* only pure memory allowed */

    /* copied from kvm-all.c */
    size = kvm_align_section(section, &start_addr);
    if (!size)
        return;

    /* use aligned delta to align the ram address */
    ram = memory_region_get_ram_ptr(mr) + section->offset_within_region +
        (start_addr - section->offset_within_address_space);
    if (ram == NULL)
        return;             /* not the region we're interested in */

    //info_report("%s: useful region: phys %lx, size %lx, virt %lx, owner %s",
    //    __func__, start_addr, size, (long)ram,
    //    object_get_typename(mr->parent_obj.parent));

    ureq.offset = start_addr;
    ureq.size = size;

    result = ioctl(ms->fds.ctl_fd, PIDFD_MEM_UNMAP, &ureq);
    if (result)
        warn_report("%s: failed unregistering memory region", __func__);
}

// constructor
static void mem_source_instance_init(Object *obj)
{
    MemSourceState *ms = MEM_SOURCE(obj);

    info_report("%s: source %p", __func__, ms);

    ms->pidfd = -1;
    ms->fds.ctl_fd = -1;
    ms->fds.mem_fd = -1;

    ms->mlisten.region_add = mlisten_region_add;
    ms->mlisten.region_del = mlisten_region_del;
    ms->mlisten.priority = 100;

    ms->machine_ready.notify = mem_source_machine_ready;
}

// destructor
static void mem_source_instance_finalize(Object *obj)
{
    MemSourceState *ms = MEM_SOURCE(obj);

    info_report("%s: source %p", __func__, ms);

    memory_listener_unregister(&ms->mlisten);

    qemu_chr_fe_deinit(&ms->chr, true);

    if (ms->pidfd != -1) {
        if (close(ms->pidfd))
            warn_report("Closing pidfd failed: %s", strerror(errno));
        ms->pidfd = -1;
    }

    if (ms->fds.ctl_fd != -1) {
        if (close(ms->fds.ctl_fd))
            warn_report("Closing control fd failed: %s", strerror(errno));
        ms->fds.ctl_fd = -1;
    }

    if (ms->fds.mem_fd != -1) {
        if (close(ms->fds.mem_fd))
            warn_report("Closing mapping fd failed: %s", strerror(errno));
        ms->fds.mem_fd = -1;
    }

    g_free(ms->chardev);
}

static void mem_source_send_introspection_ready(MemSourceState *ms, Error **errp)
{
    int result;
    MemIntrospectionPkt data;
    int fds[2];

    fds[0] = ms->pidfd;
    fds[1] = ms->fds.mem_fd;

    result = qemu_chr_fe_set_msgfds(&ms->chr, fds, 2);
    if (result == -1) {
        error_setg(errp, "Chardev '%s' does not support fd passing", ms->chardev);
        return;
    }

    memcpy(&data.dom_id, &qemu_uuid, sizeof(QemuUUID));

    result = qemu_chr_fe_write_all(&ms->chr, (const uint8_t *) &data, sizeof(data));
    if (result != sizeof(data)) {
        error_setg(errp, "Failed sending %d bytes", (int)sizeof(data));
        return;
    }
}

static int mem_chardev_can_read(void *opaque)
{
    return (int) sizeof(gboolean);
}

static void mem_chardev_read(void *opaque, const uint8_t *buf, int size)
{
    MemSourceState *ms = MEM_SOURCE(opaque);
    gboolean *ack = (gboolean *)buf;

    assert(size == sizeof(gboolean));
    info_report("%s: introspection says %s", __func__, *ack == TRUE ? "ACK" : "NACK");

    qemu_chr_fe_disconnect(&ms->chr);
    ms->handshake = true;

    /* cancel timeout */
    g_source_destroy(ms->timeout);
    g_source_unref(ms->timeout);
    ms->timeout = NULL;

    ms->handshake_complete(ms->handshake_complete_ctx);
}

// GSourceFunc
static gboolean mem_handshake_timeout(gpointer user_data)
{
    MemSourceState *ms = MEM_SOURCE(user_data);

    info_report("%s: source %p", __func__, ms);

    /* avoid receiving a reply for another message */
    qemu_chr_fe_disconnect(&ms->chr);
    ms->handshake = false;

    /* remove timeout source */
    g_source_unref(ms->timeout);
    ms->timeout = NULL;
    return G_SOURCE_REMOVE;
}

void mem_source_connect(MemSourceState *ms, MemSourceConnected *cbk,
                        void *opaque)
{
    /*
     * These FDs are set from mem_source_init_introspection().
     * If not, we assume that the kernel doesn't support remote mapping v2,
     * but we let the guest continue.
     */
    if (ms->fds.ctl_fd == -1 || ms->fds.mem_fd == -1) {
        warn_report("%s: remote mapping v2 is not supported by the current kernel",
                    __func__);
        cbk(opaque);
        return;
    }

    if (ms->handshake) {
        info_report("%s: source %p, already connected, ignored!", __func__, ms);
        cbk(opaque);
        return;
    }

    /*
     * If this function is called in quick succession before the connection was
     * established, qemu_chr_fe_connect() will do nothing. Same if the connection
     * was established.
     */
    info_report("%s: source %p, connecting...", __func__, ms);
    qemu_chr_fe_connect(&ms->chr);
    ms->handshake_complete = cbk;
    ms->handshake_complete_ctx = opaque;
}

void mem_source_disconnect(MemSourceState *ms)
{
    info_report("%s: source %p", __func__, ms);

    if (ms->timeout) {
        g_source_destroy(ms->timeout);
        g_source_unref(ms->timeout);
        ms->timeout = NULL;
    }

    qemu_chr_fe_disconnect(&ms->chr);
    ms->handshake = false;
}

static void mem_chardev_event(void *opaque, int event)
{
    MemSourceState *ms = MEM_SOURCE(opaque);
    Error *local_err = NULL;

    info_report("%s: source %p, event %d", __func__, ms, event);

    if (event == CHR_EVENT_OPENED) {
        mem_source_send_introspection_ready(ms, &local_err);

        ms->timeout = g_timeout_source_new_seconds(HANDSHAKE_TIMEOUT);
        g_source_set_callback(ms->timeout, mem_handshake_timeout, ms, NULL);
        g_source_attach(ms->timeout, NULL);
    }

    if (local_err) {
        warn_report_err(local_err);
        qemu_chr_fe_disconnect(&ms->chr);
    }
}

// 2nd part of _complete()
static void mem_source_machine_ready(Notifier *notifier, void *data)
{
    Chardev *chr;
    MemSourceState *ms = container_of(notifier, MemSourceState, machine_ready);
    Error *local_err = NULL;

    info_report("%s: source %p", __func__, ms);

    chr = qemu_chr_find(ms->chardev);
    if (!chr) {
        error_setg(&local_err, "Chardev '%s' not found", ms->chardev);
        goto out;
    }

    if (!qemu_chr_fe_init(&ms->chr, chr, &local_err)) {
        // errp already filled by qemu_chr_fe_init()
        goto out;
    }

    if (qemu_chr_fe_reconnect_time(&ms->chr, 0) != 0) {
        error_setg(&local_err, "Chardev '%s' has reconnect time, reset and disconnected", ms->chardev);
        qemu_chr_fe_disconnect(&ms->chr);
    }

    qemu_chr_fe_set_handlers(&ms->chr, mem_chardev_can_read, mem_chardev_read,
                             mem_chardev_event, NULL, ms, NULL, true);

out:
    if (local_err) {
        warn_report_err(local_err);
        qemu_chr_fe_deinit(&ms->chr, true);
    }
}

/*
 * Open file descriptors needed for introspection. These shouldn't be closed.
 * With the current guest-introspector handshake, the SVA may close and lose
 * introspector-related info, so the fds need to be re-sent to the SVA.
 */
static void mem_source_init_introspection(MemSourceState *ms, Error **errp)
{
    int result;

    ms->pidfd = syscall(__NR_pidfd_open, getpid(), 0);
    if (ms->pidfd < 0) {
        error_setg_errno(errp, errno, "Failed getting pidfd of current process");
        return;
    }

    result = syscall(__NR_pidfd_mem, ms->pidfd, &ms->fds, 0);
    if (result) {
        error_setg_errno(errp, errno, "Failed creating pidfd_mem fds");
        return;
    }

    info_report("%s: introspection seems to work...", __func__);
}

// user creatable
static void mem_source_complete(UserCreatable *uc, Error **errp)
{
    MemSourceState *ms = MEM_SOURCE(uc);

    info_report("%s: source %p", __func__, ms);

    if (!ms->chardev) {
        error_setg(errp, "Memory introspection needs a (unix socket) chardev ID");
        return;
    }

    /* all else is worthless without these fds */
    mem_source_init_introspection(ms, errp);
    if (*errp) {
        /* errp was filled by mem_source_init_introspection() */

        // TODO: remove me when we merge remote mapping v2
        warn_report_err(*errp);
        *errp = NULL;

        return;
    }

    /* start the mem listener independent of the socket connection */
    memory_listener_register(&ms->mlisten, &address_space_memory);

    /* chardevs are not available this early */
    qemu_add_machine_init_done_notifier(&ms->machine_ready);
}

// user creatable
static bool mem_source_can_be_deleted(UserCreatable *uc)
{
    MemSourceState *ms = MEM_SOURCE(uc);

    info_report("%s: source %p", __func__, ms);

    // right now we have no restrictions
    return true;
}

// property
static char *mem_source_get_chardev(Object *obj, Error **errp)
{
    MemSourceState *ms = MEM_SOURCE(obj);

    return g_strdup(ms->chardev);
}

// property
static void mem_source_set_chardev(Object *obj, const char *str, Error **errp)
{
    MemSourceState *ms = MEM_SOURCE(obj);

    g_free(ms->chardev);
    ms->chardev = g_strdup(str);
}

static void mem_source_class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *uc = USER_CREATABLE_CLASS(oc);

    object_class_property_add_str(oc, "chardev",
        mem_source_get_chardev,
        mem_source_set_chardev,
        &error_abort);
    object_class_property_set_description(oc, "chardev",
        "A backend used to communicate memory metadata",
        &error_abort);

    uc->complete = mem_source_complete;
    uc->can_be_deleted = mem_source_can_be_deleted;
}

static const TypeInfo mem_source_info = {
    .name = TYPE_MEM_SOURCE,
    .parent = TYPE_OBJECT,

    .instance_size = sizeof(MemSourceState),
    .instance_init = mem_source_instance_init,
    .instance_finalize = mem_source_instance_finalize,

    .class_init = mem_source_class_init,
    .interfaces = (InterfaceInfo[]) {
        {TYPE_USER_CREATABLE},
        {}
    }
};

static void mem_source_register_types(void)
{
    type_register_static(&mem_source_info);
}

type_init(mem_source_register_types)
