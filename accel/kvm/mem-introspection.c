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
#include "qemu/thread.h"

#include "qapi/error.h"
#include "qom/object_interfaces.h"

#include "hw/hw.h"
#include "hw/mem/pc-dimm.h"
#include "hw/qdev-properties.h"

#include "io/channel.h"
#include "io/channel-file.h"

#include "sysemu/sysemu.h"
#include "sysemu/hostmem.h"
#include "sysemu/hostmem-remmap.h"
#include "sysemu/reset.h"
#include "sysemu/kvm.h"

#include "chardev/char.h"
#include "chardev/char-fe.h"

#include <linux/remote_mapping.h>
#include <sys/ioctl.h>

#include "mem-introspection.h"

typedef struct ProcIntrospectionState ProcIntrospectionState;

#define TYPE_PROC_INTROSPECTION "proc-introspection"
#define PROC_INTROSPECTION(obj) \
    OBJECT_CHECK(ProcIntrospectionState, (obj), TYPE_PROC_INTROSPECTION)

// QIOChannelFunc
static gboolean proc_introspection_qio(QIOChannel *ioc, GIOCondition condition, gpointer data);

static void mem_introspection_domain_shutdown(MemIntrospectionState *mi,
                                              ProcIntrospectionState *pi,
                                              Error **errp);

/*
 * Holds the introspection context for a single process.
 * Every introspected memory region creates a hot-pluggable device.
 *
 * The fd belongs to this object and can be closed at any time.
 * The file will close when the last memory obtained by mmap()
 * will be munmap()-ped. That's the memory backend's problem.
 */
typedef struct ProcIntrospectionState {
    /*< private >*/
    DeviceState parent_obj;

    /*< public >*/
    QemuUUID uuid;
    int pidfd;
    int memfd;

    QIOChannel *qio;        /* domain shutdown event handler */
    guint src_id;

    bool introspected;      /* state variables... */
    bool shutdown;          /* ...must be modified under introspection lock */

    GHashTable *gpaHash;

} ProcIntrospectionState;

static void proc_introspection_start(ProcIntrospectionState *pi)
{
    info_report("%s: pi %p, domain "UUID_FMT, __func__, pi, UUID_ARG(&pi->uuid));

    pi->introspected = true;
}

static uint64_t proc_introspection_map(ProcIntrospectionState *pi,
                                       uint64_t gpa, uint64_t size, uint64_t min,
                                       Error **errp)
{
    Object *hostmem;
    Object *dimm;
    uint64_t local_gpa = -1;

    info_report("%s: pi %p, domain "UUID_FMT", gpa %lx, size %lx", __func__,
        pi, UUID_ARG(&pi->uuid), gpa, size);

    hostmem = object_new("memory-backend-remote-mapping");

    // set hostmem properties
    object_property_set_int(hostmem, pi->memfd, "fd", errp);
    object_property_set_int(hostmem, size, "size", errp);
    object_property_set_int(hostmem, gpa, "offset", errp);
    object_property_set_int(hostmem, min, "align", errp);

    /* complete hostmem => mmap() */
    user_creatable_complete(USER_CREATABLE(hostmem), errp);

    /* memory allocation in @hostmem may fail */
    if (*errp)
        goto out_hostmem;

    dimm = object_new(TYPE_PC_DIMM);

    /* set @dimm as child of machine */
    gchar *chldprop = g_strdup_printf("%p", dimm);
    object_property_add_child(container_get(qdev_get_machine(), "/remote-map"), chldprop, dimm, errp);
    g_free(chldprop);

    /* object_property_add_child() can fail if property already exists */
    if (*errp)
        goto out_dimm_noparent;

    /* set @hostmem as child of @dimm */
    object_property_add_child(dimm, "hostmem", hostmem, errp);

    /* link @dimm to @hostmem - this increments hostmem ref count */
    object_property_set_link(dimm, hostmem, PC_DIMM_MEMDEV_PROP, errp);

    object_property_set_bool(dimm, true, "realized", errp);
    if (*errp)
        goto out_dimm;

    // reference this @dimm by GPA
    local_gpa = object_property_get_uint(dimm, PC_DIMM_ADDR_PROP, errp);
    g_hash_table_insert(pi->gpaHash, GINT_TO_POINTER(local_gpa), dimm);
    info_report("%s: local gpa %lx", __func__, local_gpa);

    object_unref(dimm);             /* usage reference */
    object_unref(hostmem);          /* usage reference */

    return local_gpa;

out_dimm:
    object_unparent(dimm);          /* will drag hostmem with it */
out_dimm_noparent:
    object_unref(dimm);             /* usage reference */
out_hostmem:
    object_unref(hostmem);          /* usage reference */

    return -1;
}

static void proc_introspection_unmap(ProcIntrospectionState *pi,
                                     uint64_t gpa, Error **errp)
{
    Object *dimm;

    info_report("%s: pi %p, domain "UUID_FMT", local gpa %lx", __func__,
        pi, UUID_ARG(&pi->uuid), gpa);

    dimm = g_hash_table_lookup(pi->gpaHash, GINT_TO_POINTER(gpa));
    if (!dimm) {
        warn_report("remote mapped DIMM @ %lx not present", gpa);
    } else {
        g_hash_table_remove(pi->gpaHash, GINT_TO_POINTER(gpa));
        qdev_unplug(DEVICE(dimm), errp);
    }
}

static bool proc_introspection_remap(ProcIntrospectionState *pi,
                                     uint64_t gpa, Error **errp)
{
    Object *dimm;
    HostMemoryBackendRM *backend;

    info_report("%s: pi %p, domain "UUID_FMT", local gpa %lx", __func__,
        pi, UUID_ARG(&pi->uuid), gpa);

    dimm = g_hash_table_lookup(pi->gpaHash, GINT_TO_POINTER(gpa));
    if (!dimm) {
        error_setg(errp, "Invalid address %lx", gpa);
        return false;
    }

    backend = MEMORY_BACKEND_RM(object_property_get_link(dimm, PC_DIMM_MEMDEV_PROP, errp));
    assert(backend);

    remote_memory_backend_remap(backend, errp);
    if (*errp)
        return false;

    return true;
}

/*
 * Mark the introspection as ended. This must be called under mi->intro_lock.
 * By the time this function is called, all children + associations must have
 * been removed, either by request or by reset.
 */
static void proc_introspection_end(ProcIntrospectionState *pi)
{
    info_report("%s: pi %p, domain "UUID_FMT, __func__, pi, UUID_ARG(&pi->uuid));

    assert(g_hash_table_size(pi->gpaHash) == 0);

    pi->introspected = false;
}

/* Work on the object state. This must be called under mi->intro_lock. */
static void proc_introspection_shutdown(ProcIntrospectionState *pi)
{
    info_report("%s: pi %p, domain "UUID_FMT, __func__, pi, UUID_ARG(&pi->uuid));

    pi->shutdown = true;
}

// constructor
static void proc_introspection_instance_init(Object *obj)
{
    ProcIntrospectionState *pi = PROC_INTROSPECTION(obj);

    info_report("%s: pi %p", __func__, pi);

    pi->pidfd = -1;
    pi->memfd = -1;
    pi->gpaHash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void proc_introspection_realize(DeviceState *dev, Error **errp)
{
    ProcIntrospectionState *pi = PROC_INTROSPECTION(dev);

    info_report("%s: pi %p, domain "UUID_FMT, __func__,
        pi, UUID_ARG(&pi->uuid));

    /* properties have been assigned, fd should be open */
    if (fcntl(pi->memfd, F_GETFL) == -1 && errno == EBADF) {
        pi->memfd = -1;
        error_setg_errno(errp, errno, "Can't do mappings");
    }

    /* poll waiting for the pidfd to close */
    pi->qio = QIO_CHANNEL(qio_channel_file_new_fd(pi->pidfd));
    pi->src_id = qio_channel_add_watch(pi->qio, G_IO_IN,
        proc_introspection_qio, pi, NULL);
}

/* Unrealization will be done as result of unparenting. */
static void proc_introspection_unrealize(DeviceState *dev, Error **errp)
{
    ProcIntrospectionState *pi = PROC_INTROSPECTION(dev);

    info_report("%s: pi %p, domain "UUID_FMT, __func__,
        pi, UUID_ARG(&pi->uuid));

    if (pi->pidfd != -1) {
        if (close(pi->pidfd))
            error_setg_errno(errp, errno, "%s: closing fd %d failed",
                __func__, pi->pidfd);
        pi->pidfd = -1;
    }

    if (pi->memfd != -1) {
        if (close(pi->memfd))
            error_setg_errno(errp, errno, "%s: closing fd %d failed",
                __func__, pi->memfd);
        pi->memfd = -1;
    }

    if (pi->src_id != 0) {
        g_source_remove(pi->src_id);
        pi->src_id = 0;
    }

    if (pi->qio) {
        object_unref(OBJECT(pi->qio));
        pi->qio = NULL;
    }
}

static gboolean reset_ghr_func(gpointer key, gpointer value, gpointer user_data)
{
    PCDIMMDevice *dimm = (PCDIMMDevice *)value;
    HotplugHandler *hotplug_ctrl;
    Error *local_err = NULL;

    info_report("%s: unplugging DIMM @ %lx", __func__, dimm->addr);

    /* synchronously remove the slot */
    hotplug_ctrl = qdev_get_hotplug_handler(DEVICE(dimm));
    hotplug_handler_unplug(hotplug_ctrl, DEVICE(dimm), &local_err);

    object_unparent(OBJECT(dimm));

    if (local_err)
        warn_report_err(local_err);

    return TRUE;
}

/*
 * In case of a real machine reset during introspection, this call comes on the
 * main thread, so there is no need no take qemu_global_mutex.
 * Also a reset is triggered on realization, but the gpaHash should be empty.
 */
static void proc_introspection_reset(DeviceState *dev)
{
    ProcIntrospectionState *pi = PROC_INTROSPECTION(dev);

    info_report("%s: pi %p, domain "UUID_FMT, __func__,
        pi, UUID_ARG(&pi->uuid));

    /* remove all children -> dimms */
    g_hash_table_foreach_remove(pi->gpaHash, reset_ghr_func, NULL);
    pi->introspected = false;
}

// destructor
static void proc_introspection_instance_finalize(Object *obj)
{
    ProcIntrospectionState *pi = PROC_INTROSPECTION(obj);

    info_report("%s: pi %p, domain "UUID_FMT, __func__,
        pi, UUID_ARG(&pi->uuid));

    g_hash_table_destroy(pi->gpaHash);
}

static Property proc_introspection_properties[] = {
    DEFINE_PROP_UUID("uuid", ProcIntrospectionState, uuid),
    DEFINE_PROP_INT32("pidfd", ProcIntrospectionState, pidfd, -1),
    DEFINE_PROP_INT32("memfd", ProcIntrospectionState, memfd, -1),
    DEFINE_PROP_END_OF_LIST(),
};

static void proc_introspection_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = proc_introspection_realize;
    dc->unrealize = proc_introspection_unrealize;
    dc->reset = proc_introspection_reset;
    dc->props = proc_introspection_properties;
    dc->desc = "Domain introspection device";
}

static const TypeInfo proc_introspection_info = {
    .name = TYPE_PROC_INTROSPECTION,
    .parent = TYPE_DEVICE,

    .instance_size = sizeof(ProcIntrospectionState),
    .instance_init = proc_introspection_instance_init,
    .instance_finalize = proc_introspection_instance_finalize,

    .class_init = proc_introspection_class_init,
};








typedef struct MemIntrospectionState {
    /* private */
    Object parent_obj;

    /* public */
    char *chardev;
    CharBackend chr;
    Notifier machine_ready;

    QemuMutex intro_lock;

    GHashTable *ready;          /* uuid -> pi */
    GHashTable *introspected;   /* uuid -> pi */
    GHashTable *gpaHash;        /* gpa -> pi */
} MemIntrospectionState;

static ProcIntrospectionState *
proc_introspection_alloc(MemIntrospectionState *mi,
    const QemuUUID *uuid, int fds[2], Error **errp)
{
    Object *pi;

    info_report("%s: domain "UUID_FMT, __func__, UUID_ARG(uuid));

    pi = object_new(TYPE_PROC_INTROSPECTION);

    /* set @pi as child of @mi */
    gchar *chldprop = g_strdup_printf("dom-"UUID_FMT, UUID_ARG(uuid));
    object_property_add_child(OBJECT(mi), chldprop, pi, errp);
    g_free(chldprop);

    // TODO: there is no func for setting UUID, work-around this
    ProcIntrospectionState *pi_dev = PROC_INTROSPECTION(pi);
    memcpy(&pi_dev->uuid, uuid, sizeof(*uuid));

    /* pass the fds tp @pi - this object will close the fds */
    object_property_set_int(pi, fds[0], "pidfd", errp);
    object_property_set_int(pi, fds[1], "memfd", errp);

    /* link back to owner @mi */
    object_property_add_const_link(pi, "introspection", OBJECT(mi), errp);

    /* trigger initialization of @pi */
    object_property_set_bool(pi, true, "realized", errp);

    /* insert in ready list */
    g_hash_table_insert(mi->ready, qemu_uuid_dup(uuid), pi);

    return PROC_INTROSPECTION(pi);
}

// QIOChannelFunc for @pi
static gboolean proc_introspection_qio(QIOChannel *ioc, GIOCondition condition, gpointer data)
{
    ProcIntrospectionState *pi = PROC_INTROSPECTION(data);
    MemIntrospectionState *mi;
    Error *local_err = NULL;

    info_report("%s: domain "UUID_FMT" shutting down", __func__, UUID_ARG(&pi->uuid));

    pi->src_id = 0; /* this source will auto-remove */

    mi = MEM_INTROSPECTION(object_property_get_link(OBJECT(pi), "introspection", &local_err));
    assert(mi);
    mem_introspection_domain_shutdown(mi, pi, &local_err);

    if (local_err)
        warn_report_err(local_err);

    return G_SOURCE_REMOVE;
}

static ProcIntrospectionState *
proc_introspection_lookup_ready(MemIntrospectionState *mi, const QemuUUID *uuid)
{
    Object *pi;

    pi = g_hash_table_lookup(mi->ready, uuid);
    if (pi)
        object_ref(pi);

    return PROC_INTROSPECTION(pi);
}

static void
move_to_introspected(MemIntrospectionState *mi, ProcIntrospectionState *pi,  Error **errp)
{
    g_hash_table_remove(mi->ready, &pi->uuid);
    g_hash_table_insert(mi->introspected, qemu_uuid_dup(&pi->uuid), pi);
}

static ProcIntrospectionState *
proc_introspection_lookup_introspected(MemIntrospectionState *mi, const QemuUUID *uuid)
{
    Object *pi;

    pi = g_hash_table_lookup(mi->introspected, uuid);
    if (pi)
        object_ref(pi);

    return PROC_INTROSPECTION(pi);
}

static void
move_to_ready(MemIntrospectionState *mi, ProcIntrospectionState *pi,  Error **errp)
{
    g_hash_table_remove(mi->introspected, &pi->uuid);
    g_hash_table_insert(mi->ready, qemu_uuid_dup(&pi->uuid), pi);
}

// entry point - domain ready for introspection
static void mem_introspection_domain_ready(MemIntrospectionState *mi,
                                           const QemuUUID *uuid, int fds[2],
                                           Error **errp)
{
    ProcIntrospectionState *pi;

    info_report("%s: mi %p, domain "UUID_FMT", pidfd %d, memfd %d", __func__,
        mi, UUID_ARG(uuid), fds[0], fds[1]);

    qemu_mutex_lock(&mi->intro_lock);

    /*
     * this event and mem_introspection_dev_shutdown() come from 2 different
     * sources, but should be serialized on the same thread
     */
    pi = proc_introspection_lookup_ready(mi, uuid);
    if (pi) {
        /* this happens when introspection reconnects */
        error_setg(errp, "Domain "UUID_FMT" already present", UUID_ARG(uuid));
        close(fds[0]);
        close(fds[1]);
        goto out;
    }

    /* allocate the @pi for the current session */
    pi = proc_introspection_alloc(mi, uuid, fds, errp);
    object_unref(OBJECT(pi));

out:
    qemu_mutex_unlock(&mi->intro_lock);

    info_report("%s: -", __func__);
}

// entry point - introspection start
void mem_introspection_start(MemIntrospectionState *mi, const QemuUUID *uuid,
                             CPUState *cs, Error **errp)
{
    ProcIntrospectionState *pi;

    info_report("%s: mi %p, domain "UUID_FMT, __func__, mi, UUID_ARG(uuid));

    qemu_mutex_lock(&mi->intro_lock);

    /* mem_introspection_start() should come after mem_introspection_domain_ready() */
    pi = proc_introspection_lookup_ready(mi, uuid);
    if (!pi) {
        error_setg(errp, "Domain "UUID_FMT" not ready", UUID_ARG(uuid));
        goto out;
    }

    proc_introspection_start(pi);
    move_to_introspected(mi, pi, errp);

    object_unref(OBJECT(pi));

out:
    qemu_mutex_unlock(&mi->intro_lock);

    info_report("%s: -", __func__);
}

// entry point - map request
void mem_introspection_map(MemIntrospectionState *mi, const QemuUUID *uuid,
                           uint64_t gpa, uint64_t size, uint64_t min,
                           CPUState *cs, Error **errp)
{
    ProcIntrospectionState *pi;
    uint64_t local_gpa = -1;

    info_report("%s: mi %p, domain "UUID_FMT", gpa %lx, size %lx", __func__,
        mi, UUID_ARG(uuid), gpa, size);

    qemu_mutex_lock(&mi->intro_lock);

    pi = proc_introspection_lookup_introspected(mi, uuid);
    if (!pi) {
        qemu_mutex_unlock(&mi->intro_lock);
        error_setg(errp, "Domain "UUID_FMT" not introspected", UUID_ARG(uuid));
        goto out;
    }

    qemu_mutex_unlock(&mi->intro_lock);

    qemu_mutex_lock_iothread();

    local_gpa = proc_introspection_map(pi, gpa, size, min, errp);
    if (local_gpa != -1)
        g_hash_table_insert(mi->gpaHash, GINT_TO_POINTER(local_gpa), pi);

    qemu_mutex_unlock_iothread();

    object_unref(OBJECT(pi));

out:
    /* adjust local_gpa for ioctl() */
    if (*errp)
        local_gpa = error_get_errno(*errp) ? -error_get_errno(*errp) : -EINVAL;

    kvm_vcpu_ioctl(cs, KVM_INTROSPECTION_MAP, local_gpa);

    info_report("%s: -", __func__);
}

// entry point - unmap request
void mem_introspection_unmap(MemIntrospectionState *mi, const QemuUUID *uuid,
                             uint64_t gpa, CPUState *cs, Error **errp)
{
    ProcIntrospectionState *pi;

    info_report("%s: mi %p, domain "UUID_FMT", local gpa %lx", __func__,
        mi, UUID_ARG(uuid), gpa);

    qemu_mutex_lock(&mi->intro_lock);

    pi = proc_introspection_lookup_introspected(mi, uuid);
    if (!pi) {
        qemu_mutex_unlock(&mi->intro_lock);
        error_setg(errp, "Domain "UUID_FMT" not introspected", UUID_ARG(uuid));
        goto out;
    }

    qemu_mutex_unlock(&mi->intro_lock);

    qemu_mutex_lock_iothread();

    g_hash_table_remove(mi->gpaHash, GINT_TO_POINTER(gpa));
    proc_introspection_unmap(pi, gpa, errp);

    qemu_mutex_unlock_iothread();

    object_unref(OBJECT(pi));

out:
    info_report("%s: -", __func__);
}

// entry point - remap request
bool mem_introspection_remap(MemIntrospectionState *mi, uint64_t gpa,
                             CPUState *cs, Error **errp)
{
    ProcIntrospectionState *pi;
    bool result = false;

    info_report("%s: mi %p, local gpa %lx", __func__, mi, gpa);

    gpa = kvm_start_of_slot(cs->kvm_state, gpa);

    pi = g_hash_table_lookup(mi->gpaHash, GINT_TO_POINTER(gpa));
    if (!pi) {
        error_setg(errp, "Address %lx does not belong to introspector", gpa);
        goto out;
    }

    result = proc_introspection_remap(pi, gpa, errp);

out:
    info_report("%s: -", __func__);

    return result;
}

// entry point - introspection end
void mem_introspection_end(MemIntrospectionState *mi, const QemuUUID *uuid,
                           CPUState *cs, Error **errp)
{
    ProcIntrospectionState *pi;

    info_report("%s: mi %p, domain "UUID_FMT, __func__, mi, UUID_ARG(uuid));

    qemu_mutex_lock(&mi->intro_lock);

    pi = proc_introspection_lookup_introspected(mi, uuid);
    if (!pi) {
        error_setg(errp, "Domain "UUID_FMT" not introspected", UUID_ARG(uuid));
        goto out;
    }

    proc_introspection_end(pi);

    if (pi->shutdown) {
        g_hash_table_remove(mi->introspected, &pi->uuid);
        object_unparent(OBJECT(pi));
    }
    else {
        /* mem_introspection_shutdown() is yet to arrive */
        move_to_ready(mi, pi, errp);
    }

    object_unref(OBJECT(pi));           /* usage reference */

out:
    qemu_mutex_unlock(&mi->intro_lock);

    info_report("%s: -", __func__);
}

// entry point - domain shutdown
static void mem_introspection_domain_shutdown(MemIntrospectionState *mi, ProcIntrospectionState *pi,
                                              Error **errp)
{
    info_report("%s: mi %p, domain "UUID_FMT, __func__, mi, UUID_ARG(&pi->uuid));

    qemu_mutex_lock(&mi->intro_lock);

    proc_introspection_shutdown(pi);

    if (pi->introspected) {
        /* mem_introspection_end() is yet to arrive */
    }
    else {
        g_hash_table_remove(mi->ready, &pi->uuid);
        object_unparent(OBJECT(pi));
    }

    qemu_mutex_unlock(&mi->intro_lock);

    info_report("%s: -", __func__);
}

static int mem_introspection_reset_helper(Object *child, void *opaque)
{
    ProcIntrospectionState *pi = PROC_INTROSPECTION(child);

    device_reset(DEVICE(pi));

    return 0;
}

static gboolean mem_introspection_reset_ghr(gpointer key, gpointer value, gpointer user_data)
{
    ProcIntrospectionState *pi = (ProcIntrospectionState *)value;

    object_unparent(OBJECT(pi));

    return TRUE;
}

// entry point - reset handler
static void mem_introspection_reset(void *opaque)
{
    MemIntrospectionState *mi = MEM_INTROSPECTION(opaque);

    info_report("%s: mi %p", __func__, mi);

    qemu_mutex_lock(&mi->intro_lock);

    /* this will trigger the @pi to unplug its DIMMs */
    object_child_foreach(OBJECT(mi), mem_introspection_reset_helper, NULL);

    /*
     * every @pi child is either ready or introspected
     * remove (unparent) @pis by looking up the hast tables
     * at the same time remove them from the hash tables
     */
    g_hash_table_foreach_remove(mi->ready, mem_introspection_reset_ghr, NULL);
    g_hash_table_foreach_remove(mi->introspected, mem_introspection_reset_ghr, NULL);

    qemu_mutex_unlock(&mi->intro_lock);

    info_report("%s: -", __func__);
}

// hash helpers
static guint qemu_uuid_hash_func(gconstpointer key)
{
    // TODO: for now return the first bytes comprising an int
    return *(guint *)key;
    // TODO: use a real hash function if there is one
}

static gboolean qemu_uuid_equal_func(gconstpointer keya, gconstpointer keyb)
{
    if (!memcmp(keya, keyb, sizeof(QemuUUID)))
        return TRUE;

    return FALSE;
}

static void qemu_uuid_key_destroy(gpointer key)
{
    g_free(key);
}

// constructor
static void mem_introspection_instance_init(Object *obj)
{
    MemIntrospectionState *mi = MEM_INTROSPECTION(obj);

    info_report("%s: mi %p", __func__, mi);

    qemu_mutex_init(&mi->intro_lock);

    mi->ready = g_hash_table_new_full(qemu_uuid_hash_func,
        qemu_uuid_equal_func, qemu_uuid_key_destroy, NULL);
    mi->introspected = g_hash_table_new_full(qemu_uuid_hash_func,
        qemu_uuid_equal_func, qemu_uuid_key_destroy, NULL);
    mi->gpaHash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

// destructor
static void mem_introspection_instance_finalize(Object *obj)
{
    MemIntrospectionState *mi = MEM_INTROSPECTION(obj);

    info_report("%s: mi %p", __func__, mi);

    qemu_chr_fe_deinit(&mi->chr, true);
    qemu_unregister_reset(mem_introspection_reset, mi);

    qemu_mutex_destroy(&mi->intro_lock);

    g_hash_table_destroy(mi->ready);
    g_hash_table_destroy(mi->introspected);
    g_hash_table_destroy(mi->gpaHash);

    g_free(mi->chardev);
}

static int mem_chardev_can_read(void *opaque)
{
    return (int) sizeof(MemIntrospectionPkt);
}

static void mem_chardev_read(void *opaque, const uint8_t *buf, int size)
{
    MemIntrospectionState *mi = opaque;
    MemIntrospectionPkt *data = (MemIntrospectionPkt *) buf;
    Error *local_err = NULL;
    gboolean ack = TRUE;
    int fds[2];
    int result;

    assert(size == sizeof(MemIntrospectionPkt));

    result = qemu_chr_fe_get_msgfds(&mi->chr, fds, 2);
    if (result == -1) {
        error_setg(&local_err, "%s: failed receiving fds", __func__);
        goto out;
    }

    //info_report("%s: got fd %d from machine "UUID_FMT, __func__, fd, UUID_ARG(&data->dom_id));

    mem_introspection_domain_ready(mi, &data->dom_id, fds, &local_err);

out:
    if (local_err) {
        warn_report_err(local_err);
        ack = FALSE;
    }

    qemu_chr_fe_write(&mi->chr, (const uint8_t *)&ack, (int)sizeof(ack));
}

static void mem_introspection_machine_ready(Notifier *notifier, void *data)
{
    MemIntrospectionState *mi = container_of(notifier, MemIntrospectionState, machine_ready);
    Error *local_err = NULL;
    Chardev *chr;

    info_report("%s: mi %p", __func__, mi);

    // chardevs are added later to tree - WHY ?
    chr = qemu_chr_find(mi->chardev);
    if (!chr) {
        error_setg(&local_err, "Chardev '%s' not found", mi->chardev);
        goto out;
    }

    // init chardev front-end
    if (!qemu_chr_fe_init(&mi->chr, chr, &local_err)) {
        // errp already filled by qemu_chr_fe_init()
        goto out;
    }

    qemu_chr_fe_set_handlers(&mi->chr, mem_chardev_can_read, mem_chardev_read,
                             NULL, NULL, mi, NULL, true);

out:
    if (local_err)
        warn_report_err(local_err);
}

// user creatable
static void mem_introspection_complete(UserCreatable *uc, Error **errp)
{
    MemIntrospectionState *mi = MEM_INTROSPECTION(uc);

    info_report("%s: mi %p", __func__, mi);

    if (!mi->chardev) {
        error_setg(errp, "Chardev ID needed for receiving memory info");
        return;
    }

    // chardevs are added later to tree
    mi->machine_ready.notify = mem_introspection_machine_ready;
    qemu_add_machine_init_done_notifier(&mi->machine_ready);

    qemu_register_reset(mem_introspection_reset, mi);
}

// user creatable
static bool mem_introspection_can_be_deleted(UserCreatable *uc)
{
    MemIntrospectionState *mi = MEM_INTROSPECTION(uc);
    bool can;

    info_report("%s: mi %p", __func__, mi);

    qemu_mutex_lock(&mi->intro_lock);
    can = g_hash_table_size(mi->introspected) != 0;
    qemu_mutex_unlock(&mi->intro_lock);

    if (!can)
        warn_report("%s: nope, introspection sessions are running", __func__);

    return can;
}

static char *mem_introspection_get_chardev(Object *obj, Error **errp)
{
    MemIntrospectionState *mp = MEM_INTROSPECTION(obj);

    return g_strdup(mp->chardev);
}

static void mem_introspection_set_chardev(Object *obj, const char *str, Error **errp)
{
    MemIntrospectionState *mp = MEM_INTROSPECTION(obj);

    g_free(mp->chardev);
    mp->chardev = g_strdup(str);
}

static void mem_introspection_class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *uc = USER_CREATABLE_CLASS(oc);

    object_class_property_add_str(oc, "chardev",
        mem_introspection_get_chardev,
        mem_introspection_set_chardev,
        &error_abort);
    object_class_property_set_description(oc, "chardev",
        "A backend used to communicate memory metadata",
        &error_abort);

    uc->can_be_deleted = mem_introspection_can_be_deleted;
    uc->complete = mem_introspection_complete;
}

static const TypeInfo mem_introspection_info = {
    .name = TYPE_MEM_INTROSPECTION,
    .parent = TYPE_OBJECT,

    .instance_size = sizeof(MemIntrospectionState),
    .instance_init = mem_introspection_instance_init,
    .instance_finalize = mem_introspection_instance_finalize,

    .class_init = mem_introspection_class_init,
    .interfaces = (InterfaceInfo[]) {
        {TYPE_USER_CREATABLE},
        {}
    }
};

static void mem_introspection_register_types(void)
{
    type_register_static(&proc_introspection_info);
    type_register_static(&mem_introspection_info);
}

type_init(mem_introspection_register_types)
