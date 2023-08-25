/*
 * VM Introspection
 *
 * Copyright (C) 2017-2020 Bitdefender S.R.L.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qemu/error-report.h"
#include "qom/object_interfaces.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "sysemu/kvm.h"
#include "crypto/secret.h"
#include "crypto/hash.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "migration/vmstate.h"
#include "migration/misc.h"
#include "qapi/qmp/qobject.h"
#include "monitor/monitor.h"
#include "exec/address-spaces.h"
#include "qemu/units.h"

#include "sysemu/vmi-intercept.h"
#include "sysemu/vmi-handshake.h"
#include "mem-introspection.h"

#define HANDSHAKE_TIMEOUT_SEC 10
#define UNHOOK_TIMEOUT_SEC 60

typedef struct VMIntrospection {
    Object parent_obj;

    Error *init_error;

    char *chardevid;
    Chardev *chr;
    CharBackend sock;
    bool connected;

    char *memsrc_chardevid;
    MemSourceState *memSource;

    char *memintro_chardevid;
    MemIntrospectionState *memIntro;

    char *keyid;
    Object *key;
    uint8_t cookie_hash[QEMU_VMI_COOKIE_HASH_SIZE];
    bool key_with_cookie;

    qemu_vmi_from_introspector hsk_in;
    uint64_t hsk_in_read_pos;
    uint64_t hsk_in_read_size;
    GSource *hsk_timer;
    uint32_t handshake_timeout;

    int intercepted_action;
    GSource *unhook_timer;
    uint32_t unhook_timeout;
    bool async_unhook;

    int reconnect_time;

    int64_t vm_start_time;

    Notifier machine_ready;
    Notifier migration_state_change;
    Notifier shutdown;
    bool created_from_command_line;

    void *qmp_monitor;
    QDict *qmp_rsp;

    bool kvmi_hooked;

    GArray *allowed_commands;
    GArray *allowed_events;

    GHashTable *alloc_gfns;
    QemuThread *alloc_thread;
} VMIntrospection;

typedef struct VMIntrospectionClass {
    ObjectClass parent_class;
    uint32_t instance_counter;
    VMIntrospection *uniq;
} VMIntrospectionClass;

static const char *action_string[] = {
    "none",
    "suspend",
    "resume",
};

static bool suspend_pending;

static __s32 all_IDs = -1;

#define TYPE_VM_INTROSPECTION "introspection"

#define VM_INTROSPECTION(obj) \
    OBJECT_CHECK(VMIntrospection, (obj), TYPE_VM_INTROSPECTION)
#define VM_INTROSPECTION_CLASS(class) \
    OBJECT_CLASS_CHECK(VMIntrospectionClass, (class), TYPE_VM_INTROSPECTION)

static Error *vm_introspection_init(VMIntrospection *i);
static void disconnect_and_unhook_kvmi(VMIntrospection *i);
static bool vmi_maybe_wait_for_unhook(VMIntrospection *i,
                                      VMI_intercept_command action);

static bool vmi_unhook_pending(void *opaque)
{
    VMIntrospection *i = opaque;
    bool pending;

    qemu_mutex_lock_iothread();
    pending = i->connected;
    qemu_mutex_unlock_iothread();

    return pending;
}

static void migration_state_notifier(Notifier *notifier, void *data)
{
    MigrationState *s = data;
    VMIntrospection *i;

    if (migration_in_setup(s)) {
        qemu_mutex_lock_iothread();

        i = container_of(notifier, VMIntrospection, migration_state_change);

        if (i->connected && i->intercepted_action == VMI_INTERCEPT_NONE) {
            vmi_maybe_wait_for_unhook(i, VMI_INTERCEPT_MIGRATE);
        }

        qemu_mutex_unlock_iothread();
    }
}

static void vmi_machine_ready(Notifier *notifier, void *data)
{
    VMIntrospection *i = container_of(notifier, VMIntrospection, machine_ready);

    i->init_error = vm_introspection_init(i);
    if (i->init_error) {
        Error *err = error_copy(i->init_error);

        error_report_err(err);
        if (i->created_from_command_line) {
            exit(1);
        }
    }
}

static void vmi_shutdown_notify(Notifier *notifier, void *data)
{
    VMIntrospection *i = container_of(notifier, VMIntrospection, shutdown);

    disconnect_and_unhook_kvmi(i);
}

static void update_vm_start_time(VMIntrospection *i)
{
    i->vm_start_time = qemu_clock_get_ms(QEMU_CLOCK_HOST) / 1000;
}

static void vmi_reset(void *opaque)
{
    VMIntrospection *i = opaque;

    if (i->connected) {
        info_report("VMI: Reset, closing the socket...");
    }

    disconnect_and_unhook_kvmi(i);

    update_vm_start_time(i);
}

static const VMStateDescription vmstate_introspection = {
    .name = "vm_introspection",
    .minimum_version_id = 1,
    .version_id = 1,
    .dev_unplug_pending = vmi_unhook_pending,
    .fields = (VMStateField[]) {
        VMSTATE_INT64(vm_start_time, VMIntrospection),
        VMSTATE_END_OF_LIST()
    }
};

static void init_mem_introspection(VMIntrospection *i, Error **errp)
{
    Object *obj;

    if (i->memsrc_chardevid && i->memintro_chardevid) {
        error_setg(errp, "VMI: can't have both mem source & introspection");
        return;
    }

    if (i->memsrc_chardevid) {
        obj = object_new(TYPE_MEM_SOURCE);
        object_property_set_str(obj, i->memsrc_chardevid, "chardev", errp);
        object_property_add_child(OBJECT(i), "mem-source", obj, errp);
        user_creatable_complete(USER_CREATABLE(obj), errp);
        i->memSource = MEM_SOURCE(obj);
        object_unref(obj);
    }

    if (i->memintro_chardevid) {
        obj = object_new(TYPE_MEM_INTROSPECTION);
        object_property_set_str(obj, i->memintro_chardevid, "chardev", errp);
        object_property_add_child(OBJECT(i), "mem-introspection", obj, errp);
        user_creatable_complete(USER_CREATABLE(obj), errp);
        i->memIntro = MEM_INTROSPECTION(obj);
        object_unref(obj);
    }
}

static void vmi_complete(UserCreatable *uc, Error **errp)
{
    VMIntrospectionClass *ic = VM_INTROSPECTION_CLASS(OBJECT(uc)->class);
    VMIntrospection *i = VM_INTROSPECTION(uc);

    if (ic->instance_counter > 1) {
        error_setg(errp, "VMI: only one introspection object can be created");
        return;
    }

    if (!i->chardevid) {
        error_setg(errp, "VMI: chardev is not set");
        return;
    }

    i->machine_ready.notify = vmi_machine_ready;
    qemu_add_machine_init_done_notifier(&i->machine_ready);

    init_mem_introspection(i, errp);
    if (*errp) {
        /* errp was filled inside init_mem_introspection() */
        return;
    }

    /*
     * If the introspection object is created while parsing the command line,
     * the machine_ready callback will be called later. At that time,
     * it vm_introspection_init() fails, exit() will be called.
     *
     * If the introspection object is created through QMP, machine_init_done
     * is already set and qemu_add_machine_init_done_notifier() will
     * call our machine_done() callback. If vm_introspection_init() fails,
     * we don't call exit() and report the error back to the user.
     */
    if (i->init_error) {
        *errp = i->init_error;
        i->init_error = NULL;
        return;
    }

    ic->uniq = i;

    update_vm_start_time(i);

    vmstate_register(NULL, 0, &vmstate_introspection, i);

    i->migration_state_change.notify = migration_state_notifier;
    add_migration_state_change_notifier(&i->migration_state_change);

    i->shutdown.notify = vmi_shutdown_notify;
    qemu_register_shutdown_notifier(&i->shutdown);

    qemu_register_reset(vmi_reset, i);
}

static void prop_set_memsrc(Object *obj, const char *value, Error **errp)
{
    VMIntrospection *i = VM_INTROSPECTION(obj);

    g_free(i->memsrc_chardevid);
    i->memsrc_chardevid = g_strdup(value);
}

static void prop_set_memintro(Object *obj, const char *value, Error **errp)
{
    VMIntrospection *i = VM_INTROSPECTION(obj);

    g_free(i->memintro_chardevid);
    i->memintro_chardevid = g_strdup(value);
}

static void prop_set_chardev(Object *obj, const char *value, Error **errp)
{
    VMIntrospection *i = VM_INTROSPECTION(obj);

    g_free(i->chardevid);
    i->chardevid = g_strdup(value);
}

static void prop_set_key(Object *obj, const char *value, Error **errp)
{
    VMIntrospection *i = VM_INTROSPECTION(obj);

    g_free(i->keyid);
    i->keyid = g_strdup(value);
}

static bool prop_get_async_unhook(Object *obj, Error **errp)
{
    VMIntrospection *i = VM_INTROSPECTION(obj);

    return i->async_unhook;
}

static void prop_set_async_unhook(Object *obj, bool value, Error **errp)
{
    VMIntrospection *i = VM_INTROSPECTION(obj);

    i->async_unhook = value;
}

static void prop_get_uint32(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    uint32_t *value = opaque;

    visit_type_uint32(v, name, value, errp);
}

static void prop_set_uint32(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    uint32_t *value = opaque;
    Error *local_err = NULL;

    visit_type_uint32(v, name, value, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
    }
}

static void prop_add_to_array(Object *obj, Visitor *v,
                              const char *name, void *opaque,
                              Error **errp)
{
    Error *local_err = NULL;
    GArray *arr = opaque;
    uint32_t value;

    visit_type_uint32(v, name, &value, &local_err);
    if (!local_err && value == (uint32_t)all_IDs) {
        error_setg(&local_err, "VMI: add %s: invalid id %d", name, value);
    }
    if (local_err) {
        error_propagate(errp, local_err);
    } else {
        g_array_append_val(arr, value);
    }
}

static bool vmi_can_be_deleted(UserCreatable *uc)
{
    VMIntrospection *i = VM_INTROSPECTION(uc);

    return !i->connected;
}

static void gfn_free(gpointer value)
{
    MemoryRegion *ram = value;
    memory_region_del_subregion(get_system_memory(), ram);

    object_unparent(OBJECT(ram));
}

static void class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *uc = USER_CREATABLE_CLASS(oc);

    uc->complete = vmi_complete;
    uc->can_be_deleted = vmi_can_be_deleted;
}

static void instance_init(Object *obj)
{
    VMIntrospectionClass *ic = VM_INTROSPECTION_CLASS(obj->class);
    VMIntrospection *i = VM_INTROSPECTION(obj);

    ic->instance_counter++;

    i->created_from_command_line = (qdev_hotplug == false);

    object_property_add_str(obj, "chardev-memsrc", NULL, prop_set_memsrc, NULL);
    object_property_add_str(obj, "chardev-memintro", NULL, prop_set_memintro,
                            NULL);
    object_property_add_str(obj, "chardev", NULL, prop_set_chardev, NULL);
    object_property_add_str(obj, "key", NULL, prop_set_key, NULL);

    i->allowed_commands = g_array_new(FALSE, FALSE, sizeof(uint32_t));
    object_property_add(obj, "command", "uint32",
                        prop_add_to_array, NULL,
                        NULL, i->allowed_commands, NULL);
    i->allowed_events = g_array_new(FALSE, FALSE, sizeof(uint32_t));
    object_property_add(obj, "event", "uint32",
                        prop_add_to_array, NULL,
                        NULL, i->allowed_events, NULL);

    i->handshake_timeout = HANDSHAKE_TIMEOUT_SEC;
    object_property_add(obj, "handshake_timeout", "uint32",
                        prop_set_uint32, prop_get_uint32,
                        NULL, &i->handshake_timeout, NULL);

    i->unhook_timeout = UNHOOK_TIMEOUT_SEC;
    object_property_add(obj, "unhook_timeout", "uint32",
                        prop_set_uint32, prop_get_uint32,
                        NULL, &i->unhook_timeout, NULL);

    i->async_unhook = true;
    object_property_add_bool(obj, "async_unhook",
                             prop_get_async_unhook,
                             prop_set_async_unhook, NULL);

    i->alloc_gfns = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, gfn_free);
}

static void disconnect_memsource(VMIntrospection *i)
{
    if (i->memSource) {
        mem_source_disconnect(i->memSource);
    }
}

static void disconnect_chardev(VMIntrospection *i)
{
    if (i->connected) {
        qemu_chr_fe_disconnect(&i->sock);
    }
}

static void unhook_kvmi(VMIntrospection *i)
{
    if (i->kvmi_hooked) {
        if (kvm_vm_ioctl(kvm_state, KVM_INTROSPECTION_UNHOOK, NULL)) {
            error_report("VMI: ioctl/KVM_INTROSPECTION_UNHOOK failed, errno %d",
                         errno);
        }
        i->kvmi_hooked = false;
    }
}

static void disconnect_and_unhook_kvmi(VMIntrospection *i)
{
    disconnect_chardev(i);
    disconnect_memsource(i);
    unhook_kvmi(i);
}

static void cancel_timer(GSource *timer)
{
    if (timer) {
        g_source_destroy(timer);
        g_source_unref(timer);
    }
}

static void cancel_handshake_timer(VMIntrospection *i)
{
    cancel_timer(i->hsk_timer);
    i->hsk_timer = NULL;
}

static void cancel_unhook_timer(VMIntrospection *i)
{
    cancel_timer(i->unhook_timer);
    i->unhook_timer = NULL;
}

static void instance_finalize(Object *obj)
{
    VMIntrospectionClass *ic = VM_INTROSPECTION_CLASS(obj->class);
    VMIntrospection *i = VM_INTROSPECTION(obj);

    if (i->allowed_commands) {
        g_array_free(i->allowed_commands, TRUE);
    }
    if (i->allowed_events) {
        g_array_free(i->allowed_events, TRUE);
    }

    if (i->alloc_gfns) {
        g_hash_table_destroy(i->alloc_gfns);
    }

    g_free(i->memintro_chardevid);
    g_free(i->memsrc_chardevid);
    g_free(i->chardevid);
    g_free(i->keyid);

    cancel_unhook_timer(i);
    cancel_handshake_timer(i);

    if (i->chr) {
        qemu_chr_fe_deinit(&i->sock, true);
    }

    error_free(i->init_error);

    qobject_unref(i->qmp_rsp);

    ic->instance_counter--;
    if (!ic->instance_counter) {
        ic->uniq = NULL;
    }

    qemu_unregister_reset(vmi_reset, i);
}

static const TypeInfo info = {
    .name              = TYPE_VM_INTROSPECTION,
    .parent            = TYPE_OBJECT,
    .class_init        = class_init,
    .class_size        = sizeof(VMIntrospectionClass),
    .instance_size     = sizeof(VMIntrospection),
    .instance_finalize = instance_finalize,
    .instance_init     = instance_init,
    .interfaces        = (InterfaceInfo[]){
        {TYPE_USER_CREATABLE},
        {}
    }
};

static void register_types(void)
{
    type_register_static(&info);
}

type_init(register_types);

static bool send_handshake_info(VMIntrospection *i, Error **errp)
{
    qemu_vmi_to_introspector send = {};
    const char *vm_name;
    int r;

    send.struct_size = sizeof(send);
    send.start_time = i->vm_start_time;
    memcpy(&send.uuid, &qemu_uuid, sizeof(send.uuid));
    vm_name = qemu_get_vm_name();
    if (vm_name) {
        snprintf(send.name, sizeof(send.name), "%s", vm_name);
        send.name[sizeof(send.name) - 1] = 0;
    }

    r = qemu_chr_fe_write_all(&i->sock, (uint8_t *)&send, sizeof(send));
    if (r != sizeof(send)) {
        error_setg_errno(errp, errno, "VMI: error writing to '%s'",
                         i->chardevid);
        return false;
    }

    /* tcp_chr_write may call tcp_chr_disconnect/CHR_EVENT_CLOSED */
    if (!i->connected) {
        error_setg(errp, "VMI: qemu_chr_fe_write_all() failed");
        return false;
    }

    return true;
}

static bool validate_handshake_cookie(VMIntrospection *i)
{
    if (!i->key_with_cookie) {
        return true;
    }

    return 0 == memcmp(&i->cookie_hash, &i->hsk_in.cookie_hash,
                       sizeof(i->cookie_hash));
}

static bool validate_handshake(VMIntrospection *i, Error **errp)
{
    uint32_t min_accepted_size;

    min_accepted_size = offsetof(qemu_vmi_from_introspector, cookie_hash)
                        + QEMU_VMI_COOKIE_HASH_SIZE;

    if (i->hsk_in.struct_size < min_accepted_size) {
        error_setg(errp, "VMI: not enough or invalid handshake data");
        return false;
    }

    if (!validate_handshake_cookie(i)) {
        error_setg(errp, "VMI: received cookie doesn't match");
        return false;
    }

    /*
     * Check hsk_in.struct_size and sizeof(hsk_in) before accessing any
     * other fields. We might get fewer bytes from applications using
     * old versions if we extended the qemu_vmi_from_introspector structure.
     */

    return true;
}

static bool set_allowed_features(int ioctl, GArray *allowed, Error **errp)
{
    struct kvm_introspection_feature feature;
    gint i;

    feature.allow = 1;

    if (allowed->len == 0) {
        feature.id = all_IDs;
        if (kvm_vm_ioctl(kvm_state, ioctl, &feature)) {
            goto out_err;
        }
    } else {
        for (i = 0; i < allowed->len; i++) {
            feature.id = g_array_index(allowed, uint32_t, i);
            if (kvm_vm_ioctl(kvm_state, ioctl, &feature)) {
                goto out_err;
            }
        }
    }

    return true;

out_err:
    error_setg_errno(errp, errno,
                     "VMI: feature %d with id %d failed",
                     ioctl, feature.id);
    return false;
}

static gboolean vm_introspection_alloc_gfn(uint64_t gfn);
static gboolean vm_introspection_free_gfn(uint64_t gfn);

static void* wait_alloc_free_gfn(void *unused)
{
    struct kvm_introspection_gfn gfn = { .ret = -1 };
    int r;

    rcu_register_thread();

    do {
        gfn.gfn = 0;
        r = kvm_vcpu_ioctl(first_cpu, KVM_INTROSPECTION_GFN, &gfn);
        switch (r) {
        case KVM_INTROSPECTION_GFN_REPLY_ALLOC:
            gfn.ret = !vm_introspection_alloc_gfn(gfn.gfn);
            break;
        case KVM_INTROSPECTION_GFN_REPLY_FREE:
            gfn.ret = !vm_introspection_free_gfn(gfn.gfn);
            break;
        }
    } while (r >= KVM_INTROSPECTION_GFN_REPLY_WAIT);

    rcu_unregister_thread();
    return NULL;
}

static bool connect_kernel(VMIntrospection *i, Error **errp)
{
    struct kvm_introspection_hook kernel;

    memset(&kernel, 0, sizeof(kernel));
    memcpy(kernel.uuid, &qemu_uuid, sizeof(kernel.uuid));
    kernel.fd = object_property_get_int(OBJECT(i->chr), "fd", NULL);

    if (kvm_vm_ioctl(kvm_state, KVM_INTROSPECTION_HOOK, &kernel)) {
        error_setg_errno(errp, errno,
                         "VMI: ioctl/KVM_INTROSPECTION_HOOK failed");
        if (errno == EPERM) {
            error_append_hint(errp,
                              "Reload the kvm module with kvm.introspection=on\n");
        }

        return false;
    }

    if (!set_allowed_features(KVM_INTROSPECTION_COMMAND,
                              i->allowed_commands, errp)) {
        goto error;
    }

    if (!set_allowed_features(KVM_INTROSPECTION_EVENT,
                              i->allowed_events, errp)) {
        goto error;
    }

    i->alloc_thread = g_malloc0(sizeof(QemuThread));
    qemu_thread_create(i->alloc_thread, i->chardevid, wait_alloc_free_gfn, NULL, QEMU_THREAD_JOINABLE);

    info_report("VMI: machine hooked");
    i->kvmi_hooked = true;

    return true;

error:
    if (kvm_vm_ioctl(kvm_state, KVM_INTROSPECTION_UNHOOK, NULL)) {
        error_setg_errno(errp, errno,
                         "VMI: ioctl/KVM_INTROSPECTION_UNHOOK failed");
    }

    return false;
}

static void enable_socket_reconnect(VMIntrospection *i)
{
    if (i->reconnect_time) {
        info_report("VMI: re-enable socket reconnect");
        qemu_chr_fe_reconnect_time(&i->sock, i->reconnect_time);
        qemu_chr_fe_disconnect(&i->sock);
        i->reconnect_time = 0;
    }
}

static void maybe_disable_socket_reconnect(VMIntrospection *i)
{
    if (i->reconnect_time == 0) {
        info_report("VMI: disable socket reconnect");
        i->reconnect_time = qemu_chr_fe_reconnect_time(&i->sock, 0);
    }
}

static void continue_with_the_intercepted_action(VMIntrospection *i)
{
    switch (i->intercepted_action) {
    case VMI_INTERCEPT_SUSPEND:
        vm_stop(RUN_STATE_PAUSED);
        break;
    case VMI_INTERCEPT_MIGRATE:
        break;
    default:
        error_report("VMI: %s: unexpected action %d",
                     __func__, i->intercepted_action);
        break;
    }

    info_report("VMI: continue with '%s'",
                action_string[i->intercepted_action]);

    if (i->qmp_rsp) {
        monitor_qmp_respond_later(i->qmp_monitor, i->qmp_rsp);
        i->qmp_monitor = NULL;
        i->qmp_rsp = NULL;
    }
}

/*
 * We should read only the handshake structure,
 * which might have a different size than what we expect.
 */
static int vmi_chr_can_read(void *opaque)
{
    VMIntrospection *i = opaque;

    if (i->hsk_timer == NULL || !i->connected) {
        return 0;
    }

    /* first, we read the incoming structure size */
    if (i->hsk_in_read_pos == 0) {
        return sizeof(i->hsk_in.struct_size);
    }

    /* validate the incoming structure size */
    if (i->hsk_in.struct_size < sizeof(i->hsk_in.struct_size)) {
        return 0;
    }

    /* read the rest of the incoming structure */
    return i->hsk_in.struct_size - i->hsk_in_read_pos;
}

static bool enough_bytes_for_handshake(VMIntrospection *i)
{
    return i->hsk_in_read_pos  >= sizeof(i->hsk_in.struct_size)
        && i->hsk_in_read_size == i->hsk_in.struct_size;
}

static bool validate_and_connect(VMIntrospection *i, Error **errp)
{
    if (!validate_handshake(i, errp)) {
        return false;
    }

    if (!connect_kernel(i, errp)) {
        return false;
    }

    return true;
}

static void vmi_chr_read(void *opaque, const uint8_t *buf, int size)
{
    VMIntrospection *i = opaque;
    size_t to_read;

    i->hsk_in_read_size += size;

    to_read = sizeof(i->hsk_in) - i->hsk_in_read_pos;
    if (to_read > size) {
        to_read = size;
    }

    if (to_read) {
        memcpy((uint8_t *)&i->hsk_in + i->hsk_in_read_pos, buf, to_read);
        i->hsk_in_read_pos += to_read;
    }

    if (enough_bytes_for_handshake(i)) {
        Error *local_err = NULL;

        cancel_handshake_timer(i);

        if (!validate_and_connect(i, &local_err)) {
            error_append_hint(&local_err, "reconnecting\n");
            warn_report_err(local_err);
            qemu_chr_fe_disconnect(&i->sock);
        }
    }
}

static gboolean vmi_hsk_timeout(gpointer opaque)
{
    VMIntrospection *i = opaque;

    warn_report("VMI: the handshake takes too long");
    disconnect_and_unhook_kvmi(i);

    g_source_unref(i->hsk_timer);
    i->hsk_timer = NULL;
    return G_SOURCE_REMOVE;
}

static void vmi_start_handshake(void *opaque)
{
    VMIntrospection *i = opaque;
    Error *local_err = NULL;

    if (!send_handshake_info(i, &local_err)) {
        error_append_hint(&local_err, "reconnecting\n");
        warn_report_err(local_err);
        qemu_chr_fe_disconnect(&i->sock);
        return;
    }

    info_report("VMI: handshake started");
}

/*
 * We have two sockets: one for introspection and one for remote mapping.
 * These might be connected to two different "processes".
 *
 * We have to wait until the first socket is connected (the introspection
 * tool is started), connect the remote mapping socket, wait for its
 * handshake and then do the hanshake for the introspection socket.
 *
 * Both handshakes are event-based and running on the main loop:
 *   - trigger the connection
 *   - send the data when the socket is connected
 *   - finish the handshake when enough data is available to be read
 *     from the socket.
 */
static void vmi_chr_event_open(VMIntrospection *i)
{
    i->connected = true;

    if (suspend_pending || !migration_is_idle()) {
        info_report("VMI: %s: too soon (suspend=%d, migrate=%d)",
                    __func__, suspend_pending, !migration_is_idle());
        maybe_disable_socket_reconnect(i);
        qemu_chr_fe_disconnect(&i->sock);
        return;
    }

    memset(&i->hsk_in, 0, sizeof(i->hsk_in));
    i->hsk_in_read_pos = 0;
    i->hsk_in_read_size = 0;

    i->hsk_timer = qemu_chr_timeout_add_ms(i->chr,
                                           i->handshake_timeout * 1000,
                                           vmi_hsk_timeout, i);

    if (i->memSource) {
        info_report("VMI: connect memory source first");
        mem_source_connect(i->memSource, vmi_start_handshake, i);
    } else {
        vmi_start_handshake(i);
    }
}

static void vmi_chr_event_closed(VMIntrospection *i)
{
    i->connected = false;

    if (i->kvmi_hooked) {
        warn_report("VMI: introspection tool disconnected");
        disconnect_and_unhook_kvmi(i);
    }

    cancel_unhook_timer(i);
    cancel_handshake_timer(i);

    if (suspend_pending || !migration_is_idle()) {
        maybe_disable_socket_reconnect(i);

        if (i->intercepted_action != VMI_INTERCEPT_NONE) {
            continue_with_the_intercepted_action(i);
            i->intercepted_action = VMI_INTERCEPT_NONE;
        }
    }
}

static void vmi_chr_event(void *opaque, int event)
{
    VMIntrospection *i = opaque;

    switch (event) {
    case CHR_EVENT_OPENED:
        vmi_chr_event_open(i);
        break;
    case CHR_EVENT_CLOSED:
        vmi_chr_event_closed(i);
        break;
    default:
        break;
    }
}

static gboolean unhook_timeout_cbk(gpointer opaque)
{
    VMIntrospection *i = opaque;

    warn_report("VMI: the introspection tool is too slow");
    disconnect_and_unhook_kvmi(i);

    g_source_unref(i->unhook_timer);
    i->unhook_timer = NULL;
    return G_SOURCE_REMOVE;
}

static VMIntrospection *vm_introspection_object(void)
{
    VMIntrospectionClass *ic;

    ic = VM_INTROSPECTION_CLASS(object_class_by_name(TYPE_VM_INTROSPECTION));

    return ic ? ic->uniq : NULL;
}

bool vm_introspection_qmp_delay(void *mon, QDict *rsp)
{
    VMIntrospection *i = vm_introspection_object();
    bool intercepted;

    intercepted = i && i->intercepted_action == VMI_INTERCEPT_SUSPEND;

    if (intercepted) {
        i->qmp_monitor = mon;
        i->qmp_rsp = rsp;
    }

    return intercepted;
}

/*
 * This ioctl succeeds only when KVM signals the introspection tool.
 * (the socket is connected and the event was sent without error).
 */
static bool signal_introspection_tool_to_unhook(VMIntrospection *i)
{
    int err;

    err = kvm_vm_ioctl(kvm_state, KVM_INTROSPECTION_PREUNHOOK, NULL);

    return !err;
}

static bool record_intercept_action(VMI_intercept_command action)
{
    switch (action) {
    case VMI_INTERCEPT_SUSPEND:
        suspend_pending = true;
        break;
    case VMI_INTERCEPT_RESUME:
        suspend_pending = false;
        break;
    default:
        return false;
    }

    return true;
}

static void wait_until_the_socket_is_closed(VMIntrospection *i)
{
    info_report("VMI: start waiting until socket is closed");

    while (i->connected) {
        main_loop_wait(false);
    }

    info_report("VMI: continue with the intercepted action");

    maybe_disable_socket_reconnect(i);
}

static bool vmi_maybe_wait_for_unhook(VMIntrospection *i,
                                      VMI_intercept_command action)
{
    if (!signal_introspection_tool_to_unhook(i)) {
        disconnect_and_unhook_kvmi(i);
        return false;
    }

    i->unhook_timer = qemu_chr_timeout_add_ms(i->chr,
                                              i->unhook_timeout * 1000,
                                              unhook_timeout_cbk, i);

    if (!i->async_unhook) {
        wait_until_the_socket_is_closed(i);
        return false;
    }

    i->intercepted_action = action;
    return true;
}

static bool intercept_action(VMIntrospection *i,
                             VMI_intercept_command action, Error **errp)
{
    if (i->intercepted_action != VMI_INTERCEPT_NONE) {
        error_report("VMI: unhook in progress");
        return false;
    }

    switch (action) {
    case VMI_INTERCEPT_RESUME:
        enable_socket_reconnect(i);
        return false;
    default:
        break;
    }

    return vmi_maybe_wait_for_unhook(i, action);
}

bool vm_introspection_intercept(VMI_intercept_command action, Error **errp)
{
    VMIntrospection *i = vm_introspection_object();
    bool intercepted = false;

    if (record_intercept_action(action) && i) {
        info_report("VMI: intercept command: %s", action_string[action]);

        intercepted = intercept_action(i, action, errp);

        info_report("VMI: intercept action: %s",
                    intercepted ? "delayed" : "continue");
    }

    return intercepted;
}

static bool make_cookie_hash(const char *key_id, uint8_t *cookie_hash,
                             Error **errp)
{
    uint8_t *cookie = NULL, *hash = NULL;
    size_t cookie_size, hash_size = 0;
    bool done = false;

    if (qcrypto_secret_lookup(key_id, &cookie, &cookie_size, errp) == 0
            && qcrypto_hash_bytes(QCRYPTO_HASH_ALG_SHA1,
                                  (const char *)cookie, cookie_size,
                                  &hash, &hash_size, errp) == 0) {
        if (hash_size == QEMU_VMI_COOKIE_HASH_SIZE) {
            memcpy(cookie_hash, hash, QEMU_VMI_COOKIE_HASH_SIZE);
            done = true;
        } else {
            error_setg(errp, "VMI: hash algorithm size mismatch");
        }
    }

    g_free(cookie);
    g_free(hash);

    return done;
}

static Error *vm_introspection_init(VMIntrospection *i)
{
    Error *err = NULL;
    int kvmi_version;
    Chardev *chr;

    if (!kvm_enabled()) {
        error_setg(&err, "VMI: missing KVM support");
        return err;
    }

    kvmi_version = kvm_check_extension(kvm_state, KVM_CAP_INTROSPECTION);
    if (kvmi_version == 0) {
        error_setg(&err,
                   "VMI: missing kernel built with CONFIG_KVM_INTROSPECTION");
        return err;
    }

    if (i->keyid) {
        if (!make_cookie_hash(i->keyid, i->cookie_hash, &err)) {
            return err;
        }
        i->key_with_cookie = true;
    } else {
        warn_report("VMI: the introspection tool won't be 'authenticated'");
    }

    chr = qemu_chr_find(i->chardevid);
    if (!chr) {
        error_setg(&err, "VMI: device '%s' not found", i->chardevid);
        return err;
    }

    if (!qemu_chr_fe_init(&i->sock, chr, &err)) {
        error_append_hint(&err, "VMI: device '%s' not initialized\n",
                          i->chardevid);
        return err;
    }

    i->chr = chr;

    if (qemu_chr_fe_reconnect_time(&i->sock, -1) <= 0) {
        error_setg(&err, "VMI: missing reconnect=N for '%s'",
                          i->chardevid);
        return err;
    }

    qemu_chr_fe_set_handlers(&i->sock, vmi_chr_can_read, vmi_chr_read,
                             vmi_chr_event, NULL, i, NULL, true);

    /*
     * The reconnect timer is triggered by either machine init or by a chardev
     * disconnect. For the QMP creation, when the machine is already started,
     * use an artificial disconnect just to restart the timer.
     */
    if (!i->created_from_command_line) {
        qemu_chr_fe_disconnect(&i->sock);
    }

    return NULL;
}

static gboolean vm_introspection_alloc_gfn(uint64_t gfn)
{
    VMIntrospection *i = vm_introspection_object();
    qemu_mutex_lock_iothread();

    uint64_t p_address = gfn << TARGET_PAGE_BITS, *key;
    g_autofree char *region_name = g_strdup_printf("gfn.%lX", p_address);
    MemoryRegion *sysmem = get_system_memory(), *ram;

    if (memory_region_find(sysmem, p_address, 1 << TARGET_PAGE_BITS).size) {
        qemu_mutex_unlock_iothread();
        return false;
    }

    ram = g_new(MemoryRegion, 1);
    memory_region_init_ram(ram, NULL, region_name, 1 << TARGET_PAGE_BITS, &error_fatal);
    memory_region_add_subregion(sysmem, p_address, ram);

    key = g_malloc(sizeof(uint64_t));
    *key = gfn;
    g_hash_table_insert(i->alloc_gfns, key, ram);

    qemu_mutex_unlock_iothread();
    return true;
}

static gboolean remove_gfn(gpointer key, gpointer value, gpointer user_data)
{
    return *(uint64_t*)key == *(uint64_t*)&user_data;
}

static gboolean vm_introspection_free_gfn(uint64_t gfn)
{
    char ret;
    VMIntrospection *i = vm_introspection_object();
    qemu_mutex_lock_iothread();
    ret = !!g_hash_table_foreach_remove(i->alloc_gfns, remove_gfn, (gpointer)gfn);
    qemu_mutex_unlock_iothread();
    return ret;
}

void vm_introspection_handle_exit(CPUState *cs,
                                  struct kvm_introspection_exit *kvmi)
{
    VMIntrospection *i = vm_introspection_object();
    MemIntrospectionState *mi = i ? i->memIntro : NULL;
    Error *err = NULL;

    if (!mi) {
        warn_report("VMI: memory introspection object not available");
        return;
    }

    switch (kvmi->type) {
    case KVM_EXIT_INTROSPECTION_START:
        mem_introspection_start(mi, (const QemuUUID *) &kvmi->kvmi_start.uuid,
                                cs, &err);
        break;

    case KVM_EXIT_INTROSPECTION_MAP:
        mem_introspection_map(mi, (const QemuUUID *) &kvmi->kvmi_map.uuid,
                              kvmi->kvmi_map.gpa, kvmi->kvmi_map.len,
                              kvmi->kvmi_map.min, cs, &err);
        break;

    case KVM_EXIT_INTROSPECTION_UNMAP:
        mem_introspection_unmap(mi, (const QemuUUID *) &kvmi->kvmi_unmap.uuid,
                                kvmi->kvmi_unmap.gpa, cs, &err);
        break;

    case KVM_EXIT_INTROSPECTION_END:
        mem_introspection_end(mi, (const QemuUUID *) &kvmi->kvmi_end.uuid, cs,
                              &err);
        break;

    default:
        warn_report("invalid introspection request (%lld)", kvmi->type);
        break;
    }

    if (err) {
        error_report_err(err);
    }
}

bool vm_introspection_remap(CPUState *cs, hwaddr paddr)
{
    VMIntrospection *i = vm_introspection_object();
    MemIntrospectionState *mi = i ? i->memIntro : NULL;
    Error *err = NULL;
    bool result;

    if (!mi)
        return false;

    result = mem_introspection_remap(mi, (uint64_t)paddr, cs, &err);

    if (err) {
        error_report_err(err);
        return false;
    }

    return result;
}
