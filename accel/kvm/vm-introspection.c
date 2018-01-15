/*
 * VM Introspection
 *
 * Copyright (C) 2017-2018 Bitdefender S.R.L.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qom/object.h"
#include "qom/object_interfaces.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "sysemu/vm-introspection.h"

typedef struct VMIntrospection {
    Object parent_obj;
    char *chardevid;
    Chardev *chr;
    CharBackend sock;
    char *keyid;
    Object *key;
    guint watch;
    KVMState *kvm;
    /* allow, deny commands and events */
    struct kvm_introspection h;
} VMIntrospection;

#define TYPE_VM_INTROSPECTION "introspection"

#define VM_INTROSPECTION(obj)                                                  \
    OBJECT_CHECK(VMIntrospection, (obj), TYPE_VM_INTROSPECTION)

static void complete(UserCreatable *uc, Error **errp)
{
    VMIntrospection *i = VM_INTROSPECTION(uc);

    if (!i->chardevid || !i->keyid) {
        error_setg(errp, "introspection needs 'chardev' ,"
                         "'key' property set");
        return;
    }
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

static void class_init(ObjectClass *oc, void *data)
{
    USER_CREATABLE_CLASS(oc)->complete = complete;
}

static void instance_init(Object *obj)
{
    object_property_add_str(obj, "key", NULL, prop_set_key, NULL);
    object_property_add_str(obj, "chardev", NULL, prop_set_chardev, NULL);
}

static void instance_finalize(Object *obj)
{
    VMIntrospection *i = VM_INTROSPECTION(obj);

    if (i->chr) {
        if (i->watch) {
            g_source_remove(i->watch);
            i->watch = 0;
        }
        qemu_chr_fe_deinit(&i->sock, true);
    }

    g_free(i->chardevid);
    g_free(i->keyid);
}

static const TypeInfo info = {
    .name              = TYPE_VM_INTROSPECTION,
    .parent            = TYPE_OBJECT,
    .class_init        = class_init,
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

static bool do_handshake(CharBackend *sock, Object *key, const char *sock_name,
                         Error **errp)
{
    VMIntrospection_handshake send, recv;
    size_t sz = sizeof(send);

    /* TODO: do the cookie dance */

    send.struct_size = sz;
    memcpy(&send.uuid, &qemu_uuid, sizeof(send.uuid));

    /* !!! tcp_chr_write() will return sz if not connected */
    if (qemu_chr_fe_write_all(sock, (uint8_t *)&send, sz) != sz) {
        error_setg_errno(errp, errno, "error writing to '%s'", sock_name);
        return false;
    }

    if (qemu_chr_fe_read_all(sock, (uint8_t *)&recv, sz) != sz) {
        error_setg_errno(errp, errno, "error reading from '%s'", sock_name);
        return false;
    }

    if (memcmp(&send, &recv, sz)) {
        error_setg(errp, "handshake failed");
        return false;
    }

    return true;
}

static bool connect_fd(VMIntrospection *i, Error **errp)
{
    memset(&i->h, 0, sizeof(i->h));
    i->h.fd = -1;
    /* TODO: proper handling of allow,deny props */
    i->h.commands = i->h.events = -1;

    if (do_handshake(&i->sock, i->key, i->chardevid, errp)) {
        i->h.fd = object_property_get_int(OBJECT(i->chr), "fd", errp);

        if (i->h.fd == -1) {
            error_append_hint(errp, "no file handle from '%s'", i->chardevid);
        }
    }

    return (i->h.fd != -1);
}

static bool connect_introspection(VMIntrospection *i, Error **errp)
{
    int ret;

    if (!connect_fd(i, errp)) {
        error_append_hint(errp, "introspection handshake failed\n");
        return false;
    }

    ret = kvm_vm_ioctl(i->kvm, KVM_INTROSPECTION, &i->h);

    if (ret < 0) {
        error_setg_errno(errp, -errno, "ioctl/KVM_INTROSPECTION failed");
        return false;
    }

    return true;
}

static gboolean force_reconnect(GIOChannel *chan, GIOCondition cond,
                                void *opaque)
{
    VMIntrospection *i = opaque;

    qemu_chr_fe_disconnect(&i->sock);

    return TRUE;
}

static void chr_event(void *opaque, int event)
{
    VMIntrospection *i = opaque;

    switch (event) {
    case CHR_EVENT_OPENED: {
        Error *err = NULL;
        if (connect_introspection(i, &err)) {
            info_report("introspection connected");
            i->watch = qemu_chr_fe_add_watch(&i->sock, G_IO_HUP,
                                             force_reconnect, i);
        } else {
            error_append_hint(&err, "reconnecting\n");
            warn_report_err(err);
            qemu_chr_fe_disconnect(&i->sock);
        }
        break;
    }
    case CHR_EVENT_CLOSED:
        if (i->watch) {
            info_report("introspection disconnected");
            g_source_remove(i->watch);
            i->watch = 0;
        }
        break;
    default:
        break;
    }
}

static void connect_or_add_watch(VMIntrospection *i, Error **errp)
{
    Error *err = NULL;

    if (qemu_chr_fe_backend_open(&i->sock) && connect_introspection(i, &err)) {
        return;
    }

    if (!err) { /* !open */
        error_setg(&err, "introspection socket is not open");
    }

    error_append_hint(&err, "reconnecting as soon as possible\n");
    warn_report_err(err);

    qemu_chr_fe_set_handlers(&i->sock, NULL, NULL, chr_event, NULL, i, NULL,
                             true);
}

void vm_introspection_connect(KVMState *s, const char *id, Error **errp)
{
    VMIntrospection *i;
    Object *obj;

    obj = object_resolve_path_component(object_get_objects_root(), id);
    if (!obj) {
        error_setg(errp, "introspection object '%s' not found", id);
        return;
    }

    i = VM_INTROSPECTION(obj);

    i->kvm = s;

    i->key = object_resolve_path_component(object_get_objects_root(), i->keyid);
    if (!i->key) {
        error_setg(errp, "No secret object with id '%s'", i->keyid);
        return;
    }

    i->chr = qemu_chr_find(i->chardevid);
    if (!i->chr) {
        error_setg(errp, "Device '%s' not found", i->chardevid);
        return;
    }

    if (!qemu_chr_fe_init(&i->sock, i->chr, errp)) {
        i->chr = NULL;
        error_setg(errp, "Device '%s' not initialized", i->chardevid);
        return;
    }

    connect_or_add_watch(i, errp);
}
