/*
 * VM Introspection
 *
 * Copyright (C) 2017 Bitdefender S.R.L.
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
#include "sysemu/vm-introspection.h"

typedef struct VMIntrospection {
    Object parent_obj;
    char *chardevid;
    char *keyid;
    /* allow, deny commands and events */
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

    if (qemu_chr_fe_write_all(sock, (uint8_t *)&send, sz) != sz) {
        error_setg(errp, "error writing to '%s': %d", sock_name, errno);
        return false;
    }

    if (qemu_chr_fe_read_all(sock, (uint8_t *)&recv, sz) != sz) {
        error_setg(errp, "error reading from '%s': %d", sock_name, errno);
        return false;
    }

    if (memcmp(&send, &recv, sz)) {
        error_setg(errp, "handshake failed");
        return false;
    }

    return true;
}

int vm_introspection_fd(Object *obj, uint32_t *commands, uint32_t *events,
                        Error **errp)
{
    VMIntrospection *i = VM_INTROSPECTION(obj);
    Chardev *chr;
    CharBackend sock;
    Object *key;
    int fd = -1;

    /* TODO: proper handling of allow,deny props */
    *commands = *events = -1;

    key = object_resolve_path_component(object_get_objects_root(), i->keyid);
    if (!key) {
        error_setg(errp, "No secret object with id '%s'", i->keyid);
        return -1;
    }

    chr = qemu_chr_find(i->chardevid);
    if (chr == NULL) {
        error_setg(errp, "Device '%s' not found", i->chardevid);
        return -1;
    }

    if (!qemu_chr_fe_init(&sock, chr, &error_abort)) {
        error_setg(errp, "Device '%s' not initialized", i->chardevid);
        return -1;
    }

    if (do_handshake(&sock, key, i->chardevid, errp)) {
        fd = object_property_get_int(OBJECT(chr), "fd", errp);
        if (fd != -1) {
            fd = dup(fd);
        } else {
            error_setg(errp, "no file handle from '%s': %d", i->chardevid,
                       errno);
        }
    }

    qemu_chr_fe_deinit(&sock, true);

    return fd;
}
