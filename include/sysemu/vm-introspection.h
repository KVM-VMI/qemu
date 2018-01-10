/*
 * VM Introspection
 *
 * Copyright (C) 2017-2018 Bitdefender S.R.L.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VM_INTROSPECTION_H
#define VM_INTROSPECTION_H

/**
 * VMIntrospection:
 *
 * The VMIntrospection object is used to do the handshake with an
 * introspection tool and pass the connection to KVM.
 *
 *  $QEMU -chardev socket,id=chardev0,type=vsock,cid=10,port=1234,reconnect=1 \
 *        -object secret,id=key0,data=some                                    \
 *        -object introspection,id=kvmi,chardev=chardev0,key=key0             \
 *        -accel kvm,introspection=kvmi
 *
 */

/**
 * VMIntrospection_handshake:
 *
 * This structure is passed to the introspection tool during the handshake.
 *
 * @struct_size: the structure size (in case we extend it)
 * @uuid: the UUID (the introspector may apply different settings based on this)
 */
typedef struct VMIntrospection_handshake {
    uint32_t struct_size;
    QemuUUID uuid;
    /* ... */
} VMIntrospection_handshake;

/**
 * vm_introspection_connect:
 * @s: the KVM context (used with kvm_vm_ioctl)
 * @id: the introspection object name
 * @errp: error object handle
 */
extern void vm_introspection_connect(KVMState *s, const char *id, Error **errp);

#endif
