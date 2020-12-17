/*
 * VM Introspection
 *
 * Copyright (C) 2020 Bitdefender S.R.L.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef MEM_INTROSPECTION_H
#define MEM_INTROSPECTION_H

#include "qemu/uuid.h"

#include <linux/kvm.h>
#include <linux/kvm_para.h>

#define PI_READY_WAIT_MS 3000

typedef struct MemSourceState MemSourceState;
typedef struct MemIntrospectionState MemIntrospectionState;

#define TYPE_MEM_SOURCE "mem-source"
#define MEM_SOURCE(obj) \
    OBJECT_CHECK(MemSourceState, (obj), TYPE_MEM_SOURCE)

#define TYPE_MEM_INTROSPECTION "mem-introspection"
#define MEM_INTROSPECTION(obj) \
    OBJECT_CHECK(MemIntrospectionState, (obj), TYPE_MEM_INTROSPECTION)

typedef struct MemIntrospectionPkt {
    QemuUUID dom_id;
} MemIntrospectionPkt;

/*
 * Mem-source interface with VMI. Use according to the following cycle:
 * mem_source_connect() -> mem_source_disconnect()
 * Extra calls will be a NOP.
 */
typedef void MemSourceConnected(void *opaque);
void mem_source_connect(MemSourceState *ms, MemSourceConnected *cbk,
                        void *opaque);
void mem_source_disconnect(MemSourceState *ms);

/* mem-introspection interface with VCPU */
void mem_introspection_start(MemIntrospectionState *mi, const QemuUUID *uuid,
                             CPUState *cs, Error **errp);
void mem_introspection_map(MemIntrospectionState *mi, const QemuUUID *uuid,
                           uint64_t gpa, uint64_t size, uint64_t min, CPUState *cs, Error **errp);
void mem_introspection_unmap(MemIntrospectionState *mi, const QemuUUID *uuid,
                             uint64_t gpa, CPUState *cs, Error **errp);
void mem_introspection_end(MemIntrospectionState *mi, const QemuUUID *uuid,
                           CPUState *cs, Error **errp);
bool mem_introspection_remap(MemIntrospectionState *mi, uint64_t gpa,
                             CPUState *cs, Error **errp);

#endif /* MEM_INTROSPECTION_H */
