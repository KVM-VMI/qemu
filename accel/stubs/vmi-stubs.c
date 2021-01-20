#include "qemu/osdep.h"
#include "qapi/qmp/qdict.h"

#include "sysemu/vmi-intercept.h"

bool vm_introspection_intercept(VMI_intercept_command ic, Error **errp)
{
    return false;
}

bool vm_introspection_qmp_delay(void *mon, QDict *rsp)
{
    return false;
}
