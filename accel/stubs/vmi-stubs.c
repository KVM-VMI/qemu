#include "qemu/osdep.h"
#include "qom/object.h"

#include "sysemu/vmi-intercept.h"

bool vm_introspection_intercept(VMI_intercept_command ic, Error **errp)
{
    return false;
}

bool vm_introspection_qmp_delay(void *mon, QObject *id, bool resume)
{
    return false;
}
