/*
 * xc_xfair.c
 *
 *  Created on: May 12, 2015
 *      Author: luthfi
 */

#include "xc_private.h"
#include <stdio.h>

int
xc_sched_xfair_schedule_set(
    xc_interface *xch,
	uint32_t cpupool_id,
    struct xen_sysctl_xfair_schedule *schedule)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(
        schedule,
        sizeof(*schedule),
        XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, schedule) )
    {
        return -1;
    }

    sysctl.cmd = XEN_SYSCTL_scheduler_op;
    sysctl.u.scheduler_op.cpupool_id = cpupool_id;
    sysctl.u.scheduler_op.sched_id = XEN_SCHEDULER_XFAIR;
    sysctl.u.scheduler_op.cmd = XEN_SYSCTL_SCHEDOP_putinfo;
    set_xen_guest_handle(sysctl.u.scheduler_op.u.sched_xfair.schedule,
            schedule);
    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, schedule);
    return rc;
}

int
xc_sched_xfair_schedule_get(
    xc_interface *xch,
	uint32_t cpupool_id,
    struct xen_sysctl_xfair_schedule *schedule)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(
        schedule,
        sizeof(*schedule),
        XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, schedule) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_scheduler_op;
    sysctl.u.scheduler_op.cpupool_id = cpupool_id;
    sysctl.u.scheduler_op.sched_id = XEN_SCHEDULER_XFAIR;
    sysctl.u.scheduler_op.cmd = XEN_SYSCTL_SCHEDOP_getinfo;
    set_xen_guest_handle(sysctl.u.scheduler_op.u.sched_xfair.schedule,
            schedule);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, schedule);

    return rc;
}


