/****************************************************************************
 * (C) 2015 - Luthfi Idris
 ****************************************************************************
 *
 *        File: common/sched_xfair.c
 *      Author: Luthfi Idris
 *
 * Description: Local Scheduler
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/timer.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/errno.h>
#include <xen/list.h>
#include <xen/guest_access.h>
#include <public/sysctl.h>


/**************************************************************************
 * Private Macros                                                         *
 **************************************************************************/
typedef int bool;
#define true 1
#define false 0
bool x = true;

/* Default timeslice : 10ns */
#define DEFAULT_TIMESLICE MILLISECS(10)

/**
 * Retrieve the idle VCPU for a given physical CPU
 */
#define IDLETASK(cpu)  (idle_vcpu[cpu])

/**
 * Return a pointer to the xfair-specific scheduler data information
 * associated with the given VCPU (vc)
 */
#define XVCPU(vc) ((xfair_vcpu *)(vc)->sched_priv)

/**
 * Return the global scheduler private data given the scheduler ops pointer
 */
#define SCHED_PRIV(s) ((xfair_private *)((s)->sched_data))

/**************************************************************************
 * Private Type Definitions                                               *
 **************************************************************************/

/* Virtual CPU */
typedef struct xfair_vcpu_s {
	/* vc points to Xen's struct vcpu so we can get to it from an
	 * xfair_vcpu pointer. */
	struct vcpu *vc;
	/* awake holds whether the VCPU has been woken with vcpu_wake() */
	bool_t	awake;
	/* list holds the linked list information for the list this VCPU
	 * is stored in */
	struct list_head	list;
} xfair_vcpu;

/**
 * The sched_entry_t structure holds a single entry of the
 * xfair schedule.
 */
typedef struct xfair_entry_s{
	/* dom_handle holds the handle ("UUID") for the domain that this
	 * schedule entry refers to. UUID for dom0 is 0, otherwise information of
	 * UUID domU are received from XENSTORE */
	xen_domain_handle_t dom_handle;
	/* vcpu_id holds the VCPU number for the VCPU that this schedule
	 * entry refers to. */
	int             vcpu_id;
	/* runtime holds the number of nanoseconds that the VCPU for this
	 * schedule entry should be allowed to run per major frame. */
	s_time_t            runtime;
	/* vc holds a pointer to the Xen VCPU structure */
	struct vcpu *       vc;
} xfair_entry;

/**
 * This structure defines data that is global to an instance of the scheduler
 */
typedef struct xfair_private_s{
	/* lock for the whole pluggable scheduler, nests inside cpupool_lock */
	spinlock_t lock;
	/**
	 * This array holds the active  xfair schedule.
	 *
	 * When the system tries to start a new VCPU, this schedule is scanned
	 * to look for a matching (handle, VCPU #) pair. If both the handle (UUID)
	 * and VCPU number match, then the VCPU is allowed to run. Its run time
	 * (per major frame) is given in the third entry of the schedule.
	*/
	xfair_entry schedule[XFAIR_MAX_DOMAINS_PER_SCHEDULE];
    /**
     * This variable holds the number of entries that are valid in
     * the xfair_schedule table.
     *
     * This is not necessarily the same as the number of domains in the
     * schedule. A domain could be listed multiple times within the schedule,
     * or a domain with multiple VCPUs could have a different
     * schedule entry for each VCPU.
     */
    unsigned int num_schedule_entries;
    /*
    *
    * the major frame time for the xfair schedule
    */
    s_time_t major_frame;
    /*
    *
    * the time that the next major frame start
    */
    s_time_t next_major_frame;
	/**
	 * pointers to all Xen VCPU structures for iterating through
	 */
    struct list_head vcpu_list;
} xfair_private;

/**************************************************************************
 * Helper functions                                                       *
 **************************************************************************/
/* Function to find dom0 in an array list, if found then move to
 * the head of the array
 */
static void find_dom0(const struct scheduler *ops)
{
	unsigned int i, z,
	temp, index, n_entries = SCHED_PRIV(ops)->num_schedule_entries;

	printk("CALLING FIND_DOM0 \n");
	for (i = 0; i < n_entries; i++)
	{
		if (SCHED_PRIV(ops)->schedule[i].vc->domain->domain_id == 0)
		{
			/*printk("FOUND DOM0\n");*/
			index = i;
			temp = SCHED_PRIV(ops)->schedule[index].vc->domain->domain_id;
			for (z = index; z > 0; z--)
			{
				SCHED_PRIV(ops)->schedule[z].vc->domain->domain_id = SCHED_PRIV(ops)->schedule[z-1].vc->domain->domain_id;
			}
			SCHED_PRIV(ops)->schedule[0].vc->domain->domain_id = temp;
		}
	}
}

/* Function to find domU (other than dom0) in an array list, if found then move to
 * the head of the array
 */
static void find_domU(const struct scheduler *ops)
{
	unsigned int i, z,
	temp, index, n_entries = SCHED_PRIV(ops)->num_schedule_entries;

	printk("CALLING FIND_DOMU \n");
	for (i = 0; i < n_entries; i++)
	{
		if (SCHED_PRIV(ops)->schedule[i].vc->domain->domain_id != 0)
		{
			/*printk("FOUND DOMU\n");*/
			index = i;
			temp = SCHED_PRIV(ops)->schedule[index].vc->domain->domain_id;
			for (z = index; z > 0; z--)
			{
				SCHED_PRIV(ops)->schedule[z].vc->domain->domain_id = SCHED_PRIV(ops)->schedule[z-1].vc->domain->domain_id;
			}
			SCHED_PRIV(ops)->schedule[0].vc->domain->domain_id = temp;
		}
	}
}

/**
 * This function compares two domain handles.
 *
 * @param h1        Pointer to handle 1
 * @param h2        Pointer to handle 2
 *
 * @return          <ul>
 *                  <li> <0:  handle 1 is less than handle 2
 *                  <li>  0:  handle 1 is equal to handle 2
 *                  <li> >0:  handle 1 is greater than handle 2
 *                  </ul>
 */
static int dom_handle_cmp(const xen_domain_handle_t h1,
                          const xen_domain_handle_t h2)
{
	return memcmp(h1, h2, sizeof(xen_domain_handle_t));
}

/**
 * This function searches the vcpu list to find a VCPU that matches
 * the domain handle and VCPU ID specified.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param handle    Pointer to handler
 * @param vcpu_id   VCPU ID
 *
 * @return          <ul>
 *                  <li> Pointer to the matching VCPU if one is found
 *                  <li> NULL otherwise
 *                  </ul>
 */
static struct vcpu *find_vcpu(
    const struct scheduler *ops,
    xen_domain_handle_t handle,
    int vcpu_id)
{
    xfair_vcpu *xvcpu;

    printk("CALLING FIND_VCPU \n");
    /* loop through the vcpu_list looking for the specified VCPU */
    list_for_each_entry ( xvcpu, &SCHED_PRIV(ops)->vcpu_list, list )
        if ( (dom_handle_cmp(xvcpu->vc->domain->handle, handle) == 0)
             && (vcpu_id == xvcpu->vc->vcpu_id) )
            return xvcpu->vc;

    return NULL;
}

/**
 * This function updates the pointer to the Xen VCPU structure for each entry
 * in the xfair schedule.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @return          <None>
 */
static void update_schedule_vcpus(const struct scheduler *ops)
{
    unsigned int i, n_entries = SCHED_PRIV(ops)->num_schedule_entries;

    printk("CALLING UPDATE_SCHEDULE_VCPU \n");
    for ( i = 0; i < n_entries; i++ )
        SCHED_PRIV(ops)->schedule[i].vc =
            find_vcpu(ops,
                      SCHED_PRIV(ops)->schedule[i].dom_handle,
                      SCHED_PRIV(ops)->schedule[i].vcpu_id);
}

/**
 * This function is called by the adjust_global scheduler hook to put
 * in place a new xfair schedule.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          <ul>
 *                  <li> 0 = success
 *                  <li> !0 = error
 *                  </ul>
 */
static int
xfair_sched_set(
		const struct scheduler *ops,
		struct xen_sysctl_xfair_schedule  *schedule)
{
	xfair_private *sched_priv = SCHED_PRIV(ops);
	s_time_t total = 0;
	unsigned int i;
	unsigned long flags;
	int rc = -EINVAL;

	spin_lock_irqsave(&sched_priv->lock, flags);

	printk("CALLING SCHED_SET \n");
	/* Check for valid major frame and number of schedule entries. */
    if ( (schedule->major_frame <= 0)
         || (schedule->num_sched_entries < 1)
         || (schedule->num_sched_entries > XFAIR_MAX_DOMAINS_PER_SCHEDULE) )
        goto fail;

	for (i = 0; i < schedule->num_sched_entries; i++)
	{
		/* Check for a valid VCPU ID and run time. */
		if ((schedule->sched_entries[i].vcpu_id >= MAX_VIRT_CPUS)
				|| (schedule->sched_entries[i].runtime <= 0))
			goto fail;

		/* Add this entry's run time to total run time. */
		total += schedule->sched_entries[i].runtime;
	}

    /*
     * Error if the major frame is not large enough to run all entries as
     * indicated by comparing the total run time to the major frame length.
     */
    if ( total > schedule->major_frame )
        goto fail;

	/* Copy the new schedule into place. */
	sched_priv->num_schedule_entries = schedule->num_sched_entries;
	sched_priv->major_frame = schedule->major_frame;
	for ( i = 0; i < schedule->num_sched_entries; i++)
	{
		memcpy(sched_priv->schedule[i].dom_handle,
				schedule->sched_entries[i].dom_handle,
				sizeof(sched_priv->schedule[i].dom_handle));
		sched_priv->schedule[i].vcpu_id = schedule->sched_entries[i].vcpu_id;
		sched_priv->schedule[i].runtime = schedule->sched_entries[i].runtime;
	}
	update_schedule_vcpus(ops);
   /*
	 * The newly-installed schedule takes effect immediately. We do not even
	 * wait for the current major frame to expire.
	 *
	 * Signal a new major frame to begin. The next major frame is set up by
	 * the do_schedule callback function when it is next invoked.
	 */
	sched_priv->next_major_frame = NOW();
	rc = 0;

fail:
	spin_unlock_irqrestore(&sched_priv->lock, flags);

	return rc;
}

/**
 * This function is called by the adjust_global scheduler hook to read the
 * current xfair schedule
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @return          <ul>
 *                  <li> 0 = success
 *                  <li> !0 = error
 *                  </ul>
 */

static int
xfair_sched_get(
    const struct scheduler *ops,
    struct xen_sysctl_xfair_schedule *schedule)
{
    xfair_private *sched_priv = SCHED_PRIV(ops);
    unsigned int i;
    unsigned long flags;

    spin_lock_irqsave(&sched_priv->lock, flags);

    printk("CALLING SCHED_GET \n");
    schedule->num_sched_entries = sched_priv->num_schedule_entries;
    schedule->major_frame = sched_priv->major_frame;
    for ( i = 0; i < sched_priv->num_schedule_entries; i++ )
    {
        memcpy(schedule->sched_entries[i].dom_handle,
               sched_priv->schedule[i].dom_handle,
               sizeof(sched_priv->schedule[i].dom_handle));
        schedule->sched_entries[i].vcpu_id = sched_priv->schedule[i].vcpu_id;
        schedule->sched_entries[i].runtime = sched_priv->schedule[i].runtime;
    }

    spin_unlock_irqrestore(&sched_priv->lock, flags);

    return 0;
}

/**************************************************************************
 * Scheduler callback functions                                           *
 **************************************************************************/

/**
 * This function performs initialization for an instance of the scheduler.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          <ul>
 *                  <li> 0 = success
 *                  <li> !0 = error
 *                  </ul>
 */
static int
xfair_init(struct scheduler *ops)
{
    xfair_private *prv;

    printk("CALLING INIT \n");
    prv = xzalloc(xfair_private);
    if ( prv == NULL )
        return -ENOMEM;

    ops->sched_data = prv;

    prv->next_major_frame = 0;
    spin_lock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->vcpu_list);

    return 0;
}

/**
 * This function performs deinitialization for an instance of the scheduler
 *
 * @param ops       Pointer to this instance of the scheduler structure
 */
static void
xfair_deinit(const struct scheduler *ops)
{
	printk("CALLING DEINIT \n");
	xfree(SCHED_PRIV(ops));
}

/**
 * This function allocates scheduler-specific data for a VCPU
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          Pointer to the allocated data
 */
static void *
xfair_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    xfair_private *sched_priv = SCHED_PRIV(ops);
    xfair_vcpu *svc;
    unsigned int entry;
    unsigned long flags;

    /*
     * Allocate memory for the XFAIR-specific scheduler data information
     * associated with the given VCPU (vc).
     */
    printk("CALLING ALLOC_VDATA \n");
    svc = xmalloc(xfair_vcpu);
    if ( svc == NULL )
        return NULL;

    spin_lock_irqsave(&sched_priv->lock, flags);

    /*
      * Add every one of dom0's vcpus to the schedule, as long as there are
      * slots available.
      */
     if ( vc->domain->domain_id == 0 )
     {
         entry = sched_priv->num_schedule_entries;

         if ( entry < XFAIR_MAX_DOMAINS_PER_SCHEDULE )
         {
             sched_priv->schedule[entry].dom_handle[0] = '\0';
             sched_priv->schedule[entry].vcpu_id = vc->vcpu_id;
             sched_priv->schedule[entry].runtime = DEFAULT_TIMESLICE;
             sched_priv->schedule[entry].vc = vc;

             sched_priv->major_frame += DEFAULT_TIMESLICE;
             ++sched_priv->num_schedule_entries;
         }
     }

    /*
     * Initialize our XFAIR scheduler-specific information for the VCPU.
     * The VCPU starts "asleep." When Xen is ready for the VCPU to run, it
     * will call the vcpu_wake scheduler callback function and our scheduler
     * will mark the VCPU awake.
     */
    svc->vc = vc;
    svc->awake = 0;
    if ( !is_idle_vcpu(vc) )
        list_add(&svc->list, &SCHED_PRIV(ops)->vcpu_list);
    update_schedule_vcpus(ops);

    spin_unlock_irqrestore(&sched_priv->lock, flags);

    return svc;
}

/**
 * This function frees scheduler-specific VCPU data
 *
 * @param ops       Pointer to this instance of the scheduler structure
 */
static void
xfair_free_vdata(const struct scheduler *ops, void *priv)
{
    xfair_vcpu *av = priv;

    printk("CALLING FREE_VDATA \n");
    if (av == NULL)
        return;

    if ( !is_idle_vcpu(av->vc) )
        list_del(&av->list);

    xfree(av);
    update_schedule_vcpus(ops);
}

/**
 * This function allocates scheduler-specific data for a physical CPU
 *
 * We do not actually make use of any per-CPU data but the hypervisor expects
 * a non-NULL return value
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          Pointer to the allocated data
 */
static void *
xfair_alloc_pdata(const struct scheduler *ops, int cpu)
{
	printk("CALLING ALLOC_PDATA \n");
	/* return a non-NULL value to keep schedule.c happy */
    return SCHED_PRIV(ops);
}

/**
 * This function frees scheduler-specific data for a physical CPU
 *
 * @param ops       Pointer to this instance of the scheduler structure
 */
static void
xfair_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
	printk("CALLING FREE_PDATA \n");
	/* nop */
}

/**
 * This function allocates scheduler-specific data for a domain
 *
 * We do not actually make use of any per-domain data but the hypervisor
 * expects a non-NULL return value
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          Pointer to the allocated data
 */
static void *
xfair_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
	printk("CALLING ALLOC_DOMDATA \n");
	/* return a non-NULL value to keep schedule.c happy */
    return SCHED_PRIV(ops);
}

/**
 * This function frees scheduler-specific data for a domain
 *
 * @param ops       Pointer to this instance of the scheduler structure
 */
static void
xfair_free_domdata(const struct scheduler *ops, void *data)
{
	printk("CALLING FREE_DOMDATA \n");
	/* nop */
}

/**
 * Xen scheduler callback function to sleep a VCPU
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param vc        Pointer to the VCPU structure for the current domain
 */
static void
xfair_vcpu_sleep(const struct scheduler *ops, struct vcpu *vc)
{
	printk("CALLING VCPU_SLEEP \n");
	if ( XVCPU(vc) != NULL )
        XVCPU(vc)->awake = 0;

    /*
     * If the VCPU being put to sleep is the same one that is currently
     * running, raise a softirq to invoke the scheduler to switch domains.
     */
    if ( per_cpu(schedule_data, vc->processor).curr == vc )
        cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
}

/**
 * Xen scheduler callback function to wake up a VCPU
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param vc        Pointer to the VCPU structure for the current domain
 */
static void
xfair_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
	printk("CALLING VCPU_WAKE \n");
	if ( XVCPU(vc) != NULL )
        XVCPU(vc)->awake = 1;

    cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
}

/**
 * Xen scheduler callback function to select a VCPU to run.
 * This is the main scheduler routine.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param now       Current time
 *
 * @return          Address of the VCPU structure scheduled to be run next
 *                  Amount of time to execute the returned VCPU
 *                  Flag for whether the VCPU was migrated
 */
static struct task_slice xfair_do_schedule(
    const struct scheduler *ops,
    s_time_t now,
    bool_t tasklet_work_scheduled)
{
    struct task_slice ret;                      /* hold the chosen domain */
    struct vcpu * new_task = NULL;
    static unsigned int sched_index = 0;
    static s_time_t next_switch_time;
    xfair_private *sched_priv = SCHED_PRIV(ops);
    /*static unsigned int i;*/
    const unsigned int cpu = smp_processor_id();
    unsigned long flags;

    printk("CALLING DO_SCHEDULE \n");

    spin_lock_irqsave(&sched_priv->lock, flags);

    if ( sched_priv->num_schedule_entries < 1 )
           sched_priv->next_major_frame = now + DEFAULT_TIMESLICE;
    else if ( now >= sched_priv->next_major_frame )
    {
		   /* time to enter a new major frame
			* the first time this function is called, this will be true */
		   /* start with the first domain in the schedule */
		   sched_index = 0;
		   sched_priv->next_major_frame = now + sched_priv->major_frame;
		   next_switch_time = now + sched_priv->schedule[0].runtime;
	}
	else
	{
	  while ( (now >= next_switch_time)
				&& (sched_index < sched_priv->num_schedule_entries) )
		{
			/* time to switch to the next domain in this major frame */
			sched_index++;
			next_switch_time += sched_priv->schedule[sched_index].runtime;
		}
	}
    /*
     * If we exhausted the domains in the schedule and still have time left
     * in the major frame then switch next at the next major frame.
     */
    if ( sched_index >= sched_priv->num_schedule_entries )
        next_switch_time = sched_priv->next_major_frame;

    /*printk("NUM SCHED ENTRIES: %i\n", sched_priv->num_schedule_entries);*/
    /*printk("Domain before condition: %i\n", sched_priv->schedule[sched_index].vc->domain->domain_id);*/

    /*
     * If there are more domains to run in the current major frame, set
     * new_task equal to the address of next domain's VCPU structure.
     * Otherwise, set new_task equal to the address of the idle task's VCPU
     * structure.
     */
	/*printk("SCHED INDEX : %i \n", sched_index);*/
/*    new_task = (sched_index < sched_priv->num_schedule_entries)
        ? sched_priv->schedule[sched_index].vc
        : IDLETASK(cpu);*/

	/*printk("DOMAIN after condition : %i \n", new_task->domain->domain_id);*/
    /* Check to see if the new task can be run (awake & runnable). */
/*	if (new_task == NULL)
		printk("NEW TASK IS NULL\n");
	if(XVCPU(new_task) == NULL)
		printk("XVCPU IS NULL\n");
	if(!(XVCPU(new_task)->awake))
		printk("NOT AWAKE\n");
	if(!(vcpu_runnable(new_task)))
		printk("NOT RUNNABLE\n");*/
    if ( !( (new_task != NULL)&& (XVCPU(new_task) != NULL)&& XVCPU(new_task)->awake
    		&& vcpu_runnable(new_task)) )
    {
        new_task = IDLETASK(cpu);
       /* printk("DOMAIN check idle : %i \n", new_task->domain->domain_id);*/
    }

    BUG_ON(new_task == NULL);

    spin_unlock_irqrestore(&sched_priv->lock, flags);

    /* Tasklet work (which runs in idle VCPU context) overrides all else. */
    if ( tasklet_work_scheduled )
    {
        new_task = IDLETASK(cpu);
        /*printk("DOMAIN after work scheduled : %i \n", new_task->domain->domain_id);*/
    }


    /* Running this task would result in a migration */
    if ( !is_idle_vcpu(new_task)
         && (new_task->processor != cpu) )
        new_task = IDLETASK(cpu);

    if (sched_priv->schedule[sched_index].vc->domain->domain_id == 0)
    		{
    			if (x == true)
    			{
    				new_task = sched_priv->schedule[sched_index].vc;
    				x = false;
    				/*printk("dom0 1st\n");*/
    			}
    			else
    			{
    				find_domU(ops);
    				new_task = sched_priv->schedule[sched_index].vc;
    				x = true;
    				/*printk("domU 1st\n");*/
    			}
    		}
    		else
    		{
    			if (x == false)
    			{
    				new_task = sched_priv->schedule[sched_index].vc;
    				x = true;
    				/*printk("domU 2nd\n");*/
    			}
    			else
    			{
    				find_dom0(ops);
    				new_task = sched_priv->schedule[sched_index].vc;
    				x  = false;
    				/*printk("dom0 2nd \n");*/
    			}
    		}

    /*
     * Return the amount of time the next domain has to run and the address
     * of the selected task's VCPU structure.
     */
    ret.task = new_task;
    ret.time = next_switch_time - now;
    ret.migrated = 0;
    printk("DOMAIN : %i \n", new_task->domain->domain_id);
    printk("TIME : %ld \n", ret.time);

    BUG_ON(ret.time <= 0);

    return ret;
}

/**
 * Xen scheduler callback function to select a CPU for the VCPU to run on
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param v         Pointer to the VCPU structure for the current domain
 *
 * @return          Number of selected physical CPU
 */
static int
xfair_pick_cpu(const struct scheduler *ops, struct vcpu *vc)
{
    cpumask_t *online;
    unsigned int cpu;

    printk("CALLING PICK_CPU \n");
    /*
     * If present, prefer vc's current processor, else
     * just find the first valid vcpu .
     */
    online = cpupool_scheduler_cpumask(vc->domain->cpupool);

    cpu = cpumask_first(online);

    if ( cpumask_test_cpu(vc->processor, online)
         || (cpu >= nr_cpu_ids) )
        cpu = vc->processor;
    return cpu;
}

/*
 * Xen scheduler callback function to perform a global (not domain-specific)
 * adjustment. It is used by the adjust_global scheduler to put in place a new
 * xfair schedule or to retrieve the schedule currently in place.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param sc        Pointer to the scheduler operation specified by Domain 0
*/

static int
xfair_adjust_global(const struct scheduler *ops,
                        struct xen_sysctl_scheduler_op *sc)
{
    xen_sysctl_xfair_schedule_t local_sched;
    int rc = -EINVAL;

    printk("CALLING ADJUST_GLOBAL \n");
    switch ( sc->cmd )
    {
    case XEN_SYSCTL_SCHEDOP_putinfo:
       if ( copy_from_guest(&local_sched, sc->u.sched_xfair.schedule, 1) )
        {
            rc = -EFAULT;
            break;
        }
        rc = xfair_sched_set(ops, &local_sched);
        break;
    case XEN_SYSCTL_SCHEDOP_getinfo:
        rc = xfair_sched_get(ops, &local_sched);
        if ( rc )
            break;

        if ( copy_to_guest(sc->u.sched_xfair.schedule, &local_sched, 1) )
            rc = -EFAULT;
        break;
    }

    return rc;
}

/**
 * This structure defines our scheduler for Xen.
 * The entries tell Xen where to find our scheduler-specific
 * callback functions.
 * The symbol must be visible to the rest of Xen at link time.
 */
const struct scheduler sched_xfair_def = {
    .name           = "XFair Table Driver Scheduler",
    .opt_name       = "xfair",
    .sched_id       = XEN_SCHEDULER_XFAIR,
    .sched_data     = NULL,

    .init           = xfair_init,
    .deinit         = xfair_deinit,


    .alloc_vdata    = xfair_alloc_vdata,
    .free_vdata     = xfair_free_vdata,
    .alloc_pdata    = xfair_alloc_pdata,
    .free_pdata     = xfair_free_pdata,
    .alloc_domdata  = xfair_alloc_domdata,
    .free_domdata   = xfair_free_domdata,

    .init_domain    = NULL,
    .destroy_domain = NULL,

    .insert_vcpu    = NULL,
    .remove_vcpu    = NULL,

	.sleep			= xfair_vcpu_sleep,
	.wake			= xfair_vcpu_wake,
    .yield          = NULL,
    .context_saved  = NULL,

    .pick_cpu       = xfair_pick_cpu,
    .do_schedule    = xfair_do_schedule,

	.adjust         = NULL,
	.adjust_global 	= xfair_adjust_global,

    .dump_settings  = NULL,
    .dump_cpu_state = NULL,

    .tick_suspend   = NULL,
    .tick_resume    = NULL,

};
