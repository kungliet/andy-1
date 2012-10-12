/*
 * arch_domain.c
 *
 * Copyright (C) 2008 Samsung Electronics
 *          JooYoung Hwang  <jooyoung.hwang@samsung.com>
 *
 * Secure Xen on ARM architecture designed by Sang-bum Suh consists of
 * Xen on ARM and the associated access control.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public version 2 of License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdarg.h>
#include <xen/config.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <xen/errno.h>
#include <xen/smp.h>
#include <xen/irq_cpustat.h>
#include <xen/softirq.h>
#include <asm/flushtlb.h>
#include <asm/current.h>	
#include <asm/cpu-ops.h>

#define switch_mm(mm)	cpu_switch_ttb(mm)

extern unsigned long pa_dom_shared_info[3];

void __switch_to( struct vcpu *, struct vcpu_guest_context *, struct vcpu_guest_context *);

#define switch_to(prev,next,last)                                       \
do {                                                                    \
         __switch_to(prev,&prev->arch.guest_context, &next->arch.guest_context);   \
} while (0)


unsigned long hypercall_create_continuation(unsigned int op,
        const char *format, ...)
{
	printk("hypercall_create_continuation: Not Yet.\n");

	return 0;
}

extern struct domain* idle_domain;

int arch_domain_create(struct domain *d)
{
    int pdpt_order, rc;

    pdpt_order = get_order_from_bytes(PDPT_L1_ENTRIES * sizeof(pte_t));
    d->arch.mm_perdomain_pt = alloc_xenheap_pages(pdpt_order);
    if ( d->arch.mm_perdomain_pt == NULL )
        goto fail_nomem;
    memset(d->arch.mm_perdomain_pt, 0, PAGE_SIZE << pdpt_order);

    mapcache_init(d);

    if ( !is_idle_domain(d) )
    {
        d->arch.ioport_caps = 
            rangeset_new(d, "I/O Ports", RANGESETF_prettyprint_hex);
        if ( d->arch.ioport_caps == NULL )
            goto fail_nomem;
		
        if ( (d->shared_info = alloc_xenheap_page()) == NULL )
            goto fail_nomem;

		// TODO
		// Let the idle domain see the shared info of the guest domain
		// so that we can log time stamp in idle domain context. 
		idle_domain->shared_info = d->shared_info;
        if ( (rc = ptwr_init(d)) != 0 )
            goto fail_nomem;

        memset(d->shared_info, 0, PAGE_SIZE);
        SHARE_PFN_WITH_DOMAIN(virt_to_page(d->shared_info), d);
    }
	
	return 0;
		
fail_nomem:
    free_xenheap_page(d->shared_info);
    free_xenheap_pages(d->arch.mm_perdomain_pt, pdpt_order);

    return -ENOMEM;
}


void arch_domain_destroy(struct domain *d)
{
    free_xenheap_pages(
        d->arch.mm_perdomain_pt,
        get_order_from_bytes(PDPT_L1_ENTRIES * sizeof(pte_t)));


	free_xenheap_page(phys_to_virt(pa_dom_shared_info[d->domain_id]));
}



void machine_halt(void)
{
    printf("machine_halt called: spinning....\n");
    while(1);
}

void machine_restart(char * __unused)
{
    printf("machine_restart called: spinning....\n");
    while(1);
}

void free_perdomain_pt(struct domain *d)
{
	printk("free_perdomain_pt : Not Yet\n");
}

struct vcpu *alloc_vcpu_struct(struct domain *d, unsigned int vcpu_id)
{
    struct vcpu *v;

    if ( (v = xmalloc(struct vcpu)) == NULL )
        return NULL;

    memset(v, 0, sizeof(*v));

    v->vcpu_id = vcpu_id;

    v->arch.guest_context.sys_regs.vpsr = 0x13; 
    v->arch.guest_context.sys_regs.vdacr = DOMAIN_KERNEL_VALUE;

    return v;
}

void free_vcpu_struct(struct vcpu *v)
{
    BUG_ON(v->next_in_list != NULL);
    if ( v->vcpu_id != 0 )
        v->domain->vcpu[v->vcpu_id - 1]->next_in_list = NULL;
    xfree(v);
}

/* This is called by arch_final_setup_guest and do_boot_vcpu */
int arch_set_info_guest(struct vcpu *v, vcpu_guest_context_t *c)
{
	printk("arch_set_info_guest : Not Yet\n");

	return 0;
}

extern void ret_to_user(void);

void new_thread(struct vcpu *d,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info)
{
	unsigned long *domain_stack;
	struct cpu_info *ci;
	struct cpu_user_regs *domain_context;
	struct cpu_user_regs *regs = &d->arch.guest_context.user_regs;

	domain_stack = alloc_xenheap_pages(STACK_ORDER);
	if(domain_stack == NULL) {
		return;
	}

	ci = (struct cpu_info *)domain_stack;
	ci->cur_vcpu = d;

	domain_stack += (STACK_SIZE - sizeof(struct cpu_user_regs))/sizeof(unsigned long);

	domain_context = (struct cpu_user_regs *)domain_stack;
	domain_context->r0 = 0;
	domain_context->r12 = start_info;
	domain_context->r13 = start_stack;
	domain_context->r15 = start_pc;

	domain_context->psr = 0x13;

	regs->r13 = (unsigned long)domain_stack;
	regs->r14 = (unsigned long)ret_to_user;
}

void domain_relinquish_memory(struct domain *d)
{
	printk("domain_relinquish_memory : Not Yet\n");
}

void dump_pageframe_info(struct domain *d)
{
	printk("dump_pageframe_info : Not Yet\n");
}

static struct vcpu * prev_vcpu = NULL;
void context_switch(struct vcpu *prev, struct vcpu *next)
{

	local_irq_disable();

	if(is_idle_domain(current->domain)){
		if( next!=prev_vcpu ){
			if (prev_vcpu)
				save_ptbase(prev_vcpu);
			write_ptbase(next);
		}
		prev_vcpu = NULL;
	} else {
		if( (is_idle_domain(next->domain)) ) {
			prev_vcpu = current;
		} else {
			save_ptbase(current); 
			write_ptbase(next);
		}
	}
	context_saved(prev);
	local_irq_enable();

	switch_to(prev,next,prev);
}



void continue_running(struct vcpu *same)
{
	return ;
}

int __sync_lazy_execstate(void)
{
	printk("sync_lazy_execstate : Not Yet\n");
	return 0;
}
void sync_lazy_execstate_cpu(unsigned int cpu)
{
	printk("sync_lazy_execstate_cpu : Not Yet\n");
}

void sync_lazy_execstate_mask(cpumask_t mask)
{
	printk("sync_lazy_execstate_mask : Not Yet\n");
}

void sync_vcpu_execstate(struct vcpu *v)
{
	printk("sync_vcpu_execstate : Not Yet\n");
}

static void relinquish_memory(struct domain *d, struct list_head *list)
{
    struct list_head *ent;
    struct page_info  *page;
    unsigned long     x, y;

    /* Use a recursive lock, as we may enter 'free_domheap_page'. */
    spin_lock_recursive(&d->page_alloc_lock);

    ent = list->next;
    while ( ent != list )
    {
        page = list_entry(ent, struct page_info, list);

//	printk("[relinquish_memory 1] page = 0x%x, type_info = 0x%x, count_info = 0x%x\n",page,page->u.inuse.type_info,page->count_info);
        /* Grab a reference to the page so it won't disappear from under us. */
        if ( unlikely(!get_page(page, d)) )
        {
            /* Couldn't get a reference -- someone is freeing this page. */
            ent = ent->next;
            continue;
        }

        if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
            put_page_and_type(page);

        if ( test_and_clear_bit(_PGC_allocated, (unsigned long *)&page->count_info) )
            put_page(page);

        /*
         * Forcibly invalidate base page tables at this point to break circular
         * 'linear page table' references. This is okay because MMU structures
         * are not shared across domains and this domain is now dead. Thus base
         * tables are not in use so a non-zero count means circular reference.
         */
        y = page->u.inuse.type_info;
        for ( ; ; )
        {
            x = y;
            if ( likely((x & (PGT_type_mask|PGT_validated)) !=
                        (PGT_base_page_table|PGT_validated)) )
                break;

            y = cmpxchg((u32*)&page->u.inuse.type_info, x, x & ~PGT_validated);
            if ( likely(y == x) )
            {
   //         	printk("[relinquish_memory 2] page = 0x%x, type_info = 0x%x, count_info = 0x%x\n",page,page->u.inuse.type_info,page->count_info);
                free_page_type(page, PGT_base_page_table);
                break;
            }
}

        /* Follow the list chain and /then/ potentially free the page. */
        ent = ent->next;
        put_page(page);
    }

    spin_unlock_recursive(&d->page_alloc_lock);
}


void domain_relinquish_resources(struct domain *d)
{
	struct vcpu *v;
    unsigned long pfn;


	ptwr_destroy(d);

	    /* Drop the in-use references to page-table bases. */
    for_each_vcpu ( d, v )
    {
        if ( (pfn = pagetable_get_pfn(v->arch.guest_table)) != 0 )
        {
           
            put_page(mfn_to_page(pfn));

            v->arch.guest_table = mk_pagetable(0);
        }
    }


	    /* Relinquish every page of memory. */
    relinquish_memory(d, &d->xenpage_list);
   // relinquish_memory(d, &d->page_list);
	printk("domain_relinquish_resources : Not Yet\n");
}

void arch_dump_domain_info(struct domain *d)
{
	printk("arch_dump_domain_info : Not Yet\n");
}

static inline void default_idle(void)
{
	int cpu = smp_processor_id();

	local_irq_disable();
	while ( !softirq_pending(cpu) ) {
		cpu_idle();
	}
	local_irq_enable();
}

static void continue_cpu_idle_loop(void)
{
//	int cpu = smp_processor_id();

	while(1) {
		local_irq_disable();
		cpu_idle();
		local_irq_enable();
		raise_softirq(SCHEDULE_SOFTIRQ);
			do_softirq();
	}
}

void startup_cpu_idle_loop(void)
{
	raise_softirq(SCHEDULE_SOFTIRQ);
	continue_cpu_idle_loop();
}

long arch_do_vcpu_op(int cmd, struct vcpu *v, GUEST_HANDLE(void) arg)
{
	return -ENOSYS;
}

