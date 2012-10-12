/*
 * xensetup.c
 *
 * Copyright (C) 2008 Samsung Electronics
 *          JooYoung Hwang <jooyoung.hwang@samsung.com>
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

#include <xen/config.h>
#include <xen/debug.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <asm/mm.h>
#include <xen/compile.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <asm/page.h>
#include <xen/string.h>
#include <asm/memmap.h>
#include <public/sched.h>
#include <xen/xmalloc.h>  	
#include <asm/current.h> 
#include <asm/linkage.h>
#include <xen/guest_access.h>
#include <asm/flushtlb.h>
#include <asm/irq.h>
#include <asm/trap.h>
#include <security/acm/policy_conductor.h>
#include <security/acm/acm_hooks.h>
#include <asm/pgtable.h>
#include <asm/memory.h>
#include <asm/init.h>
#include <asm/cpu-ops.h>
#include <asm/platform.h>
#include <public/version.h>
#include <security/ssm-xen/sra_func.h>
#include <xen/softirq.h>

#ifdef CONFIG_GCOV_XEN
#include <xen/gcov.h>
#endif

#define DOM_CREATE_SUCCESS	1
#define DOM_CREATE_FAIL		0

#define BANNER "\n\rXen/ARM virtual machine monitor for ARM architecture\n\r"		\
	       "Copyright (C) 2007 Samsung Electronics Co, Ltd. All Rights Reserved.\n" \


struct vcpu *idle_vcpu[NR_CPUS];

extern struct domain *dom1;

struct domain *idle_domain;
struct meminfo system_memory = {0,};

unsigned long xenheap_phys_start;
unsigned long xenheap_phys_end;

cpumask_t cpu_online_map; 

int early_boot = 1;

struct domain_addr_set {
        unsigned long   guest_memory_start;
        unsigned long   guest_memory_size;
        unsigned long   elf_image_address;
        unsigned long   elf_image_size;
        unsigned long   initrd_address;
        unsigned long   initrd_size;
        unsigned long   command_line_address;
        unsigned long   stack_start;
};

struct domain_addr_set domain_addrs[4]= {
	{
		MEMMAP_GUEST_0_START_PADDR,             // guest memory start
		MEMMAP_GUEST_0_SIZE,                    // guest memory size
		MEMMAP_GUEST_0_ELF_IMAGE_PADDR,         // elf image address
		MEMMAP_GUEST_0_ELF_MAX_SIZE,              // elf image size
		0,     // ramdisk image address
		0,          // ramdisk image size
		0,                                   // commandline
		0 
	},
	{
		MEMMAP_GUEST_1_START_PADDR,             // guest memory start
		MEMMAP_GUEST_1_SIZE,                    // guest memory size
		MEMMAP_GUEST_1_ELF_IMAGE_PADDR,         // elf image address
		MEMMAP_GUEST_1_ELF_MAX_SIZE,              // elf image size
		0,     // ramdisk image address
		0,          // ramdisk image size
		0,                                   // commandline
		0 
	},
	{
		MEMMAP_GUEST_2_START_PADDR,             // guest memory start
		MEMMAP_GUEST_2_SIZE,                    // guest memory size
		MEMMAP_GUEST_2_ELF_IMAGE_PADDR,         // elf image address
		MEMMAP_GUEST_2_ELF_MAX_SIZE,              // elf image size
		0,     // ramdisk image address
		0,          // ramdisk image size
		0,                                   // commandline
		0
	},
	{
		MEMMAP_GUEST_3_START_PADDR,             // guest memory start
		MEMMAP_GUEST_3_SIZE,                    // guest memory size
		MEMMAP_GUEST_3_ELF_IMAGE_PADDR,         // elf image address
		MEMMAP_GUEST_3_ELF_MAX_SIZE,              // elf image size
		0,     // ramdisk image address
		0,          // ramdisk image size
		0,                                   // commandline
		0
	},
};


void console_init(void)
{
        init_console();
}

void arch_get_xen_caps(xen_capabilities_info_t info)
{
	char *p = info;

	p++;

	*(p-1) = 0;

	BUG_ON((p - info) > sizeof(xen_capabilities_info_t));

}

static unsigned long find_lowest_pfn(struct meminfo *mi)
{
	int i;
	unsigned long start = 0xFFFFFFFF;

	for(i = 0; i < mi->nr_banks; i++) {
		struct memory_bank *bank = &mi->banks[i];

		if(bank->base < start) {
			start = bank->base;
		}
	}

	return start >> PAGE_SHIFT;
}

static unsigned long find_highest_pfn(struct meminfo *mi)
{
	int i;
	unsigned long end=0;

	for(i = 0; i < mi->nr_banks; i++) {
		struct memory_bank *bank = &mi->banks[i];

		if(end < bank->base + bank->size) {
			end = bank->base + bank->size;
		}
	}

	return end >> PAGE_SHIFT;
}

static void memory_setup(void)
{
	unsigned long nr_pages = 0;
	unsigned long i, s, e;
	unsigned long xen_pstart;
	unsigned long xen_pend;


        /* set page table base */
        idle_pg_table = (pde_t *) ((unsigned int) IDLE_PG_TABLE_ADDR + PAGE_OFFSET);

	/*
	 * Memory holes will be reserved during
	 * init_boot_pages().
	 */
	min_page = find_lowest_pfn(&system_memory);
	max_page = find_highest_pfn(&system_memory);

	xen_pstart = min_page << PAGE_SHIFT; 
	xen_pend = max_page << PAGE_SHIFT;

	/* Initialise boot-time allocator with all RAM situated after modules. */
	xenheap_phys_start = init_boot_allocator(__pa(&_end));
	xenheap_phys_end   = xen_pstart + (MEMMAP_XEN_DIRECTMAP_MBYTES << 20);

        nr_pages = 0;
	for ( i = 0; i < system_memory.nr_banks; i++ ) {
		nr_pages += system_memory.banks[i].size >> PAGE_SHIFT;

		/* Initialise boot heap, skipping Xen heap and dom0 modules. */
		s = system_memory.banks[i].base;
		e = s + system_memory.banks[i].size;
		
		if ( s < xenheap_phys_end )
			s = xenheap_phys_end;
		if( e > xen_pend )
			e = xen_pend;
		init_boot_pages(s, e);
	}

	total_pages = nr_pages;

	init_frametable();

	end_boot_allocator();

	/* Initialise the Xen heap, skipping RAM holes. */
	nr_pages = 0;
	for ( i = 0; i < system_memory.nr_banks; i++ ) {
		s = system_memory.banks[i].base;
		e = s + system_memory.banks[i].size;
		if ( s < xenheap_phys_start )
			s = xenheap_phys_start;
		if ( e > xenheap_phys_end )
			e = xenheap_phys_end;
		if ( s < e ) {
			nr_pages += (e - s) >> PAGE_SHIFT;
			init_xenheap_pages(s, e);
		}
	}
}

asmlinkage void start_xen(void *params)
{
	platform_setup();

	memory_setup();

	/* initialize a serial device. */
	console_init();

#if CONFIG_GCOV_XEN
	gcov_core_init();
#endif
	printk(BANNER);

#ifdef CONFIG_VMM_SECURITY
	if ( sra_init() != 0 )
	  PANIC("Error Secure Repository Agent initialization\n");
#endif

	scheduler_init();

	idle_domain = domain_create(IDLE_DOMAIN_ID, 0);

	BUG_ON(idle_domain == NULL);

	set_current(idle_domain->vcpu[0]);
	idle_vcpu[0] = current;


	paging_init();

	open_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ, new_tlbflush_clock_period);
	
	trap_init();

	/* initialize timer soft-irq */
	timer_init();

	arch_init_memory();

	init_acm();

	#ifndef DIRECT_INVOCATION_OF_T_TIMER_FN
	schedulers_start(); 
	#endif

#ifdef UNIT_TEST
	/* Unit Test Example */
	embunit_test_example();
#endif

	dom0 = domain_create(0, 0);

	if ( dom0 == NULL )
        	PANIC("Error creating domain 0\n");

	DPRINTK(3,"\n\n Construct domain 0 \n\n");

	
	if ( construct_dom0(dom0,
			domain_addrs[0].guest_memory_start,
			domain_addrs[0].guest_memory_size,
			domain_addrs[0].elf_image_address,
			domain_addrs[0].elf_image_size,
			domain_addrs[0].initrd_address,
			domain_addrs[0].initrd_size,
	                NULL) != 0)				// stack start
		PANIC("Could not set up DOM0 guest OS\n");

	DPRINTK(3," dom0 execution envirionment configuration!! \n");
	
	set_bit(_DOMF_privileged, &dom0->domain_flags);

	domain_unpause_by_systemcontroller(dom0);

	local_irq_enable();

	startup_cpu_idle_loop();
}

int get_guest_domain_address( dom0_op_t * dom0_op)
{
	unsigned int domain_id;
	unsigned int ret=0;
	dom0_op_t * op = dom0_op;
	
	domain_id = op->u.guest_image_info.domain;

	/* return guest domain loading physical address */
	op->u.guest_image_info.guest_image_address = domain_addrs[domain_id].elf_image_address;
	op->u.guest_image_info.guest_image_size    = domain_addrs[domain_id].elf_image_size;

	return ret;
}

extern int construct_guest_dom(struct domain *d,
                    unsigned long guest_start, unsigned long guest_size,
                    unsigned long image_start, unsigned long image_size,
                    unsigned long initrd_start, unsigned long initrd_size,
                    char *cmdline);

int create_guest_domain( dom0_op_t * dom0_op )
{
	unsigned int domain_id;
	unsigned long guest_va;
	struct domain *dom;

	domain_id = dom0_op->u.guest_image_info.domain;


	guest_va = dom0_op->u.guest_image_info.guest_image_address;
	DEBUG( " ==== passed guest image app virtual address is : [%08lx]\n", guest_va);

        dom = find_domain_by_id(domain_id);
        if ( dom == NULL )
	{
		//dom = domain_create(domain_id, 0);
        //	if ( dom == NULL )
	       		PANIC("Could not find the domain structure for DOM guest OS\n");
		return DOM_CREATE_FAIL;	
	}

	dom->store_port = dom0_op->u.guest_image_info.store_port;
	dom->console_port = dom0_op->u.guest_image_info.console_port;
		
	if ( construct_guest_dom( dom,
			domain_addrs[domain_id].guest_memory_start,
			domain_addrs[domain_id].guest_memory_size,
			domain_addrs[domain_id].elf_image_address,
			domain_addrs[domain_id].elf_image_size,
			domain_addrs[domain_id].initrd_address,
			domain_addrs[domain_id].initrd_size,
			NULL) != 0)           // stack start
      	        {
        	        put_domain(dom);
	        PANIC("Could not set up DOM1 guest OS\n");
			return DOM_CREATE_FAIL;	
		}
	dom0_op->u.guest_image_info.store_mfn = dom->store_mfn;
	dom0_op->u.guest_image_info.console_mfn = dom->console_mfn;

	//domain_unpause_by_systemcontroller(dom);
	
	put_domain(dom);
	return DOM_CREATE_SUCCESS;	
}
