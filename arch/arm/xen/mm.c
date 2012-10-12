/*
 * mm.c
 *
 * Copyright (C) 2008 Samsung Electronics
 *          SungKwan Heo  <sk.heo@samsung.com>
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

#include <xen/lib.h>
#include <xen/types.h>
#include <xen/cpumask.h>
#include <xen/list.h>
#include <xen/kernel.h>
#include <xen/string.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/domain_page.h>
#include <xen/irq_cpustat.h>
#include <xen/event.h>
#include <xen/iocap.h>
#include <xen/debug.h>
#include <xen/perfc.h>
#include <security/acm/acm_hooks.h>
#include <asm/page.h>
#include <asm/config.h>
#include <asm/domain.h>
#include <asm/pgtable.h>
#include <asm/flushtlb.h>
#include <asm/mm.h>
#include <asm/io.h>
#include <asm/domain.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <asm/init.h>
#include <asm/uaccess.h>
#include <asm/bitops.h>
#include <asm/memmap.h>
#include <asm/memory.h>
#include <asm/cpu-ops.h>
#include <asm/arch/io.h>

#define MEM_LOG		printf

/*
 * Both do_mmuext_op() and do_mmu_update():
 * We steal the m.s.b. of the @count parameter to indicate whether this
 * invocation of do_mmu_update() is resuming a previously preempted call.
 */
#define MMU_UPDATE_PREEMPTED          (~(~0U>>1))


#define TOGGLE_MODE() ((void)0)

/* from arch/x86/x86_32/mm.c */
unsigned int PAGE_HYPERVISOR = __PAGE_HYPERVISOR;
unsigned int PAGE_HYPERVISOR_NOCACHE = __PAGE_HYPERVISOR_NOCACHE;

static unsigned long mpt_size;

/* Used to defer flushing of memory structures. */
static struct {
#define DOP_FLUSH_TLB      (1<<0) /* Flush the local TLB.                    */
#define DOP_FLUSH_ALL_TLBS (1<<1) /* Flush TLBs of all VCPUs of current dom. */
#define DOP_RELOAD_LDT     (1<<2) /* Reload the LDT shadow mapping.          */
	unsigned int   deferred_ops;

	/* If non-NULL, specifies a foreign subject domain for some operations. */
	struct domain *foreign;
} __cacheline_aligned percpu_info[NR_CPUS];


/*
 * Returns the current foreign domain; defaults to the currently-executing
 * domain if a foreign override hasn't been specified.
 */
#define FOREIGNDOM (percpu_info[smp_processor_id()].foreign ?: current->domain)

/* Private domain structs for DOMID_XEN and DOMID_IO. */
static struct domain *dom_xen, *dom_io;

/* Frame table and its size in pages. */
struct page_info *frame_table;
unsigned long min_page, max_page;
unsigned long total_pages;


pde_t *idle_pg_table;

static int modify_pte(pte_t *, pte_t);
static int modify_pde(pde_t *, pde_t, unsigned long, unsigned long);

extern void xen_tlb_dump(void);

void register_memory_bank(unsigned long base, unsigned long size)
{
	struct memory_bank *bank;

	/*
	 * Ensure that start/size are aligned to a page boundary.
	 * Size is appropriately rounded down, start is rounded up.
	 */
	size -= base & ~PAGE_MASK;

	bank = &system_memory.banks[system_memory.nr_banks++];

	bank->base = PAGE_ALIGN(base);
	bank->size  = size & PAGE_MASK;
	bank->node  = 0;
}

void create_mapping(unsigned long *pgd_base, struct map_desc *md)
{
	unsigned long *pde;
	unsigned long flags, va, pa, end;

	pde = pgd_base + pgd_index(md->virtual);
	va = md->virtual;
	pa = md->physical;
	end = pa + md->length;

	if(((va | pa | end) & ~SECTION_MASK) == 0) {
		flags = PDE_TYPE_SECTION;
		switch(md->type) {
			case MT_RAM :
				flags |= PDE_AP_SRW_URO | PDE_CACHEABLE | PDE_BUFFERABLE | PDE_DOMAIN_HYPERVISOR;
				break;
			case MT_IO :
				flags |= PDE_AP_SRW_UNO;
				break;
		}

		do {
			*pde = (pa & SECTION_MASK) | flags;
			pa += SECTION_SIZE;
			pde++;
		} while(pa < end);
	}
}

pde_t *virt_to_xen_l2e(unsigned long v)
{
	return &idle_pg_table[l2_linear_offset(v)];
}


void __init zap_low_mappings(pde_t *base)
{
	int i;
	u32 addr;

	for (i = 0; ; i++) {
		addr = (i << L2_PAGETABLE_SHIFT);
		if (addr >= HYPERVISOR_VIRT_START)
			break;
		if (l2e_get_paddr(base[i]) != addr)
			continue;
		base[i] = l2e_empty();
	}
	update_tlbflush_clock();
	cpu_flush_tlb_all();
}


void save_ptbase(struct vcpu *v)
{
	unsigned long offset_p_v;
	unsigned long ttb_address = cpu_get_ttb();

	v->arch.guest_table.pfn   = ttb_address >> PAGE_SHIFT;

	offset_p_v = v->arch.guest_pstart - v->arch.guest_vstart;
	ttb_address = ttb_address - (unsigned long)offset_p_v;

	v->arch.guest_vtable = (intpde_t  *)ttb_address;
}

void write_ptbase(struct vcpu *v)
{
	update_tlbflush_clock();
	cpu_switch_ttb(pagetable_get_paddr(v->arch.guest_table));
}

/**
 * \brief initialize page table of xen.
 * creation of machine2physical table and setup page tables of guest domains to access the table with read-only permission.
 * mapping of io registers, exception table, and flash memory area.
 */

#if 1
void paging_init(void)
{
	int 		i;
	int		mpt_order;
	int		mpt_nr_pages;
	void 		*ioremap_pt;
	void		*mpt_pt;
	void		*vector_pt;
	pte_t 		*excvec_l1e, *mpt_l1e;
	struct page_info *pg;

	idle_vcpu[0]->arch.monitor_table = mk_pagetable(__pa(idle_pg_table));

	/* ASSUMPTION: memory size is 2^n, MPT size < 1MB */
	mpt_size 	= (max_page-min_page) * BYTES_PER_LONG;
	mpt_nr_pages	= mpt_size >> PAGE_SHIFT;
	mpt_order	= LOG_2(mpt_nr_pages);
    
	if ( (pg = alloc_domheap_pages(NULL, mpt_order, 0)) == NULL )
		PANIC("Not enough memory to bootstrap Xen.\n");

	/* Read/Write MPT */
	mpt_pt = alloc_xenheap_page();
	clear_page(mpt_pt);

	for( i = 0; i < mpt_nr_pages; i++ ) {
		mpt_l1e = (pte_t *) mpt_pt + pte_index(RDWR_MPT_VIRT_START+i*PAGE_SIZE);
		*mpt_l1e = l1e_from_paddr(page_to_phys(pg)+i*PAGE_SIZE, __L1_PAGE_HYPERVISOR_SMALL);
	}


	vector_pt = alloc_xenheap_page();
	clear_page(vector_pt);

        /* L1 page table for exception vector */
	excvec_l1e = (pte_t *) vector_pt + pte_index(EXCEPTION_VEC_VIRT_START );
	*excvec_l1e = l1e_from_paddr(PHYS_OFFSET, __L1_PAGE_HYPERVISOR_SMALL | PTE_SMALL_AP_URO_SRW);
#ifdef CONFIG_RAM_START_ZERO
	for(i=1; i<256; i++) {
		*(excvec_l1e+pte_index(0+i*PAGE_SIZE)) =l1e_from_paddr(i*PAGE_SIZE, __L1_PAGE_HYPERVISOR_SMALL | PTE_SMALL_AP_URO_SRW);
	}
#endif
	idle_pg_table[l2_linear_offset(EXCEPTION_VEC_VIRT_START)] =
        l2e_from_page(virt_to_page(vector_pt), __L2_PAGE_HYPERVISOR_TABLE);

	cpu_flush_cache_page((unsigned long)mpt_pt);


	idle_pg_table[l2_linear_offset(RDWR_MPT_VIRT_START)] = 
		l2e_from_page(virt_to_page(mpt_pt), __L2_PAGE_HYPERVISOR_TABLE);

	cpu_flush_cache_page((unsigned long) &idle_pg_table[l2_linear_offset(RDWR_MPT_VIRT_START)]);


    /* Read-only MPT */ 
    mpt_pt = alloc_xenheap_page();
    clear_page(mpt_pt);

    for( i = 0; i < mpt_nr_pages; i++ )
    {
        mpt_l1e = (pte_t *) mpt_pt + pte_index(RO_MPT_VIRT_START+i*PAGE_SIZE);
        *mpt_l1e = l1e_from_paddr(page_to_phys(pg)+i*PAGE_SIZE, __L1_PAGE_USER_RO_SMALL);
    }

    cpu_flush_cache_page((unsigned long)mpt_pt);

    idle_pg_table[l2_linear_offset(RO_MPT_VIRT_START)] = 
        l2e_from_page(virt_to_page(mpt_pt), __L2_PAGE_HYPERVISOR_TABLE);

    cpu_flush_cache_page((unsigned long) &idle_pg_table[l2_linear_offset(RO_MPT_VIRT_START)]);


    /* Fill with an obvious debug pattern. */
	/* TODO: set up machine to physical table. */
    for ( i = min_page; i < min_page+(mpt_size / BYTES_PER_LONG); i++)
        set_pfn_from_mfn(i, 0x55555555);


    /* TODO: Create page tables for ioremap(). */
    DPRINTK(3, "Update page tables for ioremap\n");
    
    ioremap_pt = alloc_xenheap_page();
    clear_page(ioremap_pt);
}
#endif

/* seutp a page table entry for idle domain to access domain shared info */
void set_idle_shared_info(struct domain *d)
{
	static void *shared_info_map_pt;
	pte_t *shared_info_l1e;
	unsigned long shared_info_vaddr;

	shared_info_vaddr = DOM_SHARED_INFO_PAGE_BASE_VADDR + (d->domain_id << PAGE_SHIFT);

	if( d->domain_id == 0 )	/* first call */
	{
		unsigned long pte_old, pte_max;

		shared_info_map_pt = alloc_xenheap_page();
		clear_page(shared_info_map_pt);

		pte_old = (unsigned long)idle_pg_table[l2_linear_offset(shared_info_vaddr)].l2;
		pte_old &= 0xFFF00000;
		pte_max = pte_old + 0x100000;

		shared_info_l1e = (pte_t *)shared_info_map_pt;

		while(pte_old < pte_max) {
			*shared_info_l1e = l1e_from_paddr(pte_old, __L1_PAGE_USER_SMALL);
			shared_info_l1e++;

			pte_old += 0x1000;
		}

		/* L2 page table for shared info map */
		idle_pg_table[l2_linear_offset(shared_info_vaddr)] =         \
			l2e_from_page(virt_to_page(shared_info_map_pt), __L2_PAGE_HYPERVISOR_TABLE);
	}
	
	/* L1 page table for shared info map */
	shared_info_l1e = (pte_t *) shared_info_map_pt+ pte_index(shared_info_vaddr);
	*shared_info_l1e = l1e_from_paddr(__pa(d->shared_info), __L1_PAGE_USER_SMALL);

	update_tlbflush_clock();
	cpu_flush_tlb_all();

	cpu_flush_cache_all();
}



/**
 * \brief initializes frame table.
 */
void init_frametable(void)
{
	unsigned long pfn;
	unsigned long nr_pages;


	/* number of pages required for frame table */
	nr_pages  = PFN_UP((max_page - min_page) * sizeof(struct page_info));

	pfn = alloc_boot_pages(nr_pages, 1);
	if ( pfn == 0 ) {
		PANIC("Not enough memory for frame table\n");
	}

	frame_table = (struct page_info *)(__va(pfn << PAGE_SHIFT));

	memset(frame_table, 0, nr_pages << PAGE_SHIFT);
}

/**
 * \brief updates the frame table regarding M2P table's pages.
 */
void subarch_init_memory(struct domain *dom_xen)
{
    unsigned long m2p_start_mfn;
    unsigned int i, j;

    /*
     * We are rather picky about the layout of 'struct page_info'. The
     * count_info and domain fields must be adjacent, as we perform atomic
     * 64-bit operations on them. Also, just for sanity, we assert the size
     * of the structure here.
     */
    if ( (offsetof(struct page_info, u.inuse._domain) != 
          (offsetof(struct page_info, count_info) + sizeof(u32))) ||
         ((offsetof(struct page_info, count_info) & 7) != 0) ||
         (sizeof(struct page_info) != 24) )
    {
        printk("Weird page_info layout (%ld,%ld,%d)\n",
               offsetof(struct page_info, count_info),
               offsetof(struct page_info, u.inuse._domain),
               sizeof(struct page_info));
        BUG();
    }

    /* M2P table is mappable read-only by privileged domains. */
    for ( i = 0; i < (mpt_size >> L2_PAGETABLE_SHIFT); i++ )
    {
        m2p_start_mfn = l2e_get_pfn(
            idle_pg_table[l2_linear_offset(RDWR_MPT_VIRT_START) + i]);
        for ( j = 0; j < L2_PAGETABLE_ENTRIES; j++ )
        {
            struct page_info *page = pfn_to_page(m2p_start_mfn + j);
            page->count_info = PGC_allocated | 1;
            /* Ensure it's only mapped read-only by domains. */
            page->u.inuse.type_info = PGT_gdt_page | 1;
            page_set_owner(page, dom_xen);
        }
    }
}

/**
 * \brief update the frame table according to the 
 */
void arch_init_memory(void)
{
    memset(percpu_info, 0, sizeof(percpu_info));

    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = alloc_domain();
    atomic_set(&dom_xen->refcnt, 1);
    dom_xen->domain_id = DOMID_XEN;

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = alloc_domain();
    atomic_set(&dom_io->refcnt, 1);
    dom_io->domain_id = DOMID_IO;

    subarch_init_memory(dom_xen);
}

#ifdef VVERBOSE
int ptwr_debug = 0x0;
#define PTWR_PRINTK(_f, _a...) \
 do { if ( unlikely(ptwr_debug) ) printk( _f , ## _a ); } while ( 0 )
#define PTWR_PRINT_WHICH (which ? 'I' : 'A')
#else
#define PTWR_PRINTK(_f, _a...) ((void)0)
#endif


#ifdef PERF_ARRAYS

/**************** writeable pagetables profiling functions *****************/

#define ptwr_eip_buckets        256

int ptwr_eip_stat_threshold[] = {1, 10, 50, 100, L1_PAGETABLE_ENTRIES};

#define ptwr_eip_stat_thresholdN (sizeof(ptwr_eip_stat_threshold)/sizeof(int))

struct {
    unsigned long eip;
    domid_t       id;
    u32           val[ptwr_eip_stat_thresholdN];
} typedef ptwr_eip_stat_t;

ptwr_eip_stat_t ptwr_eip_stats[ptwr_eip_buckets];

static inline unsigned int ptwr_eip_stat_hash( unsigned long eip, domid_t id )
{
    return (((unsigned long) id) ^ eip ^ (eip>>8) ^ (eip>>16) ^ (eip>24)) % 
        ptwr_eip_buckets;
}

static void ptwr_eip_stat_inc(u32 *n)
{
    int i, j;

    if ( ++(*n) != 0 )
        return;

    *n = ~0;

    /* Re-scale all buckets. */
    for ( i = 0; i <ptwr_eip_buckets; i++ )
        for ( j = 0; j < ptwr_eip_stat_thresholdN; j++ )
            ptwr_eip_stats[i].val[j] >>= 1;
}

static void ptwr_eip_stat_update(unsigned long eip, domid_t id, int modified)
{
    int i, j, b;

    i = b = ptwr_eip_stat_hash(eip, id);

    do
    {
        if ( !ptwr_eip_stats[i].eip )
        {
            /* doesn't exist */
            ptwr_eip_stats[i].eip = eip;
            ptwr_eip_stats[i].id = id;
            memset(ptwr_eip_stats[i].val,0, sizeof(ptwr_eip_stats[i].val));
        }

        if ( ptwr_eip_stats[i].eip == eip )
        {
            for ( j = 0; j < ptwr_eip_stat_thresholdN; j++ )
                if ( modified <= ptwr_eip_stat_threshold[j] )
                    break;
            BUG_ON(j >= ptwr_eip_stat_thresholdN);
            ptwr_eip_stat_inc(&ptwr_eip_stats[i].val[j]);
            return;
        }

        i = (i+1) % ptwr_eip_buckets;
    }
    while ( i != b );
   
    printk("ptwr_eip_stat: too many EIPs in use!\n");
    
    ptwr_eip_stat_print();
    ptwr_eip_stat_reset();
}

void ptwr_eip_stat_reset(void)
{
    memset(ptwr_eip_stats, 0, sizeof(ptwr_eip_stats));
}

void ptwr_eip_stat_print(void)
{
    struct domain *e;
    domid_t d;
    int i, j;

    for_each_domain( e )
    {
        d = e->domain_id;

        for ( i = 0; i < ptwr_eip_buckets; i++ )
        {
            if ( ptwr_eip_stats[i].eip && ptwr_eip_stats[i].id != d )
                continue;

            printk("D %d  eip %08lx ",
                   ptwr_eip_stats[i].id, ptwr_eip_stats[i].eip);

            for ( j = 0; j < ptwr_eip_stat_thresholdN; j++ )
                printk("<=%u %4u \t",
                       ptwr_eip_stat_threshold[j],
                       ptwr_eip_stats[i].val[j]);
            printk("\n");
        }
    }
}

#else /* PERF_ARRAYS */

#define ptwr_eip_stat_update(eip, id, modified) ((void)0)

#endif

#if 0

int ptwr_init(struct domain *d)
{
	void *x = alloc_xenheap_page();
	void *y = alloc_xenheap_page();

	if ( (x == NULL) || (y == NULL) ) {
		free_xenheap_page(x);
		free_xenheap_page(y);

		return -ENOMEM;
	}

	d->arch.ptwr[PTWR_PT_ACTIVE].page   = x;
	d->arch.ptwr[PTWR_PT_INACTIVE].page = y;

	return 0;
}

void ptwr_destroy(struct domain *d)
{
	LOCK_BIGLOCK(d);

	cleanup_writable_pagetable(d);
	
	UNLOCK_BIGLOCK(d);

	free_xenheap_page(d->arch.ptwr[PTWR_PT_ACTIVE].page);
	free_xenheap_page(d->arch.ptwr[PTWR_PT_INACTIVE].page);
}

void cleanup_writable_pagetable(struct domain *d)
{
	if ( unlikely(!VM_ASSIST(d, VMASST_TYPE_writable_pagetables)) )
		return;

        if ( d->arch.ptwr[PTWR_PT_ACTIVE].l1va )
		ptwr_flush(d, PTWR_PT_ACTIVE);
        if ( d->arch.ptwr[PTWR_PT_INACTIVE].l1va )
		ptwr_flush(d, PTWR_PT_INACTIVE);
}

/* Flush the given writable p.t. page and write-protect it again. */
void ptwr_flush(struct domain *d, const int which)
{
    unsigned long l1va;
    pte_t *pl1e, pte, *ptep;
    pde_t *pl2e;
    unsigned int   modified;

    //ASSERT(!shadow_mode_enabled(d));

    if ( unlikely(d->arch.ptwr[which].vcpu != current) )
        /* Don't use write_ptbase: it may switch to guest_user on x86/64! */
        cpu_switch_ttb(pagetable_get_paddr(
            d->arch.ptwr[which].vcpu->arch.guest_table));
    else
        TOGGLE_MODE();

    l1va = d->arch.ptwr[which].l1va;
    ptep = (pte_t *)&linear_pg_table[l1_linear_offset(l1va)];

    /*
     * STEP 1. Write-protect the p.t. page so no more updates can occur.
     */

    //if ( unlikely(__get_user(pte.l1, &ptep->l1)) )
    if ( unlikely(get_user(pte.l1, &ptep->l1)) )
    {
        MEM_LOG("ptwr: Could not read pte at %p", ptep);
        /*
         * Really a bug. We could read this PTE during the initial fault,
         * and pagetables can't have changed meantime.
         */
        BUG();
    }
    PTWR_PRINTK("[%c] disconnected_l1va at %p is %"PRIpte"\n",
                PTWR_PRINT_WHICH, ptep, l1e_get_intpte(pte));
    l1e_remove_flags(pte, _L1_PAGE_RW_USER);
    l1e_add_flags(pte, _L1_PAGE_RO_USER);

    /* Write-protect the p.t. page in the guest page table. */
    //if ( unlikely(__put_user(pte, ptep)) )
    if ( unlikely(put_user(pte, ptep)) )
    {
        MEM_LOG("ptwr: Could not update pte at %p", ptep);
        /*
         * Really a bug. We could write this PTE during the initial fault,
         * and pagetables can't have changed meantime.
         */
        BUG();
    }

    /* Ensure that there are no stale writable mappings in any TLB. */
    /* NB. INVLPG is a serialising instruction: flushes pending updates. */
    flush_tlb_one_mask(d->domain_dirty_cpumask, l1va);
    PTWR_PRINTK("[%c] disconnected_l1va at %p now %"PRIpte"\n",
                PTWR_PRINT_WHICH, ptep, l1e_get_intpte(pte));

    /*
     * STEP 2. Validate any modified PTEs.
     */

    if ( likely(d == current->domain) )
    {
        pl1e = map_domain_page(l1e_get_pfn(pte));
        modified = revalidate_l1(d, pl1e, d->arch.ptwr[which].page);
        unmap_domain_page(pl1e);
        perfc_incr_histo(wpt_updates, modified, PT_UPDATES);
        ptwr_eip_stat_update(d->arch.ptwr[which].eip, d->domain_id, modified);
        d->arch.ptwr[which].prev_nr_updates = modified;
    }
    else
    {
        /*
         * Must make a temporary global mapping, since we are running in the
         * wrong address space, so no access to our own mapcache.
         */
        pl1e = map_domain_page_global(l1e_get_pfn(pte));
        modified = revalidate_l1(d, pl1e, d->arch.ptwr[which].page);
        unmap_domain_page_global(pl1e);
    }

    /*
     * STEP 3. Reattach the L1 p.t. page into the current address space.
     */

    if ( which == PTWR_PT_ACTIVE )
    {
        pl2e = &__linear_l2_table[d->arch.ptwr[which].l2_idx];
        l2e_add_flags(*pl2e, _L2_PAGE_PRESENT); 
    }

    /*
     * STEP 4. Final tidy-up.
     */

    d->arch.ptwr[which].l1va = 0;

    if ( unlikely(d->arch.ptwr[which].vcpu != current) )
        write_ptbase(current);
    else 
        TOGGLE_MODE();
}
#else
void cleanup_writable_pagetable(struct domain *d){return ;}
int ptwr_init(struct domain *d){return 0;}
void ptwr_destroy(struct domain *d){return;}
void ptwr_flush(struct domain *d, const int which){return;}
#endif

static int get_page_from_pagenr(unsigned long page_nr, struct domain *d)
{
    struct page_info *page;
    
    if ( unlikely(!pfn_valid(page_nr))) {
		MEM_LOG("Could not get page ref for pfn %lx", page_nr);
        return 0;
    }
    page = pfn_to_page(page_nr);

    if ( unlikely(!get_page(page, d)) )
    {
        MEM_LOG("Could not get page ref for pfn %lx", page_nr);
        return 0;
    }

    return 1;
}


static int get_page_and_type_from_pagenr(unsigned long page_nr, 
                                         unsigned long type,
                                         struct domain *d)
{
    struct page_info *page = pfn_to_page(page_nr);

    if ( unlikely(!get_page_from_pagenr(page_nr, d)) )
        return 0;

    if ( unlikely(!get_page_type(page, type)) )
    {
        put_page(page);
        return 0;
    }

    return 1;
}

int get_page_from_pte(pte_t pte, struct domain *d)
{
    unsigned long mfn = l1e_get_pfn(pte);
    struct page_info *page = pfn_to_page(mfn);
    int okay;


#if 0
    if ((mfn >= 0x40000) && (mfn < 0x60000))
        return 1;
#endif

    if ( !(l1e_get_flags(pte) & _L1_PAGE_PRESENT) )
        return 1;

    if ( unlikely(!pfn_valid(mfn)) ||
         unlikely(page_get_owner(page) == dom_io) )
    {
        /* DOMID_IO reverts to caller for privilege checks. */
        if ( d == dom_io )
            d = current->domain;

        /* No reference counting for out-of-range I/O pages. */
        if ( !pfn_valid(mfn) )
            return 1;

        d = dom_io;
    }

    /* check if the page table is xen or domain and use a correct _PAGE_RW flag */
    okay = ((l1e_get_flags(pte) & _L1_PAGE_RW_USER) ?
            get_page_and_type(page, d, PGT_writable_page) :
            get_page(page, d));
    if ( !okay )
    {
        MEM_LOG("Error getting mfn %lx (pfn %lx) from L1 entry %" PRIpte
                " for dom%d",
                mfn, get_pfn_from_mfn(mfn), l1e_get_intpte(pte), d->domain_id);
    }

    return okay;
}


/* NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'. */
static int 
get_page_from_l2e(
    pde_t l2e, unsigned long pfn,
    struct domain *d, unsigned long vaddr)
{
    int rc;

    ASSERT(!shadow_mode_refcounts(d));

    if ( !(l2e_get_flags(l2e) & _L2_PAGE_PRESENT) )
        return 1;

    if ( unlikely((l2e_get_flags(l2e) & L2_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L2 flags %x", l2e_get_flags(l2e) & L2_DISALLOW_MASK);
        return 0;
    }

    vaddr >>= L2_PAGETABLE_SHIFT;
    vaddr <<= PGT_va_shift;
    rc = get_page_and_type_from_pagenr(
        l2e_get_pfn(l2e), PGT_l1_page_table | vaddr, d);

#if CONFIG_PAGING_LEVELS == 2
    if ( unlikely(!rc) )
        rc = get_linear_pagetable(l2e, pfn, d);
#endif
    return rc;
}


void put_page_from_l1e(pte_t l1e, struct domain *d)
{
    unsigned long    pfn  = l1e_get_pfn(l1e);
    struct page_info *page = pfn_to_page(pfn);
    struct domain   *e;

    if ( !(l1e_get_flags(l1e) & _L1_PAGE_PRESENT) || !pfn_valid(pfn) )
        return;

    e = page_get_owner(page);

    /*
     * Check if this is a mapping that was established via a grant reference.
     * If it was then we should not be here: we require that such mappings are
     * explicitly destroyed via the grant-table interface.
     * 
     * The upshot of this is that the guest can end up with active grants that
     * it cannot destroy (because it no longer has a PTE to present to the
     * grant-table interface). This can lead to subtle hard-to-catch bugs,
     * hence a special grant PTE flag can be enabled to catch the bug early.
     * 
     * (Note that the undestroyable active grants are not a security hole in
     * Xen. All active grants can safely be cleaned up when the domain dies.)
     */
    if ( (l1e_get_flags(l1e) & _PAGE_GNTTAB) &&
         !(d->domain_flags & (DOMF_shutdown|DOMF_dying)) )
    {
        MEM_LOG("Attempt to implicitly unmap a granted PTE %" PRIpte,
                l1e_get_intpte(l1e));
        domain_crash(d);
    }

    // [TODO]
	//  - check if the page table is xen or domain and use a correct _PAGE_RW flag
	//
    if ( l1e_get_flags(l1e) & _L1_PAGE_RW_USER )
    {
        put_page_and_type(page);
    }
    else
    {
        put_page(page);
    }
}


/*
 * NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'.
 * Note also that this automatically deals correctly with linear p.t.'s.
 */
static void put_page_from_l2e(pde_t l2e, unsigned long pfn)
{
    if ( (l2e_get_flags(l2e) & _L2_PAGE_PRESENT) && 
         (l2e_get_pfn(l2e) != pfn) )
        put_page_and_type(pfn_to_page(l2e_get_pfn(l2e)));
}


static int alloc_page_table(struct page_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_pfn(page);
    pte_t *pl1e;
    int            i;

    pl1e = map_domain_page(pfn);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l1_slot(i) &&
             unlikely(!get_page_from_pte(pl1e[i], d)) )
            goto fail;

    unmap_domain_page(pl1e);
    return 1;

 fail:
    MEM_LOG("Failure in alloc_page_table: entry %d", i);
    while ( i-- > 0 )
        if ( is_guest_l1_slot(i) )
            put_page_from_l1e(pl1e[i], d);

    unmap_domain_page(pl1e);
    return 0;
}


#define create_pae_xen_mappings(pl3e) (1)
#define l1_backptr(bp,l2o,l2t)                                   \
    ({ *(bp) = (unsigned long)(l2o) << L2_PAGETABLE_SHIFT; 1; })


static int alloc_page_dir(struct page_info *page, unsigned long type)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_pfn(page);
    unsigned long  vaddr;
    pde_t *pl2e;
    int            i;

    pl2e = map_domain_page(pfn);

    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
    {
        if ( !l1_backptr(&vaddr, i, type) )
            goto fail;
        if ( is_guest_l2_slot(type, i) &&
             unlikely(!get_page_from_l2e(pl2e[i], pfn, d, vaddr)) )
            goto fail;
    }

    /* Xen private mappings. */
    memcpy(&pl2e[L2_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[L2_PAGETABLE_FIRST_XEN_SLOT],
           L2_PAGETABLE_XEN_SLOTS * sizeof(pde_t));
    pl2e[pde_index(LINEAR_PT_VIRT_START)] =
        l2e_from_pfn(pfn, __PAGE_HYPERVISOR);
    for ( i = 0; i < PDPT_L2_ENTRIES; i++ )
        pl2e[pde_index(PERDOMAIN_VIRT_START) + i] =
            l2e_from_page(
                virt_to_page(page_get_owner(page)->arch.mm_perdomain_pt) + i,
                __PAGE_HYPERVISOR);
//#endif

    unmap_domain_page(pl2e);
    return 1;

 fail:
    MEM_LOG("Failure in alloc_l2_table: entry %d", i);
    while ( i-- > 0 )
        if ( is_guest_l2_slot(type, i) )
            put_page_from_l2e(pl2e[i], pfn);

    unmap_domain_page(pl2e);
    return 0;
}


static void free_page_table(struct page_info *page)
{
	int 		i;
	pte_t		*pte;
	u32		pfn; 
	struct domain	*d;

	pfn = page_to_pfn(page);
	d   = page_get_owner(page);

	pte = map_domain_page(pfn);

	for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
		if ( is_guest_l1_slot(i) )
			put_page_from_l1e(pte[i], d);

	unmap_domain_page(pte);
}


static void free_page_dir(struct page_info *page)
{
	int 	i;
	pde_t 	*pde;
	u32	pfn = page_to_pfn(page);

	pfn = page_to_pfn(page);
	pde = map_domain_page(pfn);

	for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
		if ( is_guest_l2_slot(page->u.inuse.type_info, i) )
			put_page_from_l2e(pde[i], pfn);

	unmap_domain_page(pde);
}



int alloc_page_type(struct page_info *page, unsigned long type)
{
	switch ( type & PGT_type_mask ) {
		case PGT_l1_page_table:
			return alloc_page_table(page);

		case PGT_l2_page_table:
			return alloc_page_dir(page, type);

		default:
			printk(	"Bad type in alloc_page_type %lx t=%" PRtype_info " c=%x\n", 
				type, page->u.inuse.type_info,
       	       			page->count_info);
			BUG();
	}

	return 0;
}


void free_page_type(struct page_info *page, unsigned long type)
{
	struct domain *owner;
	
	owner = page_get_owner(page);

	if ( likely(owner != NULL) ) {
        /*
         * We have to flush before the next use of the linear mapping
         * (e.g., update_va_mapping()) or we could end up modifying a page
         * that is no longer a page table (and hence screw up ref counts).
         */
	        percpu_info[smp_processor_id()].deferred_ops |= DOP_FLUSH_ALL_TLBS;
	}

	switch ( type & PGT_type_mask ) {
		case PGT_l1_page_table:
			free_page_table(page);
			break;

		case PGT_l2_page_table:
			free_page_dir(page);
			break;

		default:
			printk(	"%s: type %lx pfn %lx\n",__FUNCTION__,
				type, page_to_pfn(page));
			BUG();
	}
}


void put_page_type(struct page_info *page)
{
    unsigned long nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x - 1;

        ASSERT((x & PGT_count_mask) != 0);

        /*
         * The page should always be validated while a reference is held. The 
         * exception is during domain destruction, when we forcibly invalidate 
         * page-table pages if we detect a referential loop.
         * See domain.c:relinquish_list().
         */
        ASSERT((x & PGT_validated) || 
               test_bit(_DOMF_dying, &page_get_owner(page)->domain_flags));

        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            /* Record TLB information for flush later. Races are harmless. */
            page->tlbflush_timestamp = tlbflush_current_time();
            
            if ( unlikely((nx & PGT_type_mask) <= PGT_l4_page_table) &&
                 likely(nx & PGT_validated) )
            {
                /*
                 * Page-table pages must be unvalidated when count is zero. The
                 * 'free' is safe because the refcnt is non-zero and validated
                 * bit is clear => other ops will spin or fail.
                 */
                if ( unlikely((y = cmpxchg_u32((u32 *) &page->u.inuse.type_info, (u32) x, 
                                               (u32) x & ~PGT_validated)) != x) )
                    goto again;
                /* We cleared the 'valid bit' so we do the clean up. */
                free_page_type(page, x);
                /* Carry on, but with the 'valid bit' now clear. */
                x  &= ~PGT_validated;
                nx &= ~PGT_validated;
            }
        }
        else if ( unlikely(((nx & (PGT_pinned | PGT_count_mask)) == 
                            (PGT_pinned | 1)) &&
                           ((nx & PGT_type_mask) != PGT_writable_page)) )
        {
            /* Page is now only pinned. Make the back pointer mutable again. */
            nx |= PGT_va_mutable;
        }
    }
    while ( unlikely((y = cmpxchg_u32((u32 *)&page->u.inuse.type_info, (u32) x, (u32) nx)) != x) );
}


int get_page_type(struct page_info *page, unsigned long type)
{
    unsigned long nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            MEM_LOG("Type count overflow on pfn %lx", page_to_pfn(page));
            return 0;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            if ( (x & (PGT_type_mask|PGT_va_mask)) != type )
            {
                if ( (x & PGT_type_mask) != (type & PGT_type_mask) )
                {
                    /*
                     * On type change we check to flush stale TLB
                     * entries. This may be unnecessary (e.g., page
                     * was GDT/LDT) but those circumstances should be
                     * very rare.
                     */
                    cpumask_t mask =
                        page_get_owner(page)->domain_dirty_cpumask;
                    tlbflush_filter(mask, page->tlbflush_timestamp);

                    if ( unlikely(!cpus_empty(mask)) )
                    {
                        perfc_incrc(need_flush_tlb_flush);
                        flush_tlb_mask(mask);
                    }
                }

                /* We lose existing type, back pointer, and validity. */
                nx &= ~(PGT_type_mask | PGT_va_mask | PGT_validated);
                nx |= type;

                /* No special validation needed for writable pages. */
                /* Page tables and GDT/LDT need to be scanned for validity. */
                if ( type == PGT_writable_page )
                    nx |= PGT_validated;
            }
        }
        else
        {
            if ( unlikely((x & (PGT_type_mask|PGT_va_mask)) != type) )
            {
                if ( unlikely((x & PGT_type_mask) != (type & PGT_type_mask) ) )
                {
                    if ( current->domain == page_get_owner(page) )
                    {
                        /*
                         * This ensures functions like set_gdt() see up-to-date
                         * type info without needing to clean up writable p.t.
                         * state on the fast path.
                         */
                        LOCK_BIGLOCK(current->domain);
                        cleanup_writable_pagetable(current->domain);
                        y = page->u.inuse.type_info;
                        UNLOCK_BIGLOCK(current->domain);
                        /* Can we make progress now? */
                        if ( ((y & PGT_type_mask) == (type & PGT_type_mask)) ||
                             ((y & PGT_count_mask) == 0) )
                            goto again;
                    }
                    if ( ((x & PGT_type_mask) != PGT_l2_page_table) ||
                         ((type & PGT_type_mask) != PGT_l1_page_table) )
                        MEM_LOG("Bad type (saw %" PRtype_info
                                " != exp %" PRtype_info ") "
                                "for mfn %lx (pfn %lx)",
                                x, type, page_to_pfn(page),
                                get_pfn_from_mfn(page_to_pfn(page)));
                    return 0;
                }
                else if ( (x & PGT_va_mask) == PGT_va_mutable )
                {
                    /* The va backpointer is mutable, hence we update it. */
                    nx &= ~PGT_va_mask;
                    nx |= type; /* we know the actual type is correct */
                }
                else if ( ((type & PGT_va_mask) != PGT_va_mutable) &&
                          ((type & PGT_va_mask) != (x & PGT_va_mask)) )
                {
                    /* This table is possibly mapped at multiple locations. */
                    nx &= ~PGT_va_mask;
                    nx |= PGT_va_unknown;
                }
            }
            if ( unlikely(!(x & PGT_validated)) )
            {
                /* Someone else is updating validation of this page. Wait... */
                while ( (y = page->u.inuse.type_info) == x )
                    cpu_relax();
                goto again;
            }
        }
    }
    while ( unlikely((y = cmpxchg_u32((u32 *) &page->u.inuse.type_info, (u32) x, (u32) nx)) != x) );

    if ( unlikely(!(nx & PGT_validated)) )
    {
        /* Try to validate page type; drop the new reference on failure. */
        if ( unlikely(!alloc_page_type(page, type)) )
        {
            MEM_LOG("Error while validating mfn %lx (pfn %lx) for type %"
                    PRtype_info ": caf=%08x taf=%" PRtype_info,
                    page_to_pfn(page), get_pfn_from_mfn(page_to_pfn(page)),
                    type, page->count_info, page->u.inuse.type_info);
            /* Noone else can get a reference. We hold the only ref. */
            page->u.inuse.type_info = 0;
            return 0;
        }

        /* Noone else is updating simultaneously. */
        __set_bit(_PGT_validated, &page->u.inuse.type_info);
    }

    return 1;
}

#define find_first_set_bit(word) (ffs(word)-1)

static inline cpumask_t vcpumask_to_pcpumask(
    struct domain *d, unsigned long vmask)
{
    unsigned int vcpu_id;
    cpumask_t    pmask = CPU_MASK_NONE;
    struct vcpu *v;

    while ( vmask != 0 )
    {
        vcpu_id = find_first_set_bit(vmask);
        vmask &= ~(1UL << vcpu_id);
        if ( (vcpu_id < MAX_VIRT_CPUS) &&
             ((v = d->vcpu[vcpu_id]) != NULL) )
            cpus_or(pmask, pmask, v->vcpu_dirty_cpumask);
    }

    return pmask;
}


static void process_deferred_ops(unsigned int cpu)
{
    unsigned int deferred_ops;

    deferred_ops = percpu_info[cpu].deferred_ops;
    percpu_info[cpu].deferred_ops = 0;

    if ( deferred_ops & (DOP_FLUSH_ALL_TLBS|DOP_FLUSH_TLB) )
    {

        if ( deferred_ops & DOP_FLUSH_ALL_TLBS )
            flush_tlb_mask(d->domain_dirty_cpumask);
        else
            local_flush_tlb();
    }

    if ( unlikely(percpu_info[cpu].foreign != NULL) )
    {
        put_domain(percpu_info[cpu].foreign);
        percpu_info[cpu].foreign = NULL;
    }
}


/*******************************************************************/

/* Re-validate a given p.t. page, given its prior snapshot */
int revalidate_l1(
    struct domain *d, pte_t *l1page, pte_t *snapshot)
{
    pte_t ol1e, nl1e;
    int modified = 0, i;

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
    {
        ol1e = snapshot[i];
        nl1e = l1page[i];

        if ( likely(l1e_get_intpte(ol1e) == l1e_get_intpte(nl1e)) )
            continue;

        /* Update number of entries modified. */
        modified++;

        /*
         * Fast path for PTEs that have merely been write-protected
         * (e.g., during a Unix fork()). A strict reduction in privilege.
         */
        if ( likely(l1e_get_intpte(ol1e) == (l1e_get_intpte(nl1e)|_L1_PAGE_RW_USER)) )
        {
            if ( likely(l1e_get_flags(nl1e) & _L1_PAGE_PRESENT) )
                put_page_type(pfn_to_page(l1e_get_pfn(nl1e)));
            continue;
        }

        if ( unlikely(!get_page_from_pte(nl1e, d)) )
        {
            /*
             * Make the remaining p.t's consistent before crashing, so the
             * reference counts are correct.
             */
            memcpy(&l1page[i], &snapshot[i],
                   (L1_PAGETABLE_ENTRIES - i) * sizeof(pte_t));

            /* Crash the offending domain. */
            MEM_LOG("ptwr: Could not revalidate l1 page");
            domain_crash(d);
            break;
        }
        
        put_page_from_l1e(ol1e, d);
    }

    return modified;
}



static int set_foreigndom(unsigned int cpu, domid_t domid)
{
    struct domain *e, *d = current->domain;
    int okay = 1;

    if ( (e = percpu_info[cpu].foreign) != NULL )
        put_domain(e);
    percpu_info[cpu].foreign = NULL;
    
    if ( domid == DOMID_SELF )
        goto out;

    if ( !IS_PRIV(d) )
    {
        switch ( domid )
        {
        case DOMID_IO:
            get_knownalive_domain(dom_io);
            percpu_info[cpu].foreign = dom_io;
            break;
        default:
            MEM_LOG("Dom %u cannot set foreign dom", d->domain_id);
            okay = 0;
            break;
        }
    }
    else
    {
        percpu_info[cpu].foreign = e = find_domain_by_id(domid);
        if ( e == NULL )
        {
            switch ( domid )
            {
            case DOMID_XEN:
                get_knownalive_domain(dom_xen);
                percpu_info[cpu].foreign = dom_xen;
                break;
            case DOMID_IO:
                get_knownalive_domain(dom_io);
                percpu_info[cpu].foreign = dom_io;
                break;
            default:
                MEM_LOG("Unknown domain '%u'", domid);
                okay = 0;
                break;
            }
        }
    }

 out:
    return okay;
}



int do_mmuext_op(mmuext_op_t *uops, u32 count, u32 *pdone, u32 foreigndom)
{
    struct mmuext_op op;
    int rc = 0, i = 0, okay, cpu = smp_processor_id();
    unsigned long mfn, type, done = 0;
    struct page_info *page;
    struct vcpu *v = current;
    struct domain *d = v->domain;
    const int zero = 0;

    LOCK_BIGLOCK(d);

    cleanup_writable_pagetable(d);

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(pdone != NULL) )
            (void)get_user(done, pdone);
    }

    if ( !set_foreigndom(cpu, foreigndom) )
    {
        rc = -EINVAL;
        goto out;
    }

    if ( unlikely(!array_access_ok(uops, count, sizeof(op))) )
    {
        rc = -EFAULT;
        goto out;
    }

    for ( i = 0; i < count; i++ )
    {
        if ( unlikely(__copy_from_user(&op, uops, sizeof(op)) != 0) )
        {
            MEM_LOG("Bad __copy_from_user");
            rc = -EFAULT;
            break;
        }

        okay = 1;
        mfn  = op.arg1.mfn;
        page = pfn_to_page(mfn);

         acm_mmuext_op();

        switch ( op.cmd )
        {
        case MMUEXT_PIN_L1_TABLE:
            type = PGT_l1_page_table | PGT_va_mutable;

        pin_page:
            okay = get_page_and_type_from_pagenr(mfn, type, FOREIGNDOM);
            if ( unlikely(!okay) )
            {
                MEM_LOG("Error while pinning mfn %lx", mfn);
                break;
            }
            
            if ( unlikely(test_and_set_bit(_PGT_pinned,
                                           &page->u.inuse.type_info)) )
            {
                MEM_LOG("Mfn %lx already pinned", mfn);
                put_page_and_type(page);
                okay = 0;
                break;
            }
            
            break;

#ifndef CONFIG_X86_PAE /* Unsafe on PAE because of Xen-private mappings. */
        case MMUEXT_PIN_L2_TABLE:
            type = PGT_l2_page_table | PGT_va_mutable;
            goto pin_page;
#endif

        case MMUEXT_UNPIN_TABLE:
            if ( unlikely(!(okay = get_page_from_pagenr(mfn, d))) )
            {
                MEM_LOG("Mfn %lx bad domain (dom=%p)",
                        mfn, page_get_owner(page));
            }
            else if ( likely(test_and_clear_bit(_PGT_pinned, 
                                                &page->u.inuse.type_info)) )
            {
                put_page_and_type(page);
                put_page(page);
            }
            else
            {
                okay = 0;
                put_page(page);
                MEM_LOG("Mfn %lx not pinned", mfn);
            }
            break;

        case MMUEXT_NEW_BASEPTR:
             cpu_switch_ttb(op.arg1.mfn);
             break;

        
        case MMUEXT_TLB_FLUSH_LOCAL:
            percpu_info[cpu].deferred_ops |= DOP_FLUSH_TLB;
            printf("[do_mmuext_op] WARNING: TLB flush is deferred\n");
            break;
    
        case MMUEXT_INVLPG_LOCAL:
            local_flush_tlb_one(op.arg1.linear_addr);
            break;

        case MMUEXT_TLB_FLUSH_MULTI:
        case MMUEXT_INVLPG_MULTI:
        {
            unsigned long vmask;
            cpumask_t     pmask;
            if ( unlikely(get_user(vmask, (unsigned long *)op.arg2.vcpumask)) )
            {
                okay = 0;
                break;
            }
            pmask = vcpumask_to_pcpumask(d, vmask);
            if ( op.cmd == MMUEXT_TLB_FLUSH_MULTI )
                flush_tlb_mask(pmask);
            else
                flush_tlb_one_mask(pmask, op.arg1.linear_addr);
            break;
        }

        case MMUEXT_TLB_FLUSH_ALL:
            flush_tlb_mask(d->domain_dirty_cpumask);
            break;
    
        case MMUEXT_INVLPG_ALL:
            flush_tlb_one_mask(d->domain_dirty_cpumask, op.arg1.linear_addr);
            break;

        case MMUEXT_COHERENT_KERN_RANGE:
		cpu_coherent_range(op.arg1.linear_addr, op.arg2.end);
            break;

        case MMUEXT_COHERENT_USER_RANGE:
		cpu_coherent_range(op.arg1.linear_addr, op.arg2.end);

            break;

        case MMUEXT_DRAIN_WB:
		while(1);
            asm("mcr	p15, 0, %0, c7, c10, 4" : : "r" (zero));
            break;

        case MMUEXT_INVALIDATE_I_TLB_ENTRY:
		while(1);
            asm("mcr	p15, 0, %0, c8, c5, 1" : : "r" (op.arg1.linear_addr));
            break;

        case MMUEXT_INVALIDATE_D_TLB_ENTRY:
		while(1);
            asm("mcr	p15, 0, %0, c8, c6, 1" : : "r" (op.arg1.linear_addr));
            break;

        case MMUEXT_FLUSH_KERN_TLB_RANGE:
		cpu_flush_tlb_range(op.arg1.linear_addr, op.arg2.end);
            break;


        case MMUEXT_FLUSH_USER_CACHE_RANGE:
		cpu_flush_cache_range(op.arg1.linear_addr, op.arg2.end);
		break;
            
        case MMUEXT_FLUSH_KERN_DCACHE_PAGE:
		cpu_flush_cache_page(op.arg1.linear_addr);
		break;

        case MMUEXT_DMAC_INV_RANGE:
		cpu_invalidate_dma_range(op.arg1.linear_addr, op.arg2.end);
            break;
            
        case MMUEXT_DMAC_CLEAN_RANGE:
		cpu_clean_dma_range(op.arg1.linear_addr, op.arg2.end);
            break;

        case MMUEXT_DMAC_FLUSH_RANGE:
	           cpu_flush_dma_range(op.arg1.linear_addr, op.arg2.end);
            break;
        

        case MMUEXT_FLUSH_CACHE:
		cpu_flush_cache_all();
            break;

        case MMUEXT_DCACHE_CLEAN_AREA:
	    	cpu_clean_cache_range(op.arg1.linear_addr, op.arg2.size);
            break;

        case MMUEXT_FLUSH_TLB_PAGE:
                cpu_flush_tlb_entry(op.arg1.linear_addr);
            break;

        case MMUEXT_FLUSH_TLB_ALL:
			update_tlbflush_clock();
                cpu_flush_tlb_all();
            break;

        case MMUEXT_FLUSH_TLB_MM:
			update_tlbflush_clock();
	    	cpu_flush_tlb_all();
            break;


        case MMUEXT_FLUSH_TLB_KERNEL_PAGE:
	    	cpu_flush_tlb_entry((unsigned long) op.arg1.linear_addr);
            break;


        case MMUEXT_FLUSH_PMD_ENTRY:
                cpu_flush_cache_entry((unsigned long) op.arg1.linear_addr);
            break;

        case MMUEXT_CLEAN_PMD_ENTRY:
                cpu_clean_cache_range((unsigned long) op.arg1.linear_addr, 32);
            break;

        case MMUEXT_CLEAR_USER_PAGE:
		while((op.arg1.linear_addr & 0x7) != 0);
		cpu_clear_page((void *)op.arg1.linear_addr, op.arg2.addr);
            break;

        case MMUEXT_COPY_USER_PAGE:
		while((op.arg1.linear_addr & 0x7) != 0);
		cpu_copy_page((void *)op.arg1.linear_addr, (void *)op.arg2.addr, op.arg3.addr);
            break;

        case MMUEXT_GET_PGD:
            op.arg1.phys_addr = (unsigned long) cpu_get_pgd_phys();
            if ( copy_to_user(uops, &op, sizeof(op)) )
                return -EFAULT;
            break;

        case MMUEXT_DEBUG_TLB_DUMP:
            xen_tlb_dump();
            break;

        default:
            MEM_LOG("Invalid extended pt command 0x%x", op.cmd);
            okay = 0;
            break;
        }

        if ( unlikely(!okay) )
        {
            rc = -EINVAL;
            break;
        }

        uops++;
    }

 out:
    process_deferred_ops(cpu);

    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(pdone != NULL) )
        __put_user(done + i, pdone);

    UNLOCK_BIGLOCK(d);


    return rc;
}

void *map_domain_page_into_guest_va_space(struct vcpu *v, unsigned long pfn)
{
    unsigned long physaddr, virtaddr;
    unsigned long guest_paddr, guest_vaddr;
    unsigned long page_offset;

    guest_paddr = v->arch.guest_pstart;
    guest_vaddr = v->arch.guest_vstart;

    physaddr = (pfn) << PAGE_SHIFT;

    if( guest_paddr > guest_vaddr ) // imx21
    {
        page_offset = guest_paddr - guest_vaddr;
        virtaddr = physaddr - page_offset;
    }
    else // omap
    {
        page_offset = guest_vaddr - guest_paddr;
        virtaddr = physaddr + page_offset;
    }

    return (void *) virtaddr;
}



int do_mmu_update(
    struct mmu_update *ureqs,
    unsigned int count,
    unsigned int *pdone,
    unsigned int foreigndom)
{
    struct mmu_update req;
    void *va;
    unsigned long gpfn, mfn;
    struct page_info *page;
    int rc = 0, okay = 1, i = 0, cpu = smp_processor_id();
    unsigned int cmd, done = 0;
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned long type_info;
    struct domain_mmap_cache mapcache, sh_mapcache;

    LOCK_BIGLOCK(d);


    cleanup_writable_pagetable(d);

    if ( unlikely(count & MMU_UPDATE_PREEMPTED) )
    {
        count &= ~MMU_UPDATE_PREEMPTED;
        if ( unlikely(pdone != NULL) )
            (void)get_user(done, pdone);
    }

    domain_mmap_cache_init(&mapcache);
    domain_mmap_cache_init(&sh_mapcache);


    if ( !set_foreigndom(cpu, foreigndom) )
    {
        rc = -EINVAL;
        goto out;
    }

    perfc_incrc(calls_to_mmu_update); 
    perfc_addc(num_page_updates, count);
    perfc_incr_histo(bpt_updates, count, PT_UPDATES);

    if ( unlikely(!array_access_ok(ureqs, count, sizeof(req))) )
    {
        rc = -EFAULT;
        goto out;
    }

    for ( i = 0; i < count; i++ )
    {
        if ( unlikely(__copy_from_user(&req, ureqs, sizeof(req)) != 0) )
        {
            MEM_LOG("Bad __copy_from_user");
            rc = -EFAULT;
            break;
        }

        cmd = req.ptr & (sizeof(pte_t)-1);
        okay = 0;

        switch ( cmd )
        {
            /*
             * MMU_NORMAL_PT_UPDATE: Normal update to any level of page table.
             */
        case MMU_NORMAL_PT_UPDATE:

            gpfn = req.ptr >> PAGE_SHIFT;

            mfn = gpfn;

            if ( unlikely(!get_page_from_pagenr(mfn, current->domain)) )
            {
                MEM_LOG("Could not get page for normal update");
                break;
            }

            //va = (void *) map_domain_page_into_guest_va_space(v, mfn);
		va = map_domain_page_with_cache(mfn, &mapcache);
            va = (void *)((unsigned long)va +
                          (unsigned long)(req.ptr & ~PAGE_MASK));
            page = pfn_to_page(mfn);

            switch ( (type_info = page->u.inuse.type_info) & PGT_type_mask )
            {
            case PGT_l1_page_table: 

                if ( likely(get_page_type(
                    page, type_info & (PGT_type_mask|PGT_va_mask))) )
                {
                    pte_t l1e;

                    /* FIXME: doesn't work with PAE */
                    l1e = l1e_from_intpte(req.val);
                    okay = modify_pte(va, l1e);
                    put_page_type(page);
                }
                break;

            case PGT_l2_page_table:

                if ( likely(get_page_type(
                    page, type_info & (PGT_type_mask|PGT_va_mask))) )
                {
                    pde_t l2e;

                    /* FIXME: doesn't work with PAE */
                    l2e = l2e_from_intpte(req.val);
                    okay = modify_pde(
                        (pde_t *)va, l2e, mfn, type_info);

                    put_page_type(page);
                }
                break;

            default:
                if ( likely(get_page_type(page, PGT_writable_page)) )
                {
	             if(!acm_mod_default_entry(req.val))
						 break;

                *(intpte_t *)va = req.val;
                okay = 1;

                put_page_type(page);

		// HERE
		percpu_info[cpu].deferred_ops |= DOP_FLUSH_TLB;

		cpu_clean_cache_range((unsigned long)va, 32);
                }
                else
                    printf("[do_mmuext_op] page table is not updated\n");
                break;
            }

            unmap_domain_page_with_cache(va, &mapcache);

            put_page(page);
            break;

        case MMU_MACHPHYS_UPDATE:
            mfn = req.ptr >> PAGE_SHIFT;
            gpfn = req.val;

            if ( unlikely(!get_page_from_pagenr(mfn, FOREIGNDOM)) )
            {
                MEM_LOG("Could not get page for mach->phys update");
                break;
            }

            set_pfn_from_mfn(mfn, gpfn);
            okay = 1;

            put_page(pfn_to_page(mfn));
            break;

        default:
            MEM_LOG("Invalid page update command %x", cmd);
            break;
        }

        if ( unlikely(!okay) )
        {
            rc = -EINVAL;
            break;
        }

        ureqs++;
    }

 out:
    domain_mmap_cache_destroy(&mapcache);
    domain_mmap_cache_destroy(&sh_mapcache);

    process_deferred_ops(cpu);

    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(pdone != NULL) )
        __put_user(done + i, pdone);

    UNLOCK_BIGLOCK(d);


    return rc;
}




pte_t *get_pl1pte_from_virtaddr(struct vcpu *v, unsigned long va)
{
    pde_t *l2tab, *l2pte;
    pte_t *l1tab, *l1pte;

    l2tab = (pde_t *) v->arch.guest_vtable;
    l2pte = &l2tab[l2_linear_offset(va)];

//	pde_t aa = l2tab[l2_linear_offset(va)];
//	pde_t *bb = &l2tab[l2_linear_offset(va)];
//	unsigned long cc = l2e_coarse_pt_get_paddr(*l2pte);
//	unsigned long dd = (v->arch.guest_pstart) - (v->arch.guest_vstart);


    l1tab = (pte_t *) ((unsigned long) l2e_coarse_pt_get_paddr(*l2pte) - (v->arch.guest_pstart - v->arch.guest_vstart));

    l1pte = &l1tab[pte_index(va)];

    return l1pte;
}


void set_shared_info_mapping_xen( struct domain * d, unsigned long va, unsigned long pa )
{
	struct vcpu *v;
	pte_t *l1pte;

	v = (struct vcpu *)d->vcpu[0];
	l1pte = get_pl1pte_from_virtaddr( v, va );
	
	*l1pte = l1e_from_paddr( pa, __L1_PAGE_USER_SMALL);

	update_tlbflush_clock();
	cpu_flush_tlb_all();
	cpu_flush_cache_all();

	return;
}



extern void xen_tlb_dump(void);
extern struct domain* idle_domain;


/* temporal implementation  for saving each domain shared info physical address */
unsigned long pa_dom_shared_info[3];


int do_update_va_mapping(u32 va, u32 flags, u64 val64)
{
    pte_t val = l1e_from_intpte(val64);
    struct vcpu   *v   = current;
    struct domain *d   = v->domain;
    unsigned int   cpu = smp_processor_id();
    unsigned long  vmask, bmap_ptr;
    cpumask_t      pmask;
    int            rc  = 0;
    unsigned long pa_shared_info; //, old_shared_info;

    perfc_incrc(calls_to_update_va);
    
	if ( unlikely(!__addr_ok(va)) ) //shadow --  && !shadow_mode_external(d)) )
		return -EINVAL;
         
	LOCK_BIGLOCK(d);

	if (flags & UVMF_SHARED_INFO){
		/* 
 		*  request for establishing a shared info page 
		*   - remove a cache alias problem
		*/
		cpu_flush_cache_page((unsigned long) d->shared_info);

		pa_shared_info = virt_to_phys(d->shared_info);
		/* save current domain shared info physical address */
		pa_dom_shared_info[d->domain_id] = pa_shared_info;
		if( pa_shared_info == ((unsigned long) val.l1 & ~(PAGE_SIZE-1)) ){
			/* domain shared_info = shared_info base + domain id * page size */
			va = va + (d->domain_id << PAGE_SHIFT);
			d->shared_info = (shared_info_t *) va;
			v->vcpu_info = &d->shared_info->vcpu_info[v->vcpu_id];
		} else {
			printf("ERROR: bad shared info address");
			UNLOCK_BIGLOCK(d);
			return -EINVAL;
		}
		flags &= ~UVMF_SHARED_INFO;
		rc = d->domain_id;
	}

	cleanup_writable_pagetable(d);

	if ( unlikely(!modify_pte(get_pl1pte_from_virtaddr(v, va), val)) )
		rc = -EINVAL;

    switch ( flags & UVMF_FLUSHTYPE_MASK )
    {
    case UVMF_TLB_FLUSH:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            local_flush_tlb();
            break;
        case UVMF_ALL:
            flush_tlb_mask(d->domain_dirty_cpumask);
            break;
        default:
            if ( unlikely(get_user(vmask, (unsigned long *)bmap_ptr)) )
                rc = -EFAULT;
            pmask = vcpumask_to_pcpumask(d, vmask);
            flush_tlb_mask(pmask);
            break;
        }
        break;

    case UVMF_INVLPG:
        switch ( (bmap_ptr = flags & ~UVMF_FLUSHTYPE_MASK) )
        {
        case UVMF_LOCAL:
            local_flush_tlb_one(va);
            break;
        case UVMF_ALL:
            flush_tlb_one_mask(d->domain_dirty_cpumask, va);
            break;
        default:
            if ( unlikely(get_user(vmask, (unsigned long *)bmap_ptr)) )
                rc = -EFAULT;
            pmask = vcpumask_to_pcpumask(d, vmask);
            flush_tlb_one_mask(pmask, va);
            break;
        }
        break;
    }

    process_deferred_ops(cpu);
    
    UNLOCK_BIGLOCK(d);

    cpu_flush_cache_page((unsigned long)d->shared_info);

    return rc;
}


inline int update_l1e(pte_t *ptep, pte_t old, pte_t new)
{
	intpte_t o = l1e_get_intpte(old);
	intpte_t n = l1e_get_intpte(new);

	cmpxchg_u32((volatile u32 *) ptep, (u32) o, (u32) n);

	if ( unlikely(o != l1e_get_intpte(old)) ) {
		MEM_LOG("Failed to update %" PRIpte " -> %" PRIpte
			": saw %" PRIpte,
			l1e_get_intpte(old),
			l1e_get_intpte(new),
			o);
		
		return 0;
	}

	cpu_flush_cache_page((unsigned long)ptep & (~((1<<PAGE_SHIFT) - 1)));

	return 1;
}

static int modify_pte(pte_t *pl1e, pte_t nl1e)
{
    pte_t ol1e;
    struct domain *d = current->domain;

    if ( unlikely(__copy_from_user(&ol1e, pl1e, sizeof(ol1e)) != 0) )
        return 0;

    if(!acm_modify_pte(nl1e))
	return 0;

    if ( l1e_get_flags(nl1e) & _L1_PAGE_PRESENT )
    {
        /* Fast path for identical mapping, r/w and presence. */
        if ( !l1e_has_changed(ol1e, nl1e, _L1_PAGE_RW_USER | _L1_PAGE_PRESENT))
            return update_l1e(pl1e, ol1e, nl1e);

        if ( unlikely(!get_page_from_pte(nl1e, FOREIGNDOM)) )
            return 0;
        
        if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
        {
            put_page_from_l1e(nl1e, d);
            return 0;
        }
    }
    else
    {
        if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
            return 0;
    }

    put_page_from_l1e(ol1e, d);


    return 1;
}



#define UPDATE_ENTRY(_t,_p,_o,_n) ({                                    \
    intpte_t __o = cmpxchg_u32((intpte_t *)(_p),                    \
                           _t ## e_get_intpte(_o),                      \
                           _t ## e_get_intpte(_n));                     \
    if ( __o != _t ## e_get_intpte(_o) )                                \
        MEM_LOG("Failed to update %" PRIpte " -> %" PRIpte              \
                ": saw %" PRIpte "",                                    \
                (_t ## e_get_intpte(_o)),                               \
                (_t ## e_get_intpte(_n)),                               \
                (__o));                                                 \
    (__o == _t ## e_get_intpte(_o)); })									


/* Update the page directory entry at pdep to new value pde. pdep is within frame pfn. */
static int modify_pde(pde_t *pl2e, pde_t nl2e, unsigned long pfn, unsigned long type)
{
    pde_t ol2e;
    unsigned long vaddr = 0;

    if ( unlikely(!is_guest_l2_slot(type,pgentry_ptr_to_slot(pl2e))) )
    {
        MEM_LOG("Illegal L2 update attempt in Xen-private area %p", pl2e);
        return 0;
    }

    if(!acm_modify_pde(nl2e))
	return 0;

    if ( unlikely(__copy_from_user(&ol2e, pl2e, sizeof(ol2e)) != 0) )
        return 0;

    if ( l2e_get_flags(nl2e) & _L2_PAGE_PRESENT )
    {
        if ( unlikely(l2e_get_flags(nl2e) & L2_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L2 flags %x",
                    l2e_get_flags(nl2e) & L2_DISALLOW_MASK);
            return 0;
        }

        /* Fast path for identical mapping and presence. */
        if ( !l2e_has_changed(ol2e, nl2e, _L2_PAGE_PRESENT))
            return UPDATE_ENTRY(l2, pl2e, ol2e, nl2e);

        if ( unlikely(!l1_backptr(&vaddr, pgentry_ptr_to_slot(pl2e), type)) ||
             unlikely(!get_page_from_l2e(nl2e, pfn, current->domain, vaddr)) )
            return 0;

        if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e)) )
        {
            put_page_from_l2e(nl2e, pfn);
            return 0;
        }
    }
    else if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e)) )
    {
        return 0;
    }

    put_page_from_l2e(ol2e, pfn);

	update_tlbflush_clock();
    cpu_flush_tlb_all();
    cpu_flush_cache_all();

    return 1;
}

static int create_grant_pte_mapping(
    unsigned long pte_addr, pte_t _nl1e, struct vcpu *v)
{
    int rc = GNTST_okay;
    void *va;
    unsigned long gpfn, mfn;
    struct page_info *page;
    u32 type_info;
    pte_t ol1e;
    struct domain *d = v->domain;

    ASSERT(spin_is_locked(&d->big_lock));
    ASSERT(!shadow_mode_refcounts(d));

    gpfn = pte_addr >> PAGE_SHIFT;
    mfn = gpfn;

    if ( unlikely(!get_page_from_pagenr(mfn, current->domain)) )
    {
        MEM_LOG("Could not get page for normal update");
        return GNTST_general_error;
    }
    
    va = map_domain_page(mfn);
    va = (void *)((unsigned long)va + (pte_addr & ~PAGE_MASK));
    page = pfn_to_page(mfn);

    type_info = page->u.inuse.type_info;
    if ( ((type_info & PGT_type_mask) != PGT_l1_page_table) ||
         !get_page_type(page, type_info & (PGT_type_mask|PGT_va_mask)) )
    {
        MEM_LOG("Grant map attempted to update a non-L1 page");
        rc = GNTST_general_error;
        goto failed;
    }

    if ( __copy_from_user(&ol1e, (pte_t *)va, sizeof(ol1e)) ||
         !update_l1e(va, ol1e, _nl1e) )
    {
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    } 

    put_page_from_l1e(ol1e, d);

    put_page_type(page);
 
 failed:
    unmap_domain_page(va);
    put_page(page);
    return rc;
}

static int destroy_grant_pte_mapping(
    unsigned long addr, unsigned long frame, struct domain *d)
{
    int rc = GNTST_okay;
    void *va;
    unsigned long gpfn, mfn;
    struct page_info *page;
    u32 type_info;
    pte_t ol1e;

    ASSERT(!shadow_mode_refcounts(d));

    gpfn = addr >> PAGE_SHIFT;
    mfn = gpfn;

    if ( unlikely(!get_page_from_pagenr(mfn, current->domain)) )
    {
        MEM_LOG("Could not get page for normal update");
        return GNTST_general_error;
    }
    
    va = map_domain_page(mfn);
    va = (void *)((unsigned long)va + (addr & ~PAGE_MASK));
    page = pfn_to_page(mfn);

    type_info = page->u.inuse.type_info;
    if ( ((type_info & PGT_type_mask) != PGT_l1_page_table) ||
         !get_page_type(page, type_info & (PGT_type_mask|PGT_va_mask)) )
    {
        MEM_LOG("Grant map attempted to update a non-L1 page");
        rc = GNTST_general_error;
        goto failed;
    }

    if ( __copy_from_user(&ol1e, (pte_t *)va, sizeof(ol1e)) )
    {
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    }
    
    /* Check that the virtual address supplied is actually mapped to frame. */
    if ( unlikely((l1e_get_intpte(ol1e) >> PAGE_SHIFT) != frame) )
    {
        MEM_LOG("PTE entry %lx for address %lx doesn't match frame %lx",
                (unsigned long)l1e_get_intpte(ol1e), addr, frame);
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    }

    /* Delete pagetable entry. */
    if ( unlikely(__put_user(0, (intpte_t *)va)))
    {
        MEM_LOG("Cannot delete PTE entry at %p", va);
        put_page_type(page);
        rc = GNTST_general_error;
        goto failed;
    }

    put_page_type(page);

 failed:
    unmap_domain_page(va);
    put_page(page);
    return rc;
}


static int create_grant_va_mapping(vaddr_t va, pte_t nl1e, struct vcpu *v)
{
    pte_t *pl1e, ol1e;
    struct domain *d = v->domain;
    
    ASSERT(spin_is_locked(&d->big_lock));

    pl1e = get_pl1pte_from_virtaddr(v, va);

    if ( unlikely(__copy_from_user(&ol1e, pl1e, sizeof(ol1e)) != 0) ||
         !update_l1e(pl1e, ol1e, nl1e) )
        return GNTST_general_error;

    put_page_from_l1e(ol1e, d);

    return GNTST_okay;
}

static int destroy_grant_va_mapping(
    unsigned long addr, unsigned long frame, struct vcpu* v)
{
    pte_t *pl1e, ol1e;
    
    pl1e = get_pl1pte_from_virtaddr(v, addr);

    
    if ( unlikely(__get_user(ol1e.l1, &pl1e->l1) != 0) )
    {
        MEM_LOG("Could not find PTE entry for address %lx", addr);
        return GNTST_general_error;
    }

    /*
     * Check that the virtual address supplied is actually mapped to
     * frame.
     */
    if ( unlikely(l1e_get_pfn(ol1e) != frame) )
    {
        MEM_LOG("PTE entry %lx for address %lx doesn't match frame %lx",
                l1e_get_pfn(ol1e), addr, frame);
        return GNTST_general_error;
    }

    /* Delete pagetable entry. */
    if ( unlikely(__put_user(0, &pl1e->l1)) )
    {
        MEM_LOG("Cannot delete PTE entry at %p", (unsigned long *)pl1e);
        return GNTST_general_error;
    }
    
    return 0;
}

int create_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags)
{
    pte_t pte = l1e_from_pfn(frame, GRANT_PTE_FLAGS);
        
    if ( (flags & GNTMAP_application_map) )
        l1e_add_flags(pte,PTE_SMALL_AP_URW_SRW);
    if ( !(flags & GNTMAP_readonly) )
        l1e_add_flags(pte,PTE_SMALL_AP_URW_SRW);

    if ( flags & GNTMAP_contains_pte )
        return create_grant_pte_mapping(addr, pte, current);
    return create_grant_va_mapping(addr, pte, current);
}

int destroy_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags)
{

    // check if the last param (current) of destory_grant_pte_mapping() is correct
    // it is added not to use the linear_pg_table[]
    if ( flags & GNTMAP_contains_pte )
        return destroy_grant_pte_mapping(addr, frame, current->domain);
    return destroy_grant_va_mapping(addr, frame, current);
}


int steal_page_for_grant_transfer(
    struct domain *d, struct page_info *page)
{
    u32 _d, _nd, x, y;
	unsigned long flags;

    spin_lock(&d->page_alloc_lock);

    /*
     * The tricky bit: atomically release ownership while there is just one 
     * benign reference to the page (PGC_allocated). If that reference 
     * disappears then the deallocation routine will safely spin.
     */
    _d  = pickle_domptr(d);
    _nd = page->u.inuse._domain;
    y   = page->count_info;
    do {
        x = y;
        if (unlikely((x & (PGC_count_mask|PGC_allocated)) !=
                     (1 | PGC_allocated)) || unlikely(_nd != _d)) { 
            DPRINTK("gnttab_transfer: Bad page %p: ed=%p(%u), sd=%p,"
                    " caf=%08x, taf=%" PRtype_info "\n", 
                    (void *) page_to_pfn(page),
                    d, d->domain_id, unpickle_domptr(_nd), x, 
                    page->u.inuse.type_info);
            spin_unlock(&d->page_alloc_lock);
            return -1;
        }
      
        // CHECK this code again

		local_irq_save(flags);

		if( (x == page->count_info) && (_d == page->u.inuse._domain) )  {
			page->u.inuse._domain = _d;
			y  = x;
			_nd =_d ;
		}
		else {
			y  = page->count_info;
			_nd = page->u.inuse._domain;
		}

		local_irq_restore(flags);


    } while (unlikely(_nd != _d) || unlikely(y != x));

    /*
     * Unlink from 'd'. At least one reference remains (now anonymous), so 
     * noone else is spinning to try to delete this page from 'd'.
     */
    d->tot_pages--;
    list_del(&page->list);

    spin_unlock(&d->page_alloc_lock);

    return 0;
}

long arch_memory_op(int op, GUEST_HANDLE(void) arg)
{
	return 0;
}
