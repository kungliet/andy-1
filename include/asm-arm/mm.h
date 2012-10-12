
#ifndef __XEN_ASM_MM_H__
#define __XEN_ASM_MM_H__

#include <xen/cpumask.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <asm/io.h>
#include <asm/types.h>
#include <asm/flushtlb.h>
#include <asm/pgtable.h>
#include <asm/config.h>
#include <asm/atomic.h>
#include <asm/page.h>
#include <asm/cpu-ops.h>
#include <asm/cpu-domain.h>
#include <public/xen.h>

/*
 * Per-page-frame information.
 * 
 * Every architecture must ensure the following:
 *  1. 'struct page_info' contains a 'struct list_head list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn) ((_pfn)->u.free.order)

struct page_info
{
    /* Each frame can be threaded onto a doubly-linked list. */
    struct list_head list;

    /* Reference count and various PGC_xxx flags and fields. */
    u32 count_info;

    /* Context-dependent fields follow... */
    union {

        /* Page is in use: ((count_info & PGC_count_mask) != 0). */
        struct {
            /* Owner of this page (NULL if page is anonymous). */
            u32 _domain; /* pickled format */
            /* Type reference count and various PGT_xxx flags and fields. */
            unsigned long type_info;
        } __attribute__ ((packed)) inuse;

        /* Page is on a free list: ((count_info & PGC_count_mask) == 0). */
        struct {
            /* Order-size of the free chunk this page is the head of. */
            u32 order;
            /* Mask of possibly-tainted TLBs. */
            cpumask_t cpumask;
        } __attribute__ ((packed)) free;

    } u;

    /* Timestamp from 'TLB clock', used to reduce need for safety flushes. */
    u32 tlbflush_timestamp;
};

extern struct page_info *frame_table;
extern unsigned long min_page, max_page;
extern unsigned long total_pages;
void init_frametable(void);


#ifdef MEMORY_GUARD
void memguard_init(void);
void memguard_guard_range(void *p, unsigned long l);
void memguard_unguard_range(void *p, unsigned long l);
#else
#define memguard_init()                ((void)0)
#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)  ((void)0)
#endif /* MEMORY_GUARD */


void memguard_guard_stack(void *p);


#define IS_XEN_HEAP_FRAME(_pfn) (page_to_phys(_pfn) < xenheap_phys_end)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated      31
#define PGC_allocated       (1U<<_PGC_allocated)

#define PTWR_PT_ACTIVE 0
#define PTWR_PT_INACTIVE 1

#define PTWR_CLEANUP_ACTIVE 1
#define PTWR_CLEANUP_INACTIVE 2

int  ptwr_init(struct domain *);



#define pickle_domptr(_d)   ((u32)(unsigned long)(_d))
#define unpickle_domptr(_d) ((struct domain *)(unsigned long)(_d))
#define PRtype_info	"08lx"

#define page_get_owner(_p)    (unpickle_domptr((_p)->u.inuse._domain))
#define page_set_owner(_p,_d) ((_p)->u.inuse._domain = pickle_domptr(_d))

#define XENSHARE_writable 0
#define XENSHARE_readonly 1

#define share_xen_page_with_guest(p, d, r)		do { } while(0)
#define share_xen_page_with_privileged_guests(p, r)	do { } while(0)
#define SHARE_PFN_WITH_DOMAIN(_pfn, _dom)								\
    do {																\
        page_set_owner(((struct page_info *) _pfn), (_dom));				\
        /* The incremented type count is intended to pin to 'writable'. */ \
        (_pfn)->u.inuse.type_info = PGT_writable_page | PGT_validated | 1; \
        wmb(); /* install valid domain ptr before updating refcnt. */	\
        spin_lock(&(_dom)->page_alloc_lock);							\
		/* _dom holds an allocation reference */						\
        ASSERT((_pfn)->count_info == 0);								\
		(_pfn)->count_info |= PGC_allocated | 1;						\
        if ( unlikely((_dom)->xenheap_pages++ == 0) )					\
            get_knownalive_domain(_dom);								\
        list_add_tail(&(_pfn)->list, &(_dom)->xenpage_list);			\
        spin_unlock(&(_dom)->page_alloc_lock);							\
    } while ( 0 )


 /* The following page types are MUTUALLY EXCLUSIVE. */
#define PGT_none            (0U<<29) /* no special uses of this page */
#define PGT_l1_page_table   (1U<<29) /* using this page as an L1 page table? */
#define PGT_l2_page_table   (2U<<29) /* using this page as an L2 page table? */
#define PGT_l3_page_table   (3U<<29) /* using this page as an L3 page table? */
#define PGT_l4_page_table   (4U<<29) /* using this page as an L4 page table? */
#define PGT_gdt_page        (5U<<29) /* using this page in a GDT? */
#define PGT_ldt_page        (6U<<29) /* using this page in an LDT? */
#define PGT_writable_page   (7U<<29) /* has writable mappings of this page? */

#define PGT_l1_shadow       PGT_l1_page_table
#define PGT_l2_shadow       PGT_l2_page_table
#define PGT_l3_shadow       PGT_l3_page_table
#define PGT_l4_shadow       PGT_l4_page_table
#define PGT_hl2_shadow      (5U<<29)
#define PGT_snapshot        (6U<<29)
#define PGT_writable_pred   (7U<<29) /* predicted gpfn with writable ref */

#define PGT_fl1_shadow      (5U<<29)
#define PGT_type_mask       (7U<<29) /* Bits 29-31. */

 /* Has this page been validated for use as its current type? */
#define _PGT_validated      28
#define PGT_validated       (1U<<_PGT_validated)
 /* Owning guest has pinned this page to its current type? */
#define _PGT_pinned         27
#define PGT_pinned          (1U<<_PGT_pinned)

 /* The 11 most significant bits of virt address if this is a page table. */
#define PGT_va_shift        16
#define PGT_va_mask         (((1U<<11)-1)<<PGT_va_shift)
 /* Is the back pointer still mutable (i.e. not fixed yet)? */
#define PGT_va_mutable      (((1U<<11)-1)<<PGT_va_shift)
 /* Is the back pointer unknown (e.g., p.t. is mapped at multiple VAs)? */
#define PGT_va_unknown      (((1U<<11)-2)<<PGT_va_shift)


 /* 16-bit count of uses of this frame as its current type. */
#define PGT_count_mask      ((1U<<16)-1)

 /* 23-bit mfn mask for shadow types: good for up to 32GB RAM. */
#define PGT_mfn_mask        ((1U<<23)-1)

#define PGT_score_shift     23
#define PGT_score_mask      (((1U<<4)-1)<<PGT_score_shift)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated      31
#define PGC_allocated       (1U<<_PGC_allocated)
 /* Set when fullshadow mode marks a page out-of-sync */
#define _PGC_out_of_sync     30
#define PGC_out_of_sync     (1U<<_PGC_out_of_sync)
 /* Set when fullshadow mode is using a page as a page table */
#define _PGC_page_table      29
#define PGC_page_table      (1U<<_PGC_page_table)
 /* 29-bit count of references to this frame. */
#define PGC_count_mask      ((1U<<29)-1)

/* We trust the slab allocator in slab.c, and our use of it. */
#define PageSlab(page)	    (1)
#define PageSetSlab(page)   ((void)0)
#define PageClearSlab(page) ((void)0)


/* Writable Pagetables */
struct ptwr_info {
	/* Linear address where the guest is updating the p.t. page. */
	unsigned long l1va;

	/* Copy of the p.t. page, taken before guest is given write access. */
	pte_t *page;

	/* Index in L2 page table where this L1 p.t. is always hooked. */
	unsigned int l2_idx; /* NB. Only used for PTWR_PT_ACTIVE. */

	/* Info about last ptwr update batch. */
	unsigned int prev_nr_updates;

	/* VCPU which created writable mapping. */
	struct vcpu *vcpu;

	/* EIP of the original write fault (stats collection only). */
	unsigned long eip;
};

void ptwr_destroy(struct domain *);
void ptwr_flush(struct domain *, const int);
//int  ptwr_do_page_fault(struct domain *, unsigned long,
//                        struct cpu_user_regs *);
int  revalidate_l1(struct domain *, pte_t *, pte_t *);

void cleanup_writable_pagetable(struct domain *d);


/*
 * The MPT (machine->physical mapping table) is an array of word-sized
 * values, indexed on machine frame number. It is expected that guest OSes
 * will use it to store a "physical" frame number to give the appearance of
 * contiguous (or near contiguous) physical memory.
 */
#undef  machine_to_phys_mapping
#define machine_to_phys_mapping  ((unsigned long *)RDWR_MPT_VIRT_START)
#define INVALID_M2P_ENTRY        (~0UL)
#define VALID_M2P(_e)            (!((_e) & (1UL<<(BITS_PER_LONG-1))))
#define IS_INVALID_M2P_ENTRY(_e) (!VALID_M2P(_e))

#define set_pfn_from_mfn(mfn, pfn) (machine_to_phys_mapping[(mfn)-min_page] = (pfn))
#define get_pfn_from_mfn(mfn)      (machine_to_phys_mapping[(mfn)-min_page])

#define set_gpfn_from_mfn(mfn, pfn)	set_pfn_from_mfn(mfn, pfn)
#define get_gpfn_from_mfn(mfn)		get_pfn_from_mfn(mfn)

#define mfn_to_gmfn(_d, mfn)	(mfn)

#define gmfn_to_mfn(_d, gpfn)	(gpfn)
/*
 * The phys_to_machine_mapping is the reversed mapping of MPT for full
 * virtualization.  It is only used by shadow_mode_translate()==true
 * guests, so we steal the address space that would have normally
 * been used by the read-only MPT map.
 */
#define phys_to_machine_mapping ((unsigned long *)RO_MPT_VIRT_START)
#define INVALID_MFN             (~0UL)
#define VALID_MFN(_mfn)         (!((_mfn) & (1U<<31)))


int alloc_page_type(struct page_info *page, unsigned long type);
void free_page_type(struct page_info *page, unsigned long type);

void put_page_type(struct page_info *page);
int  get_page_type(struct page_info *page, unsigned long type);
int  get_page_from_l1e(pte_t l1e, struct domain *d);
void put_page_from_l1e(pte_t l1e, struct domain *d);

extern void zap_low_mappings(pde_t *base);

void arch_init_memory(void);


static inline u32 cmpxchg_u32(volatile u32* v, u32 old, u32 new)
{
	u32 ret;
	unsigned long flags;

	local_irq_save(flags);

	ret = *v;
	if (likely(ret == old))
		*v = new;

	local_irq_restore(flags);
	
	return ret;
}

static inline u32 cmpxchg(volatile u32* v, u32 old, u32 new)
{
	u32 ret;
	unsigned long flags;

	local_irq_save(flags);

	ret = *v;
	if (likely(ret == old))
		*v = new;

	local_irq_restore(flags);

	return ret;
}

static inline void put_page(struct page_info *page)
{
	u32 nx, x, y = page->count_info;

	do {
		x  = y;
		nx = x - 1;
	} while ( unlikely((y = cmpxchg_u32(&page->count_info, x, nx)) != x) );

	if ( unlikely((nx & PGC_count_mask) == 0) ) {
		free_domheap_page(page);
	}
}


/*
 * 
 */
static inline int get_page(struct page_info *page,
                           struct domain *domain)
{
	u32 x, nx, y = page->count_info;
	u32 d, nd = page->u.inuse._domain;
	u32 _domain = pickle_domptr(domain);
	unsigned long flags;

	do {
		x  = y;
		nx = x + 1;
		d  = nd;

		if ( unlikely((x & PGC_count_mask) == 0) ||  /* Not allocated? */
		     unlikely((nx & PGC_count_mask) == 0) || /* Count overflow? */
		     unlikely(d != _domain) )                /* Wrong owner? */
		{
			printf("shadow mode is not implemented on xen-arm\n");

			return 0;
		}

		local_irq_save(flags);
	

		if( (x == page->count_info) && (d == page->u.inuse._domain) )
		{
			page->count_info     = nx;
			page->u.inuse._domain = d;
			y  = x;
			nd =d ;
		}
		else 
		{
			y  = page->count_info;
			nd = page->u.inuse._domain;
		}

		local_irq_restore(flags);

    } while ( unlikely(nd != d) || unlikely(y != x) );

    return 1;
}

static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}


static inline int get_page_and_type(struct page_info *page,
                                    struct domain *domain,
                                    unsigned long type)
{
    int rc = get_page(page, domain);

    if ( likely(rc) && unlikely(!get_page_type(page, type)) )
    {
        put_page(page);
        rc = 0;
    }

    return rc;
}

extern void save_ptbase(struct vcpu *v);
extern void write_ptbase(struct vcpu *v);

#endif /* __ASM_X86_MM_H__ */
