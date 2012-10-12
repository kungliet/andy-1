/*
 *  linux/include/asm-arm/page.h
 *
 *  Copyright (C) 1995-2003 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _ASMARM_PAGE_H
#define _ASMARM_PAGE_H

#include <asm/config.h>

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT		12
#define PAGE_SIZE		(1 << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))

#ifdef __KERNEL__
/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	(((addr) + PAGE_SIZE - 1) & PAGE_MASK)

#ifndef __ASSEMBLY__

struct cpu_user_fns {
	void (*cpu_clear_user_page)(void *p, unsigned long user);
	void (*cpu_copy_user_page)(void *to, const void *from,
				   unsigned long user);
};

#define clear_page(_p)      memset((void *)(_p), 0, PAGE_SIZE)
extern void copy_page(void *to, const void *from);

#define pte_val(x)      (x)

#endif /* !__ASSEMBLY__ */


#ifdef __XEN__

/****************************************************************************
 * Xen Paging
 *  - originally from xen/include/x86/{page.h, x86_32/page.h}
 ***************************************************************************/
#include <asm/config.h>
#include <asm/types.h>

#ifndef __ASSEMBLY__

#include <xen/lib.h>

static inline int get_order_from_bytes(physaddr_t size)
{
	int order;

	size = (size - 1) >> PAGE_SHIFT;
	for ( order = 0; size; order++ )
		size >>= 1;

	return order;
}

static inline int get_order_from_pages(unsigned long nr_pages)
{
	int order;

	nr_pages--;
	for ( order = 0; nr_pages; order++ )
		nr_pages >>= 1;

	return order;
}

#include <asm/pgtable.h>

extern root_pgentry_t *idle_pg_table;
extern pde_t *idle_pg_table_l2;

extern void paging_init(void);

/* Convert between Xen-heap virtual addresses and machine addresses. */
#define PAGE_OFFSET         ((unsigned long)__PAGE_OFFSET)
#define virt_to_maddr(va)   ((unsigned long)(va)-PAGE_OFFSET)
#define maddr_to_virt(ma)   ((void *)((unsigned long)(ma)+PAGE_OFFSET))
/* Shorthand versions of the above functions. */
#define __pa(x)             (virt_to_maddr(x))
#define __va(x)             (maddr_to_virt(x))

#define pfn_to_page(_pfn)   (frame_table + (_pfn - min_page))
#define phys_to_page(kaddr) (frame_table + (((kaddr) >> PAGE_SHIFT) - min_page) )
#define virt_to_page(kaddr) (frame_table + (((__pa(kaddr) >> PAGE_SHIFT)) - min_page) )
#define pfn_valid(_pfn)     (((_pfn) >= min_page) && ((_pfn) <= max_page))

#define pfn_to_phys(pfn)    ((physaddr_t)(pfn) << PAGE_SHIFT)
#define phys_to_pfn(pa)     ((unsigned long)((pa) >> PAGE_SHIFT))


#define mfn_to_page(_mfn)	pfn_to_page(_mfn)
#define mfn_valid(_mfn)		pfn_valid(_mfn)

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) ((_a) >> L1_PAGETABLE_SHIFT)
#define l2_linear_offset(_a) ((_a) >> L2_PAGETABLE_SHIFT)

extern unsigned int PAGE_HYPERVISOR;
extern unsigned int PAGE_HYPERVISOR_NOCACHE;


/* Get direct integer representation of a pte's contents (intpte_t). */
#define l1e_get_intpte(x)          ((x).l1)
#define l2e_get_intpte(x)          ((x).l2)

/* Get pfn mapped by pte (unsigned long). */
#define l1e_get_pfn(x)             \
    ((unsigned long)(((x).l1 & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT))
#define l2e_get_pfn(x)             \
    ((unsigned long)(((x).l2 & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT))

/* Get physical address of page mapped by pte (physaddr_t). */
#define l1e_get_paddr(x)           \
    ((physaddr_t)(((x).l1 & (PADDR_MASK&PAGE_MASK))))
#define l2e_get_paddr(x)           \
    ((physaddr_t)(((x).l2 & (PADDR_MASK&PAGE_MASK))))

/* for ARM section entry and coarse page table */
#define l2e_section_get_paddr(x) l2e_get_paddr(x)
#define l2e_coarse_pt_get_paddr(x) \
    ((physaddr_t)(((x).l2 & (PADDR_MASK & 0xFFFFFC00))))

/* Get pointer to info structure of page mapped by pte (struct page_info *). */
#define l1e_get_page(x)           (pfn_to_page(l1e_get_pfn(x)))
#define l2e_get_page(x)           (pfn_to_page(l2e_get_pfn(x)))

/* Get pte access flags (unsigned int). */
#define l1e_get_flags(x)           (get_pte_flags((x).l1))
#define l2e_get_flags(x)           (get_pte_flags((x).l2))

/* Construct an empty pte. */
#define l1e_empty()                ((pte_t) { 0 })
#define l2e_empty()                ((pde_t) { 0 })


// TODO: SBZ (should be zero) fileds 
/* Construct a pte from a pfn and access flags. */
#define l1e_from_pfn(pfn, flags)   \
    ((pte_t) { ((intpte_t)(pfn) << PAGE_SHIFT) | put_pte_flags(flags) })
#define l2e_from_pfn(pfn, flags)   \
    ((pde_t) { ((intpte_t)(pfn) << PAGE_SHIFT) | put_pte_flags(flags) })

static inline pte_t l1e_from_paddr(physaddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (pte_t) { pa | put_pte_flags(flags) };
}
static inline pde_t l2e_from_paddr(physaddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (pde_t) { pa | put_pte_flags(flags) };
}

/* Construct a pte from its direct integer representation. */
#define l1e_from_intpte(intpte)    ((pte_t) { (intpte_t)(intpte) })
#define l2e_from_intpte(intpte)    ((pde_t) { (intpte_t)(intpte) })

/* Get pte access flags (unsigned int). */
#define l1e_get_flags(x)           (get_pte_flags((x).l1))
#define l2e_get_flags(x)           (get_pte_flags((x).l2))

/* Construct a pte from a page pointer and access flags. */
#define l1e_from_page(page, flags) (l1e_from_pfn(page_to_pfn(page),(flags)))
#define l2e_from_page(page, flags) (l2e_from_pfn(page_to_pfn(page),(flags)))

/* Add extra flags to an existing pte. */
#define l1e_add_flags(x, flags)    ((x).l1 |= put_pte_flags(flags))
#define l2e_add_flags(x, flags)    ((x).l2 |= put_pte_flags(flags))

/* Remove flags from an existing pte. */
#define l1e_remove_flags(x, flags) ((x).l1 &= ~put_pte_flags(flags))
#define l2e_remove_flags(x, flags) ((x).l2 &= ~put_pte_flags(flags))

/* Check if a pte's page mapping or significant access flags have changed. */
#define l1e_has_changed(x,y,flags) \
    ( !!(((x).l1 ^ (y).l1) & ((PADDR_MASK&PAGE_MASK)|put_pte_flags(flags))) )
#define l2e_has_changed(x,y,flags) \
    ( !!(((x).l2 ^ (y).l2) & ((PADDR_MASK&PAGE_MASK)|put_pte_flags(flags))) )

/* Pagetable walking. */
#define l2e_to_l1e(x)              ((pte_t *)__va(l2e_get_paddr(x)))

/* Given a virtual address, get an entry offset into a page table. */
#define pte_index(a)         \
    (((a) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1))
#define pde_index(a)         \
    (((a) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1))


/* Convert a pointer to a page-table entry into pagetable slot index. */
#define pgentry_ptr_to_slot(_p)    \
    (((unsigned long)(_p) & ~PAGE_MASK) / sizeof(*(_p)))


/* page-table type */
typedef struct { u32 pfn; } pagetable_t;

#define pagetable_get_paddr(x) ((physaddr_t)(x).pfn << PAGE_SHIFT)
#define pagetable_get_pfn(x)   ((x).pfn)
#define mk_pagetable(pa)       \
    ({ pagetable_t __p; __p.pfn = (pa) >> PAGE_SHIFT; __p; })

extern void cpu_switch_ttb(physaddr_t);


#define LINEAR_PT_OFFSET (LINEAR_PT_VIRT_START)

#define linear_l1_table							\
    ((pte_t *)(LINEAR_PT_VIRT_START))

// [TODO] check PAGETABLE_ORDER
#define __linear_l2_table												\
    ((pde_t *)(LINEAR_PT_VIRT_START +							\
					  (LINEAR_PT_OFFSET >> (ROOT_PAGETABLE_ORDER<<0))))

#define linear_pg_table linear_l1_table
#define linear_l2_table(_ed) ((_ed)->arch.guest_vtable)


// [TODO]
//  - replace values with constants defined in pgtable.h

#define _L2_PAGE_SECTION  	0x002U
#define _L2_PAGE_COARSE_PT	0x001U
#define _L2_PAGE_PRESENT	0x003U
#define _L2_PAGE_BUFFERABLE 0x004U
#define _L2_PAGE_CACHEABLE	0x008U

#define _L1_PAGE_SMALL_PG	0x002U
#define _L1_PAGE_PRESENT	0x002U
#define _L1_PAGE_BUFFERABLE 0x004U
#define _L1_PAGE_CACHEABLE	0x008U
#define _L1_PAGE_AP_MANAGER	0xFF0U
#define _L1_PAGE_RW_USER	PTE_SMALL_AP_URW_SRW
#define _L1_PAGE_RO_USER	PTE_SMALL_AP_URO_SRW


/* Map physical page range in Xen virtual address space. */
#define MAP_SMALL_PAGES (1UL<<16) /* don't use superpages for the mapping */

/*
 * Debug option: Ensure that granted mappings are not implicitly unmapped.
 * WARNING: This will need to be disabled to run OSes that use the spare PTE
 * bits themselves (e.g., *BSD).
 */
#ifndef NDEBUG
#define _PAGE_GNTTAB   _PAGE_AVAIL2
#else
#define _PAGE_GNTTAB   0
#endif

/*
 * Disallow unused flag bits plus PAT, PSE and GLOBAL. Also disallow GNTTAB
 * if we are using it for grant-table debugging. Permit the NX bit if the
 * hardware supports it.
 */
#define L2_BASE_DISALLOW_MASK (0x00000200U)
#define L1_BASE_DISALLOW_MASK (0x00000001U)


#endif /* !__ASSEMBLY__ within __XEN__ */
#endif /* !__XEN__ */
#endif /* __KERNEL__ */
#endif
