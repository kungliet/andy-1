#ifndef __ARM_PGTABLE_H__
#define __ARM_PGTABLE_H__

#include <asm/cpu-domain.h>

#define PDE_TYPE_FAULT          (0x10)
#define PDE_TYPE_COARSE         (0x11)
#define PDE_TYPE_SECTION        (0x12)
#define PDE_TYPE_FINE           (0x13)

#define PDE_BIT4		(1 << 4)

#define PDE_AP_SRW_UNO          (0x01 << 10)
#define PDE_AP_SRW_URO          (0x02 << 10)
#define PDE_AP_SRW_URW          (0x03 << 10)

#define PDE_BUFFERABLE		(0x04)
#define PDE_CACHEABLE		(0x08)

#define PDE_WRITEBACK		(PDE_CACHEABLE | PDE_BUFFERABLE)
#define PDE_WRITETHROUGH	(PDE_CACHEABLE)
#define PDE_SHARED		(0)

#define PDE_DOMAIN_HYPERVISOR   (DOMAIN_HYPERVISOR << 5)
#define PDE_DOMAIN_SUPERVISOR	(DOMAIN_SUPERVISOR << 5)
#define PDE_DOMAIN_USER         (DOMAIN_USER << 5)
#define PDE_DOMAIN_IO           (DOMAIN_IO << 5)

#define PDE_TYPE_HYPERVISOR	(PDE_TYPE_SECTION | PDE_DOMAIN_HYPERVISOR | PDE_AP_SRW_UNO | PDE_WRITEBACK)
#define PDE_TYPE_IO		(PDE_TYPE_SECTION | PDE_DOMAIN_IO | PDE_AP_SRW_URW)

#define PMD_TYPE_MASK           (3 << 0)
#define PMD_TYPE_FAULT          (0 << 0)
#define PMD_TYPE_TABLE          (1 << 0)
#define PMD_TYPE_SECT           (2 << 0)
#define PMD_BIT4                (1 << 4)
#define PMD_DOMAIN(x)           ((x) << 5)
#define PMD_PROTECTION          (1 << 9)        /* v5 */

/*
 * section
 */
#define PMD_SECT_BUFFERABLE     (1 << 2)
#define PMD_SECT_CACHEABLE      (1 << 3)
#define PMD_SECT_AP_WRITE       (1 << 10)
#define PMD_SECT_AP_READ        (1 << 11)
#define PMD_SECT_TEX(x)         ((x) << 12)     /* v5 */
#define PMD_SECT_APX            (1 << 15)       /* v6 */
#define PMD_SECT_S              (1 << 16)       /* v6 */
#define PMD_SECT_nG             (1 << 17)       /* v6 */

#define PMD_SECT_UNCACHED       (0)
#define PMD_SECT_BUFFERED       (PMD_SECT_BUFFERABLE)
#define PMD_SECT_WT             (PMD_SECT_CACHEABLE)
#define PMD_SECT_WB             (PMD_SECT_CACHEABLE | PMD_SECT_BUFFERABLE)
#define PMD_SECT_MINICACHE      (PMD_SECT_TEX(1) | PMD_SECT_CACHEABLE)
#define PMD_SECT_WBWA           (PMD_SECT_TEX(1) | PMD_SECT_CACHEABLE | PMD_SECT_BUFFERABLE)


/*
 * Difinition for Page Table Entries
 */

#define PTE_TYPE_FAULT          (0x00)
#define PTE_TYPE_LARGE          (0x01)
#define PTE_TYPE_SMALL          (0x02)
#define PTE_TYPE_TINY           (0x03)

#define PTE_TYPE_MASK		(0x03)

#define PTE_BUFFERABLE          (0x04)
#define PTE_CACHEABLE           (0x08)

#define PTE_AP_MASK             (0xff << 4)

#define PTE_AP_UNO_SRW          (0x55 << 4)
#define PTE_AP_URO_SRW          (0xaa << 4)
#define PTE_AP_URW_SRW          (0xff << 4)

#define SECTION_SIZE            (0x100000)
#define PGD_SIZE                (0x4000)
#define PGT_SIZE                (0x400)

#define SECTION_MASK		(~(SECTION_SIZE - 1))
#define PGD_SHIFT               (20)
#define PGT_SHIFT               (12)

#define PGD_ALIGN(x)		((x + (0x4000 - 1)) & ~(0x4000 - 1))
#define PGT_ALIGN(x)		((x + (0x1000 - 1)) & ~(0x1000 - 1))
#define pgd_index(x)		((x) >> 20)


#define PMD_SHIFT               21
#define PMD_SIZE                (1UL << PMD_SHIFT)
#define PMD_MASK                (~(PMD_SIZE-1))

/*
 *   - small page
 */
#define PTE_SMALL_AP_MASK	(0xff << 4)
#define PTE_SMALL_AP_UNO_SRO	(0x00 << 4)
#define PTE_SMALL_AP_UNO_SRW	(0x55 << 4)
#define PTE_SMALL_AP_URO_SRW	(0xaa << 4)
#define PTE_SMALL_AP_URW_SRW	(0xff << 4)

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      20      /* REMARK: not 22 (x86) */

#define ROOT_PAGETABLE_SHIFT    L2_PAGETABLE_SHIFT

#define L1_PAGETABLE_ORDER	8
#define L2_PAGETABLE_ORDER      12
#define ROOT_PAGETABLE_ORDER    L2_PAGETABLE_ORDER
#define L1_PAGETABLE_ENTRIES    (1<<L1_PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<L2_PAGETABLE_ORDER)
#define ROOT_PAGETABLE_ENTRIES  L2_PAGETABLE_ENTRIES

#define PADDR_BITS              32
#define PADDR_MASK              (~0UL)

#define _PAGE_NX                0U

#define L1_DISALLOW_MASK	L1_BASE_DISALLOW_MASK
#define L2_DISALLOW_MASK	L2_BASE_DISALLOW_MASK


#define L2_PAGE_TABLE_SIZE		(PAGE_SIZE << 2)

#define __PAGE_HYPERVISOR       		(PMD_TYPE_SECT | PMD_SECT_BUFFERABLE | PMD_SECT_CACHEABLE | PMD_DOMAIN(DOMAIN_HYPERVISOR) | PMD_SECT_AP_WRITE)
#define __PAGE_HYPERVISOR_NOCACHE		(PMD_TYPE_SECT | PMD_DOMAIN(DOMAIN_HYPERVISOR) | PMD_SECT_AP_WRITE)

#define __PAGE_HYPERVISOR_SECT		(PMD_TYPE_SECT | PMD_SECT_BUFFERABLE | PMD_SECT_CACHEABLE | PMD_DOMAIN(DOMAIN_HYPERVISOR) | PMD_SECT_AP_WRITE)
#define __PAGE_HYPERVISOR_SMALL		(PMD_TYPE_SMALL | PTE_BUFFERABLE | PTE_CACHEABLE | PTE_SMALL_AP_UNO_SRW)

#define __L2_PAGE_HYPERVISOR_SECT		(PMD_TYPE_SECT | PMD_SECT_BUFFERABLE | PMD_SECT_CACHEABLE | PMD_DOMAIN(DOMAIN_HYPERVISOR) | PMD_SECT_AP_WRITE)
#define __L2_PAGE_HYPERVISOR_TABLE		(PMD_TYPE_TABLE | PMD_DOMAIN(DOMAIN_HYPERVISOR))
#define __L1_PAGE_HYPERVISOR_SMALL		(PTE_TYPE_SMALL | PTE_BUFFERABLE | PTE_CACHEABLE | PTE_SMALL_AP_UNO_SRW)


#define __L2_PAGE_HYPERVISOR_SECT_NOCACHE (PMD_TYPE_SECT | PMD_DOMAIN(DOMAIN_HYPERVISOR) | PMD_SECT_AP_WRITE)
#define __L1_PAGE_HYPERVISOR_SMALL_NOCACHE      (PTE_TYPE_SMALL | PTE_SMALL_AP_UNO_SRW)

#define __L2_PAGE_USER_SECT (PMD_TYPE_SECT | PMD_SECT_BUFFERABLE | PMD_SECT_CACHEABLE | PMD_DOMAIN(DOMAIN_KERNEL) | PMD_SECT_AP_WRITE | PMD_SECT_AP_READ)
#define __L2_PAGE_USER_TABLE (PMD_TYPE_TABLE | PMD_DOMAIN(DOMAIN_KERNEL))
#define __L1_PAGE_USER_SMALL    (PTE_TYPE_SMALL | PTE_BUFFERABLE | PTE_CACHEABLE | PTE_SMALL_AP_URW_SRW)
#define __L1_PAGE_USER_SMALL_NOCACHE    (PTE_TYPE_SMALL | PTE_SMALL_AP_URW_SRW)
#define __L1_PAGE_USER_RO_SMALL         (PTE_TYPE_SMALL | PTE_BUFFERABLE | PTE_CACHEABLE | PTE_SMALL_AP_URO_SRW)


#define GRANT_PTE_FLAGS		(PTE_TYPE_SMALL | PTE_BUFFERABLE | PTE_CACHEABLE | PTE_AP_URW_SRW)


#ifndef __ASSEMBLY__

#include <asm/types.h>

/* read access (should only be used for debug printk's) */
typedef u32 intpte_t;
typedef u32 intpde_t;
#define PRIpte "08x"

typedef struct { intpte_t l1; } pte_t;
typedef struct { intpte_t l2; } pde_t;
typedef pde_t root_pgentry_t;

/* misc */
#define is_guest_l1_slot(_s)    (1)
#define is_guest_l2_slot(_t,_s) ((_s) < L2_PAGETABLE_FIRST_XEN_SLOT)

/* Extract flags into 12-bit integer, or turn 12-bit flags into a pte mask. */
#define get_pte_flags(x) ((int)(x) & 0xFFF)
#define put_pte_flags(x) ((intpte_t)((x) & 0xFFF))

#define cpu_get_pgd_phys()	\
	({						\
		unsigned long pg;			\
		__asm__("mrc	p15, 0, %0, c2, c0, 0"	\
			 : "=r" (pg) : : "cc");		\
		pg &= ~0x3fff;				\
	})

#endif /* __ASSEMBLY__ */

#endif /* _ASMARM_PGTABLE_H */
