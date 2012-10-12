#ifndef __ASM_ARM_GRANT_TABLE_H__
#define __ASM_ARM_GRANT_TABLE_H__

#include <asm/mm.h>

#define ORDER_GRANT_FRAMES 2

/*
 * Caller must own caller's BIGLOCK, is responsible for flushing the TLB, and
 * must hold a reference to the page.
 */
int create_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags);
int destroy_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags);


int steal_page_for_grant_transfer(
    struct domain *d, struct page_info *page);

#define gnttab_create_shared_mfn(d, t, i)                                \
    do {                                                                 \
        SHARE_PFN_WITH_DOMAIN(                                           \
            virt_to_page((char *)(t)->shared + ((i) * PAGE_SIZE)), (d)); \
        set_pfn_from_mfn(                                                \
            (virt_to_phys((t)->shared) >> PAGE_SHIFT) + (i),             \
            INVALID_M2P_ENTRY);                                          \
    } while ( 0 )

#define gnttab_create_shared_page(d, t, i)	gnttab_create_shared_mfn(d, t, i)

#define gnttab_shared_mfn(d, t, i)                      \
    ((virt_to_phys((t)->shared) >> PAGE_SHIFT) + (i))

#define gnttab_shared_gmfn(d, t, i)			\
    (mfn_to_gmfn(d, gnttab_shared_mfn(d, t, i)))

//#define gnttab_log_dirty(d, f) mark_dirty((d), (f))
#define gnttab_log_dirty(d, f)



#endif /* __ASM_ARM_GRANT_TABLE_H__ */
