/*
 * domain_build.c
 *
 * Copyright (C) 2008 Samsung Electronics
 *          ChanJu Park  <bestworld@samsung.com>
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

#include <xen/sched.h>
#include <xen/elf.h>
#include <xen/domain.h>
#include <xen/mm.h>
#include <xen/errno.h>
#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/current.h>
#include <xen/compile.h>
#include <xen/iocap.h>
#include <xen/xmalloc.h>
#include <public/xen.h>
#include <asm/mm.h>
#include <asm/memmap.h>
#include <asm/time.h>
#include <public/security/secure_storage_struct.h>
#include <security/ssm-xen/sra_func.h>
#include <security/crypto/crypto.h>
#include <security/acm/acm_hooks.h>

#include <public/version.h>

extern struct domain * idle_domain;

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)
#define DOM0	0x00
#define panic	printf

#define is_initial_dom_create(v)   ((v->domain->domain_id) == 0)

#ifdef CONFIG_VMM_SECURITY_IMAGE_VERIFICATION
static void image_verification_for_security(unsigned long image_addr, domid_t domain_id);
#endif

static const char *feature_names[XENFEAT_NR_SUBMAPS * 32] = {
	[XENFEAT_writable_page_tables]       = "writable_page_tables",
	[XENFEAT_auto_translated_physmap]    = "auto_translated_physmap",
	[XENFEAT_supervisor_mode_kernel]     = "supervisor_mode_kernel",
};

static void parse_features(
	const char *feats,
	uint32_t supported[XENFEAT_NR_SUBMAPS],
	uint32_t required[XENFEAT_NR_SUBMAPS])
{
	const char *end, *p;
	int i, req;

	if ((end = strchr(feats, ',')) == NULL)
		end = feats + strlen(feats);

	while (feats < end) {
		p = strchr(feats, '|');
		if ((p == NULL) || (p > end))
			p = end;

		req = (*feats == '!');
		if (req)
			feats++;

		for (i = 0; i < XENFEAT_NR_SUBMAPS * 32; i++) {
			if (feature_names[i] == NULL)
				continue;

			if (strncmp(feature_names[i], feats, p - feats) == 0) {
				set_bit(i, (unsigned long *)supported);
			if (req)
				set_bit(i, (unsigned long *)required);
			break;
		}
	}

	if (i == XENFEAT_NR_SUBMAPS * 32) {
		printk("Unknown kernel feature \"%.*s\".\n",
		(int)(p-feats), feats);
		if (req)
			panic("Domain 0 requires an unknown hypervisor feature.\n");
	}

	feats = p;
	if ( *feats == '|' )
		feats++;
	}
}

static struct page_info *alloc_chunk(struct domain *d, unsigned long max_pages)
{
	struct page_info *page = NULL;
	unsigned int order;

	order = get_order_from_pages(max_pages);

	if (acm_alloc_chunk(d, order) <= 0) {
		return NULL;
	}

	if ((max_pages & (max_pages-1)) != 0) {
		order--;
	}

	while ((page = alloc_domheap_pages(d, order, 0)) == NULL) {
		if (order-- == 0) 
			break;
		
	}

	return page;
}

int setup_pg_tables(struct vcpu *v,
                    unsigned long dsi_v_start,
                    unsigned long v_end,
                    unsigned long alloc_spfn,
                    unsigned long vpt_start,
                    unsigned long vpt_end)
{
	unsigned long count;
        unsigned long mpt_alloc;
        unsigned long mfn;
        unsigned long x;
        unsigned long init_exception_table;
	unsigned long mapcache_pages;

        struct page_info *page = NULL;
        struct domain *d = NULL;

	pde_t *pde = NULL, *l2start = NULL;
	pte_t *pte = NULL, *l1start = NULL;

	ASSERT(v);	

        d = v->domain;

	/* get physical address for mpt_alloc */
	/* alloc_spfn should be pointed to the physical start address of memory 
	 * that is allocated to the current domain
	 */
	mpt_alloc = (vpt_start - dsi_v_start) + (unsigned long)pfn_to_phys(alloc_spfn);
	l2start = pde = (pde_t *)mpt_alloc; 
	mpt_alloc += L2_PAGE_TABLE_SIZE;

	/* copy page table of idle domain to guest domain */
	memcpy(pde, &idle_pg_table[0], L2_PAGE_TABLE_SIZE);

        /* mapcache */
	mapcache_pages = (unsigned long)alloc_xenheap_page();
	clear_page(mapcache_pages);
	d->arch.mapcache.l1tab = (pte_t *)mapcache_pages;
	
	pte = (pte_t *)virt_to_phys((void *)mapcache_pages); 
	pde = l2start + l2_linear_offset(MAPCACHE_VIRT_START);
	
	for (count = 0; count < 4; count++) {
		*(pde + count) = l2e_from_paddr((unsigned long)pte, __L2_PAGE_USER_TABLE);		
		pte += 256;
	}

	pte = NULL;
	pde = l2start;

	/* guest start address (phys/virtual addr) */
	v->arch.guest_pstart = pfn_to_phys(alloc_spfn);
	v->arch.guest_vstart = dsi_v_start;

	/* guest page table address (phys addr) */
	v->arch.guest_table  = mk_pagetable((unsigned long)l2start);
	v->arch.guest_vtable = (intpde_t *)vpt_start;

	pde += l2_linear_offset(dsi_v_start);
	mfn = alloc_spfn;

	for (count = 0; count < ((v_end - dsi_v_start) >> PAGE_SHIFT); count++) {
		if ( !((unsigned long)pte & (PAGE_SIZE/4 - 1)) ) {               /* /4 for ARM PT */
			if ( !((unsigned long)pte & (PAGE_SIZE/2 - 1)) ) {       /* /2 for ARM Linux PT */
				l1start = pte = (pte_t *)mpt_alloc;
				mpt_alloc += PAGE_SIZE;
				clear_page(pte);
			}

			*pde = l2e_from_paddr((unsigned long)pte, __L2_PAGE_USER_TABLE);
			pde++;

			if (count == 0)
				pte += pte_index(dsi_v_start);
		}

		*pte = l1e_from_pfn(mfn, __L1_PAGE_USER_SMALL);

                page = pfn_to_page(mfn);
                if ( !get_page_and_type(page, d, PGT_writable_page) )
                        BUG();

		/* Pages that are part of page tables must be read only. */
                if ( (count >= ((vpt_start - dsi_v_start) >> PAGE_SHIFT)) &&
                        (count <  ((vpt_end - dsi_v_start) >> PAGE_SHIFT)) ) {
                        l1e_remove_flags(*pte, PTE_SMALL_AP_URW_SRW);
                        l1e_add_flags(*pte, PTE_SMALL_AP_URO_SRW);

                        /* if page is page directory */
                        /* [CHECK] why should set 1page directory only at arm? */
                        if ( count < (((vpt_start - dsi_v_start) >> PAGE_SHIFT) + 1) ) {
                                page->u.inuse.type_info &= ~PGT_type_mask;
                                page->u.inuse.type_info |= PGT_l2_page_table;

                                get_page(page, d); /* an extra ref because of readable mapping */

                                /* Get another ref to L2 page so that it can be pinned. */
                                if ( !get_page_and_type(page, d, PGT_l2_page_table) )
                                        BUG();
                                set_bit(_PGT_pinned, &page->u.inuse.type_info);
                        }
                        /* if page is page table */
                        else {
                                page->u.inuse.type_info &= ~PGT_type_mask;
                                page->u.inuse.type_info |= PGT_l1_page_table;
                                /* Don't know that the follow code need at arm */
                                /*
                                page->u.inuse.type_info |=
                                        ((dsi_v_start >> L2_PAGETABLE_SHIFT) + (count - ((vpt_start - dsi_v_start) >> PAGE_SHIFT) - 1)) << PGT_va_shift;
                                */
                                get_page(page, d); /* an extra ref because of readable mapping */
                        }
                }

		pte++;
		mfn++;
	}

        /* PT for fixmap */
        pde = l2start + l2_linear_offset(HYPERVISOR_VIRT_START - (1<<L2_PAGETABLE_SHIFT)*2);
        pte = (pte_t *)mpt_alloc;
        mpt_alloc += PAGE_SIZE;
        clear_page(pte);

        *pde++ = l2e_from_paddr((unsigned long)pte, __L2_PAGE_USER_TABLE);
        *pde++ = l2e_from_paddr((unsigned long)(pte + 256), __L2_PAGE_USER_TABLE);

        /* PT for low exception table */
        pde = l2start + l2_linear_offset(0);
        pte = (pte_t *)mpt_alloc;
        mpt_alloc += PAGE_SIZE;
        clear_page(pte);

        /*
         * __L2_PAGE_USER_TABLE attribute should be replace with corrent value.
         */
        *pde = l2e_from_paddr((unsigned long)pte, __L2_PAGE_HYPERVISOR_TABLE);
        pte += pte_index(0);
        
        init_exception_table = idle_pg_table[0].l2;

        init_exception_table = (init_exception_table & 0xFFFFF000);
        x = *((unsigned long *)init_exception_table);
        *(unsigned long *)pte = x;

	/* zap low mappings and reinstate the caller's page tables */
	zap_low_mappings(l2start);

        return 0;
}

int setup_m2p_tables(struct domain *d,
                    unsigned long alloc_spfn,
                    unsigned long alloc_epfn,
                    unsigned long vphysmap_start,
                    unsigned long nr_pages)
{
        unsigned long pfn;
        unsigned long mfn;

        struct page_info *page = NULL;

	ASSERT(d);

	for (pfn = 0; pfn < d->tot_pages; pfn++) {
		mfn = pfn + alloc_spfn;
#ifndef NDEBUG
#define REVERSE_START ((v_end - dsi.v_start) >> PAGE_SHIFT)
		if (pfn > REVERSE_START)
			mfn = alloc_epfn - (pfn - REVERSE_START);
#endif
		/* write pfn->mfn table in guest table */
		((unsigned long *)vphysmap_start)[pfn] = mfn;

		/* set mfn->pfn table in vmm table */
		set_pfn_from_mfn(mfn, pfn);
	}

	while (pfn < nr_pages) {
		if ((page = alloc_chunk(d, nr_pages - d->tot_pages)) == NULL)
			panic("Not enough RAM for DOM0 reservation.\n");

		while (pfn < d->tot_pages) {
			mfn = page_to_pfn(page);
#ifndef NDEBUG
#define pfn (nr_pages - 1 - (pfn - (alloc_epfn - alloc_spfn)))
#endif
			((unsigned long *)vphysmap_start)[pfn] = mfn;
			set_pfn_from_mfn(mfn, pfn);
#undef pfn
			page++; pfn++;
		}
	}

        return 0;
}

extern void set_shared_info_mapping_xen( struct domain * d, unsigned long va, unsigned long pa );
extern pte_t *get_pl1pte_from_virtaddr(struct vcpu *v, unsigned long va);

int setup_shared_info_mapping(struct domain *d, struct vcpu *old_v)
{
    	struct vcpu *v      = NULL;
        struct domain **pod = NULL;
        unsigned long s_pa;
        unsigned long s_va;
        pte_t *pval         = NULL;
	unsigned long flags;

	ASSERT(d);

        v = d->vcpu[0];

        if (old_v != NULL) {
                local_irq_save(flags);
                save_ptbase(old_v);
                write_ptbase(v);
        }

        write_lock(&domlist_lock);
        for (pod = &domain_list; *pod != NULL; pod = &(*pod)->next_in_list) {
		struct vcpu *pod_v      = NULL;
		pte_t * l1pte = NULL;
		
                if ((*pod)->domain_id == d->domain_id)
                        continue;

                /* link the new domain's shared_info page address to others. */
                s_va = DOM_SHARED_INFO_PAGE_BASE_VADDR + (d->domain_id << PAGE_SHIFT);  

                /* d->shared_info contains xen private virtual address yet. */
                s_pa = virt_to_phys(d->shared_info);
                write_ptbase((*pod)->vcpu[0]);
                set_shared_info_mapping_xen((struct domain *)(*pod), s_va, s_pa);

		pod_v = (*pod)->vcpu[0];
		l1pte = get_pl1pte_from_virtaddr( pod_v,s_va );
		l1e_remove_flags(*l1pte, PTE_SMALL_AP_URW_SRW);
		l1e_add_flags(*l1pte, PTE_SMALL_AP_URO_SRW);
		
                /* link other domains' shared_info page address to the new domain.
                 * to make virt_to_phys correctly work.
                 */
		
                pval = get_pl1pte_from_virtaddr((*pod)->vcpu[0], (unsigned long)((*pod)->shared_info));

	        ASSERT(pval);

                if (!pval)
                        BUG();

                s_pa = l1e_get_paddr(*pval);
                write_ptbase(v);
                set_shared_info_mapping_xen(d, (unsigned long)((*pod)->shared_info), s_pa);
		
		l1pte = get_pl1pte_from_virtaddr((struct vcpu *)v,(unsigned long)((*pod)->shared_info));
		 l1e_remove_flags(*l1pte, PTE_SMALL_AP_URW_SRW);
		 l1e_add_flags(*l1pte, PTE_SMALL_AP_URO_SRW);
        }
        write_unlock(&domlist_lock);

        if (old_v != NULL) {
                write_ptbase(old_v);
                local_irq_restore(flags);
        }

        return 0;
}

extern struct page_info *set_guest_pages(
    struct domain *d, unsigned long guest_paddr, unsigned int guest_size, unsigned int flags);

extern void init_domain_time(struct domain *d);

int construct_dom0(struct domain *d,
                    unsigned long guest_start, unsigned long guest_size,
                    unsigned long image_start, unsigned long image_size,
                    unsigned long initrd_start, unsigned long initrd_size,
                    char *cmdline)
{
	char    *p = NULL;
	int     i;
        int     rc;

        unsigned long nr_pages;
        unsigned long nr_pt_pages;

	unsigned long alloc_spfn;
	unsigned long alloc_epfn;
        unsigned long guest_phys_offset;

        unsigned long vinitrd_start;
        unsigned long vinitrd_end;
        unsigned long vphysmap_start;
        unsigned long vphysmap_end;
        unsigned long vstartinfo_start;
        unsigned long vstartinfo_end;
        unsigned long vstack_start;
        unsigned long vstack_end;
        unsigned long vpt_start;
        unsigned long vpt_end;
        unsigned long v_end;
	 unsigned long flags;

	struct page_info *page = NULL;
	struct start_info *si  = NULL;
	struct domain_setup_info dsi;
	struct vcpu *v         = NULL;

	uint32_t domain_features_supported[XENFEAT_NR_SUBMAPS] = { 0 };
	uint32_t domain_features_required[XENFEAT_NR_SUBMAPS] = { 0 };

	ASSERT(d);

	v = d->vcpu[0];
	BUG_ON(d->domain_id != 0);
	BUG_ON(d->vcpu[0] == NULL);

	ASSERT(v);

	BUG_ON(test_bit(_VCPUF_initialised, &v->vcpu_flags));

	memset(&dsi, 0, sizeof(struct domain_setup_info));

	dsi.image_addr = image_start;
	dsi.image_len  = image_size;

	printk("*** LOADING DOMAIN : %d ***\n", (int)d->domain_id);

	d->max_pages = ~0U;

#ifdef CONFIG_VMM_SECURITY_IMAGE_VERIFICATION
        image_verification_for_security( (unsigned long)dsi.image_addr, d->domain_id);
#endif

	rc = parseelfimage(&dsi);
	if (rc != 0) {
		return rc;
	}

#ifdef CONFIG_VMM_SECURITY_ACM
        d->scid = dsi.scid;
        d->acm_batterylife = 100;
        acm_weight_dom_cpu(d);
#else
        d->scid = ~(0x0UL);
#endif

	if (dsi.xen_section_string == NULL) {
		printk("Not a Xen-ELF image: '__xen_guest' section not found.\n");
		return -EINVAL;
	}

	if ((p = strstr(dsi.xen_section_string, "FEATURES=")) != NULL) {
		parse_features(p + strlen("FEATURES="),
			domain_features_supported,
			domain_features_required);

		printk("Guest kernel supports features = { %08x }.\n",
			domain_features_supported[0]);
		printk("Guest kernel requires features = { %08x }.\n",
                        domain_features_required[0]);

		if (domain_features_required[0]) {
			printk("Guest kernel requires an unsupported hypervisor feature.\n");
			return -EINVAL;
		}
	}

        /* Align load address to 1MB boundary. */
        dsi.v_start &= ~((1UL << L2_PAGETABLE_SHIFT) - 1);

	nr_pages = guest_size >> PAGE_SHIFT;

	vinitrd_start       = round_pgup(dsi.v_end);
	vinitrd_end         = vinitrd_start + initrd_size;
	vphysmap_start      = round_pgup(vinitrd_end);
	vphysmap_end        = vphysmap_start + (nr_pages * sizeof(unsigned long));
	vstartinfo_start    = round_pgup(vphysmap_end);
	vstartinfo_end      = vstartinfo_start + PAGE_SIZE;
	vpt_start           = PGD_ALIGN(vstartinfo_end);

	/* get page table size */
        nr_pt_pages = ((nr_pages << PAGE_SHIFT) >> L2_PAGETABLE_SHIFT) + 1;
	nr_pt_pages /= 2;       // because arm
	nr_pt_pages += (L2_PAGE_TABLE_SIZE >> PAGE_SHIFT);      // 4page for page directory
        nr_pt_pages += 2;       // for fixmap pt
	nr_pt_pages += 1;	// for exception vector

	vpt_end             = vpt_start + (nr_pt_pages * PAGE_SIZE);
	vstack_start        = vpt_end;
	vstack_end          = vstack_start + PAGE_SIZE;    
        v_end               = dsi.v_start + (nr_pages << PAGE_SHIFT);

	page = set_guest_pages(d, guest_start,guest_size, (~ALLOC_DOM_DMA));

	if (page == NULL) {
		printk("Not enough RAM for domain %d allocation.\n", d->domain_id);
		return -ENOMEM;
	}

	alloc_spfn = page_to_pfn(page);
	alloc_epfn = alloc_spfn + d->tot_pages;

	printk("Physical Memory Arrangement: " "%"PRIphysaddr"->%"PRIphysaddr,
		pfn_to_phys(alloc_spfn), pfn_to_phys(alloc_epfn));

	if (d->tot_pages < nr_pages)
		printk(" (%lu pages to be allocated)", nr_pages - d->tot_pages);

	printk("\nVIRTUAL MEMORY ARRANGEMENT:\n"
		" Loaded kernel: %p->%p\n"
		" Init. ramdisk: %p->%p\n"
		" Phys-Mach map: %p->%p\n"
		" Start info:    %p->%p\n"
		" Page tables:   %p->%p\n"
		" Boot stack:    %p->%p\n"
		" TOTAL:         %p->%p\n",
		_p(dsi.v_kernstart), _p(dsi.v_kernend),
		_p(vinitrd_start), _p(vinitrd_end),
		_p(vphysmap_start), _p(vphysmap_end),
		_p(vstartinfo_start), _p(vstartinfo_end),
		_p(vpt_start), _p(vpt_end),
		_p(vstack_start), _p(vstack_end),
		_p(dsi.v_start), _p(v_end));
        printk(" ENTRY ADDRESS: %p\n", _p(dsi.v_kernentry));

	if ((v_end - dsi.v_start) > (nr_pages * PAGE_SIZE)) {
		printk("Initial guest OS requires too much space\n"
			"(%luMB is greater than %luMB limit)\n",
			(v_end - dsi.v_start) >> 20, (nr_pages << PAGE_SHIFT) >> 20);
		return -ENOMEM;
	}

        rc = setup_pg_tables(v, dsi.v_start, v_end, alloc_spfn, vpt_start, vpt_end);

	if (rc != 0) {
		return rc;
	}

        /* Mask all upcalls... */
	for (i = 0; i < MAX_VIRT_CPUS; i++)
		d->shared_info->vcpu_info[i].evtchn_upcall_mask = 1;

	for (i = 1; i < num_online_cpus(); i++)
		(void)alloc_vcpu(d, i, i);

        /* changed info guest domain context */
	local_irq_save(flags);
	save_ptbase(current);
	write_ptbase(v);

	guest_phys_offset = v->arch.guest_pstart - v->arch.guest_vstart;
        dsi.image_addr -= guest_phys_offset;

	/* Copy the OS image and free temporary buffer. */
	(void)loadelfimage(&dsi);

	memzero((void *) (image_start - guest_phys_offset), image_size);

	/* Copy the initial ramdisk and free temporary buffer. */
	if (initrd_size != 0) {
		memcpy((void *)vinitrd_start, (const void *)(initrd_start - guest_phys_offset), initrd_size);
		memzero((void *)(initrd_start  - guest_phys_offset), initrd_size);
	}

	/* Set up start info area. */
	si = (start_info_t *)vstartinfo_start;
	memset(si, 0, PAGE_SIZE);

	si->nr_pages = nr_pages;
	si->shared_info = virt_to_phys(d->shared_info);
	si->flags        = SIF_PRIVILEGED | SIF_INITDOMAIN;
	si->pt_base      = vpt_start;
	si->nr_pt_frames = nr_pt_pages;
	si->mfn_list     = vphysmap_start;
	si->min_mfn      = min_page;
	sprintf(si->magic, "xen-%i.%i-arm_%d%s",
		XEN_VERSION, XEN_SUBVERSION, BITS_PER_LONG, "");

	if (initrd_size != 0) {
		si->mod_start = vinitrd_start;
		si->mod_len   = initrd_size;
		printk("Initrd len 0x%lx, start at 0x%lx\n",
			si->mod_len, si->mod_start);
	}

	memset(si->cmd_line, 0, sizeof(si->cmd_line));
	if (cmdline != NULL)
		strncpy((char *)si->cmd_line, cmdline, sizeof(si->cmd_line)-1);

	/* Write the phys->machine and machine->phys table entries. */
        rc = setup_m2p_tables(d, alloc_spfn, alloc_epfn, vphysmap_start, nr_pages);
	if (rc != 0) {
		local_irq_restore(flags);
		return rc;
	}

	write_ptbase(current);
	local_irq_restore(flags);

	init_domain_time((struct domain *)d);

	set_bit(_VCPUF_initialised, &v->vcpu_flags);

	new_thread(v, dsi.v_kernentry, vstack_end, vstartinfo_start);

	i = 0;

#ifndef CONFIG_VMM_SECURITY_ACM
	i |= ioports_permit_access(d, 0, 0xFFFF);
	i |= iomem_permit_access(d, 0UL, ~0UL);
	i |= irqs_permit_access(d, 0, NR_PIRQS-1);

	printk(" [TODO] dma channel access permission, in construct_dom0() \n" );	
#endif

	BUG_ON(i != 0);

	return 0;
}

int construct_guest_dom(struct domain *d,
                    unsigned long guest_start, unsigned long guest_size,
                    unsigned long image_start, unsigned long image_size,
                    unsigned long initrd_start, unsigned long initrd_size,
                    char *cmdline)
{
	char    *p = NULL;
	int     i;
        int     rc;

        unsigned long nr_pages;
        unsigned long nr_pt_pages;

	unsigned long alloc_spfn;
	unsigned long alloc_epfn;
        unsigned long guest_phys_offset;

        unsigned long vinitrd_start;
        unsigned long vinitrd_end;
        unsigned long vphysmap_start;
        unsigned long vphysmap_end;
        unsigned long vstore_mfn_start;
        unsigned long vstore_mfn_end;
        unsigned long vconsole_mfn_start;
        unsigned long vconsole_mfn_end;
        unsigned long vstartinfo_start;
        unsigned long vstartinfo_end;
        unsigned long vstack_start;
        unsigned long vstack_end;
        unsigned long vpt_start;
        unsigned long vpt_end;
        unsigned long v_end;

        unsigned long pstore_mfn_start;
        unsigned long pconsole_mfn_start;

	struct page_info *page = NULL; 
	struct start_info *si  = NULL;
	struct domain_setup_info dsi;
	struct vcpu *v         = NULL;

	uint32_t domain_features_supported[XENFEAT_NR_SUBMAPS] = { 0 };
	uint32_t domain_features_required[XENFEAT_NR_SUBMAPS] = { 0 };

	ASSERT(d);

	v = d->vcpu[0];
	BUG_ON(d->domain_id <= 0);
	BUG_ON(d->vcpu[0] == NULL);

	ASSERT(v);

	BUG_ON(test_bit(_VCPUF_initialised, &v->vcpu_flags));

        /* change current context into idle domain  */
        local_irq_disable();
        save_ptbase(current);
        write_ptbase(idle_domain->vcpu[0]);

	memset(&dsi, 0, sizeof(struct domain_setup_info));

	dsi.image_addr = image_start;
	dsi.image_len  = image_size;

	printk("*** LOADING DOMAIN : %d ***\n", (int)d->domain_id);

	d->max_pages = ~0U;

#ifdef CONFIG_VMM_SECURITY_IMAGE_VERIFICATION
        image_verification_for_security( (unsigned long)dsi.image_addr, d->domain_id);
#endif

	rc = parseelfimage(&dsi);
	if (rc != 0) {
        local_irq_enable();
		return rc;
	}

#ifdef CONFIG_VMM_SECURITY_ACM
        d->scid = dsi.scid;
        d->acm_batterylife = 100;
        acm_weight_dom_cpu(d);
#else
        d->scid = ~(0x0UL);
#endif

	if (dsi.xen_section_string == NULL) {
		printk("Not a Xen-ELF image: '__xen_guest' section not found.\n");
        local_irq_enable();
		return -EINVAL;
	}

	if ((p = strstr(dsi.xen_section_string, "FEATURES=")) != NULL) {
		parse_features(p + strlen("FEATURES="),
			domain_features_supported,
			domain_features_required);

		printk("Guest kernel supports features = { %08x }.\n",
			domain_features_supported[0]);
		printk("Guest kernel requires features = { %08x }.\n",
                        domain_features_required[0]);

		if (domain_features_required[0]) {
			printk("Guest kernel requires an unsupported hypervisor feature.\n");
			local_irq_enable();
			return -EINVAL;
		}
	}

        /* Align load address to 1MB boundary. */
        dsi.v_start &= ~((1UL << L2_PAGETABLE_SHIFT) - 1);

	nr_pages = guest_size >> PAGE_SHIFT;

	vinitrd_start       = round_pgup(dsi.v_end);
	vinitrd_end         = vinitrd_start + initrd_size;
	vphysmap_start      = round_pgup(vinitrd_end);
        vphysmap_end        = vphysmap_start + (nr_pages * sizeof(unsigned long));
        vstore_mfn_start    = round_pgup(vphysmap_end);
        vstore_mfn_end      = vstore_mfn_start + PAGE_SIZE;
        vconsole_mfn_start  = round_pgup(vstore_mfn_end);
        vconsole_mfn_end    = vconsole_mfn_start + PAGE_SIZE;
	vstartinfo_start    = round_pgup(vconsole_mfn_end);
	vstartinfo_end      = vstartinfo_start + PAGE_SIZE;
	vpt_start           = PGD_ALIGN(vstartinfo_end);

	/* get page table size */
        nr_pt_pages = ((nr_pages << PAGE_SHIFT) >> L2_PAGETABLE_SHIFT) + 1;
	nr_pt_pages /= 2;       // because arm
	nr_pt_pages += (L2_PAGE_TABLE_SIZE >> PAGE_SHIFT);      // 4page for page directory
        nr_pt_pages += 2;       // for fixmap pt
	nr_pt_pages += 1;	// for exception vector

	vpt_end             = vpt_start + (nr_pt_pages * PAGE_SIZE);
	vstack_start        = vpt_end;
	vstack_end          = vstack_start + PAGE_SIZE;    
        v_end               = dsi.v_start + (nr_pages << PAGE_SHIFT);

	page = (struct page_info *)set_guest_pages(d, guest_start, guest_size, ~ALLOC_DOM_DMA);

	ASSERT(page);

	if (page == NULL) {
		printk("Not enough RAM for domain %d allocation.\n", d->domain_id);
		local_irq_enable();
		return -ENOMEM;
	}

	alloc_spfn = page_to_pfn(page);
	alloc_epfn = alloc_spfn + d->tot_pages;

	printk("Physical Memory Arrangement: " "%"PRIphysaddr"->%"PRIphysaddr,
		pfn_to_phys(alloc_spfn), pfn_to_phys(alloc_epfn));

	if (d->tot_pages < nr_pages)
		printk(" (%lu pages to be allocated)", nr_pages - d->tot_pages);

	printk("\nVIRTUAL MEMORY ARRANGEMENT:\n"
		" Loaded kernel: %p->%p\n"
		" Init. ramdisk: %p->%p\n"
		" Phys-Mach map: %p->%p\n"
                " Store mfn:     %p->%p\n"
                " Console mfn:   %p->%p\n"
		" Start info:    %p->%p\n"
		" Page tables:   %p->%p\n"
		" Boot stack:    %p->%p\n"
		" TOTAL:         %p->%p\n",
		_p(dsi.v_kernstart), _p(dsi.v_kernend),
		_p(vinitrd_start), _p(vinitrd_end),
		_p(vphysmap_start), _p(vphysmap_end),
                _p(vstore_mfn_start), _p(vstore_mfn_end),
                _p(vconsole_mfn_start), _p(vconsole_mfn_end),
		_p(vstartinfo_start), _p(vstartinfo_end),
		_p(vpt_start), _p(vpt_end),
		_p(vstack_start), _p(vstack_end),
		_p(dsi.v_start), _p(v_end));
        printk(" ENTRY ADDRESS: %p\n", _p(dsi.v_kernentry));

	if ((v_end - dsi.v_start) > (nr_pages * PAGE_SIZE)) {
		printk("Initial guest OS requires too much space\n"
			"(%luMB is greater than %luMB limit)\n",
			(v_end - dsi.v_start) >> 20, (nr_pages << PAGE_SHIFT) >> 20);
		local_irq_enable();
		return -ENOMEM;
        }

        rc = setup_pg_tables(v, dsi.v_start, v_end, alloc_spfn, vpt_start, vpt_end);
	if (rc != 0) {
		local_irq_enable();
		return rc;
	}

        /* Mask all upcalls... */
	for (i = 0; i < MAX_VIRT_CPUS; i++)
		d->shared_info->vcpu_info[i].evtchn_upcall_mask = 1;

	for (i = 1; i < num_online_cpus(); i++)
		(void)alloc_vcpu(d, i, i);

        /* changed info guest domain context */
        save_ptbase(idle_domain->vcpu[0]);
        write_ptbase(v);

	guest_phys_offset = v->arch.guest_pstart - v->arch.guest_vstart;
        dsi.image_addr -= guest_phys_offset;

	/* Copy the OS image and free temporary buffer. */
	(void)loadelfimage(&dsi);

	memzero((void *) (image_start - guest_phys_offset), image_size);

	/* Copy the initial ramdisk and free temporary buffer. */
	if (initrd_size != 0) {
		memcpy((void *)vinitrd_start, (const void *)(initrd_start - guest_phys_offset), initrd_size);
		memzero((void *)(initrd_start  - guest_phys_offset), initrd_size);
	}

	/* Set up start info area. */
	si = (start_info_t *)vstartinfo_start;
	memset(si, 0, PAGE_SIZE);

	si->nr_pages = nr_pages;
	si->shared_info = virt_to_phys(d->shared_info);
	si->flags        = 0;
	si->pt_base      = vpt_start;
	si->nr_pt_frames = nr_pt_pages;
	si->mfn_list     = vphysmap_start;
	si->min_mfn      = min_page;

        pstore_mfn_start = vstore_mfn_start - dsi.v_start + pfn_to_phys(alloc_spfn);
        printk("store_mfn physical addres %lx\n",pstore_mfn_start);
        si->store_mfn = (pstore_mfn_start>>PAGE_SHIFT);
        d->store_mfn = (pstore_mfn_start>>PAGE_SHIFT);
        si->store_evtchn = d->store_port;

        /* init store_mfn */
        memset((void *)vstore_mfn_start, (int)0, (size_t)PAGE_SIZE);

        pconsole_mfn_start = vconsole_mfn_start - dsi.v_start + pfn_to_phys(alloc_spfn);
        printk("console_mfn physical addres %lx\n",pconsole_mfn_start);
        si->console_mfn = (pconsole_mfn_start>>PAGE_SHIFT);
        d->console_mfn = (pconsole_mfn_start>>PAGE_SHIFT);
        si->console_evtchn = d->console_port;

        /* init console_mfn */
        memset((void *)vconsole_mfn_start, (int)0, (size_t)PAGE_SIZE);

	sprintf(si->magic, "xen-%i.%i-arm_%d%s",
		XEN_VERSION, XEN_SUBVERSION, BITS_PER_LONG, "");

	if (initrd_size != 0) {
		si->mod_start = vinitrd_start;
		si->mod_len   = initrd_size;
		printk("Initrd len 0x%lx, start at 0x%lx\n",
			si->mod_len, si->mod_start);
	}

	memset(si->cmd_line, 0, sizeof(si->cmd_line));
	if (cmdline != NULL)
		strncpy((char *)si->cmd_line, cmdline, sizeof(si->cmd_line)-1);

	/* Write the phys->machine and machine->phys table entries. */
        rc = setup_m2p_tables(d, alloc_spfn, alloc_epfn, vphysmap_start, nr_pages);
	if (rc != 0) {
		local_irq_enable();
		return rc;
	}

        /* setup shared info table which is specified each domain */
        rc = setup_shared_info_mapping(d, NULL);
	if (rc != 0) {
		local_irq_enable();
		return rc;
	}

	write_ptbase(current);
	local_irq_enable();

	init_domain_time(d);

	set_bit(_VCPUF_initialised, &v->vcpu_flags);

	new_thread(v, dsi.v_kernentry, vstack_end, vstartinfo_start);

	i = 0;

#ifndef CONFIG_VMM_SECURITY_ACM
	i |= ioports_permit_access(d, 0, 0xFFFF);
	i |= iomem_permit_access(d, 0UL, ~0UL);
	i |= irqs_permit_access(d, 0, NR_PIRQS-1);

	printk(" [TODO] dma channel access permission, in construct_guest_dom() \n" );	
#endif

	BUG_ON(i != 0);

	return 0;
}

#ifdef CONFIG_VMM_SECURITY_IMAGE_VERIFICATION
/**
 *  *
 *  @param dom_id domain id
 *  @return 0 if succeed, 1 if no image exists, -1 if fails
 *  */
static int verify_image(void* image, int dom_id)
{
        void* signature = NULL;
        size_t image_size;
        size_t sig_size;
        image_type_t image_type;
        image_type_t sig_type;
        default_struct_t* part = NULL;

        /* get image and hash */
        switch (dom_id) {
                case 0:
                    image_type = SECURE_DOM_IMG;
                    sig_type = SECURE_DOM_SIGNED_HASH;
                    break;
                case 1:
                    image_type = DRIVER_DOM_IMG;
                    sig_type = DRIVER_DOM_SIGNED_HASH;
                    break;
                case 2:
                    image_type = NORMAL_DOM1_IMG;
                    sig_type = NORMAL_DOM1_SIGNED_HASH;
                    break;
                case 3:
                    image_type = NORMAL_DOM2_IMG;
                    sig_type = NORMAL_DOM2_SIGNED_HASH;
                    break;
                case 4:
                    image_type = NORMAL_DOM3_IMG;
                    sig_type = NORMAL_DOM3_SIGNED_HASH;
                    break;
                case 5:
                    image_type = NORMAL_DOM4_IMG;
                    sig_type = NORMAL_DOM4_SIGNED_HASH;
                    break;
                default:
                    printk("verify_image(): Image is not registered\n");
                    return 1;
        }

        /* get image */
        part = sra_get_image(PART_OS_IMAGE, image_type);

	ASSERT(part);

        if (part == NULL) {
            printk("Can't get image part %d\n", image_type);
            return 1;
        }
        image_size = part->size;

        /* get signature */
        part = sra_get_image(PART_SP1, sig_type);

	ASSERT(part);

        if (part == NULL) {
            printk("Can't get signature %d\n", sig_type);
            return 1;
        }
        signature = part->u.ptr;
        sig_size = part->size;

        return crypto_verify_data(image, image_size, signature, sig_size);
}

static void image_verification_for_security( unsigned long image_addr, domid_t domain_id)
{
	if (verify_image( (void *)image_addr, domain_id) != 0) {   
		printk("Verification of DOM%d fails\n", (domid_t) domain_id);
		return;
	}
        else {
		printk("Verification of DOM%d succeeds \n", (domid_t) domain_id);
	}
}
#endif

int elf_sanity_check(Elf_Ehdr *ehdr)
{
        if ( !IS_ELF(*ehdr) ||
                (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) ||
                (ehdr->e_type != ET_EXEC) ) {
                printk("DOM0 image is not a Xen-compatible Elf image.\n");
                return 0;
        }

        return 1;
}
