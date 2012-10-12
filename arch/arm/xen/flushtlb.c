/******************************************************************************
 * flushtlb.c
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2004, K A Fraser
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <asm/flushtlb.h>

u32 tlbflush_clock = 1U;
u32 tlbflush_time[NR_CPUS];

/* Call with no locks held and interrupts enabled (e.g., softirq context). */
void new_tlbflush_clock_period(void)
{
    //ASSERT(local_irq_is_enabled());
    
    /* No need for atomicity: we are the only possible updater. */
    ASSERT(tlbflush_clock == 0);
    tlbflush_clock++;
}



void update_tlbflush_clock(void)
{
    u32 t, t1, t2;
    unsigned long flags;

    /* This non-reentrant function is sometimes called in interrupt context. */
    local_irq_save(flags);

    /*
     * STEP 1. Increment the virtual clock *before* flushing the TLB.
     *         If we do it after, we race other CPUs invalidating PTEs.
     *         (e.g., a page invalidated after the flush might get the old 
     *          timestamp, but this CPU can speculatively fetch the mapping
     *          into its TLB after the flush but before inc'ing the clock).
     */

    t = tlbflush_clock;
    do {
        t1 = t2 = t;
        /* Clock wrapped: someone else is leading a global TLB shootdown. */
        if ( unlikely(t1 == 0) )
            goto skip_clocktick;
        t2 = (t + 1) & WRAP_MASK;
    }
    while ( unlikely((t = cmpxchg(&tlbflush_clock, t1, t2)) != t1) );

    /* Clock wrapped: we will lead a global TLB shootdown. */
    if ( unlikely(t2 == 0) )
        raise_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ);

   skip_clocktick:
    
    /*
     * STEP 3. Update this CPU's timestamp. Note that this happens *after*
     *         flushing the TLB, as otherwise we can race a NEED_FLUSH() test
     *         on another CPU. (e.g., other CPU sees the updated CPU stamp and
     *         so does not force a synchronous TLB flush, but the flush in this
     *         function hasn't yet occurred and so the TLB might be stale).
     *         The ordering would only actually matter if this function were
     *         interruptible, and something that abuses the stale mapping could
     *         exist in an interrupt handler. In fact neither of these is the
     *         case, so really we are being ultra paranoid.
     */

    tlbflush_time[smp_processor_id()] = t2;

    local_irq_restore(flags);

}

/*
 *  lockdown TLB management
 *   - use lockdown TLB to minimize TLB flush
 */

void xen_tlb_lockdown_entry(unsigned char victim, unsigned long vaddr)
{
	unsigned long reg_c10=0;
	unsigned long curr_pc=0;
	unsigned long flags;

	if( victim > TLB_LOCKDOWN_SIZE-1 ) {
		printf("ERROR: TLB lockdown victim > TLB lockdown size\n");
		return;
	}

	if( (vaddr >= DIRECTMAP_VIRT_START) && (vaddr < DIRECTMAP_VIRT_START + (1 << 20)) )
	{
		/*  jump to the same code in the identity mapping (0xc0000000) 
		 *  to load the mapping that the current code is executed on.
		 */
		asm("adr %0, load_entry\t\n"
			"sub %0, %0, %1\t\n"
			"add %0, %0, %2\t\n"
			"mov pc, %0\t\n" 
			"load_entry:\t\n "
			: 
			: "r" (curr_pc), "r" (DIRECTMAP_VIRT_START), "r" (PHYS_OFFSET) );
	}


	local_irq_save(flags);

	asm(
		/* step 1: invalidate TLB single entry to ensure that lockaddr is not already in the TLB */	
		"mcr p15, 0, %1,  c8, c7, 1\n\t"	/* read */
		/* step 2: set the preserve bit - page table walks place the TLB entry in the lockdown region  */
		/*         set the victim */
		"mrc p15, 0, %0, c10, c0, 0\n\t"  	/* read */
		"mov %0, %2, LSL#26\n\t"			/* set victim */
		"orr %0, %0, #1\n\t"				/* set p bit */
		"mcr p15, 0, %0, c10, c0, 0\n\t"  	/* write */
		/* step 3: TLB will miss, and entry will be loaded */
		"ldr %1, [%1]\n\t" 					/* load */
		/* step 4: clear the preserve bit */
		"mrc p15, 0, %0, c10, c0, 0\n\t" 	/* read */
		"bic %0, %0, #1\n\t" 				/* clear p bit */
 		"mcr p15, 0, %0, c10, c0, 0" 		/* write */
		: 
		: "r" (reg_c10), "r" (vaddr), "r" (victim) );

	local_irq_restore(flags);

	return;
}


/*
 *  TLB dump
 *   - 
 */

void xen_tlb_main_dump(unsigned long tlb_mva[][2], unsigned long tlb_pa_ap[][2])
{
	unsigned int  entry_index;
	unsigned int  way;

	unsigned long rd_select;
	unsigned long rd_mva;
	unsigned long rd_pa_ap;

	/*
	 *  main TLB dump
	 */
	for( entry_index = 0; entry_index < TLB_MAIN_SIZE; entry_index++ ) 
	{
		for( way = 0; way < 2; way++ )
		{
			/* step 1: select way and entry index */
			rd_select = 0;
			rd_select |= (way << 31) | (entry_index << 10);
			asm("mcr p15, 0, %0, c15, c1, 0" : : "r" (rd_select));

			/* step 2: read MVA tag */
			asm("mrc p15, 5, %0, c15, c2, 0" : "=r" (rd_mva));
			tlb_mva[entry_index][way] = rd_mva;

			/* step 3: read PA and access permission */
			asm("mrc p15, 5, %0, c15, c4, 0" : "=r" (rd_pa_ap));
			tlb_pa_ap[entry_index][way] = rd_pa_ap;
		}
	}

	return;
}

void xen_tlb_lockdown_dump(unsigned long *tlb_mva, unsigned long *tlb_pa_ap)
{
	unsigned int  entry_index;

	unsigned long rd_select;
	unsigned long rd_mva;
	unsigned long rd_pa_ap;

	/*
	 *  lockdown TLB dump
	 */
	for( entry_index = 0; entry_index < TLB_LOCKDOWN_SIZE; entry_index++ ) 
	{
		/* step 1: select lockdown TLB entry */
		rd_select = 0;
		rd_select |= (entry_index << 26);
		asm("mcr p15, 0, %0, c15, c1, 0" : : "r" (rd_select));
		
		/* step 2: read MVA tag */
		asm("mrc p15, 4, %0, c15, c2, 1" : "=r" (rd_mva));
		tlb_mva[entry_index] = rd_mva;
		
		/* step 3: read PA and access permission */
		asm("mrc p15, 4, %0, c15, c4, 1" : "=r" (rd_pa_ap));
		tlb_pa_ap[entry_index] = rd_pa_ap;
	}

	return;
}

void xen_tlb_get_entry(unsigned long mva, unsigned long pa_ap, tlb_entry_t *t)
{
	t->mva_tag = (mva & 0xFFFFFC00);
	t->valid   = (mva & 0x00000010) >>  4;
	t->size    = (mva & 0x0000000F);

	t->pa      = (pa_ap & 0xFFFFFC00);
	t->domain  = (pa_ap & 0x000000F0) >>  4;
	t->ap      = (pa_ap & 0x0000000C) >>  2;
	t->c       = (pa_ap & 0x00000002) >>  1;
	t->b       = (pa_ap & 0x00000001);

	return;
}

void xen_tlb_print_entry(tlb_entry_t *t)
{
	if( t->type == TLB_TYPE_MAIN )
		printf("[%02d] way %d (valid=%d): MVA tag=0x%08x (%02d), PA=0x%08x, domain=%d, AP=%d, C=%d, B=%d\n",
			   t->index, t->way, t->valid, (unsigned int)t->mva_tag, t->size, (unsigned int) t->pa, t->domain, t->ap, t->c, t->b);
	else
		printf("[%02d] (valid=%d): MVA tag=0x%08x (%02d), PA=0x%08x, domain=%d, AP=%d, C=%d, B=%d\n",
			   t->index, t->valid, (unsigned int)t->mva_tag, t->size, (unsigned int)t->pa, t->domain, t->ap, t->c, t->b);

	return;
}

void xen_tlb_dump(void)
{
	int i, j;
	unsigned long main_tlb_mva[TLB_MAIN_SIZE][2];
	unsigned long main_tlb_pa_ap[TLB_MAIN_SIZE][2];
	unsigned long lockdown_tlb_mva[TLB_LOCKDOWN_SIZE];
	unsigned long lockdown_tlb_pa_ap[TLB_LOCKDOWN_SIZE];

	tlb_entry_t	  tlb_entry;
	unsigned long flags;

	/* disable interrupt */
	local_irq_save(flags);
	
	/* TLB dump */
	xen_tlb_main_dump(main_tlb_mva, main_tlb_pa_ap);
	xen_tlb_lockdown_dump(lockdown_tlb_mva, lockdown_tlb_pa_ap);

    /* enable interrupt */
	local_irq_restore(flags);


    /* print out */
	printf("Xen TLB Dump: ----------------------------------------\n");

	printf("* main TLB\n");
	for( i = 0; i < TLB_MAIN_SIZE; i++ ) 
	{
		for( j = 0; j < 2; j++ )
		{
			tlb_entry.type  = TLB_TYPE_MAIN;
			tlb_entry.index = i;
			tlb_entry.way   = j;
			xen_tlb_get_entry  (main_tlb_mva[i][j], main_tlb_pa_ap[i][j], &tlb_entry);
			xen_tlb_print_entry(&tlb_entry);
		}
	}

	printf("* lockdown TLB\n");
	for( i = 0; i < TLB_LOCKDOWN_SIZE; i++ ) 
	{
		tlb_entry.type  = TLB_TYPE_LOCKDOWN;
		tlb_entry.index = i;
		xen_tlb_get_entry  (lockdown_tlb_mva[i], lockdown_tlb_pa_ap[i], &tlb_entry);
		xen_tlb_print_entry(&tlb_entry);
	}

	printf("End of Xen TLB Dump: ---------------------------------\n");

	return;
}

