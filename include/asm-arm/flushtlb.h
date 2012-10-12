#ifndef __ARM_TLB_H__
#define __ARM_TLB_H__

#include <xen/config.h>
#include <xen/smp.h>

/* Debug builds: Wrap frequently to stress-test the wrap logic. */
#ifdef NDEBUG
#define WRAP_MASK (0xFFFFFFFFU)
#else
#define WRAP_MASK (0x000003FFU)
#endif

#define TLB_TYPE_MAIN           0
#define TLB_TYPE_LOCKDOWN       1

#define TLB_MAIN_SIZE           32
#define TLB_LOCKDOWN_SIZE       8

typedef struct {
        char            type;           /* main or lockdown */
        char            way;            /* way0 or way1 in main TLB */
        short int       index;          /* entry index */
        unsigned long   mva_tag;        /* MVA 22 bits */
        short int       valid;          /* valid bit */
        short int       size;           /* b1011=1MB section, b0011=4KB page, ... */
        unsigned long   pa;             /* phys addr 22 bits */
        char            domain;         /* domain */
        char            ap;             /* access permission */
        char            c;              /* cachable bit */
        char            b;              /* bufferable bit */
} tlb_entry_t;

/* The current time as shown by the virtual TLB clock. */
extern u32 tlbflush_clock;

/* Time at which each CPU's TLB was last flushed. */
extern u32 tlbflush_time[NR_CPUS];

#define tlbflush_current_time() tlbflush_clock

/*
 * @cpu_stamp is the timestamp at last TLB flush for the CPU we are testing.
 * @lastuse_stamp is a timestamp taken when the PFN we are testing was last 
 * used for a purpose that may have caused the CPU's TLB to become tainted.
 */
static inline int NEED_FLUSH(u32 cpu_stamp, u32 lastuse_stamp)
{
    u32 curr_time = tlbflush_current_time();
    /*
     * Two cases:
     *  1. During a wrap, the clock ticks over to 0 while CPUs catch up. For
     *     safety during this period, we force a flush if @curr_time == 0.
     *  2. Otherwise, we look to see if @cpu_stamp <= @lastuse_stamp.
     *     To detect false positives because @cpu_stamp has wrapped, we
     *     also check @curr_time. If less than @lastuse_stamp we definitely
     *     wrapped, so there's no need for a flush (one is forced every wrap).
     */
    return ((curr_time == 0) ||
            ((cpu_stamp <= lastuse_stamp) &&
             (lastuse_stamp <= curr_time)));
}

/*
 * Filter the given set of CPUs, removing those that definitely flushed their
 * TLB since @page_timestamp.
 */
#define tlbflush_filter(mask, page_timestamp)                   \
do {                                                            \
    unsigned int cpu;                                           \
    for_each_cpu_mask ( cpu, mask )                             \
        if ( !NEED_FLUSH(tlbflush_time[cpu], page_timestamp) )  \
            cpu_clear(cpu, mask);                               \
} while ( 0 )

extern void new_tlbflush_clock_period(void);

#define local_flush_tlb()			\
	do { 				\
		update_tlbflush_clock();	\
		cpu_flush_tlb_all();		\
		}while(0)
		
#define flush_tlb_mask(mask)       local_flush_tlb() //	cpu_flush_tlb_all()

		
#define local_flush_tlb_pge()	   	local_flush_tlb()  //cpu_flush_tlb_all()
#define local_flush_tlb_one(v) 		cpu_flush_tlb_entry(v)

#define flush_tlb_all_pge()        	local_flush_tlb_pge()
#define flush_tlb_one_mask(mask,v) 	local_flush_tlb_one(v)

/* Write pagetable base and implicitly tick the tlbflush clock. */
extern void update_tlbflush_clock(void);
extern void xen_tlb_dump(void);
extern void xen_tlb_lockdown_entry(unsigned char victim, unsigned long vaddr);
#endif /* __FLUSHTLB_H__ */
