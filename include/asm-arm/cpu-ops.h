#ifndef __ASM_CPU_OPS_H__
#define __ASM_CPU_OPS_H__

#ifndef __ASSEMBLY__
#define DECLARE_CPU_OP(gop, nop)	\
	typeof (nop) gop		\
	__attribute__((weak, alias(#nop)))

void cpu_halt(int mode);
void cpu_idle(void);

/*
 * MMU Operations
 */
void cpu_set_pte(unsigned long pte, unsigned long page);
void cpu_switch_ttb(unsigned long);
unsigned long cpu_get_ttb(void);

/*
 * Cache operations
 */
void cpu_flush_cache_all(void);
void cpu_flush_cache_range(unsigned long start, unsigned long end);
void cpu_flush_cache_page(unsigned long page);
void cpu_flush_cache_entry(unsigned long addr);
void cpu_clean_cache_range(unsigned long start, unsigned long end);

/*
 *
 */
void cpu_invalidate_dma_range(unsigned long start, unsigned long end);
void cpu_clean_dma_range(unsigned long start, unsigned long end);
void cpu_flush_dma_range(unsigned long start, unsigned long end);
void cpu_coherent_range(unsigned long start, unsigned long end);
/*
 * TLB operations
 */
void cpu_flush_tlb_all(void);
void cpu_flush_tlb_entry(unsigned long addr);
void cpu_flush_tlb_range(unsigned long start, unsigned long end);

/*
 * Page operations
 */

void cpu_copy_page(void *dst, void *src, unsigned long size);
void cpu_clear_page(void *dst, unsigned long size);
#endif

#ifdef __ASSEMBLY__
#define DECLARE_CPU_OP(gop, nop)	 \
	.set gop, nop			;\
	.global gop			;
#endif

#endif

