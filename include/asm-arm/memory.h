#ifndef __ASM_MEMORY_H__
#define __ASM_MEMORY_H__

#include <asm/config.h>

#ifdef ARCH_NR_BANKS
#define NR_BANKS	ARCH_NR_BANKS
#else
#define NR_BANKS	4
#endif

struct memory_bank {
	unsigned long	base;
	unsigned long	size;
	int		node;
};


struct meminfo {
	unsigned long nr_banks;
	struct memory_bank banks[NR_BANKS];
};

extern struct meminfo system_memory;
void register_memory_bank(unsigned long base, unsigned long size);

#endif

