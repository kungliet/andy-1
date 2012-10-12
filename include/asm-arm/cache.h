#ifndef __ARM_CACHE_H__
#define __ARM_CACHE_H__

#include <xen/prefetch.h>

#define L1_CACHE_BYTES	32

typedef struct {
	char		size;              /* cache size */
	char		assoc;             /* cache associativity */
	char		mbit;              /* multiplier bit (for ARM926EJ-S, M=0=present)*/
	char		len;               /* cache length */
} cache_size_t;

typedef struct {
	char            ctype;  /* cache type */
	char            sbit;   /* unified cache (S=0) or separage I/D cache (S=1) */
	cache_size_t    dsize;  /* d cache size */
	cache_size_t    isize;  /* i cache size */
	char            dtcm;   /* DTCM present */
	char            itcm;   /* ITCM present */
} cache_type_c0_t;

void xen_cache_info(cache_type_c0_t *pcache_info);


#endif
