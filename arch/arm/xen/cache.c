/*
 * cache.c
 *
 * Copyright (C) 2008 Samsung Electronics
 *          SungKwan Heo  <sk.heo@samsung.com>
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


#include <xen/config.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <asm/cache.h>

// n^x
static int power(int x, int y)
{
    int i, res;
    
    res = 1;
    for( i = 0; i < y; i++ )
        res = res * x;

    return res;
}



void xen_print_cache_info(void)
{
	cache_type_c0_t	cache_info;

	xen_cache_info(&cache_info);

	printf("Cache Information\n");

	printf(" - ctype = 0x%x", cache_info.ctype);
	if( cache_info.ctype == 0x0e )
		printf(" (write-back, cleaning:reg7 ops, lockdown:Format C)\n");
	else
		printf(" (unknwon)\n");

	printf(" - sbit  = 0x%x", cache_info.sbit);
	if( cache_info.sbit == 0 )
		printf(" (unifined cache)\n");
	else
		printf(" (separate I/D cache)\n");

	printf(" - d cache: size          = 0x%x", cache_info.dsize.size);
	printf(" (%dKB)\n", power(2, cache_info.dsize.size-1));

	printf("            associativity = 0x%x", cache_info.dsize.assoc);
	if( cache_info.dsize.assoc == 0x02 )
		printf(" (4-way)\n");
	else
		printf(" (reserved)\n");

	printf("            mbit          = 0x%x", cache_info.dsize.mbit);
	if( cache_info.dsize.mbit == 0 )
		printf(" (present)\n");
	else
		printf(" (absent)\n");
		
	printf("            line length   = 0x%x", cache_info.dsize.len);
	if( cache_info.dsize.len == 0x02 )
		printf(" (8words = 32bytes)\n");
	else
		printf(" (reserved)\n");


	printf(" - i cache: size          = 0x%x", cache_info.isize.size);
	printf(" (%dKB)\n", power(2, cache_info.dsize.size-1));

	printf("            associativity = 0x%x", cache_info.isize.assoc);
	if( cache_info.isize.assoc == 0x02 )
		printf(" (4-way)\n");
	else
		printf(" (reserved)\n");

	printf("            mbit          = 0x%x", cache_info.isize.mbit);
	if( cache_info.isize.mbit == 0 )
		printf(" (present)\n");
	else
		printf(" (absent)\n");

	printf("            line length   = 0x%x", cache_info.isize.len);
	if( cache_info.isize.len == 0x02 )
		printf(" (8words = 32bytes)\n");
	else
		printf(" (reserved)\n");


	printf(" - DTCM  = 0x%x", cache_info.dtcm);
	if( cache_info.dtcm == 0x01 )
		printf(" (present)\n");
	else
		printf(" (absent)\n");

	printf(" - ITCM  = 0x%x", cache_info.itcm);
	if( cache_info.itcm == 0x01 )
		printf(" (present)\n");
	else
		printf(" (absent)\n");


	return;
}


void xen_cache_info(cache_type_c0_t *pcache_info)
{
	unsigned long reg_c0;

	/* read cache details */
	asm("mrc p15, 0, %0, c0, c0, 1" : "=r" (reg_c0));		
	
	pcache_info->isize.size  = (reg_c0 & 0x000003c0) >> 6;
	pcache_info->isize.assoc = (reg_c0 & 0x00000038) >> 3;
	pcache_info->isize.mbit  = (reg_c0 & 0x00000004) >> 2;
	pcache_info->isize.len   = (reg_c0 & 0x00000003);

	reg_c0 >>= 12;
	pcache_info->dsize.size  = (reg_c0 & 0x000003c0) >> 6;
	pcache_info->dsize.assoc = (reg_c0 & 0x00000038) >> 3;
	pcache_info->dsize.mbit  = (reg_c0 & 0x00000004) >> 2;
	pcache_info->dsize.len   = (reg_c0 & 0x00000003);

	reg_c0 >>= 12;
	pcache_info->sbit        = reg_c0 & 0x01;
	
	reg_c0 >>= 1;
	pcache_info->ctype       = reg_c0 & 0x0F;


	/* read TCM status register */
	asm("mrc p15, 0, %0, c0, c0, 2" : "=r" (reg_c0));		
	
	pcache_info->itcm        = (reg_c0 & 0x00000001);
	reg_c0 >>= 16;	
	pcache_info->dtcm        = (reg_c0 & 0x00000001);


	return;
}

