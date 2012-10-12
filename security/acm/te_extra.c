/*
 * te_extra.c 
 *
 * Copyright (C) 2008 Samsung Electronics 
 *          BokDeuk Jeong  <bd.jeong@samsung.com>
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

#include <security/acm/te.h>
#include <security/acm/te_extra.h>

/* Event Channel Label node operations */
int te_evtchn_equal(void *x, void *y)
{
	uint64_t val_x, val_y;
	uint64_t owner_index;

	ASSERT(x);
	owner_index = ((struct EVTCHN_Label *)x)->owner_index; 
	val_x = (owner_index << 32) + ((struct EVTCHN_Label *)x)->use;
	owner_index = ((struct EVTCHN_Label *)x)->owner_index; 

	ASSERT(y);
	val_y = (owner_index << 32) + ((struct EVTCHN_Label *)y)->use;

	return (val_x == val_y ? 1: 0);
}

int te_evtchn_less(void *x, void *y)
{
	uint64_t val_x, val_y;
	uint64_t owner_index;

	ASSERT(x);
	owner_index = ((struct EVTCHN_Label *)x)->owner_index; 
	val_x = (owner_index << 32) + ((struct EVTCHN_Label *)x)->use;
	owner_index = ((struct EVTCHN_Label *)x)->owner_index; 

	ASSERT(y);
	val_y = (owner_index << 32) + ((struct EVTCHN_Label *)y)->use;

	return (val_x < val_y ? 1: 0);
}

int te_evtchn_greater(void *x, void *y)
{
	uint64_t val_x, val_y;
	uint64_t owner_index;

	ASSERT(x);
	owner_index = ((struct EVTCHN_Label *)x)->owner_index; 
	val_x = (owner_index << 32) + ((struct EVTCHN_Label *)x)->use;
	owner_index = ((struct EVTCHN_Label *)x)->owner_index; 

	ASSERT(y);
	val_y = (owner_index << 32) + ((struct EVTCHN_Label *)y)->use;

	return (val_x > val_y ? 1: 0);
}

/* Grant Table Label node operations */
int te_gnttab_equal(void *x, void *y)
{
	uint64_t val_x, val_y;
	uint64_t owner_index, mem_space;

	ASSERT(x);
	owner_index = ((struct GNTTAB_Label *)x)->owner_index; 
	mem_space = ((struct GNTTAB_Label *)x)->mem_space;
	val_x = (owner_index << 48) + 
		( mem_space << 32) + 
		((struct GNTTAB_Label *)x)->use;

	ASSERT(y);
	owner_index = ((struct GNTTAB_Label *)y)->owner_index; 
	mem_space = ((struct GNTTAB_Label *)y)->mem_space;
	val_y = (owner_index << 48) + 
		(mem_space << 32) + 
		((struct GNTTAB_Label *)y)->use;

	return (val_x == val_y ? 1: 0);
}

int te_gnttab_less(void *x, void *y)
{
	uint64_t val_x, val_y;
	uint64_t owner_index, mem_space;

	ASSERT(x);
	owner_index = ((struct GNTTAB_Label *)x)->owner_index; 
	mem_space = ((struct GNTTAB_Label *)x)->mem_space;
	val_x = (owner_index << 48) + 
		( mem_space << 32) + 
		((struct GNTTAB_Label *)x)->use;

	ASSERT(y);
	owner_index = ((struct GNTTAB_Label *)y)->owner_index; 
	mem_space = ((struct GNTTAB_Label *)y)->mem_space;
	val_y = (owner_index << 48) + 
		(mem_space << 32) + 
		((struct GNTTAB_Label *)y)->use;

	return (val_x < val_y ? 1: 0);
}

int te_gnttab_greater(void *x, void *y)
{
	uint64_t val_x, val_y;
	uint64_t owner_index, mem_space;

	ASSERT(x);
	owner_index = ((struct GNTTAB_Label *)x)->owner_index; 
	mem_space = ((struct GNTTAB_Label *)x)->mem_space;
	val_x = (owner_index << 48) + 
		( mem_space << 32) + 
		((struct GNTTAB_Label *)x)->use;

	ASSERT(y);
	owner_index = ((struct GNTTAB_Label *)y)->owner_index; 
	mem_space = ((struct GNTTAB_Label *)y)->mem_space;
	val_y = (owner_index << 48) + 
		(mem_space << 32) + 
		((struct GNTTAB_Label *)y)->use;

	return (val_x > val_y ? 1: 0);
}

/* Device Label node operations */
int te_device_equal(void *x, void *y)
{
	uint16_t val_x, val_y;

	ASSERT(x);
	val_x = ((struct DEVICE_Label *)x)->device; 

	ASSERT(y);
	val_y = ((struct DEVICE_Label *)y)->device; 

	return (val_x == val_y ? 1: 0);
}

int te_device_less(void *x, void *y)
{
	uint16_t val_x, val_y;

	ASSERT(x);
	val_x = ((struct DEVICE_Label *)x)->device; 

	ASSERT(y);
	val_y = ((struct DEVICE_Label *)y)->device; 

	return (val_x < val_y ? 1: 0);
}

int te_device_greater(void *x, void *y)
{
	uint16_t val_x, val_y;

	ASSERT(x);
	val_x = ((struct DEVICE_Label *)x)->device; 

	ASSERT(y);
	val_y = ((struct DEVICE_Label *)y)->device; 

	return (val_x > val_y ? 1: 0);
}

/* Simple Resource Label node operations */
int te_smpres_equal(void *x, void *y)
{
	uint32_t val_x, val_y;

	ASSERT(x);
	val_x = ((struct SIMPLE_RESOURCE_Label *)x)->value; 

	ASSERT(y);
	val_y = ((struct SIMPLE_RESOURCE_Label *)y)->value; 

	return (val_x == val_y ? 1: 0);
}

int te_smpres_less(void *x, void *y)
{
	uint32_t val_x, val_y;

	ASSERT(x);
	val_x = ((struct SIMPLE_RESOURCE_Label *)x)->value; 

	ASSERT(y);
	val_y = ((struct SIMPLE_RESOURCE_Label *)y)->value; 

	return (val_x < val_y ? 1: 0);
}

int te_smpres_greater(void *x, void *y)
{
	uint32_t val_x, val_y;

	ASSERT(x);
	val_x = ((struct SIMPLE_RESOURCE_Label *)x)->value; 

	ASSERT(y);
	val_y = ((struct SIMPLE_RESOURCE_Label *)y)->value; 

	return (val_x > val_y ? 1: 0);
}

unsigned long shift_request(unsigned long request, unsigned int object_group)
{
	int shift_bits = 0;

	switch(object_group){
		/* -- DOMAIN_RESOURCE MATRIX -- */
		/* ACM_DOMAIN OPS: 8bits */
		case ACM_DOMAIN:
			shift_bits = 0;
			break;
		/* for GNTTAB_SETUP and GNTTAB_DUMP_TABLE : 4bits*/
		case ACM_GRANTTAB:
			shift_bits = 8;
			break;
		/* for EVTCHN_CONTROL: +2 bits */
		case ACM_EVENTCHN:
			shift_bits = 12;
			break;
		/* for IOMEM_CONTROL: 1bit */
		case ACM_IOMEM:
			shift_bits = 14;
			break;
		/* for PIRQ_CONTROL: 1bit */
		case ACM_PIRQ:
			shift_bits = 15;
			break;
		case ACM_MEMORY:
			if(request == MEM_CONTROL || request == MEM_GET_STAT || request == MEM_TRANSLATE_ADDR)
				shift_bits = 16;
			/* ACM_MEMEMORY OPS: 8 bits */ 
			else
				shift_bits = 0;
			break;
		case ACM_DEBUG:
			shift_bits = 20;
			break;
		case ACM_HANDLE:
			shift_bits = 21;
			break;
		case ACM_VCPU:
			if(request == VCPU_CONTROL)
				shift_bits = 22;
			break;
		/* -- SIMPLE_RESOURCE MATRIX--- */
		case ACM_TIME:
			/* ACM_MEMORY takes right most 12 bits */
			/* ACM_TIME: 1bit */
			shift_bits =  8;
			break;
		/* ACM_SCHEDULER OPS: 4bits */
		case ACM_SCHEDULER:
			shift_bits = 9;	// takes 4bits
			break;
		case ACM_TRACEBUFFER:
			shift_bits = 13;
			break;
		case ACM_PERFCOUNTER:
			shift_bits = 14;
			break;
		/* CONSOLE_READ, CONSOLE_WRITE: 2bits */	
		case ACM_CONSOLEIO:
			shift_bits = 15;
			break;
		/* ACM_POLICY OPS: 2bits */	
		case ACM_POLICY:
			shift_bits = 17;
			break;
		/*	ACM_SECUSTORAGE OPS: 4bits */
		case ACM_SECUSTORAGE:
			shift_bits = 19;
			break;
	}
	return request << shift_bits; 
}


