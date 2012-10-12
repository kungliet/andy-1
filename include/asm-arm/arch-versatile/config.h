/*
 *  arch/arm/mach-versatile/include/mach/memory.h
 *
 *  Copyright (C) 2003 ARM Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
#ifndef __ASM_ARCH_MEMORY_H
#define __ASM_ARCH_MEMORY_H

#define HZ                      100

/* Physical DRAM offset */
#define PHYS_OFFSET	(0x00000000UL) // don't use lower 64MB

/* AS PARAMS */
#define __PAGE_OFFSET		(0xFF000000UL)
#define IO_OFFSET               (0xF1000000UL)

#define IDLE_PG_TABLE_ADDR      (0x00004000UL)

#define MEMMAP_DRAM_ADDR        PHYS_OFFSET
#define MEMMAP_DRAM_SIZE        0x08000000
#define MEMMAP_NOR_ADDR         0x34000000
#define MEMMAP_NOR_SIZE         0x04000000


#endif
