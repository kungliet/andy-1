/*
 *  arch/arm/mach-versatile/include/mach/io.h
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
#ifndef __ASM_ARM_ARCH_IO_H
#define __ASM_ARM_ARCH_IO_H

#define IO_SPACE_LIMIT 0xffffffff
static inline void __iomem *__io(unsigned long addr)
{
	return (void __iomem *)addr;
}
#define __io(a)	__io(a)
#define __mem_pci(a)		(a)

#define IO_ADDRESS(x)           (((x) & 0x0fffffff) + (((x) >> 4) & 0x0f000000) + 0xf0000000)
#define __io_address(n)         __io(IO_ADDRESS(n))
#define IO_WRITE(addr, val) (*(volatile unsigned int *)(addr) = (val))
#define IO_READ(addr) (*(volatile unsigned int *)(addr))



#endif
