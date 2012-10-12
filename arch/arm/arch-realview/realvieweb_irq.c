/*
 * versatilepb_irq.c
 *
 * Copyright (C) 2008 Minsung Jang
 *         Minsung Jang  < minsung@gatech.edu >
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
#include <asm/hardware.h>
#include <asm/io.h>
#include <xen/init.h>
#include <xen/types.h>
#include <asm/irq.h>
#include <asm/arch/io.h>
#include <asm/arch/irqs.h>
#include <asm/arch/gic.h>
#include <asm/bitops.h>
#include <xen/bitops.h>


#define IRQ_START		32
#define VA_GIC_BASE             __io_address(VERSATILE_GIC_BASE)


/* 
 - Most codes are from Linux 2.6.27.
 - To do: This file contains only GIC related codes, so if you want to use SIC, write yourself
 */

extern struct irqdesc irq_desc[NR_IRQS];

#if 0 //andy
static void versatile_gic_ack_irq(unsigned int irq)
{
	IO_WRITE(VA_GIC_BASE + GIC_CPU_EOI, irq);
}
#endif

static void versatile_gic_mask_irq(unsigned int irq)
{
    IO_WRITE(VA_GIC_BASE + GIC_DIST_ENABLE_CLEAR_1, 1 << (irq-32));
}

static void versatile_gic_unmask_irq(unsigned int irq)
{
	unsigned int val;

	IO_WRITE(VA_GIC_BASE + GIC_CPU_EOI, irq);
	val = IO_READ(VA_GIC_BASE + GIC_DIST_ENABLE_SET_1);
	val |= 1 << (irq - 32);
	IO_WRITE(VA_GIC_BASE + GIC_DIST_ENABLE_SET_1, val);
}

static struct irqchip versatile_gic_chip = {
        .trigger_type = "level",
        .ack = versatile_gic_mask_irq,
        .mask = versatile_gic_mask_irq,
        .unmask = versatile_gic_unmask_irq,
};

void versatilepb_irq_init(void)
{
	int i;
	
	IO_WRITE(VA_GIC_BASE + GIC_CPU_PRIMASK, 0xf0); /* priority setting */
	IO_WRITE(VA_GIC_BASE + GIC_CPU_CTRL, 1);  /* enable gic0 */
	
	IO_WRITE(VA_GIC_BASE + GIC_DIST_CTRL, 0x0);
    IO_WRITE(VA_GIC_BASE + GIC_DIST_CONFIG + 0x08, 0x55555555);
    IO_WRITE(VA_GIC_BASE + GIC_DIST_CONFIG + 0x0c, 0x55555555);
    IO_WRITE(VA_GIC_BASE + GIC_DIST_CONFIG + 0x10, 0x55555555);
    IO_WRITE(VA_GIC_BASE + GIC_DIST_CONFIG + 0x14, 0x55555555);
    
    for(i=0; i<16; i++)
    {
		IO_WRITE(VA_GIC_BASE + GIC_DIST_PRI + 0x20 + i*4, 0xa0a0a0a0);
	}
	/* disable all interrupts */
	IO_WRITE(VA_GIC_BASE + GIC_DIST_ENABLE_CLEAR_1, 0xffffffff);
	IO_WRITE(VA_GIC_BASE + GIC_DIST_ENABLE_CLEAR_2, 0xffffffff);
    IO_WRITE(VA_GIC_BASE + GIC_DIST_CTRL, 0x1);

	for (i = IRQ_GIC_START; i < NR_IRQS; i++) {
		unsigned int irq =  i;

		set_irq_chip(irq, &versatile_gic_chip);
		set_irq_handler(irq, level_irq_handler);
		set_irq_flags(irq, IRQF_VALID);
	}
}

