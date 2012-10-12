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
#include <asm/arch/vic.h>
#include <asm/bitops.h>
#include <xen/bitops.h>

#define VERSATILE_VIC_BASE	0x10140000   /* PA of Verctored interrupt controller */
#define VERSATILE_SIC_BASE      0x10003000   /* PA of Secondary interrupt controller */
#define VA_VIC_BASE             __io_address(VERSATILE_VIC_BASE)
#define VA_SIC_BASE             __io_address(VERSATILE_SIC_BASE)
#define PIC_MASK        0xFFD00000

/* 
 - Most codes are from Linux 2.6.27.
 - To do: This file contains only VIC related codes, so if you want to use SIC, write yourself
 */

extern struct irqdesc irq_desc[NR_IRQS];

static void versatile_vic_mask_irq(unsigned int irq)
{
        IO_WRITE ( VA_VIC_BASE + VIC_INT_ENABLE_CLEAR, 1<<irq);
}

static void versatile_vic_unmask_irq(unsigned int irq)
{

	IO_WRITE (VA_VIC_BASE + VIC_INT_ENABLE, 1 << irq);
}

static struct irqchip versatile_vic_chip = {
        .trigger_type = "level",
        .ack = versatile_vic_mask_irq,
        .mask = versatile_vic_mask_irq,
        .unmask = versatile_vic_unmask_irq,
};
void versatilepb_irq_init(void)
{
        unsigned int i;

        /* Disable all interrupts initially. */
        IO_WRITE(VA_VIC_BASE + VIC_INT_SELECT, 0);
        IO_WRITE(VA_VIC_BASE + VIC_INT_ENABLE, 0);
        IO_WRITE(VA_VIC_BASE + VIC_INT_ENABLE_CLEAR, ~0);
        IO_WRITE(VA_VIC_BASE + VIC_IRQ_STATUS, 0);
        IO_WRITE(VA_VIC_BASE + VIC_ITCR, 0);
        IO_WRITE(VA_VIC_BASE + VIC_INT_SOFT_CLEAR, ~0);

        /*
         * Make sure we clear all existing interrupts
         */
        IO_WRITE(VA_VIC_BASE + VIC_VECT_ADDR,0);
        for (i = 0; i < 19; i++) {
                unsigned int value;
                
                value = IO_READ(VA_VIC_BASE + VIC_VECT_ADDR);
                IO_WRITE(VA_VIC_BASE + VIC_VECT_ADDR,value);
        }


        for (i = 0; i < 16; i++) {
                IO_WRITE(VA_VIC_BASE + VIC_VECT_CNTL0 + (i * 4),VIC_VECT_CNTL_ENABLE | i);
        }
	

        IO_WRITE(VA_VIC_BASE + VIC_DEF_VECT_ADDR,32);


        for (i = 0; i < 32; i++) {
                unsigned int irq =  IRQ_VIC_START + i;
	        set_irq_chip(irq, &versatile_vic_chip);
                set_irq_handler(irq, level_irq_handler);
	        set_irq_flags(irq, IRQF_VALID);
        }

        IO_WRITE(VA_SIC_BASE + SIC_IRQ_ENABLE_CLEAR,0);
}

