/*
 * platform.c
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

#include <xen/spinlock.h>
#include <xen/lib.h>
#include <xen/serial.h>
#include <asm/platform.h>
#include <asm/irq.h>
#include <asm/arch/config.h>
/* 
 * What to do in platform.c is to complete plaform_setup() in start_xen 
 * - Register platform initializing function by DECLARE_PLATFORM_OP
 * - Register platform halt function by DECLARE_PLATFORM_OP
 * - memory_init ->  system clk init -> uart init -> irq init -> timer init 
 */


static void versatilepb_memory_init(void)
{
        register_memory_bank( MEMMAP_DRAM_ADDR, 128 * 1024 * 1024);
//      register_memory_bank(0x04000000, 64 * 1024 * 1024);
}


/*
 * Initializing/halt/query platform 
 */
static void versatilepb_platform_setup(void)
{
        versatilepb_memory_init();
        versatilepb_uart_init();
        versatilepb_irq_init();
        versatilepb_timer_init();
}

DECLARE_PLATFORM_OP(platform_setup, versatilepb_platform_setup);

static void versatilepb_platform_halt(int mode)
{
}

DECLARE_PLATFORM_OP(platform_halt, versatilepb_platform_halt);


static void versatilepb_platform_query(struct query_data *query)
{
        switch(query->type) {
                case QUERY_MEMORY_DETAILS : break;
                case QUERY_CPU_DETAILS : break;
                default : break;
        };
}

DECLARE_PLATFORM_OP(platform_query, versatilepb_platform_query);




