/*
 * platform.c
 *
 * Copyright (C) 2008 Samsung Electronics 
 *         JaeMin Ryu  <jm77.ryu@samsung.com>
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

#include <xen/spinlock.h>
#include <xen/lib.h>
#include <xen/serial.h>
#include <asm/platform.h>
#include <asm/arch/hardware.h>
#include <asm/irq.h>
#include <asm/io.h>

enum {
    GOLDFISH_TTY_PUT_CHAR       = 0x00,
    GOLDFISH_TTY_BYTES_READY    = 0x04,
    GOLDFISH_TTY_CMD            = 0x08,

    GOLDFISH_TTY_DATA_PTR       = 0x10,
    GOLDFISH_TTY_DATA_LEN       = 0x14,

    GOLDFISH_TTY_CMD_INT_DISABLE    = 0,
    GOLDFISH_TTY_CMD_INT_ENABLE     = 1,
    GOLDFISH_TTY_CMD_WRITE_BUFFER   = 2,
    GOLDFISH_TTY_CMD_READ_BUFFER    = 3,
};

static void goldfish_platform_halt(int mode)
{
}

DECLARE_PLATFORM_OP(platform_halt, goldfish_platform_halt);

static void goldfish_memory_init(void)
{
	register_memory_bank(0x00000000, 96 * 1024 * 1024);
}

static void goldfish_uart_putc(struct serial_port *port, char c)
{
    __raw_writel(c, IO_ADDRESS(GOLDFISH_TTY_BASE) + GOLDFISH_TTY_PUT_CHAR);
}

static int goldfish_uart_getc(struct serial_port *port, char *pc)
{
	return 1;
}

static struct ns16550_defaults goldfish_uart_params = {
	//.baud      = BAUD_AUTO,
	.baud      = 38400,
	.data_bits = 8,
	.parity    = 'n',
	.stop_bits = 1
};

static struct uart_driver goldfish_uart_driver = {
	.putc = goldfish_uart_putc,
	.getc = goldfish_uart_getc
};

#define RX_MODE	(GPIO_MODE_PF | GPIO_MODE_IN)
#define TX_MODE	(GPIO_MODE_PF | GPIO_MODE_OUT)

static void goldfish_uart_init(void)
{
	serial_register_uart(0, &goldfish_uart_driver, &goldfish_uart_params);	
}

static void goldfish_sys_clk_init(void)
{
}


static void goldfish_platform_setup(void)
{
	goldfish_memory_init();
        goldfish_sys_clk_init();
	goldfish_uart_init();
        goldfish_irq_init();
        goldfish_timer_init();
}

DECLARE_PLATFORM_OP(platform_setup, goldfish_platform_setup);

static void goldfish_platform_query(struct query_data *query)
{
	switch(query->type) {
		case QUERY_MEMORY_DETAILS : break;
		case QUERY_CPU_DETAILS : break;
		default : break;
	};
}

DECLARE_PLATFORM_OP(platform_query, goldfish_platform_query);
