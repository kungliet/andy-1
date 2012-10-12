/*
 * versatilepb_serial.c
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


#include <xen/types.h>
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <asm/io.h>
#include <asm/termbits.h>
#include <xen/config.h>
#include <xen/spinlock.h>
#include <xen/serial.h>
#include <xen/byteorder/generic.h>

#include <asm/processor.h>
#include <asm/arch/io.h>
#include <asm/arch/serial_pl011.h>

#define VA_SERIAL0_BASE		__io_address(0x101F1000	/* PA */)
#define VA_SERIAL1_BASE         __io_address(0x101F2000 /* PA */)
#define CONSOLE_PORT 0
#define baudRate 38400
#define CONFIG_PL011_CLOCK      24000000
#define CONFIG_PL01x_PORTS      { (void *)0xf11f1000, (void *)0xf11f2000 }
#define NUM_PORTS (sizeof(port)/sizeof(port[0]))

volatile unsigned char *const port[] = CONFIG_PL01x_PORTS;

/* 
 *  Most codes are from arm versatile support of U-boot 
 */ 


void pl011_putc (int portnum, char c)
{
        /* Wait until there is space in the FIFO */
        while ( IO_READ (port[portnum] + UART_PL01x_FR) & UART_PL01x_FR_TXFF);

        /* Send the character */
        IO_WRITE(port[portnum] + UART_PL01x_DR, c);
}

static int pl011_getc (int portnum)
{
        unsigned int data;

        /* Wait until there is data in the FIFO */
        while (IO_READ (port[portnum] + UART_PL01x_FR) & UART_PL01x_FR_RXFE);

        data = IO_READ (port[portnum] + UART_PL01x_DR);

        /* Check for an error flag */
        if (data & 0xFFFFFF00) {
                /* Clear the error */
                IO_WRITE(port[portnum] + UART_PL01x_ECR, 0xFFFFFFFF);
                return -1;
        }

        return (int) data;
}

static void versatilepb_uart_putc (struct serial_port *port, const char c)
{
        if (c == '\n')
                pl011_putc (CONSOLE_PORT, '\r');

        pl011_putc (CONSOLE_PORT, c);
}



static int versatilepb_uart_getc (struct serial_port *port, char *pc)
{
        return pl011_getc (CONSOLE_PORT);
}



static struct uart_driver versatilepb_uart_driver = {
        .putc = versatilepb_uart_putc,
        .getc = versatilepb_uart_getc
};

static struct ns16550_defaults versatilepb_uart_params = {
        .baud      = BAUD_AUTO,
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
};

void  versatilepb_uart_init (void)
{
        unsigned int temp;
        unsigned int divider;
        unsigned int remainder;
        unsigned int fraction;

        /*
         ** First, disable everything.
         */
        IO_WRITE (port[CONSOLE_PORT] + UART_PL011_CR, 0x0);

        /*
         ** Set baud rate
         **
         ** IBRD = UART_CLK / (16 * BAUD_RATE)
         ** FBRD = ROUND((64 * MOD(UART_CLK,(16 * BAUD_RATE))) / (16 * BAUD_RATE))
         */
        temp = 16 * baudRate;
        divider = CONFIG_PL011_CLOCK / temp;
        remainder = CONFIG_PL011_CLOCK % temp;
        temp = (8 * remainder) / baudRate;
        fraction = (temp >> 1) + (temp & 1);

        IO_WRITE (port[CONSOLE_PORT] + UART_PL011_IBRD, divider);
        IO_WRITE (port[CONSOLE_PORT] + UART_PL011_FBRD, fraction);

        /*
         ** Set the UART to be 8 bits, 1 stop bit, no parity, fifo enabled.
         */
        IO_WRITE (port[CONSOLE_PORT] + UART_PL011_LCRH,
                  (UART_PL011_LCRH_WLEN_8 | 0 << 4)); //fifo DISABLE

/*        IO_WRITE (port[CONSOLE_PORT] + UART_PL011_LCRH,
                  (UART_PL011_LCRH_WLEN_8 | UART_PL011_LCRH_FEN)); */

        /*
         ** Finally, enable the UART
         */
        IO_WRITE (port[CONSOLE_PORT] + UART_PL011_CR,
                  (UART_PL011_CR_UARTEN | UART_PL011_CR_TXE |
                   UART_PL011_CR_RXE));
	
        serial_register_uart(0, &versatilepb_uart_driver, &versatilepb_uart_params);
}
