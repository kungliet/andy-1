/*
 * versatilepb_time.c
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



#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/init.h> 
#include <xen/softirq.h>
#include <xen/spinlock.h>
#include <asm/hardware.h>
#include <asm/time.h> 
#include <asm/irq.h> 
#include <asm/arch/platform.h>
#include <asm/arch/timer.h>
#include <asm/arch/io.h>

#define TIMER0_VA_BASE           __io_address(VERSATILE_TIMER0_1_BASE)
#define TIMER1_VA_BASE          (__io_address(VERSATILE_TIMER0_1_BASE) + 0x20)
#define TIMER2_VA_BASE           __io_address(VERSATILE_TIMER2_3_BASE)
#define TIMER3_VA_BASE          (__io_address(VERSATILE_TIMER2_3_BASE) + 0x20)


/* 
 * Most codes are from Linux 2.6.27.
 * Timer3 is used for timer tick.
 */

extern void timer_tick(struct cpu_user_regs *regs);

irqreturn_t versatilepb_timer_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
	/* Increment jiffies */	
        timer_tick(regs);
	/* Clear bit */
	IO_WRITE(TIMER3_VA_BASE + TIMER_INTCLR,1);
	raise_softirq(TIMER_SOFTIRQ);

        return IRQ_HANDLED;
}

static struct irqaction versatilepb_timer_irq = {
        .name           = "VersatilePB timer tick",
        .dev_id         = NULL,
        .handler        = versatilepb_timer_interrupt
};

void versatilepb_timer_init (void)
{
        u32 val;

        /* 
         * set clock frequency: 
         *      VERSATILE_REFCLK is 32KHz
         *      VERSATILE_TIMCLK is 1MHz
         */
        val = IO_READ(__io_address(VERSATILE_SCTL_BASE));
        IO_WRITE(__io_address(VERSATILE_SCTL_BASE),
               (VERSATILE_TIMCLK << VERSATILE_TIMER1_EnSel) |
               (VERSATILE_TIMCLK << VERSATILE_TIMER2_EnSel) |
               (VERSATILE_TIMCLK << VERSATILE_TIMER3_EnSel) |
               (VERSATILE_TIMCLK << VERSATILE_TIMER4_EnSel) | val);

        /*
         * Initialise to a known state (all timers off)
         */
        IO_WRITE(TIMER0_VA_BASE + TIMER_CTRL,0);
        IO_WRITE(TIMER1_VA_BASE + TIMER_CTRL,0);
        IO_WRITE(TIMER2_VA_BASE + TIMER_CTRL,0);
        IO_WRITE(TIMER3_VA_BASE + TIMER_CTRL,0);

	/* Register IRQ */ 
        setup_irq(IRQ_TIMERINT2_3, &versatilepb_timer_irq);

	/* Enabling Timer0 */
        IO_WRITE(TIMER3_VA_BASE + TIMER_CTRL,0);
        IO_WRITE(TIMER3_VA_BASE + TIMER_LOAD,LATCH-1);
        IO_WRITE(TIMER3_VA_BASE + TIMER_VALUE,LATCH-1);
        IO_WRITE(TIMER3_VA_BASE+TIMER_CTRL,
	TIMER_CTRL_32BIT | TIMER_CTRL_ENABLE | TIMER_CTRL_PERIODIC|TIMER_CTRL_IE);

}



	
