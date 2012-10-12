/*
 * time.c
 *
 * Copyright (C) 2008 Samsung Electronics
 *          JooYoung Hwang  <jooyoung.hwang@samsung.com>
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

#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/init.h> 
#include <xen/softirq.h>
#include <xen/spinlock.h>
#include <asm/hardware.h>
#include <asm/time.h> 
#include <asm/irq.h> 

#if 0
extern struct sys_timer *system_timer;
extern void t_timer_fn(void *unused);
extern void arch_update_dom_time(void);
extern void timer_tick(struct cpu_user_regs *);
extern struct timeoffset_s system_timeoffset;
extern unsigned long freetimer_overflows;
#endif

/*
 * Returns number of us since last clock interrupt.  Note that interrupts
 * will have been disabled by do_gettimeoffset()
 */
unsigned long imx_gettimeoffset(void)
{
        unsigned long ticks;
        unsigned long results;

        /*
         * Get the current number of ticks.  Note that there is a race
         * condition between us reading the timer and checking for
         * an interrupt.  We get around this by ensuring that the
         * counter has not reloaded between our two reads.
         */
	ticks = IMX_TCN(TIMER_BASE);

        /*
         * Interrupt pending?  If so, we've reloaded once already.
         */

        if (IMX_TSTAT(TIMER_BASE) & TSTAT_COMP) {
                ticks += LATCH;
        }

        /* 
         * Convert the ticks to usecs
         */
        results = (1000000 / CLOCK_TICK_RATE) * ticks;
        return results;
}

extern void timer_tick(struct cpu_user_regs *regs);

irqreturn_t imx_timer_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
	/* clear the interrupt */
	if (IMX_TSTAT(TIMER_BASE))
		IMX_TSTAT(TIMER_BASE) = TSTAT_CAPT | TSTAT_COMP;

	// jiffies counting is necessary.
	timer_tick(regs);

	raise_softirq(TIMER_SOFTIRQ);

	return IRQ_HANDLED;
}

static struct irqaction imx_timer_irq = {
	.name		= "i.MX Timer Tick",
	.dev_id		= NULL,
	.handler	= imx_timer_interrupt
};

void imx_timer_init(void)
{
	/*
	 * Initialise to a known state (all timers off, and timing reset)
	 */
	IMX_TCTL(TIMER_BASE) = 0;
	IMX_TPRER(TIMER_BASE) = 0;
	IMX_TCMP(TIMER_BASE) = LATCH-1;

	IMX_TCTL(TIMER_BASE) = TCTL_CLK_32 | TCTL_IRQEN | TCTL_TEN; 
	/*
	 * Make irqs happen for the system timer
	 */
	setup_irq(TIM1_INT, &imx_timer_irq); 
}
