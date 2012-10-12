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

#include <asm/arch/timer.h>

/*
 * Returns number of us since last clock interrupt.  Note that interrupts
 * will have been disabled by do_gettimeoffset()
 */
irqreturn_t goldfish_timer_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs);
static int goldfish_timer_ready;
typedef u64 cycles_t;
cycles_t get_cycles(void)
{
    uint32_t timer_base = IO_ADDRESS(GOLDFISH_TIMER_BASE);
    unsigned long irqflags;
    cycles_t rv;

    rv = __raw_readl(timer_base + TIMER_TIME_LOW);
    rv |= (int64_t)__raw_readl(timer_base + TIMER_TIME_HIGH) << 32;
    return rv;
}

static int goldfish_timer_set_next_event(unsigned long cycles)
{
    uint32_t timer_base = IO_ADDRESS(GOLDFISH_TIMER_BASE);
    uint64_t alarm;

    alarm = __raw_readl(timer_base + TIMER_TIME_LOW);
    alarm |= (int64_t)__raw_readl(timer_base + TIMER_TIME_HIGH) << 32;
    alarm += cycles;
    __raw_writel(alarm >> 32, timer_base + TIMER_ALARM_HIGH);
    __raw_writel(alarm, timer_base + TIMER_ALARM_LOW);

    return 0;
}

#ifndef ARCH_CLOCK_TICK_RATE
#error "ARCH_CLOCK_TICK_RATE not defined"
#endif

#define CLOCK_TICK_RATE		ARCH_CLOCK_TICK_RATE

#define LATCH  ((CLOCK_TICK_RATE + HZ/2) / HZ)

irqreturn_t goldfish_timer_interrupt(int irq, void *dev_id, struct cpu_user_regs *regs)
{
    uint32_t timer_base = IO_ADDRESS(GOLDFISH_TIMER_BASE);

    timer_tick(regs);

    raise_softirq(TIMER_SOFTIRQ);

    __raw_writel(1, timer_base + TIMER_CLEAR_INTERRUPT);

    goldfish_timer_set_next_event(LATCH);

    return IRQ_HANDLED;
}

static struct irqaction goldfish_timer_irq = {
    .name       = "Goldfish Timer Tick",
    .flags      = IRQF_DISABLED,
    .handler    = goldfish_timer_interrupt,
    .dev_id     = NULL,
};

void goldfish_timer_init(void)
{
    int res;

    res = setup_irq(IRQ_TIMER, &goldfish_timer_irq);
    if (res)
        printk(KERN_ERR "goldfish_timer_init: setup_irq failed\n");

    __raw_writel(0, IO_ADDRESS(GOLDFISH_TIMER_BASE) + TIMER_ALARM_HIGH);
    __raw_writel(0x10000000, IO_ADDRESS(GOLDFISH_TIMER_BASE) + TIMER_ALARM_LOW);

    goldfish_timer_ready = 1;
}

