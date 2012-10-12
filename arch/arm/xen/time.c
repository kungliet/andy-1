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

#include <xen/init.h>
#include <xen/time.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/types.h>
#include <asm/current.h>
#include <asm/div64.h>
#include <asm/time.h>

#define INITIAL_JIFFIES 0UL;

u64 jiffies_64 = INITIAL_JIFFIES;

#ifndef __ARMEB__
#define jiffies  jiffies_64;
#else
#define jiffies  jiffies_64 + 4;
#endif

extern rwlock_t domlist_lock;
extern unsigned long long jiffies_64;

unsigned long loops_per_jiffy = (1<<12);
unsigned long freetimer_overflows;

/* UTC time at last 'time update'. */
static u32 wc_sec, wc_nsec;

static spinlock_t wc_lock = SPIN_LOCK_UNLOCKED;

struct timeoffset_s system_timeoffset = {0,0};

#ifdef CONFIG_VMM_TIME_PROFILING
s_time_t system_time_array[MAX_SYSTEM_TIME_ARRAY];
int st_index = 0;

void put_current_stime(int type)
{
       if(st_index > MAX_SYSTEM_TIME) 
		st_index = 0;

        system_time_array[st_index] = NOW();
        st_index ++;
        system_time_array[st_index] = type;
        st_index ++;
}

void put_timeout_stime(s_time_t timeout)
{
       if(st_index > MAX_SYSTEM_TIME) 
		st_index = 0;

        system_time_array[st_index] = timeout; 
        st_index ++;
        system_time_array[st_index] = t_timeout; 
        st_index ++;
}
#endif

unsigned long long get_timebase(void)
{
	return (unsigned long long)(jiffies_64 * (1000000000 / HZ));
}

/*
 * Return nanoseconds from time of boot
 */
s_time_t get_s_time(void)
{
	s_time_t now_time;
	unsigned long flag;
	
	local_irq_save(flag);	

	now_time = (s64)get_timebase();

	local_irq_restore(flag);	

	return now_time;
}

static inline void version_update_begin(u32 *version)
{
	ASSERT(version);

        /* Explicitly OR with 1 just in case version number gets out of sync. */
        *version = (*version + 1) | 1;
        wmb();
}

static inline void version_update_end(u32 *version)
{
	ASSERT(version);

        wmb();
        (*version)++;
}

void do_timer(struct cpu_user_regs *regs)
{
	jiffies_64++;
}

void timer_tick(struct cpu_user_regs *regs)
{
	do_timer(regs);
}

void send_timer_event(struct vcpu *v)
{
        send_guest_virq(v, VIRQ_TIMER);
}

static inline void __update_dom_time(struct vcpu *v)
{   
	struct vcpu_time_info *u = NULL;

	ASSERT(v);

	u = &v->domain->shared_info->vcpu_info[v->vcpu_id].time;

	version_update_begin(&u->version);
        get_s_time();
        u->freetimer_overflows = freetimer_overflows;
        u->system_time = system_timeoffset.system_time;
        u->offset = system_timeoffset.offset;
	version_update_end(&u->version);
}

void update_dom_time(struct vcpu *v)
{
       __update_dom_time(v);
}

void arch_update_dom_time(void)
{
    	struct vcpu *v = current;

	__update_dom_time(v);
}

/* Set clock to <secs,usecs> after 00:00:00 UTC, 1 January, 1970. */
void do_settime(unsigned long secs, unsigned long nsecs, u64 system_time_base)
{
        u64 x;
        u32 y, _wc_sec, _wc_nsec;
        struct domain *d = NULL;
        shared_info_t *s = NULL;

        x = (secs * 1000000000ULL) + (u64)nsecs - system_time_base;
        y = do_div(x, 1000000000);

        wc_sec  = _wc_sec  = (u32)x;
        wc_nsec = _wc_nsec = (u32)y;

        read_lock(&domlist_lock);
        spin_lock(&wc_lock);

        for_each_domain ( d )
        {
                s = d->shared_info;
                version_update_begin(&s->wc_version);
                s->wc_sec  = _wc_sec;
                s->wc_nsec = _wc_nsec;
                version_update_end(&s->wc_version);
        }

        spin_unlock(&wc_lock);
        read_unlock(&domlist_lock);
}

void init_domain_time(struct domain *d)
{
	spin_lock(&wc_lock);

	ASSERT(d);

	version_update_begin(&d->shared_info->wc_version);

	d->shared_info->wc_sec  = wc_sec;
	d->shared_info->wc_nsec = wc_nsec;
	version_update_end(&d->shared_info->wc_version);
	spin_unlock(&wc_lock);
}
