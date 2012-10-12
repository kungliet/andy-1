#ifndef __ARM_TIME_H__
#define __ARM_TIME_H__

#include <xen/types.h>
#include <xen/cache.h>
#include <asm/arch/config.h>
#include <asm/arch/timex.h>

#ifndef HZ
#warning "HZ is not defined. Use default value 100"
#define HZ		100 /* Internal kernel timer frequency */
#endif

#ifndef ARCH_CLOCK_TICK_RATE
#error "ARCH_CLOCK_TICK_RATE not defined"
#endif

#define CLOCK_TICK_RATE		ARCH_CLOCK_TICK_RATE

#define LATCH  ((CLOCK_TICK_RATE + HZ/2) / HZ)

struct timespec {
	long	tv_sec;		/* seconds */
	long	tv_nsec;	/* nanoseconds */
};
	
struct timeoffset_s {
        u64 system_time;
        u64 offset;
}__cacheline_aligned;

#define watchdog_disable() ((void)0)
#define watchdog_enable()  ((void)0)

#endif
