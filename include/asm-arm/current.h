/**
 * @file        include/xen-asm/current.h
 * @brief       current vcpu related header file
 * 
 * @author      chanju, park    (beastworld@samsung.com)
 * @author   
 *
 * @version     2006-06-20      basic setup, modified from ia-64, ppc
 * 
 * @copyright   Copyright (c) samsung electronics, co.
 */


#ifndef _ASM_CURRENT_H_
#define _ASM_CURRENT_H_


struct vcpu;

struct cpu_info {
	struct vcpu *cur_vcpu;
	ulong saved_regs[2];
};

static inline struct cpu_info * current_cpu_info(void)
{
	register unsigned long sp asm("r13");
	return (struct cpu_info *) ( sp & ~(STACK_SIZE -1)  ); 
}

static inline struct vcpu *get_current(void)
{
        return current_cpu_info()->cur_vcpu;
}

#define current get_current()

static inline void set_current(struct vcpu *v)
{   
    current_cpu_info()->cur_vcpu = v;
}

#define guest_cpu_user_regs()	(&current->arch.guest_context.user_regs)

#endif //_ASM_CURRENT_H_
