/**
 * @file	arch-arm.h	(include/public/arch-arm.h)
 * @brief	archtecture specifiec configuration
 * 
 * @author	chanju, park	(beastworld@samsung.com)
 * @version	2006-06-08	basic setup, modified from ia-64, ppc
 * @copyright	Copyright (c) samsung electronics, co.
 */

#ifndef __XEN_PUBLIC_ARCH_ARM_32_H__
#define __XEN_PUBLIC_ARCH_ARM_32_H__



#ifdef __XEN__
#define __DEFINE_GUEST_HANDLE(name, type) \
    typedef struct { type *p; } __guest_handle_ ## name
#else
#define __DEFINE_GUEST_HANDLE(name, type) \
    typedef type * __guest_handle_ ## name
#endif
    
#define DEFINE_GUEST_HANDLE(name) __DEFINE_GUEST_HANDLE(name, name)
#define GUEST_HANDLE(name)        __guest_handle_ ## name
    
#ifndef __ASSEMBLY__
/* Guest handles for primitive C types. */
__DEFINE_GUEST_HANDLE(uchar, unsigned char);
__DEFINE_GUEST_HANDLE(uint,  unsigned int);
__DEFINE_GUEST_HANDLE(ulong, unsigned long);
DEFINE_GUEST_HANDLE(char);
DEFINE_GUEST_HANDLE(int);
DEFINE_GUEST_HANDLE(long);
DEFINE_GUEST_HANDLE(void);
#endif


/*
 * Virtual addresses beyond this are not modifiable by guest OSes. The 
 * machine->physical mapping table starts at this address, read-only.
 */
#define __HYPERVISOR_VIRT_START 0xFC000000

#ifndef HYPERVISOR_VIRT_START
#define HYPERVISOR_VIRT_START mk_unsigned_long(__HYPERVISOR_VIRT_START)
#endif

#ifndef machine_to_phys_mapping
#define machine_to_phys_mapping ((unsigned long *)HYPERVISOR_VIRT_START)
#endif



#ifndef __ASSEMBLY__

typedef struct cpu_user_regs
{
	__u32	r0;
	__u32	r1;
	__u32	r2;
	__u32	r3;
	__u32	r4;
	__u32	r5;
	__u32	r6;
	__u32	r7;
	__u32	r8;
	__u32	r9;
	__u32	r10;
	__u32	r11;
	__u32	r12;
	__u32	r13;
	__u32	r14;
	__u32	r15;
	__u32	psr;
	__u32	ctx;
} cpu_user_regs_t;

typedef struct cpu_ext_regs {
	__u64	wr0;
	__u64	wr1;
	__u64	wr2;
	__u64	wr3;
	__u64	wr4;
	__u64	wr5;
	__u64	wr6;
	__u64	wr7;
	__u64	wr8;
	__u64	wr9;
	__u64	wr10;
	__u64	wr11;
	__u64	wr12;
	__u64	wr13;
	__u64	wr14;
	__u64	wr15;
	__u32	wcssf;
	__u32	wcasf;
	__u32	wcgr0;
	__u32	wcgr1;
	__u32	wcgr2;
	__u32	wcgr3;
	__u32	wcid;
	__u32	wcon;
}cpu_ext_regs_t;

typedef struct cpu_sys_regs {
	__u32	vpsr;
	__u32	vksp;
	__u32	vusp;
	__u32	vdacr;
	__u32	vfar;
	__u32	vfsr;
	__u32	vcp0;
	__u32	vcp1;
}cpu_sys_regs_t;

typedef cpu_user_regs_t	cpu_bounce_frame_t;

#define DEFINE_GUEST_HANDLE(name) __DEFINE_GUEST_HANDLE(name, name)
#define GUEST_HANDLE(name)        __guest_handle_ ## name

typedef struct trap_info {
	__u32	vector;
	__u32	flags;
	__u32	address;
}trap_info_t;
DEFINE_GUEST_HANDLE(trap_info_t);

typedef struct vcpu_guest_context {
	cpu_user_regs_t user_regs;	/* User-level CPU registers     */
	cpu_ext_regs_t	ext_regs;
	cpu_sys_regs_t	sys_regs;
	__u32		event_callback;
	__u32		failsafe_callback;	/* Address of failsafe callback  */
 	trap_info_t	trap_ctx[8];
} vcpu_guest_context_t;
DEFINE_GUEST_HANDLE(vcpu_guest_context_t);


typedef struct {
} arch_vcpu_info_t;

#define MAX_VIRT_CPUS 1
#endif

typedef struct arch_shared_info {
	__u32	max_pfn;
	__u32	pfn_to_mfn_frame_list_list;
	__u32	 nmi_reason;
} arch_shared_info_t;

#endif
