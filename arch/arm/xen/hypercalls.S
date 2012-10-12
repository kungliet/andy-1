/*
 * hypercalls.S
 *
 * Copyright (C) 2008 Samsung Electronics
 *          JaeMIn Ryu  <jm77.ryu@samsung.com>
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

#include <asm/linkage.h>
#include <xen/config.h> 
#include <asm/page.h>
#include <asm/system.h>
#include <asm/cpu-domain.h>
#include <asm/asm-offsets.h>
#include <asm/asm-macros.h>
#include <asm/arch/entry-macro.S>

#define HYPERCALL_VECTOR_NO	0x82

	.align  5
ENTRY(ret_from_hypercall)
	str	r0, [sp, #S_R0]	

	b	ret_to_user

	.align  5
ENTRY(vector_swi)
	sub	sp, sp, #S_FRAME_SIZE
	stmia	sp, {r0 - r12}
	add	r8, sp, #S_PC
	stmdb	r8, {sp, lr}^
	mrs	r8, spsr
	str	lr, [sp, #S_PC]
	str	r8, [sp, #S_PSR]

	vcpu	r8
	add	r8, r8, #(OFFSET_ARCH_VCPU + OFFSET_GUEST_CONTEXT)
	ldr	r9, [r8, #(OFFSET_SYS_REGS + OFFSET_VPSR)]
	ldr	r10, [sp, #S_SP]
	cmp	r9, #PSR_MODE_USR
	streq   r10, [r8, #(OFFSET_SYS_REGS + OFFSET_VUSP)]
	strne   r10, [r8, #(OFFSET_SYS_REGS + OFFSET_VKSP)]

	ldr     r8, [sp, #S_PSR]
	bic     r8, r8, #PSR_MODE_MASK
	orr     r8, r8, r9
	str     r8, [sp, #S_PSR]

	ldr	r10, [lr, #-4]
	bic	r10, r10, #0xff000000
	
	cmp	r10, #HYPERCALL_VECTOR_NO
	moveq	r12, #0x18
	movne	r12, #0x08
	str	r12, [sp, #S_CONTEXT]

	beq	process_hypercalls

	b	do_upcall

process_hypercalls:
	enable_irq ip

	adr	lr, ret_from_hypercall
	adr	tbl, hypercall_table	
	add	tbl, tbl, scno, lsl #2
	ldr	pc, [tbl]


ENTRY(do_dma_op)
	mov	pc, lr
	
ENTRY(do_set_trap_table)
	mov	pc, lr

ENTRY(do_stack_switch)
	mov	pc, lr

ENTRY(do_fpu_taskswitch)
	mov	pc, lr

ENTRY(do_arch_sched_op)
	mov	pc, lr

ENTRY(do_set_debugreg)
	mov	pc, lr

ENTRY(do_get_debugreg)
	mov	pc, lr

ENTRY(do_update_descriptor)
	mov	pc, lr

ENTRY(do_update_va_mapping_otherdomain)
	mov	pc, lr

#ifndef CONFIG_VMM_SECURITY_ACM	
ENTRY(do_acm_op)
	mov	pc, lr
#endif	

ENTRY(do_set_domain)
	mov	pc, lr

ENTRY(do_print_profile)
	mov	pc, lr

ENTRY(do_dummy)
	mov	pc, lr

ENTRY(do_get_system_time)
	mov	pc, lr

ENTRY(do_iwmmxt_op)
	mov	pc, lr

/*
 * Register usage:
 * R0 - Argument, frame set that holds registers to be loaded into CPU
 */
ENTRY(do_restore_guest_context)
	disable_irq	ip

	vcpu	r4

	ldr	r6, [r4, #OFFSET_VCPU_INFO]
	mov	r7, #0
	strb	r7, [r6, #OFFSET_EVTCHN_UPCALL_MASK]

	add     r5, r4, #(OFFSET_ARCH_VCPU + OFFSET_GUEST_CONTEXT)
	add     r0, r0, #S_FRAME_SIZE
	str     r0, [r5, #(OFFSET_SYS_REGS + OFFSET_VKSP)]

	add	sp, sp, #S_FRAME_SIZE

	ldmdb   r0!, {r1-r9}
	stmdb   sp!, {r1-r9}
	ldmdb   r0!, {r1-r9}
	stmdb   sp!, {r1-r9}

	mov	r1, #0x18
	str	r1, [sp, #S_CONTEXT]

	b       ret_to_user 
//	b	restore

/*
 * hypercall_table - by kcr 
 */
.type hypercall_table, #object
ENTRY(hypercall_table)
__hypercall_start:
        .long do_set_trap_table     /*  0 */
        .long do_mmu_update
        .long do_ni_hypercall
        .long do_stack_switch
        .long do_set_callbacks
        .long do_fpu_taskswitch     /*  5 */
        .long do_sched_op_compat
        .long do_dom0_op
        .long do_set_debugreg
        .long do_get_debugreg
        .long do_update_descriptor  /* 10 */
        .long do_ni_hypercall
        .long do_memory_op
        .long do_multicall
        .long do_update_va_mapping
        .long do_set_timer_op       /* 15 */
        .long do_event_channel_op
        .long do_xen_version
        .long do_console_io
        .long do_physdev_op
        .long do_grant_table_op     /* 20 */
        .long do_vm_assist
        .long do_update_va_mapping_otherdomain
        .long do_ni_hypercall
        .long do_vcpu_op
        .long do_ni_hypercall       /* 25 */
        .long do_mmuext_op
        .long do_acm_op
        .long do_nmi_op
	.long do_sched_op
	.long do_set_domain		/* 30 */
	.long do_restore_guest_context
	.long do_print_profile
	.long do_set_foreground_domain
	.long do_set_HID_irq
	.long do_dummy	
	.long do_sra_ops
	.long do_dma_op
	.long do_get_system_time
#ifdef CONFIG_GCOV_XEN
	.long do_gcov_op
#else
	.long 0
#endif
	.long do_iwmmxt_op		/* 40 */
	.long set_irq_type
__hypercall_end:

        @.rept NR_hypercalls-((.-hypercall_table)/4)
	@.rept	NR_hypercalls - (__hypercall_end - __hypercall_start) / 4
        @.long do_ni_hypercall
        @.endr
