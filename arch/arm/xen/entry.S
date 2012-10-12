/*
 * entry.S
 *
 * Copyright (C) 2008 Samsung Electronics
 *          JaeMin Ryu  <jm77.ryu@samsung.com>
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

#include <xen/config.h> 
#include <asm/init.h>
#include <asm/linkage.h>
#include <asm/arch/irqs.h>
#include <asm/page.h>
#include <asm/system.h>
#include <asm/asm-macros.h>
#include <asm/cpu-domain.h>
#include <asm/asm-offsets.h>
#include <asm/arch/entry-macro.S>

 	.align 5
__pabt_invalid:	
1:
	b	1b

__dabt_invalid:	
1:
	b	1b

__irq_invalid:	
1:
	b	1b

__und_invalid:	
1:
	b 	1b

/*
 * SVC mode handlers
 */
	.align  5
__dabt_svc:
	save_svc_context
1:
	b 	1b

__pabt_svc:
	save_svc_context
1:
	b	1b

__und_svc:
	save_svc_context

1:
	b	1b

	.align	5
__irq_svc:
	save_svc_context
#ifdef	CONFIG_MACHINE_VERSATILE
        get_irqnr_preamble r5, lr @ minsung
#endif
1:	get_irqnr_and_base r0, r6, r5, lr
	movne	r1, sp  

	@
	@ routine called with r0 = irq number, r1 = struct pt_regs *
	@
	adrne	lr, 1b
	bne	asm_do_IRQ

	/* restore svc mode register */
	ldr	r0, [sp, #S_PSR]		@ irqs are already disabled
	msr	spsr_cxsf, r0
	ldmia	sp, {r0 - pc}^			@ load r0 - pc, cpsr

ENTRY(ret_to_user)	
test_all_events:
	disable_irq 	r1			@ ensure IRQs are disabled	

	bl      get_irq_stat			@ get softirq pending status
	ldr     r1, [r0, #OFFSET_SOFTIRQ_PENDING]

	ldr	r0, =0xffff 
	tst	r1, r0	  			@ bit mask check is needed!!!

	beq	test_guest_events
	enable_irq	r1 			@ sti       @ r1.. ok??????

	bl	do_softirq
	b	test_all_events

ENTRY(test_guest_events)
	vcpu	r10
	ldr	r11, [r10, #OFFSET_VCPU_INFO]
	ldrb	r9, [r11, #OFFSET_EVTCHN_UPCALL_MASK]
	tst	r9, #0xFF
	bne	restore

	ldrb	r12, [r11, #OFFSET_EVTCHN_UPCALL_PENDING]
	tst	r12, #0xFF
	beq	restore

/*
 * Send event to guest domain
 */
ENTRY(do_upcall)
	vcpu    r10
	ldr	r11, [r10, #OFFSET_VCPU_INFO]
	add	r10, r10, #(OFFSET_ARCH_VCPU + OFFSET_GUEST_CONTEXT)

	ldr	lr, [r10, #OFFSET_HYPERVISOR_CALLBACK]
	cmp	lr, #0
	beq	restore

	mov	r9, #0x01
	strb	r9, [r11, #OFFSET_EVTCHN_UPCALL_MASK]

	mov	r4, #PSR_MODE_SVC
	str	r4, [r10, #(OFFSET_SYS_REGS + OFFSET_VPSR)]

	@ Load virtual kernel stack pointer
	ldr	r11, [r10, #(OFFSET_SYS_REGS + OFFSET_VKSP)]

	@ Align VKSP in 8-byte boundary
	sub	r12, r11, #S_FRAME_SIZE
	tst	r12, #4
	bicne	r12, r12, #4
	tst	r12, #4
1:
	bne	1b

	@ Update effective virtual kernel stack pointer.
	str	r12, [r10, #(OFFSET_SYS_REGS + OFFSET_VKSP)]

	@ Create bounce frame in guest stack
	ldmia	sp!, {r0-r8}
	stmia	r12!, {r0-r8}
	
	ldmia	sp!, {r0-r8}
	stmia	r12!, {r0-r8}

	
	sub	r12, r12, #S_FRAME_SIZE
	ldr	r0, =.LCupcall
	stmia	r0, {r12,lr}
		
	ldmia	r0, {sp, lr}^

	ldr	r0, [r12, #S_CONTEXT]
	ldr	r1, [r12, #S_PSR]
	ldr	r2, [r10, #(OFFSET_SYS_REGS + OFFSET_VFAR)]
	ldr	r3, [r10, #(OFFSET_SYS_REGS + OFFSET_VFSR)]
	mov	r7, #PSR_MODE_USR
	msr	spsr, r7

	ldr	r5, =DOMAIN_KERNEL_VALUE
	mcr     p15, 0, r5, c3, c0, 0   @ Load DAC

	movs	pc, lr

.LCupcall:
	.long	0
	.long	0

ENTRY(restore)
	vcpu    r4
	add     r5, r4, #(OFFSET_ARCH_VCPU + OFFSET_GUEST_CONTEXT)

	ldr     r1, [sp, #S_PSR]
	and	r3, r1, #PSR_MODE_MASK
	str	r3, [r5, #(OFFSET_SYS_REGS + OFFSET_VPSR)]

	bic	r1, r1, #PSR_MODE_MASK
	orr	r1, r1, #PSR_MODE_USR

	cmp     r3, #PSR_MODE_USR
        ldreq   r7, =DOMAIN_HYPERVISOR_VALUE
        ldrne   r7, =DOMAIN_KERNEL_VALUE
        mcr     p15, 0, r7, c3, c0, 0

        mrc     p15, 0, r3, c2, c0, 0          @ arbitrary read of cp15
        mov    r3, r3                        @ wait for completion
        sub     pc, pc, #4                      @ flush instruction pipeline

	ldr     lr, [sp, #S_PC]!                @ Get PC
	msr     spsr, r1                        @ save in spsr_svc
	
	ldmdb   sp, {r0 - lr}^                  @ Get calling r0 - lr
	mov     r0, r0
	add     sp, sp, #S_FRAME_SIZE - S_PC
	
	movs    pc, lr                          @ return & move spsr_svc into cpsr

/*
 * User mode handlers
 */

	.align	5
__irq_usr:	
	save_usr_context

	vcpu	r0
	add	r0, r0, #(OFFSET_ARCH_VCPU + OFFSET_GUEST_CONTEXT)
	ldr	r1, [r0, #(OFFSET_SYS_REGS + OFFSET_VPSR)]

	ldr	r2, [sp, #S_SP]
	cmp	r1, #PSR_MODE_USR
	streq	r2, [r0, #(OFFSET_SYS_REGS + OFFSET_VUSP)]
	strne	r2, [r0, #(OFFSET_SYS_REGS + OFFSET_VKSP)]

	ldr     r3, [sp, #S_PSR]
	bic     r3, r3, #PSR_MODE_MASK
	orr     r3, r3, r1
	str     r3, [sp, #S_PSR]

#ifdef	CONFIG_MACHINE_VERSATILE
	get_irqnr_preamble r5, lr @ minsung
#endif
1:	get_irqnr_and_base r0, r6, r5, lr

	movne   r1, sp
	adrne	lr, 1b
	
	bne     asm_do_IRQ

	b	ret_to_user

	.align	5
__dabt_usr: 
	save_usr_context

	vcpu    r4
	add	r4, r4, #(OFFSET_ARCH_VCPU + OFFSET_GUEST_CONTEXT)
	ldr	r5, [r4, #(OFFSET_SYS_REGS + OFFSET_VPSR)]
	ldr	r6, [sp, #S_SP]
	cmp	r5, #PSR_MODE_USR
	streq	r6, [r4, #(OFFSET_SYS_REGS + OFFSET_VUSP)]
	strne	r6, [r4, #(OFFSET_SYS_REGS + OFFSET_VKSP)]

	ldr     r3, [sp, #S_PSR]
	bic     r3, r3, #PSR_MODE_MASK
	orr     r3, r3, r5
	str     r3, [sp, #S_PSR]

	mrc	p15, 0, r0, c5, c0, 0
	str	r0, [r4, #(OFFSET_SYS_REGS + OFFSET_VFSR)]

	mrc	p15, 0, r0, c6, c0, 0
	str	r0, [r4, #(OFFSET_SYS_REGS + OFFSET_VFAR)]

	b	do_upcall


	.align	5
__und_usr:
	save_usr_context

	vcpu	r0
	add	r0, r0, #(OFFSET_ARCH_VCPU + OFFSET_GUEST_CONTEXT)
	ldr	r1, [r0, #(OFFSET_SYS_REGS + OFFSET_VPSR)]
	ldr	r2, [sp, #S_SP]
        cmp     r1, #PSR_MODE_USR
        streq   r2, [r0, #(OFFSET_SYS_REGS + OFFSET_VUSP)]
        strne   r2, [r0, #(OFFSET_SYS_REGS + OFFSET_VKSP)]

	ldr     r3, [sp, #S_PSR]
	bic     r3, r3, #PSR_MODE_MASK
	orr     r3, r3, r1
	str     r3, [sp, #S_PSR]

	b	do_upcall

	.align	5
__pabt_usr:
	save_usr_context

	vcpu	r0
	add	r0, r0, #(OFFSET_ARCH_VCPU + OFFSET_GUEST_CONTEXT)
	ldr	r1, [r0, #(OFFSET_SYS_REGS + OFFSET_VPSR)]
	ldr	r2, [sp, #S_SP]
        cmp     r1, #PSR_MODE_USR
        streq   r2, [r0, #(OFFSET_SYS_REGS + OFFSET_VUSP)]
        strne   r2, [r0, #(OFFSET_SYS_REGS + OFFSET_VKSP)]

	ldr     r3, [sp, #S_PSR]
	bic     r3, r3, #PSR_MODE_MASK
	orr     r3, r3, r1
	str     r3, [sp, #S_PSR]

        b       do_upcall


		.align	5
ENTRY(__switch_to)
	disable_irq 	ip			@ ensure IRQs are disabled	
	add     ip, r1, #(OFFSET_USER_REGS + OFFSET_R4)
save_ctx:
        stmia   ip, {r4 - sl, fp, ip, sp, lr}      @ Store most regs on stack

	mrc	p15, 0, r4, c3, c0, 0
	str	r4, [r1, #(OFFSET_SYS_REGS + OFFSET_VDACR)]
load_ctx:
	ldr	r4, [r2, #(OFFSET_SYS_REGS + OFFSET_VDACR)]
	mcr	p15, 0, r4, c3, c0, 0

	add	ip, r2, #(OFFSET_USER_REGS + OFFSET_R4)
	enable_irq	r4
        ldmia   ip,  {r4 - sl, fp, ip, sp, pc}       @ Load all regs saved previously
 
@	mov	pc, lr
	nop	
	nop	
	b	.

	.align	5
stubs_start:
INSTALL_VECTOR_STUB(irq, 0x18, PSR_MODE_IRQ, 4, .LCtab_irq)
.LCtab_irq:	.word	__irq_usr			@  0  (USR_26 / USR_32)
		.word	__irq_invalid			@  1  (FIQ_26 / FIQ_32)
		.word	__irq_invalid			@  2  (IRQ_26 / IRQ_32)
		.word	__irq_svc			@  3  (SVC_26 / SVC_32)
		.word	__irq_invalid			@  4
		.word	__irq_invalid			@  5
		.word	__irq_invalid			@  6
		.word	__irq_invalid			@  7
		.word	__irq_invalid			@  8
		.word	__irq_invalid			@  9
		.word	__irq_invalid			@  a
		.word	__irq_invalid			@  b
		.word	__irq_invalid			@  c
		.word	__irq_invalid			@  d
		.word	__irq_invalid			@  e
		.word	__irq_usr			@  f

INSTALL_VECTOR_STUB(data_abort, 0x10, PSR_MODE_ABT, 8, .LCtab_dabt)
.LCtab_dabt:	.word	__dabt_usr			@  0  (USR_26 / USR_32)
		.word	__dabt_invalid			@  1  (FIQ_26 / FIQ_32)
		.word	__dabt_invalid			@  2  (IRQ_26 / IRQ_32)
		.word	__dabt_svc			@  3  (SVC_26 / SVC_32)
		.word	__dabt_invalid			@  4
		.word	__dabt_invalid			@  5
		.word	__dabt_invalid			@  6
		.word	__dabt_invalid			@  7
		.word	__dabt_invalid			@  8
		.word	__dabt_invalid			@  9
		.word	__dabt_invalid			@  a
		.word	__dabt_invalid			@  b
		.word	__dabt_invalid			@  c
		.word	__dabt_invalid			@  d
		.word	__dabt_invalid			@  e
		.word	__dabt_usr			@  f

INSTALL_VECTOR_STUB(prefetch_abort, 0x0C, PSR_MODE_ABT, 4, .LCtab_pabt)
.LCtab_pabt:	.word	__pabt_usr			@  0 (USR_26 / USR_32)
		.word	__pabt_invalid			@  1 (FIQ_26 / FIQ_32)
		.word	__pabt_invalid			@  2 (IRQ_26 / IRQ_32)
		.word	__pabt_svc			@  3 (SVC_26 / SVC_32)
		.word	__pabt_invalid			@  4
		.word	__pabt_invalid			@  5
		.word	__pabt_invalid			@  6
		.word	__pabt_invalid			@  7
		.word	__pabt_invalid			@  8
		.word	__pabt_invalid			@  9
		.word	__pabt_invalid			@  a
		.word	__pabt_invalid			@  b
		.word	__pabt_invalid			@  c
		.word	__pabt_invalid			@  d
		.word	__pabt_invalid			@  e
		.word	__pabt_usr			@  f

INSTALL_VECTOR_STUB(undefined_instruction, 0x04, PSR_MODE_UND, 0, .LCtab_und)
.LCtab_und:	.word	__und_usr			@  0 (USR_26 / USR_32)
		.word	__und_invalid			@  1 (FIQ_26 / FIQ_32)
		.word	__und_invalid			@  2 (IRQ_26 / IRQ_32)
		.word	__und_svc			@  3 (SVC_26 / SVC_32)
		.word	__und_invalid			@  4
		.word	__und_invalid			@  5
		.word	__und_invalid			@  6
		.word	__und_invalid			@  7
		.word	__und_invalid			@  8
		.word	__und_invalid			@  9
		.word	__und_invalid			@  a
		.word	__und_invalid			@  b
		.word	__und_invalid			@  c
		.word	__und_invalid			@  d
		.word	__und_invalid			@  e
		.word	__und_usr			@  f

		.align	5

/*=============================================================================
 * Undefined FIQs
 *-----------------------------------------------------------------------------
 * Enter in FIQ mode, spsr = ANY CPSR, lr = ANY PC
 * MUST PRESERVE SVC SPSR, but need to switch to SVC mode to show our msg.
 * Basically to switch modes, we *HAVE* to clobber one register...  brain
 * damage alert!  I don't think that we can execute any code in here in any
 * other mode than FIQ...  Ok you can switch to another mode, but you can't
 * get out of that mode without clobbering one register.
 */
vector_FIQ:     disable_fiq
                subs    pc, lr, #4

/*=============================================================================
 * Address exception handler
 *-----------------------------------------------------------------------------
 * These aren't too critical.
 * (they're not supposed to happen, and won't happen in 32-bit data mode).
 */

vector_addrexcptn:
		b	vector_addrexcptn

	.align	5

.LCvswi:.word	vector_swi
stubs_end:

	.equ    stubs_offset, exception_vector_table + 0x200 - stubs_start
exception_vector_table:
	swi	0x9f0000
	b	vector_undefined_instruction + stubs_offset
	ldr	pc, .LCvswi + stubs_offset
	b	vector_prefetch_abort + stubs_offset
	b	vector_data_abort + stubs_offset
	b	vector_addrexcptn + stubs_offset
	b	vector_irq + stubs_offset
	b	vector_FIQ + stubs_offset

ENTRY(trap_init)
	stmfd	sp!, {r4 - r6, lr}

	mov	r0, #0x0
	adr	r1, exception_vector_table			@ set up the vectors
	ldmia	r1, {r1, r2, r3, r4, r5, r6, ip, lr}
	stmia	r0, {r1, r2, r3, r4, r5, r6, ip, lr}

	add	r2, r0, #0x200
	adr	r0, stubs_start		@ copy stubs to 0x200
	adr	r1, stubs_end
1:	ldr	r3, [r0], #4
	str	r3, [r2], #4
	cmp	r0, r1
	blt	1b

	LOADREGS(fd, sp!, {r4 - r6, pc})

