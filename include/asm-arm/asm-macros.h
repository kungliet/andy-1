#ifndef __ASM_ARM_ASM_MACROS_H
#define __ASM_ARM_ASM_MACROS_H

#include <asm/system.h>
#include <asm/arch/config.h>

#ifdef __ASSEMBLY__
/*
 * Endian independent macros for shifting bytes within registers.
 */
#ifndef __ARMEB__
#define pull            lsr
#define push            lsl
#define get_byte_0      lsl #0
#define get_byte_1      lsr #8
#define get_byte_2      lsr #16
#define get_byte_3      lsr #24
#define put_byte_0      lsl #0
#define put_byte_1      lsl #8
#define put_byte_2      lsl #16
#define put_byte_3      lsl #24
#else
#define pull            lsl
#define push            lsr
#define get_byte_0      lsr #24
#define get_byte_1      lsr #16
#define get_byte_2      lsr #8
#define get_byte_3      lsl #0
#define put_byte_0      lsl #24
#define put_byte_1      lsl #16
#define put_byte_2      lsl #8
#define put_byte_3      lsl #0
#endif

/*
 * Data preload for architectures that support it
 */
#define PLD(code...)

/*
 * LOADREGS - ldm with PC in register list (eg, ldmfd sp!, {pc})
 */
#ifdef __STDC__
#define LOADREGS(cond, base, reglist...)\
        ldm##cond       base,reglist
#else
#define LOADREGS(cond, base, reglist...)\
        ldm/**/cond     base,reglist
#endif

/*
 * Build a return instruction for this processor type.
 */
#define RETINSTR(instr, regs...)\
        instr   regs

@
@ Stack format (ensured by USER_* and SVC_*)
@
#define S_FRAME_SIZE    72
#define S_CONTEXT	68
#define S_PSR           64
#define S_PC            60
#define S_LR            56
#define S_SP            52
#define S_IP            48
#define S_FP            44
#define S_R10           40
#define S_R9            36
#define S_R8            32
#define S_R7            28
#define S_R6            24
#define S_R5            20
#define S_R4            16
#define S_R3            12
#define S_R2            8
#define S_R1            4
#define S_R0            0

#ifdef CONFIG_EABI_SUPPORT
#define SPFIX(code...)	code
#else
#define SPFIX(code...)
#endif

#define INSTALL_VECTOR_STUB(name, offset, mode, correction, branch_table)       \
        vector_##name:                                                  \
		vector_stub     offset, mode, correction, branch_table

	.macro vector_stub      offset, mode, correction, branch_table
	sub     sp, sp, #16
	sub     lr, lr, #\correction
	stmia   sp!, {r0, lr}

	mrs     r0, spsr
	mov     lr, #\offset
	stmia   sp!, {r0, lr}

	mrs     lr, cpsr
	eor	lr, lr, #(\mode ^ PSR_MODE_SVC)
	msr     spsr_cxsf, lr                   @ switch to SVC_32 mode

	and     r0, r0, #15
	adr     lr, \branch_table
	ldr     lr, [lr, r0, lsl #2]
	sub     r0, sp, #16
	movs    pc, lr                          @ Changes mode and branches
	.endm

	.macro save_usr_context
	sub     sp, sp, #S_FRAME_SIZE
	stmib   sp, {r1 - r12}

	ldmia   r0, {r1 - r4}
	add     r0, sp, #S_PC

	str     r1, [sp]                        @ Save the "real" r0
	stmia   r0, {r2 - r4}
	stmdb   r0, {sp, lr}^
	.endm

	.macro save_svc_context
	sub     sp, sp, #S_FRAME_SIZE
SPFIX(  tst	sp, #4                 )
SPFIX(  bicne	sp, sp, #4             )
	stmib   sp, {r1 - r12}

	ldmia   r0, {r1 - r4}
	add     r5, sp, #S_SP
	add     r0, sp, #S_FRAME_SIZE
SPFIX(  addne	r0, r0, #4  ) 
	str     r1, [sp]                @ Save real R0

	mov     r1, lr

	stmia   r5, {r0 - r4}
	.endm

	.macro restore_svc_context
	ldr     r0, [sp, #S_PSR]                @ irqs are already disabled
	msr     spsr_cxsf, r0
	ldmia   sp, {r0 - pc}^                  @ load r0 - pc, cpsr
	.endm

        .macro  disable_irq, temp
        msr	cpsr_c, #PSR_STATUS_I | PSR_MODE_SVC
        .endm

        .macro  enable_irq, temp
	msr	cpsr_c, #PSR_MODE_SVC
        .endm 

/*
 * Like adr, but force SVC mode (if required)
 */
        .macro  adrsvc, cond, reg, label
        adr\cond        \reg, \label
        .endm

	.macro	mask_pc, rd, rm
	.endm


/*
 * These are the registers used in the syscall handler, and allow us to
 * have in theory up to 7 arguments to a function - r0 to r6.
 *
 * r7 is reserved for the system call number for thumb mode.
 *
 * Note that tbl == why is intentional.
 *
 * We must set at least "tsk" and "why" when calling ret_with_reschedule.
 */
scno    .req    r7              @ syscall number
tbl     .req    r8              @ syscall table pointer
why     .req    r8              @ Linux syscall (!= 0)
tsk     .req    r9              @ current thread_info

	.macro	get_scno
	mask_pc	lr, lr
	ldr	scno, [lr, #-4]		@ get SWI instruction
	.endm

	.macro	vcpu	rd
		ldr	\rd, =(~(STACK_SIZE - 1))
		and	\rd, r13, \rd
		ldr	\rd, [\rd]
	.endm

	.macro	set_upcall_mask		rd
	.endm

	.macro	clear_upcall_mask	rd
	.endm



	.macro __local_save_flags  temp_int
	mrs    \temp_int,  cpsr                @ local_save_flags
	.endm

	.macro __local_irq_resotre  temp_int
	msr    cpsr_c, \temp_int              @ local_irq_restore
	.endm


	.macro __local_irq_save  flag tmp
	mrs     \flag, cpsr
	orr     \tmp, \flag, #128
	msr     cpsr, \tmp
	.endm

	.macro __local_irq_restore  flag 
	msr     cpsr_c, \flag       
	.endm


/*
 * Save the current IRQ state and disable IRQs.  Note that this macro
 * assumes FIQs are enabled, and that the processor is in SVC mode.
 */
	.macro	save_and_disable_irqs, oldcpsr, temp
	mrs	\oldcpsr, cpsr
	mov	\temp, #PSR_STATUS_I | PSR_MODE_SVC
	msr	cpsr_c, \temp
	.endm

/*
 * Restore interrupt state previously stored in a register.  We don't
 * guarantee that this will preserve the flags.
 */
	.macro	restore_irqs, oldcpsr
	msr	cpsr_c, \oldcpsr
	.endm

/*
 * These two are used to save LR/restore PC over a user-based access.
 * The old 26-bit architecture requires that we do.  On 32-bit
 * architecture, we can safely ignore this requirement.
 */
	.macro	save_lr
	.endm

	.macro	restore_pc
	mov	pc, lr
	.endm

	.macro spin_forever
	1:
	mov	pc, 1b
	.endm

#define USER(x...)				\
9999:	x;					\
	.section __ex_table,"a";		\
	.align	3;				\
	.long	9999b,9001f;			\
	.previous

#endif
#endif
