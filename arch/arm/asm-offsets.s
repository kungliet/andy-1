	.file	"asm-offsets.c"
	.section	.debug_abbrev,"",%progbits
.Ldebug_abbrev0:
	.section	.debug_info,"",%progbits
.Ldebug_info0:
	.section	.debug_line,"",%progbits
.Ldebug_line0:
	.text
.Ltext0:
	.align	2
	.global	main
	.type	main, %function
main:
.LFB109:
	.file 1 "xen/asm-offsets.c"
	.loc 1 58 0
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	@ lr needed for prologue
	.loc 1 59 0
#APP
	
->OFFSET_DOMAIN #12 offsetof(struct vcpu, domain)
	.loc 1 60 0
	
->OFFSET_SHARED_INFO #4 offsetof(struct domain, shared_info)
	.loc 1 61 0
	
->
	.loc 1 62 0
	
->OFFSET_VCPU_INFO #8 offsetof(struct vcpu, vcpu_info)
	.loc 1 63 0
	
->OFFSET_EVTCHN_UPCALL_MASK #1 offsetof(struct vcpu_info, evtchn_upcall_mask)
	.loc 1 64 0
	
->OFFSET_EVTCHN_UPCALL_PENDING #0 offsetof(struct vcpu_info, evtchn_upcall_pending)
	.loc 1 65 0
	
->OFFSET_ARCH_VCPU #192 offsetof(struct vcpu, arch)
	.loc 1 66 0
	
->OFFSET_GUEST_CONTEXT #0 offsetof(struct arch_vcpu, guest_context)
	.loc 1 67 0
	
->
	.loc 1 68 0
	
->OFFSET_USER_REGS #0 offsetof(struct vcpu_guest_context, user_regs)
	.loc 1 69 0
	
->OFFSET_EXT_REGS #72 offsetof(struct vcpu_guest_context, ext_regs)
	.loc 1 70 0
	
->OFFSET_SYS_REGS #232 offsetof(struct vcpu_guest_context, sys_regs)
	.loc 1 71 0
	
->OFFSET_HYPERVISOR_CALLBACK #264 offsetof(struct vcpu_guest_context, event_callback)
	.loc 1 72 0
	
->OFFSET_FAILSAFE_CALLBACK #268 offsetof(struct vcpu_guest_context, failsafe_callback)
	.loc 1 73 0
	
->
	.loc 1 74 0
	
->OFFSET_R0 #0 offsetof(struct cpu_user_regs, r0)
	.loc 1 75 0
	
->OFFSET_R1 #4 offsetof(struct cpu_user_regs, r1)
	.loc 1 76 0
	
->OFFSET_R2 #8 offsetof(struct cpu_user_regs, r2)
	.loc 1 77 0
	
->OFFSET_R3 #12 offsetof(struct cpu_user_regs, r3)
	.loc 1 78 0
	
->OFFSET_R4 #16 offsetof(struct cpu_user_regs, r4)
	.loc 1 79 0
	
->OFFSET_R5 #20 offsetof(struct cpu_user_regs, r5)
	.loc 1 80 0
	
->OFFSET_R6 #24 offsetof(struct cpu_user_regs, r6)
	.loc 1 81 0
	
->OFFSET_R7 #28 offsetof(struct cpu_user_regs, r7)
	.loc 1 82 0
	
->OFFSET_R8 #32 offsetof(struct cpu_user_regs, r8)
	.loc 1 83 0
	
->OFFSET_R9 #36 offsetof(struct cpu_user_regs, r9)
	.loc 1 84 0
	
->OFFSET_R10 #40 offsetof(struct cpu_user_regs, r10)
	.loc 1 85 0
	
->OFFSET_R11 #44 offsetof(struct cpu_user_regs, r11)
	.loc 1 86 0
	
->OFFSET_R12 #48 offsetof(struct cpu_user_regs, r12)
	.loc 1 87 0
	
->OFFSET_R13 #52 offsetof(struct cpu_user_regs, r13)
	.loc 1 88 0
	
->OFFSET_R14 #56 offsetof(struct cpu_user_regs, r14)
	.loc 1 89 0
	
->OFFSET_R15 #60 offsetof(struct cpu_user_regs, r15)
	.loc 1 90 0
	
->OFFSET_PSR #64 offsetof(struct cpu_user_regs, psr)
	.loc 1 91 0
	
->OFFSET_CTX #68 offsetof(struct cpu_user_regs, ctx)
	.loc 1 92 0
	
->
	.loc 1 93 0
	
->OFFSET_VPSR #0 offsetof(struct cpu_sys_regs, vpsr)
	.loc 1 94 0
	
->OFFSET_VKSP #4 offsetof(struct cpu_sys_regs, vksp)
	.loc 1 95 0
	
->OFFSET_VUSP #8 offsetof(struct cpu_sys_regs, vusp)
	.loc 1 96 0
	
->OFFSET_VDACR #12 offsetof(struct cpu_sys_regs, vdacr)
	.loc 1 97 0
	
->OFFSET_VFSR #20 offsetof(struct cpu_sys_regs, vfsr)
	.loc 1 98 0
	
->OFFSET_VFAR #16 offsetof(struct cpu_sys_regs, vfar)
	.loc 1 99 0
	
->OFFSET_VCP0 #24 offsetof(struct cpu_sys_regs, vcp0)
	.loc 1 100 0
	
->OFFSET_VCP1 #28 offsetof(struct cpu_sys_regs, vcp1)
	.loc 1 101 0
	
->
	.loc 1 102 0
	
->OFFSET_SOFTIRQ_PENDING #0 offsetof(struct irq_cpu_stat, __softirq_pending)
	.loc 1 103 0
	
->OFFSET_LOCAL_IRQ_COUNT #4 offsetof(struct irq_cpu_stat, __local_irq_count)
	.loc 1 106 0
	mov	r0, #0
	mov	pc, lr
.LFE109:
	.size	main, .-main
	.section	.debug_frame,"",%progbits
.Lframe0:
	.4byte	.LECIE0-.LSCIE0
.LSCIE0:
	.4byte	0xffffffff
	.byte	0x1
	.ascii	"\000"
	.uleb128 0x1
	.sleb128 -4
	.byte	0xe
	.byte	0xc
	.uleb128 0xd
	.uleb128 0x0
	.align	2
.LECIE0:
.LSFDE0:
	.4byte	.LEFDE0-.LASFDE0
.LASFDE0:
	.4byte	.Lframe0
	.4byte	.LFB109
	.4byte	.LFE109-.LFB109
	.align	2
.LEFDE0:
	.file 2 "/home/lee/imx21_2.6.21.1/xen-unstable.hg/xen/include/asm/flushtlb.h"
	.file 3 "/home/lee/imx21_2.6.21.1/xen-unstable.hg/xen/include/asm/types.h"
	.text
.Letext0:
	.section	.debug_info
	.4byte	0xa5
	.2byte	0x2
	.4byte	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	.Ldebug_line0
	.4byte	.Letext0
	.4byte	.Ltext0
	.4byte	.LASF10
	.byte	0x1
	.4byte	.LASF11
	.4byte	.LASF12
	.uleb128 0x2
	.4byte	.LASF0
	.byte	0x1
	.byte	0x6
	.uleb128 0x2
	.4byte	.LASF1
	.byte	0x1
	.byte	0x8
	.uleb128 0x2
	.4byte	.LASF2
	.byte	0x2
	.byte	0x5
	.uleb128 0x2
	.4byte	.LASF3
	.byte	0x2
	.byte	0x7
	.uleb128 0x3
	.ascii	"int\000"
	.byte	0x4
	.byte	0x5
	.uleb128 0x2
	.4byte	.LASF4
	.byte	0x4
	.byte	0x7
	.uleb128 0x2
	.4byte	.LASF5
	.byte	0x8
	.byte	0x5
	.uleb128 0x2
	.4byte	.LASF6
	.byte	0x8
	.byte	0x7
	.uleb128 0x2
	.4byte	.LASF7
	.byte	0x4
	.byte	0x7
	.uleb128 0x4
	.ascii	"u32\000"
	.byte	0x3
	.byte	0x27
	.4byte	0x48
	.uleb128 0x2
	.4byte	.LASF4
	.byte	0x4
	.byte	0x7
	.uleb128 0x2
	.4byte	.LASF8
	.byte	0x1
	.byte	0x8
	.uleb128 0x2
	.4byte	.LASF9
	.byte	0x4
	.byte	0x5
	.uleb128 0x5
	.byte	0x1
	.4byte	.LASF13
	.byte	0x1
	.byte	0x3a
	.byte	0x1
	.4byte	0x41
	.4byte	.LFB109
	.4byte	.LFE109
	.byte	0x1
	.byte	0x5d
	.uleb128 0x6
	.4byte	.LASF14
	.byte	0x2
	.byte	0x23
	.4byte	0x64
	.byte	0x1
	.byte	0x1
	.byte	0x0
	.section	.debug_abbrev
	.uleb128 0x1
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x10
	.uleb128 0x6
	.uleb128 0x12
	.uleb128 0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1b
	.uleb128 0xe
	.byte	0x0
	.byte	0x0
	.uleb128 0x2
	.uleb128 0x24
	.byte	0x0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.byte	0x0
	.byte	0x0
	.uleb128 0x3
	.uleb128 0x24
	.byte	0x0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.byte	0x0
	.byte	0x0
	.uleb128 0x4
	.uleb128 0x16
	.byte	0x0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0x0
	.byte	0x0
	.uleb128 0x5
	.uleb128 0x2e
	.byte	0x0
	.uleb128 0x3f
	.uleb128 0xc
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0xc
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x1
	.uleb128 0x40
	.uleb128 0xa
	.byte	0x0
	.byte	0x0
	.uleb128 0x6
	.uleb128 0x34
	.byte	0x0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0xc
	.uleb128 0x3c
	.uleb128 0xc
	.byte	0x0
	.byte	0x0
	.byte	0x0
	.section	.debug_pubnames,"",%progbits
	.4byte	0x17
	.2byte	0x2
	.4byte	.Ldebug_info0
	.4byte	0xa9
	.4byte	0x84
	.ascii	"main\000"
	.4byte	0x0
	.section	.debug_aranges,"",%progbits
	.4byte	0x1c
	.2byte	0x2
	.4byte	.Ldebug_info0
	.byte	0x4
	.byte	0x0
	.2byte	0x0
	.2byte	0x0
	.4byte	.Ltext0
	.4byte	.Letext0-.Ltext0
	.4byte	0x0
	.4byte	0x0
	.section	.debug_str,"MS",%progbits,1
.LASF2:
	.ascii	"short int\000"
.LASF10:
	.ascii	"GNU C 3.4.4\000"
.LASF6:
	.ascii	"long long unsigned int\000"
.LASF14:
	.ascii	"tlbflush_clock\000"
.LASF8:
	.ascii	"char\000"
.LASF11:
	.ascii	"xen/asm-offsets.c\000"
.LASF12:
	.ascii	"/home/lee/imx21_2.6.21.1/xen-unstable.hg/xen/arch/a"
	.ascii	"rm\000"
.LASF5:
	.ascii	"long long int\000"
.LASF9:
	.ascii	"long int\000"
.LASF4:
	.ascii	"unsigned int\000"
.LASF7:
	.ascii	"long unsigned int\000"
.LASF1:
	.ascii	"unsigned char\000"
.LASF0:
	.ascii	"signed char\000"
.LASF3:
	.ascii	"short unsigned int\000"
.LASF13:
	.ascii	"main\000"
	.ident	"GCC: (GNU) 3.4.4"
