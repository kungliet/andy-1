/*
 * asm-offsets.c
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
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/irq_cpustat.h>

#if defined(__APCS_26__)
#error Sorry, your compiler targets APCS-26 but this kernel requires APCS-32
#endif
/*
 * GCC 2.95.1, 2.95.2: ignores register clobber list in asm().
 * GCC 3.0, 3.1: general bad code generation.
 * GCC 3.2.0: incorrect function argument offset calculation.
 * GCC 3.2.x: miscompiles NEW_AUX_ENT in fs/binfmt_elf.c
 *            (http://gcc.gnu.org/PR8896) and incorrect structure
 *	      initialisation in fs/jffs2/erase.c
 */
#if __GNUC__ < 2 || \
   (__GNUC__ == 2 && __GNUC_MINOR__ < 95) || \
   (__GNUC__ == 2 && __GNUC_MINOR__ == 95 && __GNUC_PATCHLEVEL__ != 0 && \
					     __GNUC_PATCHLEVEL__ < 3) || \
   (__GNUC__ == 3 && __GNUC_MINOR__ < 3)
#error Your compiler is too buggy; it is known to miscompile kernels.
#error    Known good compilers: 2.95.3, 2.95.4, 2.96, 3.3
#endif

/* Use marker if you need to separate the values later */

#define DEFINE(sym, val) \
        asm volatile("\n->" #sym " %0 " #val : : "i" (val))

#define BLANK() asm volatile("\n->" : : )

int main(void)
{
  DEFINE(OFFSET_DOMAIN,			offsetof(struct vcpu,	     domain));
  DEFINE(OFFSET_SHARED_INFO,		offsetof(struct domain,	     shared_info));
  BLANK();
  DEFINE(OFFSET_VCPU_INFO,		offsetof(struct vcpu, vcpu_info));
  DEFINE(OFFSET_EVTCHN_UPCALL_MASK,	offsetof(struct vcpu_info, evtchn_upcall_mask));
  DEFINE(OFFSET_EVTCHN_UPCALL_PENDING,	offsetof(struct vcpu_info, evtchn_upcall_pending));
  DEFINE(OFFSET_ARCH_VCPU,		offsetof(struct vcpu, arch));
  DEFINE(OFFSET_GUEST_CONTEXT,		offsetof(struct arch_vcpu, guest_context));
  BLANK();
  DEFINE(OFFSET_USER_REGS,		offsetof(struct vcpu_guest_context, user_regs));
  DEFINE(OFFSET_EXT_REGS,		offsetof(struct vcpu_guest_context, ext_regs));
  DEFINE(OFFSET_SYS_REGS,		offsetof(struct vcpu_guest_context, sys_regs));
  DEFINE(OFFSET_HYPERVISOR_CALLBACK,	offsetof(struct vcpu_guest_context, event_callback));
  DEFINE(OFFSET_FAILSAFE_CALLBACK,	offsetof(struct vcpu_guest_context, failsafe_callback));
  BLANK();
  DEFINE(OFFSET_R0,			offsetof(struct cpu_user_regs, r0));
  DEFINE(OFFSET_R1,			offsetof(struct cpu_user_regs, r1));
  DEFINE(OFFSET_R2,			offsetof(struct cpu_user_regs, r2));
  DEFINE(OFFSET_R3,			offsetof(struct cpu_user_regs, r3));
  DEFINE(OFFSET_R4,			offsetof(struct cpu_user_regs, r4));
  DEFINE(OFFSET_R5,			offsetof(struct cpu_user_regs, r5));
  DEFINE(OFFSET_R6,			offsetof(struct cpu_user_regs, r6));
  DEFINE(OFFSET_R7,			offsetof(struct cpu_user_regs, r7));
  DEFINE(OFFSET_R8,			offsetof(struct cpu_user_regs, r8));
  DEFINE(OFFSET_R9,			offsetof(struct cpu_user_regs, r9));
  DEFINE(OFFSET_R10,			offsetof(struct cpu_user_regs, r10));
  DEFINE(OFFSET_R11,			offsetof(struct cpu_user_regs, r11));
  DEFINE(OFFSET_R12,			offsetof(struct cpu_user_regs, r12));
  DEFINE(OFFSET_R13,			offsetof(struct cpu_user_regs, r13));
  DEFINE(OFFSET_R14,			offsetof(struct cpu_user_regs, r14));
  DEFINE(OFFSET_R15,			offsetof(struct cpu_user_regs, r15));
  DEFINE(OFFSET_PSR,			offsetof(struct cpu_user_regs, psr));
  DEFINE(OFFSET_CTX,			offsetof(struct cpu_user_regs, ctx));
  BLANK();
  DEFINE(OFFSET_VPSR,			offsetof(struct cpu_sys_regs, vpsr));
  DEFINE(OFFSET_VKSP,			offsetof(struct cpu_sys_regs, vksp));
  DEFINE(OFFSET_VUSP,			offsetof(struct cpu_sys_regs, vusp));
  DEFINE(OFFSET_VDACR,			offsetof(struct cpu_sys_regs, vdacr));
  DEFINE(OFFSET_VFSR,			offsetof(struct cpu_sys_regs, vfsr));
  DEFINE(OFFSET_VFAR, 			offsetof(struct cpu_sys_regs, vfar));
  DEFINE(OFFSET_VCP0,			offsetof(struct cpu_sys_regs, vcp0));
  DEFINE(OFFSET_VCP1,			offsetof(struct cpu_sys_regs, vcp1));
  BLANK();
  DEFINE(OFFSET_SOFTIRQ_PENDING,	offsetof(struct irq_cpu_stat, __softirq_pending));
  DEFINE(OFFSET_LOCAL_IRQ_COUNT,	offsetof(struct irq_cpu_stat, __local_irq_count));

  return 0; 
}
