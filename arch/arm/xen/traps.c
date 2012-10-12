/*
 * traps.c
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
#include <asm/linkage.h>
#include <xen/compile.h>
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/console.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <asm/current.h>

#include <asm/signal.h>

#include <asm/system.h>

asmlinkage void __div0(void)
{
        printk("Division by zero in kernel.\n");
}

void show_registers(struct cpu_user_regs *regs)
{
}

int is_kernel_text(unsigned long addr)
{
	extern char _stext, _etext;
	if (addr >= (unsigned long) &_stext &&
	    addr <= (unsigned long) &_etext)
	    return 1;
	return 0;
}

unsigned long kernel_text_end(void)
{
	extern char _etext;
	return (unsigned long) &_etext;
}

long do_set_callbacks(unsigned long event, unsigned long failsafe)
{
	struct vcpu *d = (struct vcpu *)current;
    
	d->arch.guest_context.event_callback    = event;
	d->arch.guest_context.failsafe_callback = failsafe;

	return 0;

}

#if 0
void construct_hypercall_page(void *hypercall_page)
{
	extern asmlinkage void hypercall(void);
	char *p;
	int i;

	for ( i = 0; i < NR_hypercalls; i++) {
		p = (char *)(hypercall_page + (i * 32));
		*(p *)(p + 0) = 0x0;	/* mov ip, sp */
		*(p *)(p + 4) = 0x0;	/* stmdb sp!, {r8, r9} */
		*(p *)(p + 8) = 0x0;	/* ldr r8, [pc, #4] */
		*(p *)(p + 12) = 0x0;	/* mov pc, r8 */
		*(p *)(p + 14) = (u32)&hypercall;
		*(p *)(p + 18) = 0x0;	/* ldmia sp!, {r8, r9} */
	}
}

int do_guest_trap(int trap_nr, const struct cpu_user_regs *regs, int use_error_code)
{
	struct vcpu *v = current;
	struct trap_bounce *tb;
	const struct trap_info *ti;

	tb = &v->arch.trap_bounce;
	ti = &v->arch.guext_context.trap_ctx[trap_nr];

	tb->flasg = TBF_EXCEPTION;
	tb->address = ti->address;
}

int do_trap(int trap_nr, struct cpu_user_regs *regs, int use_error_code)
{
	if ( guest_mode(regs) ) {
		return do_guest_trap(trapnr, regs, use_error_code);
}

#endif
#if 0
long do_set_trap_table(GUEST_HANDLE(trap_info_t) traps)
{
	struct trap_info cur;
	struct trap_info *dst = current->arch.guest_context.trap_ctxt;
	long rc = 0;

	/* If no table is presented then clear the entire virtual IDT. */
	if ( guest_handle_is_null(traps) ) {
		memset(dst, 0, 8 * sizeof(*dst));
//		init_int80_direct_trap(current);
		return 0;
	}

	for ( ; ; ) {
		if ( hypercall_preempt_check() ) {
			rc = hypercall_create_continuation(
				__HYPERVISOR_set_trap_table, "h", traps);
			break;
		}

		if ( copy_from_guest(&cur, traps, 1) ) {
			rc = -EFAULT;
			break;
		}

		if ( cur.address == 0 )
			break;

//		fixup_guest_code_selector(cur.cs);

		memcpy(&dst[cur.vector], &cur, sizeof(cur));

#if 0
		if ( cur.vector == 0x80 )
			init_int80_direct_trap(current);
#endif
		guest_handle_add_offset(traps, 1);
	}

	return rc;
}
#endif
