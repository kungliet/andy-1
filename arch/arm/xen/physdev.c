#include <xen/lib.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <xen/bitmap.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/config.h>
#include <public/arch-arm.h>
#include <public/physdev.h>
#include <asm/linkage.h>	
#include <asm/config.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <asm/irq.h>
#include <asm/signal.h>
#include <security/acm/acm_hooks.h>

extern int pirq_guest_unmask(struct domain *d);


long do_physdev_op(struct physdev_op *uop)
{
	struct physdev_op op;
	long ret;
	int irq;


	if ( unlikely(copy_from_user(&op, uop, sizeof(struct physdev_op)) != 0) )
		return -EFAULT;
	
	switch ( op.cmd ) {
		case PHYSDEVOP_IRQ_UNMASK_NOTIFY:
			ret = pirq_guest_unmask(current->domain);
 			break;
		case PHYSDEVOP_IRQ_STATUS_QUERY:
        		irq = op.u.irq_status_query.irq;
        		ret = -EINVAL;
        		if ( (irq < 0) || (irq >= NR_IRQS) )
            			break;

				if(!acm_irq_status_query(irq)){
					ret = -EPERM;
					break;
				}

        		op.u.irq_status_query.flags = 0;
        		/* Edge-triggered interrupts don't need an explicit unmask downcall. */
        		if (!strstr(irq_desc[irq].chip->trigger_type, "edge") )
            			op.u.irq_status_query.flags |= PHYSDEVOP_IRQ_NEEDS_UNMASK_NOTIFY;
        		ret = 0;
        		break;

		default:
			ret = -EINVAL;
			break;
	}

	if ( copy_to_user(uop, &op, sizeof(struct physdev_op)) )
		ret = -EFAULT;

	return ret;
}
