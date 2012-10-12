#include <xen/init.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <asm/config.h>
#include <xen/lib.h>
#include <asm/signal.h>
#include <asm/irq.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <xen/bitmap.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/linkage.h>
#include <asm/hardirq.h>
#include <asm/uaccess.h>
#include <asm/string.h>
#include <asm/memmap.h>
#include <public/xen.h>
#include <acm/acm_hooks.h>
#include <xen/iocap.h>
#include <xen/dma.h>
#include <public/vdma.h>
#include <asm/current.h>
#include <public/xen.h>
#include <public/event_channel.h>

#define iterate_dma_priority_map(x, y)	(x)

struct dma_channel dma_channels[MAX_DMA_CHANNEL];

void handle_dma_event(unsigned long ch)
{
	struct dma_channel *channel;
	struct vcpu *v;

	channel = &dma_channels[ch];

	if(channel->owner) {
		v = channel->owner;

		if(!test_bit(ch, &v->domain->shared_info->vdma_mask[0])) {
			set_bit(ch, &v->domain->shared_info->vdma_pending[0]);

			send_guest_virq(v, VIRQ_VDMA);
		}
	}
}

int request_dma(vdma_priority priority)
{
	int i = 0;
	unsigned long flags;
	struct dma_channel *channel;
	struct vcpu *v = current;

	local_irq_save(flags);
	
	for(i = 0; i < MAX_DMA_CHANNEL; i++) {
		channel = &dma_channels[i];
		if(!channel->owner) {
			break;
		}
	}

	if(i < MAX_DMA_CHANNEL) {
		channel->ops->request(i);
		channel->owner = v;

		goto out;
	}

	i = -EINVAL;

out :
	local_irq_restore(flags);

	return i;
}

void release_dma(int dcn)
{
	unsigned long flags;
	struct dma_channel *channel;

	local_irq_save(flags);

	channel = &dma_channels[dcn];
	channel->ops->release(dcn);

	memset(&dma_channels[dcn], 0, sizeof(struct dma_channel));

	local_irq_restore(flags);
}

int do_dma_op(struct dma_op *uop)
{
	long ret;
	struct dma_op op;

	if ( unlikely(copy_from_user(&op, uop, sizeof(struct dma_op)) != 0) ) {
		return -EFAULT;
	}

	ret = 0;

	switch( op.cmd ) {
		case DMAOP_ENABLE:
		case DMAOP_DISABLE:
		case DMAOP_START:
		case DMAOP_ACK:
		case DMAOP_REQUEST:
			ret = request_dma(op.param.priority);
			break;
		case DMAOP_RELEASE:
			release_dma(op.param.channel);
			break;
		default:
			while(1);
			break;
	}

	return ret;
}

