/*
 * dma-op.c
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

#include <xen/init.h>
#include <xen/types.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <asm/config.h>
#include <xen/lib.h>
#include <asm/signal.h>
#include <asm/irq.h>
#include <asm/mach/irq.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <public/arch-arm.h>
#include <xen/bitmap.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/linkage.h>
#include <asm/hardirq.h>
#include <asm/uaccess.h>
#include <asm/string.h>
#include <asm/memmap.h>
#include <asm/dma.h>
#include <public/xen.h>
#include <xen/iocap.h>
#include <asm/current.h>

inline long verify_dma_address_range(unsigned long address)
{
	return 0;
}

inline long verify_dma_config(struct dma_config *config)
{
	if(verify_dma_address_range(config->source_address) != 0) {
		return -EPERM;
	}

	if(verify_dma_address_range(config->destination_address) != 0 ) {
		return -EPERM;
	}

	return 0;
}

long do_dma_op(struct dma_op *uop)
{
	long ret;
	struct dma_op op;

	if ( unlikely(copy_from_user(&op, uop, sizeof(struct dma_op)) != 0) ) {
		return -EFAULT;
	}
	
	ret = 0;

	switch( op.cmd ) {
		case DMAOP_REQUEST:
			if( !dmachn_access_permitted(current->domain, op.channel) ){
					return -EPERM;
			}
			break;
		case DMAOP_ENABLE:
		case DMAOP_DISABLE:
		case DMAOP_START:
		case DMAOP_RELEASE:
		case DMAOP_ACK_INT:
		case DMAOP_SET_COUNT:
		case DMAOP_SET_ADDRESS:
		case DMAOP_SET_CONFIG:
			if( !dmachn_access_permitted(current->domain, op.channel) )
				return -EPERM;
			break;
		case DMAOP_GET_STATUS:
		case DMAOP_GET_CONFIG:
			if( !dmachn_access_permitted(current->domain, op.channel) )
					return -EPERM;
			break;
		default:
			break;
	}

	switch ( op.cmd ) {
		case DMAOP_ENABLE:
			arch_enable_dma(op.channel);
 			break;
		case DMAOP_DISABLE:
			arch_disable_dma(op.channel);
        		break;
		case DMAOP_START:
			arch_start_dma(op.channel);
			break;
		case DMAOP_REQUEST:
			arch_request_dma(op.channel);
			break;
		case DMAOP_RELEASE:
			arch_release_dma(op.channel);
			break;
		case DMAOP_ACK_INT:
			arch_ack_dma_int(op.channel);
			break;
		case DMAOP_SET_COUNT:
			arch_set_dma_count(op.channel, op.param.count);
			break;
		case DMAOP_SET_ADDRESS:
			if(verify_dma_address_range(op.param.address) != 0) {
				return -EPERM;
			}

			arch_set_dma_address(op.channel, op.param.address, op.flags);
			break;
		case DMAOP_GET_STATUS:
			arch_get_dma_status(op.channel, &op.status);
			break;
		case DMAOP_SET_CONFIG:
			if(verify_dma_config(&op.config) != 0) {
				return -EPERM;
			}

			arch_set_dma_config(op.channel, &op.config);
			break;
		case DMAOP_GET_CONFIG:
			arch_get_dma_config(op.channel, &op.config);
			break;
		default:
			ret = -EINVAL;
			break;
	}

	if ( copy_to_user(uop, &op, sizeof(struct dma_op)) ) {
		ret = -EFAULT;
	}

	return ret;
}
