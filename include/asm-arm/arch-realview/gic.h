/*
 *  linux/include/asm-arm/hardware/gic.h
 *
 *  Copyright (C) 2002 ARM Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_ARM_HARDWARE_GIC_H
#define __ASM_ARM_HARDWARE_GIC_H

/* interrupt registes */

/* Interface Registers */
#define GIC_CPU_CTRL			0x00
#define GIC_CPU_PRIMASK			0x04
#define GIC_CPU_BINPOINT		0x08
#define GIC_CPU_INTACK			0x0c
#define GIC_CPU_EOI			    0x10
#define GIC_CPU_RUNNINGPRI		0x14
#define GIC_CPU_HIGHPRI			0x18
/* Distribution Registers */
#define GIC_DIST_CTRL			0x1000+0x000
#define GIC_DIST_CTR			0x1000+0x004
#define GIC_DIST_ENABLE_SET_1		0x1000+0x104
#define GIC_DIST_ENABLE_SET_2		0x1000+0x108
#define GIC_DIST_ENABLE_CLEAR_1		0x1000+0x184
#define GIC_DIST_ENABLE_CLEAR_2		0x1000+0x188
#define GIC_DIST_PENDING_SET_1		0x1000+0x204
#define GIC_DIST_PENDING_SET_2		0x1000+0x208
#define GIC_DIST_PENDING_CLEAR_1		0x1000+0x284
#define GIC_DIST_PENDING_CLEAR_2		0x1000+0x288
#define GIC_DIST_ACTIVE_1		0x1000+0x304
#define GIC_DIST_ACTIVE_2		0x1000+0x308
#define GIC_DIST_PRI			0x1000+0x400
#define GIC_DIST_TARGET			0x1000+0x800
#define GIC_DIST_CONFIG			0x1000+0xc00
#define GIC_DIST_SOFTINT		0x1000+0xf00

#ifndef __ASSEMBLY__
void gic_init(void __iomem *base, unsigned int irq_start, u32 gic_sources);
#endif

#endif
