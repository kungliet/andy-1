include $(BASEDIR)/Rules.mk

obj-y := xensetup.o mm.o irq.o fiq.o arch_domain.o domain_page.o time.o domain_build.o traps.o dom0_ops.o physdev.o cache.o flushtlb.o entry.o hypercalls.o

obj-$(CONFIG_CPU_ARM926T)	+= core-arm926.o
obj-$(CONFIG_CPU_COPYPAGE_V4WB)	+= copypage-v4wb.o
obj-$(CONFIG_CPU_TLB_V4WBI)	+= tlb-v4wbi.o

include $(BASEDIR)/Post.mk
