#ifndef __ASM_ARM_PROCESSOR_H__
#define __ASM_ARM_PROCESSOR_H__

#include <public/arch-arm.h>

#define barrier() __asm__ __volatile__("": : :"memory")

#ifndef __ASSEMBLY__
void write_ptbase(struct vcpu *);
void save_ptbase(struct vcpu *);
void show_registers(struct cpu_user_regs *regs);
#endif

#define cpu_relax()			barrier()

#endif /* __ASM_ARM_PROCESSOR_H */
