#include <xen/config.h>
#include <asm/io.h>
#include <xen/init.h>
#include <xen/types.h>
#include <asm/arch/irqs.h>
#include <asm/irq.h>
#include <asm/hardware.h>

extern struct irqdesc irq_desc[NR_IRQS];
static struct irqchip goldfish_internal_chip;
void set_irq_chip(unsigned int irq, struct irqchip *chip);

int GOLDFISH_READY = 0;

void goldfish_mask_irq(unsigned int irq)
{
    __raw_writel(irq, IO_ADDRESS(GOLDFISH_INTERRUPT_BASE) + GOLDFISH_INTERRUPT_DISABLE);
}

void goldfish_unmask_irq(unsigned int irq)
{
    __raw_writel(irq, IO_ADDRESS(GOLDFISH_INTERRUPT_BASE) + GOLDFISH_INTERRUPT_ENABLE);
}

static struct irqchip goldfish_irq_chip = {
	.trigger_type = "level",
	.ack = goldfish_mask_irq,
	.mask = goldfish_mask_irq,
	.unmask = goldfish_unmask_irq,
};

void goldfish_irq_init(void)
{
    unsigned int i;
    uint32_t int_base = IO_ADDRESS(GOLDFISH_INTERRUPT_BASE);

    /*
     * Disable all interrupt sources
     */
    __raw_writel(1, int_base + GOLDFISH_INTERRUPT_DISABLE_ALL);

    for (i = 0; i < NR_IRQS; i++) {
        set_irq_chip(i, &goldfish_irq_chip);
        set_irq_handler(i, level_irq_handler);
        set_irq_flags(i, IRQF_VALID);
    }
}

