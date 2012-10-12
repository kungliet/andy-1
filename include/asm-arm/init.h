#ifndef __ARM_INIT_H__
#define __ARM_INIT_H__

/*
 * Mark functions and data as being only used at initialization
 * or exit time.
 */
#define __init       \
    __attribute__ ((__section__ (".init.text")))
#define __exit       \
    __attribute_used__ __attribute__ ((__section__(".text.exit")))
#define __initdata   \
    __attribute__ ((__section__ (".init.data")))
#define __exitdata   \
    __attribute_used__ __attribute__ ((__section__ (".data.exit")))
#define __initsetup  \
    __attribute_used__ __attribute__ ((__section__ (".init.setup")))
#define __init_call  \
    __attribute_used__ __attribute__ ((__section__ (".initcall1.init")))
#define __exit_call  \
    __attribute_used__ __attribute__ ((__section__ (".exitcall.exit")))

#endif /* _XEN_ASM_INIT_H */
