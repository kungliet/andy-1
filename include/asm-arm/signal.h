#ifndef _ASMARM_SIGNAL_H
#define _ASMARM_SIGNAL_H

#if 0
#include <xen/types.h>

#define SA_NOCLDSTOP    0x00000001
#define SA_NOCLDWAIT    0x00000002
#define SA_SIGINFO      0x00000004
#define SA_THIRTYTWO    0x02000000
#define SA_RESTORER     0x04000000
#define SA_ONSTACK      0x08000000
#define SA_RESTART      0x10000000
#define SA_NODEFER      0x40000000
#define SA_RESETHAND    0x80000000

#define SA_NOMASK       SA_NODEFER
#define SA_ONESHOT      SA_RESETHAND
#define SA_INTERRUPT    0x20000000 /* dummy -- ignored */


#define SA_PROBE                0x80000000
#define SA_SAMPLE_RANDOM        0x10000000
#define SA_IRQNOMASK            0x08000000
#define SA_SHIRQ                0x04000000

#define SA_TIMER        0x40000000
#endif
#endif
