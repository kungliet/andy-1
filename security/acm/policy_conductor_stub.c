#include <xen/errno.h>
#include <acm/acm.h>
#include <acm/policy_conductor.h>
#include <acm/decision_cache.h>
#include <xen/string.h>
#include <xen/guest_access.h>
#include <public/acm_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <public/xen.h>

int ac_model_count = 0;
struct ac_model ac_models[ACM_MODEL_MAX];

struct vcpu *drvdom_vcpu = NULL;
int init_acm(void)
{
	return 1;
}

long do_acm_op(GUEST_HANDLE(acm_op_t) u_acm_op)
{
	return 0;
}

int register_decision_maker(char *model_name, uint32_t magic_num, struct acdm_ops *ops)
{
	return 0;
}

