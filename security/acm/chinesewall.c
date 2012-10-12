
/*
 * chinesewall.c
 *
 * SRC OSV, 2007, Samsung Electronics Co., Ltd.
 */

#include <security/acm/acm.h>
#include <security/acm/policy_conductor.h>
#include <security/acm/decision_cache.h>
#include <xen/sched.h>

#include "chinesewall.h"

static struct cw_policy *cw_cw_header= NULL;
static uint32_t *cw_mapping = NULL;
static uint32_t *cw_matrix = NULL;
static void *cw_bin = NULL;

static int cw_set_policy(void *bin, int size)
{
	int i = 0, j = 0;

        printk("ACM_CW: cw_set_policy\n");
        // TODO: For now, we don't distinguish between the sytem-defined policy
        // and the user-defined policy
        if ( cw_bin != NULL )
    		xfree(cw_bin);
	cw_bin = xmalloc_bytes(size);
        if ( cw_bin == NULL )
	    return 0;
	memcpy(cw_bin, bin, size);
        cw_cw_header = cw_bin;
        cw_mapping = (void *)cw_cw_header + sizeof(struct cw_policy);
        cw_matrix = cw_mapping + cw_cw_header->nr_cw_domain;
        printk("ACM_CW: nr_domain = %d, matrix size = %d\n", 
    		cw_cw_header->nr_cw_domain, cw_cw_header->domain_res_policy.matrix_size);
	printk("ACM_CW: ");
	for (i = 0; i < cw_cw_header->nr_cw_domain; i++)
		printk("mapping[%d] = %d\t ", i, cw_mapping[i]);
	printk("\n");
	for (i = 0; i < cw_cw_header->nr_cw_domain; i++) {
		printk("ACM_CW: ");
		for (j = 0; j < cw_cw_header->nr_cw_domain; j++) {
			printk("matrix[%d][%d] = %d\t ", i, j, cw_matrix[i*cw_cw_header->nr_cw_domain+j]);
		}
		printk("\n");
	}
	/*
         * TODO:-------------- Policy Revocation ------------------------------
	 */
	return 1;
}

static uint16_t cw_get_decision(aci_domain *subj, aci_object *obj, uint32_t req_type, aci_context *context)
{
	int32_t subject = 0, object = 0;
	int32_t internal_object = -1;
	int i = 0;
	struct domain *d = NULL;

	//printk("ACM_CW: cw_get_decision\n");
	if ( !cw_cw_header || !subj || !obj ) {
		// no policy or policy corrupted
		return ACM_DECISION_UNDEF;
	}
	switch (obj->object_type) {
		case ACM_DOMAIN:
		{
			object = ((aci_domain *)obj->object_info)->id;
			for (i = 0; i < cw_cw_header->nr_cw_domain; i++) {
				if ( object == cw_mapping[i] ) {
					internal_object = i;
					break;
				}
			}
			if ( internal_object != -1 ) {
				printk("ACM_CW: object id=%d (internal id=%d)\n", object, internal_object);
				for (i = 0; i < cw_cw_header->nr_cw_domain; i++) {
					// search in matrix by column since its may be faster than by row
					if ( cw_matrix[internal_object*cw_cw_header->nr_cw_domain + i] != 0 ) {
						subject = cw_mapping[i];
						if ( (d = find_domain_by_id(subject)) != NULL ) {
							printk("ACM_CW: Found first conflict - requested domain %d <-> already running domain %d\n", 
									object, subject);
							printk("ACM_CW: decision - ACM_DECISION_NOTPERMIT\n");
							return ACM_DECISION_NOTPERMIT;
						}
					}
				}
				printk("ACM_CW: decision - ACM_DECISION_PERMIT\n");
				return ACM_DECISION_PERMIT;
			}
			else {
				printk("ACM_CW: error - domain number not found in internal mapping\n");
				return ACM_DECISION_NOTPERMIT;
			}
		}
		default:
			// allow since it isn't domain operations
			return ACM_DECISION_PERMIT;
	}
}

/* private variables */
static struct acdm_ops cw_ops = {
    .set_policy = cw_set_policy,
    .get_decision = cw_get_decision,
};

int init_cw(void)
{
    printk("ACM_CW: init_cw\n");
    return register_decision_maker("Chinese Wall", CW_MAGIC_NUMBER, &cw_ops);
}
