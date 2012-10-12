
/*
 * biba.c
 *
 * SRC OSV, 2007, Samsung Electronics Co., Ltd.
 */

#include <acm/acm.h>
#include <acm/policy_conductor.h>
#include <acm/decision_cache.h>

#include "biba_blp.h"

static char *decision_str[4] = {"UNKNOWN", "PERMIT", "UNDEFINED", "NOT PERMIT"};

static biba_blp_policy  *biba_header = NULL;
static biba_blp_subject *biba_subj_arr = NULL;
static biba_blp_object  *biba_obj_arr = NULL;

static int biba_set_policy(void *bin, int size)
{
	int i;
        printk("ACM_Biba: biba_set_policy\n");
        // TODO: For now, we don't distinguish between the sytem-defined policy
        // and the user-defined policy

	if (biba_header != NULL)
	    xfree(biba_header);
	biba_header = xmalloc_bytes(size);
	if (biba_header == NULL)
	    return 0;
	memcpy(biba_header, bin, size);	

        biba_subj_arr = (biba_blp_subject *)((char *)biba_header + biba_header->subjects_offset);
        biba_obj_arr  = (biba_blp_object  *)((char *)biba_header + biba_header->objects_offset);	
        printk("ACM_Biba: nr_subjects = %d, nr_objects = %d\n", 
    		biba_header->nr_subjects, biba_header->nr_objects);
	printk("ACM_Biba: subject labels: ");
	for (i = 0; i < biba_header->nr_subjects; i++)
	    printk("%d/%d-%d ",  biba_subj_arr[i].domid, biba_subj_arr[i].sec_label_min, biba_subj_arr[i].sec_label_max);
	printk("\n");
	printk("ACM_Biba: object labels: ");
	for (i = 0; i < biba_header->nr_objects; i++)
	    printk("%d/%d ", biba_obj_arr[i].driver_signature, biba_obj_arr[i].sec_label);
	printk("\n");
	/*
         * TODO:-------------- Policy Revocation ------------------------------
	 */
	return 1;
}

static uint16_t biba_calculate_decision(int direction, domid_t subj_id, uint32_t obj_id)
{    // to do some optimizations here (binary search)
    uint32_t subj_distrust_level_min, subj_distrust_level_max, obj_distrust_level;
    int i, subj_is_found = 0, obj_is_found = 0;
    for (i = 0; i < biba_header->nr_subjects; i++) {
        if (biba_subj_arr[i].domid == subj_id) {
    	    subj_distrust_level_min = biba_subj_arr[i].sec_label_min;
    	    subj_distrust_level_max = biba_subj_arr[i].sec_label_max;
	    subj_is_found = 1;
	    break;
	}
    }	
    if (!subj_is_found)
	//return ACM_DECISION_NOTPERMIT;
	return ACM_DECISION_UNDEF;
    for (i = 0; i < biba_header->nr_objects; i++) {
        if (biba_obj_arr[i].driver_signature == obj_id) {
    	    obj_distrust_level = biba_obj_arr[i].sec_label;
	    obj_is_found = 1;
	    break;
	}
    }	
    if (!obj_is_found)
	//return ACM_DECISION_NOTPERMIT;
	return ACM_DECISION_UNDEF;
    if (direction == BBLP_INF_FLOW_OBJ_TO_SUBJ) { 
	if (subj_distrust_level_min < obj_distrust_level) // subject integrity protection
	    return ACM_DECISION_NOTPERMIT;
        return ACM_DECISION_PERMIT;
    }
    else if (direction == BBLP_INF_FLOW_SUBJ_TO_OBJ) { 
	/* We don't need this for the time present
	if (subj_distrust_level_max > obj_distrust_level) // object integrity protection
	    return ACM_DECISION_NOTPERMIT;
	*/    
	return ACM_DECISION_PERMIT;
    }
    else if (direction == BBLP_INF_FLOW_UNKNOWN) { 
	if (subj_distrust_level_min < obj_distrust_level) // subject integrity protection
	    return ACM_DECISION_NOTPERMIT;
	/* We don't need this for the time present	    
	if (subj_distrust_level_max > obj_distrust_level) // object integrity protection
	    return ACM_DECISION_NOTPERMIT;
	*/	    
	return ACM_DECISION_PERMIT;
    }
    return ACM_DECISION_UNDEF;    		
}

static uint16_t biba_get_decision(aci_domain *subj, aci_object *obj, uint32_t req_type, aci_context *context)
{
    uint16_t decision;
    if(!biba_header)
	return ACM_DECISION_UNDEF;

    switch(obj->object_type) {
		 
	case ACM_GRANTTAB:
	    printk("ACM_Biba: ACM_GNTTAB, req_type: 0x%x\n", req_type);
//	    if (req_type & ...) {
    		//gnttab.owner_type = VM_LABEL;
		//@gnttab.owner_index = ((struct aci_gnttab *)obj->object_info)->objdom_id.id;
		//@gnttab.use = ((struct aci_gnttab *)obj->object_info)->use;
		//@gnttab.mem_space = ((struct aci_gnttab *)obj->object_info)->mem_space;
		decision = biba_calculate_decision(BBLP_INF_FLOW_UNKNOWN, subj->id, ((struct aci_gnttab *)obj->object_info)->use);
		printk("ACM_Biba: ACM_GNTTAB, req_type: 0x%x, domid: %d, use: %d, decision: %s\n", 
			req_type, subj->id, ((struct aci_gnttab *)obj->object_info)->use, 
			decision_str[decision & ACMCACHE_DECISION_RMASK]);
		return decision;
//	    }
//	    else
//		return ACM_DECISION_UNDEF;
    	    break;	
			
	default:
	    return ACM_DECISION_UNDEF;
	}
}

static struct acdm_ops biba_ops = {
    .set_policy = biba_set_policy,
    .get_decision = biba_get_decision,
};

int init_biba(void)
{
    printk("ACM_Biba: init_biba\n");
    return register_decision_maker("Biba", BIBA_MAGIC_NUMBER, &biba_ops);
}
