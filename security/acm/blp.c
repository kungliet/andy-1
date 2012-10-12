/*
 * blp.c 
 *
 * Copyright (C) 2008 Samsung Electronics 
 *          SungMin Lee           <sung.min.lee@samsung.com>
 *          Vladislav Dragalchuk  <v.dragalchuk@samsung.com>
 *          BokDeuk Jeong         <bd.jeong@samsung.com>
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

#include <security/acm/acm.h>
#include <security/acm/policy_conductor.h>
#include <security/acm/decision_cache.h>
#include <security/acm/biba_blp.h>

static biba_blp_policy  *blp_header   = NULL;
static biba_blp_subject *blp_subj_arr = NULL;
static biba_blp_object  *blp_obj_arr  = NULL;

static int blp_set_policy(void *bin, int size)
{
	int i;

        printk("ACM_BLP: blp_set_policy\n");

        /* TODO: For now, we don't distinguish between the sytem-defined policy
                 and the user-defined policy */
	if (blp_header != NULL)
	    xfree(blp_header);

	blp_header = xmalloc_bytes(size);

	ASSERT(blp_header);

	if (blp_header == NULL)
	    return 0;

	memcpy(blp_header, bin, size);	
	
   	blp_subj_arr = (biba_blp_subject *)((char *)blp_header + blp_header->subjects_offset);
	blp_obj_arr  = (biba_blp_object  *)((char *)blp_header + blp_header->objects_offset);	

	printk("ACM_BLP: nr_subjects = %d, nr_objects = %d\n", 

        blp_header->nr_subjects, blp_header->nr_objects);

	printk("ACM_BLP: subject labels: ");
	
	for (i = 0; i < blp_header->nr_subjects; i++)
	    printk("%d/%d-%d ", blp_subj_arr[i].domid, blp_subj_arr[i].sec_label_min, blp_subj_arr[i].sec_label_max);
	
	printk("\n");
	printk("ACM_BLP: object labels: ");

	for (i = 0; i < blp_header->nr_objects; i++)
	    printk("%d/%d ", blp_obj_arr[i].driver_signature, blp_obj_arr[i].sec_label);

	printk("\n");
	
	return 1;
}

static uint16_t blp_calculate_decision(int direction, domid_t subj_id, uint32_t obj_id)
{    
	/* TODO:do some optimizations here (binary search) */
   	uint32_t subj_distrust_level_min, subj_distrust_level_max, obj_distrust_level;
   	int i, subj_is_found = 0, obj_is_found = 0;

   	for (i = 0; i < blp_header->nr_subjects; i++) {

      		if (blp_subj_arr[i].domid == subj_id) {
    	   		subj_distrust_level_min = blp_subj_arr[i].sec_label_min;
    	   		subj_distrust_level_max = blp_subj_arr[i].sec_label_max;
	     		subj_is_found = 1;

	      		break;
		}
	}

   	if (!subj_is_found)
	    return ACM_DECISION_NOTPERMIT;

   	for (i = 0; i < blp_header->nr_objects; i++) {
      		if (blp_obj_arr[i].driver_signature == obj_id) {
    	   		obj_distrust_level = blp_obj_arr[i].sec_label;
	      		obj_is_found = 1;
	      		break;
		}
	}

      if (!obj_is_found)
	      return ACM_DECISION_NOTPERMIT;
	      
      if (direction == BBLP_INF_FLOW_OBJ_TO_SUBJ) {
	      /* NO READ UP */
	      if (subj_distrust_level_max < obj_distrust_level) // object confidentiality protection
			return ACM_DECISION_NOTPERMIT;

      	      return ACM_DECISION_PERMIT;
      }
      else if (direction == BBLP_INF_FLOW_SUBJ_TO_OBJ) { 
	      /* NO WRITE DOWN */
	      if (subj_distrust_level_min > obj_distrust_level) // subject confidentiality protection
	          return ACM_DECISION_NOTPERMIT;

	      return ACM_DECISION_PERMIT;
      }
      else if (direction == BBLP_INF_FLOW_UNKNOWN) { 
	      if (subj_distrust_level_max < obj_distrust_level || subj_distrust_level_min > obj_distrust_level) 
	         return ACM_DECISION_NOTPERMIT;

	      return ACM_DECISION_PERMIT;
      }
	 return ACM_DECISION_NOTPERMIT;
}

static uint16_t blp_get_decision(aci_domain *subj, aci_object *obj, uint32_t req_type, aci_context *context)
{  
      	uint16_t decision = 0;

        if(!blp_header)
     		return ACM_DECISION_UNDEF;

	ASSERT(obj);
 
      	switch(obj->object_type) {
      		case ACM_GRANTTAB:
              		printk("ACM_BLP: ACM_GNTTAB, req_type: 0x%x\n", req_type);
 
           		/* To avoid the case of req_type = GNTTAB_WRITE | GNTTAB_READ,
           	   	   check the GNTTAB_WRITE first */
           		switch(req_type){
        			case GNTTAB_READ:
					ASSERT(subj);

           				decision = blp_calculate_decision(BBLP_INF_FLOW_OBJ_TO_SUBJ, 
                                        	   subj->id, 
           				   	   ((struct aci_gnttab *)obj->object_info)->use);
           				break;
 
           	      		case (GNTTAB_READ | GNTTAB_WRITE):
					ASSERT(subj);

            				decision = blp_calculate_decision(BBLP_INF_FLOW_UNKNOWN, 
                                                   subj->id, 
                                                   ((struct aci_gnttab *)obj->object_info)->use);
           				break;
 
         			case GNTTAB_WRITE:
					ASSERT(subj);

           	        		decision = blp_calculate_decision(BBLP_INF_FLOW_SUBJ_TO_OBJ, 
                                                   subj->id, 
                                                   ((struct aci_gnttab *)obj->object_info)->use);
           				break;
 
         			case GNTTAB_TRANSFER:
            				decision = blp_calculate_decision(BBLP_INF_FLOW_OBJ_TO_SUBJ,
                                                   ((struct aci_gnttab *)obj->object_info)->objdom_id.id,
                                                   ((struct aci_gnttab *)obj->object_info)->use);
           			break;
 
           		default:
           			decision = ACM_DECISION_UNDEF;
           			break;
         		}
 
         		break;	
           		
      		default:
         			return ACM_DECISION_UNDEF;
      }
 
      return decision;
}

static struct acdm_ops blp_ops = {
    .set_policy = blp_set_policy,
    .get_decision = blp_get_decision,
};

int init_blp(void)
{
    printk("ACM_BLP: init_blp\n");

    return register_decision_maker("BLP", BLP_MAGIC_NUMBER, &blp_ops);
}
