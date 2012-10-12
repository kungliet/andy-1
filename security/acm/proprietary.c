#include <security/acm/acm.h>
#include <security/acm/policy_conductor.h>
#include <security/acm/decision_cache.h>
#include "proprietary.h"
#include <xen/sched.h>
#include <public/sched_ctl.h>
#include <xen/time.h>

static uint16_t prop_get_decision(aci_domain *subj, aci_object *obj, uint32_t req_type, aci_context *context);
static int prop_set_policy(void *bin, int size);
static void prop_control_cpu_usage(struct domain *d);
static uint16_t prop_control_battery_usage(struct domain *d, int usage);
static void prop_adjust_cpu_weight(struct domain *d, prop_cpu_usage_t *cpu_usage);
static int prop_relocate_policy(void *bin);

/* private data structures */
struct vmlabel_ptrs{
	struct VM_Label *label_ptr;
	uint32_t *vm_to_dom_ptr;
};

static struct acdm_ops prop_ops = {
	.get_decision = prop_get_decision,
	.set_policy = prop_set_policy,
	.relocate_policy = prop_relocate_policy,
	.control_cpu_usage = prop_control_cpu_usage,
	.control_battery_usage = prop_control_battery_usage,
};

static struct vmlabel_ptrs vmlabel_ptr;
static struct prop_policy *prop_meta = NULL;
static void *prop_bin = NULL;
/* the number of domains under battery saving mode */
extern int nr_btsav_dom;
 
int init_proprietary(void)
{
	return register_decision_maker("Proprietary AC", PROP_MAGIC_NUMBER, &prop_ops);
}

static inline struct VM_Label *get_vm_label(unsigned long id)
{
	struct VM_Label *vmlabels, *label = NULL;
	vmlabels = prop_bin + prop_meta->vm_label_offset;
	if(id < prop_meta->nr_prop_domain && vmlabels[id].vmid == id){
		label = &vmlabels[id];
	}else{
		int i;
		for(i=0; i<prop_meta->nr_prop_domain; i++){
			if(vmlabels[i].vmid == id){
				label = &vmlabels[i];
				break;
			}
		}
	}
	return label;
}


static uint16_t prop_get_memory_policy(aci_object *obj, prop_memory_usage_t *mem_policy)
{
	unsigned int mem_value;
	struct aci_memory *mem_info = (struct aci_memory *)obj->object_info;
	mem_value = mem_info->xenheap_pages + mem_info->req_pages;
	if(mem_policy->mode == PERCENTILE){
			mem_value = mem_value*100/mem_info->sys_total; 
	}
	if(mem_value <= mem_policy->max_memory)
		return ACM_NOCACHING_DECISION_PERMIT;
	else
		return ACM_NOCACHING_DECISION_NOTPERMIT;
}

static uint16_t prop_get_evtchn_policy(aci_object *obj, prop_evtchn_usage_t *evtchn_policy) 
{
	uint16_t result = ACM_NOCACHING_DECISION_PERMIT;
	struct aci_evtchn *evtchn_info = (struct aci_evtchn *)obj->object_info;
	if(evtchn_policy->max_per_dom > 0){
		if(evtchn_info->per_rdom+1 > evtchn_policy->max_per_dom)
			result = ACM_NOCACHING_DECISION_NOTPERMIT;
		else if(evtchn_policy->max_per_dom_use > 0){
			if(evtchn_info->per_rdom_use+1 > evtchn_policy->max_per_dom_use)
				result = ACM_NOCACHING_DECISION_NOTPERMIT;
		}
	}
	return result;
}

static uint16_t prop_get_decision(aci_domain *subj, 
											aci_object *obj, 
											uint32_t req_type, 
											aci_context *context)
{
	uint16_t result;
	struct VM_Label *vm_label = NULL;
	struct prop_domain *dom_policy;
	uint32_t *domain_type_index;

	if(!prop_bin)
		return ACM_DECISION_UNDEF;

	vm_label = get_vm_label(subj->id);
	if(!vm_label)
		return ACM_DECISION_PERMIT;

	domain_type_index = (uint32_t *)(prop_bin + vm_label->domains_offset);
	dom_policy = (struct prop_domain *)(prop_bin + prop_meta->prop_policy_offset);
	dom_policy = dom_policy + *domain_type_index;

	switch(obj->object_type){
		case ACM_MEMORY:
			if(req_type == MEM_ALLOC_DOMHEAP)
				result = prop_get_memory_policy(obj, &(dom_policy->memory_usage));
			else goto PROP_MISC;
			break;
		case ACM_EVENTCHN:
			if(req_type != EVTCHN_OPEN)
				goto PROP_MISC;
			result = prop_get_evtchn_policy(obj, &(dom_policy->evtchn_usage));
			break;
			
PROP_MISC:			
		default:
			result = ACM_CACHING_DECISION_UNDEF;
			break;
	}

	return result;
}

static void prop_adjust_dom_sched(void)
{
	struct VM_Label *vm_label;
	struct domain *d;
	struct prop_domain *dom_policy;
	uint32_t *domain_type_index;
	int schedid = sched_id();
	struct sched_adjdom_cmd adjdom_cmd, sched_state;
	prop_cpu_usage_t *cpu_usage;

	sched_state.sched_id = schedid;
	sched_state.direction = SCHED_INFO_GET;
	adjdom_cmd.sched_id = schedid;
	adjdom_cmd.direction = SCHED_INFO_PUT;

	read_lock(&domlist_lock);
	for_each_domain(d){
		vm_label = get_vm_label(d->scid);

		if(!vm_label)
			continue;

		domain_type_index = (uint32_t *)(prop_bin + vm_label->domains_offset);
		dom_policy = (struct prop_domain *)(prop_bin + prop_meta->prop_policy_offset);
		dom_policy = dom_policy + *domain_type_index;
		cpu_usage = &(dom_policy->cpu_usage);

		sched_state.domain = d->domain_id;
		adjdom_cmd.domain = d->domain_id;
		if(sched_adjdom(&sched_state) < 0)
			continue;
		switch(schedid){
			case SCHED_BVT:
				if(cpu_usage->interval == 0)
					adjdom_cmd.u.bvt.mcu_adv = 200/cpu_usage->max_usage;
					//adjdom_cmd.u.bvt.mcu_adv = 1000/cpu_usage->max_usage;
				else
					adjdom_cmd.u.bvt.mcu_adv = 200*(cpu_usage->interval/cpu_usage->max_usage);
				printk("ACM: adjusting %d's mcu_adv to %d from %d\n", 
						d->scid, adjdom_cmd.u.bvt.mcu_adv, sched_state.u.bvt.mcu_adv);
				adjdom_cmd.u.bvt.warpback = sched_state.u.bvt.warpback;
				adjdom_cmd.u.bvt.warpvalue = sched_state.u.bvt.warpvalue;
				adjdom_cmd.u.bvt.warpl = sched_state.u.bvt.warpl/MILLISECS(1);
				adjdom_cmd.u.bvt.warpu = sched_state.u.bvt.warpu/MILLISECS(1);
				break;
			case SCHED_SEDF:
				if(cpu_usage->interval == 0){
					adjdom_cmd.u.sedf.weight = cpu_usage->max_usage;
					adjdom_cmd.u.sedf.period = 0;
					adjdom_cmd.u.sedf.slice = 0;
				}else{
					adjdom_cmd.u.sedf.period = cpu_usage->interval;
					adjdom_cmd.u.sedf.slice = cpu_usage->max_usage;
					adjdom_cmd.u.sedf.weight = 0;
				}
				adjdom_cmd.u.sedf.latency = sched_state.u.sedf.latency;
				adjdom_cmd.u.sedf.extratime = sched_state.u.sedf.extratime;
				break;
			default:
				goto UNLOCK_DOMLIST;
				break;
		}		
		sched_adjdom(&adjdom_cmd);
	}
UNLOCK_DOMLIST:	
	read_unlock(&domlist_lock);
}

/*flush previous policy */
void init_battery_threshold(void)
{
	struct domain *d;
	if(!prop_bin || !prop_meta)
		return;
	read_lock(&domlist_lock);
	for_each_domain(d){
		d->acm_battery_save_mode = 0;
		d->acm_shutdown = 0;
	}
	read_unlock(&domlist_lock);
	nr_btsav_dom = 0;
}

static int prop_set_policy(void *bin, int size)
{
	/*
	 * TODO: For now, we don't distinguish between the sytem-defined policy
	 * and the user-defined policy.
	 */
	prop_bin = bin;
	prop_meta = prop_bin;
	vmlabel_ptr.label_ptr = (void *)prop_meta + prop_meta->vm_label_offset;
	vmlabel_ptr.vm_to_dom_ptr = (void *)prop_meta + prop_meta->nr_vm_label*sizeof(struct VM_Label);
	// for ACM_CPUTIME
	prop_adjust_dom_sched();
	init_battery_threshold();

	printk("ACM: set proprietary policy \n");

	return 1;
}

static int prop_relocate_policy(void *bin)
{
	prop_bin = bin;
	prop_meta = prop_bin;
	vmlabel_ptr.label_ptr = (void *)prop_meta + prop_meta->vm_label_offset;
	vmlabel_ptr.vm_to_dom_ptr = (void *)prop_meta + prop_meta->nr_vm_label*sizeof(struct VM_Label);
	return 1;
}



static void prop_control_cpu_usage(struct domain *d)
{
	struct VM_Label *vm_label;
	struct prop_domain *dom_policy;
	uint32_t *domain_type_index;
	prop_cpu_usage_t *cpu_usage;

	if(prop_bin == NULL)
		return;

	vm_label = get_vm_label(d->scid);
	if(!vm_label)
		return;

	domain_type_index = (uint32_t *)(prop_bin + vm_label->domains_offset);
	dom_policy = (struct prop_domain *)(prop_bin + prop_meta->prop_policy_offset);
	dom_policy = dom_policy + *domain_type_index;
	cpu_usage = &(dom_policy->cpu_usage);

	prop_adjust_cpu_weight(d, cpu_usage);
}

/* TODO: to normalize 'mcu_adv's, we have to weights of all domains in advance! */
/*
static int normalize_mcu_adv(float mcu_adv)
{
	return (int)2*mcu_adv;
}
*/

static uint16_t prop_control_battery_usage(struct domain *d, int usage)
{
	struct VM_Label *vm_label;
	uint32_t *domain_type_index;
	struct prop_domain *dom_policy;
	prop_battery_usage_t *battery_usage;
	unsigned int result = 0;
	if(!prop_bin || !d)
		return 0;

	vm_label = get_vm_label(d->scid);
	if(!vm_label)
		return 0;
	domain_type_index = (uint32_t *)(prop_bin + vm_label->domains_offset);
	dom_policy = (struct prop_domain *)(prop_bin + prop_meta->prop_policy_offset);
	dom_policy = dom_policy + *domain_type_index;
	battery_usage = &(dom_policy->battery_usage);

	if(battery_usage->reschedule_threshold >= usage){
		if(d->acm_battery_save_mode==0){
			
			printk("ACM: %u is SET to battery save mode. usage=%u\n", d->domain_id, usage);

			// adjust domain's weight
			d->acm_battery_save_mode = 1;
			if(battery_usage->mode == CPU_TIME)
				prop_adjust_cpu_weight(d, &(battery_usage->u.cpu));
			result |= ACM_DECISION_RESCHEDULE;
			nr_btsav_dom++;
			
			printk("ACM: nr_btsav_dom:%u\n", nr_btsav_dom);

		}
	}else if(d->acm_battery_save_mode==1){

		printk("ACM: %u is RELEASED from battery save mode. usage=%u\n", d->domain_id, usage);

		// If CPU weight is defined, go back to CPU weight value,
		// else back to fair scheduling.
		d->acm_battery_save_mode = 0;
		prop_adjust_cpu_weight(d, &(dom_policy->cpu_usage));
		nr_btsav_dom--;

		printk("ACM: nr_btsav_dom:%u\n", nr_btsav_dom);

	}
	if(battery_usage->shutdown_threshold >= usage)
		result |= ACM_DECISION_SHUTDOWN;
	else
		d->acm_shutdown = 0;
	return result;
}

static void prop_adjust_cpu_weight(struct domain *d, prop_cpu_usage_t *cpu_usage)
{
	int schedid = sched_id();
	struct sched_adjdom_cmd adjdom_cmd, sched_state;

	sched_state.sched_id = schedid;
	sched_state.direction = SCHED_INFO_GET;
	adjdom_cmd.sched_id = schedid;
	adjdom_cmd.direction = SCHED_INFO_PUT;

	sched_state.domain = d->domain_id;
	adjdom_cmd.domain = d->domain_id;
	if(sched_adjdom(&sched_state) < 0)
		return;

	if(schedid == SCHED_BVT){
		if(cpu_usage==NULL || cpu_usage->max_usage==0)
			adjdom_cmd.u.bvt.mcu_adv = 10;
		else{
			if(cpu_usage->interval == 0)
				adjdom_cmd.u.bvt.mcu_adv = 200/cpu_usage->max_usage;
				//adjdom_cmd.u.bvt.mcu_adv = 1000/cpu_usage->max_usage;
			else
				adjdom_cmd.u.bvt.mcu_adv = 200*(cpu_usage->interval/cpu_usage->max_usage);
		}
		printk("ACM:adjust_cpu_weight: adjusting %d's mcu_adv to %d from %d\n", 
				d->scid, adjdom_cmd.u.bvt.mcu_adv, sched_state.u.bvt.mcu_adv);
		//printf("ACM: \t mcu_adv: %u\n", adjdom_cmd.u.bvt.mcu_adv);

		adjdom_cmd.u.bvt.warpback = sched_state.u.bvt.warpback;
		adjdom_cmd.u.bvt.warpvalue = sched_state.u.bvt.warpvalue;
		adjdom_cmd.u.bvt.warpl = sched_state.u.bvt.warpl/MILLISECS(1);
		adjdom_cmd.u.bvt.warpu = sched_state.u.bvt.warpu/MILLISECS(1);
		//adjdom_cmd.u.bvt.warpl = sched_state.u.bvt.warpl;
		//adjdom_cmd.u.bvt.warpu = sched_state.u.bvt.warpu;
	}else if(schedid == SCHED_SEDF){
		if(cpu_usage==NULL || (cpu_usage->max_usage==0 && cpu_usage->interval==0)){
			adjdom_cmd.u.sedf.weight = 0;
			adjdom_cmd.u.sedf.period = 0;
			adjdom_cmd.u.sedf.slice = 0;
		}else{
			if(cpu_usage->interval == 0){
				adjdom_cmd.u.sedf.weight = cpu_usage->max_usage;
				adjdom_cmd.u.sedf.period = 0;
				adjdom_cmd.u.sedf.slice = 0;
			}else{
				adjdom_cmd.u.sedf.period = cpu_usage->interval;
				adjdom_cmd.u.sedf.slice = cpu_usage->max_usage;
				adjdom_cmd.u.sedf.weight = 0;
			}
		}
		adjdom_cmd.u.sedf.latency = sched_state.u.sedf.latency;
		if(d->acm_battery_save_mode)
			adjdom_cmd.u.sedf.extratime = 0;
		else
			adjdom_cmd.u.sedf.extratime = 1;
	}

	sched_adjdom(&adjdom_cmd);
}


