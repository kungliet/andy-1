/*
 * Bokdeuk:
 *
 * acm_hooks.c implements acm hooks.
 * Each hook constitutes request information and asks ACI integrator of access control decision.
 * It returns 1 as grant or 0 as denial.
*/
#include <acm/acm.h>
#include <acm/acm_hooks.h>
#include <acm/aci_generator.h>
#include <asm/current.h>
#include <asm/page.h>
//#include <public/xen.h>


inline int acm_domain_simple_op(struct domain *dom, uint32_t obj_type, uint32_t req_type)
{
	return 1;
}	

int acm_pause_domain(struct domain *dom)
{
	return acm_domain_simple_op(dom, ACM_DOMAIN, DOM_PAUSE);
}

int acm_unpause_domain(struct domain *dom)
{
	return acm_domain_simple_op(dom, ACM_DOMAIN, DOM_UNPAUSE);
}

int acm_create_domain(struct domain *dom)
{
	return acm_domain_simple_op(dom, ACM_DOMAIN, DOM_CREATE);
}

int acm_copy_domain_image(struct domain *dom)
{
	return acm_domain_simple_op(dom, ACM_DOMAIN, DOM_COPY_IMAGE);
}

int acm_destroy_domain(struct domain *dom)
{
	if(dom == current->domain->domain_id || dom == DOMID_SELF)
		return ACM_DECISION_PERMIT;

	return acm_domain_simple_op(dom, ACM_DOMAIN, DOM_DESTROY);
}

int acm_remote_shutdown(struct domain *dom)
{
	return acm_domain_simple_op(dom, ACM_DOMAIN, DOM_SHUTDOWN);
}

int acm_get_domaininfo(struct domain *dom)
{
	if(dom == current->domain->domain_id || dom == DOMID_SELF)
		return ACM_DECISION_PERMIT;
	return acm_domain_simple_op(dom, ACM_DOMAIN, DOM_GET_INFO);
}

inline int acm_domain_control_op(struct domain *dom, uint32_t obj_type, uint32_t req_type)
{
#ifdef __USE_IS_PRIV
	return 1;
#else
	return acm_domain_simple_op(dom, obj_type, req_type);
#endif
}

int acm_sched_ctl(void)
{
	return 1;
}

int acm_adjust_dom(void)
{
	return 1;
}

int acm_sched_get_id(void)
{
	return 1;
}


int acm_vcpu_common_op(struct domain *dom, struct vcpu* v, uint32_t req_type)
{
	return 1;
}

int acm_set_vcpucontext(struct domain *dom, struct vcpu *v)
{
	return acm_vcpu_common_op(dom, v, VCPU_SET_CONTEXT);
}

int acm_get_vcpucontext(struct domain *dom, struct vcpu *v)
{
	return acm_vcpu_common_op(dom, v, VCPU_GET_CONTEXT);
}

int acm_get_vcpuinfo(struct domain *dom, struct vcpu *v)
{
	return acm_vcpu_common_op(dom, v, VCPU_GET_INFO);
}

int acm_set_maxvcpus(struct domain *dom)
{
	return acm_vcpu_common_op(dom, NULL, VCPU_SET_MAX);
}

int acm_set_vcpuaffinity(struct domain *dom, struct vcpu *v)
{
	return acm_vcpu_common_op(dom, v, VCPU_SET_AFFINITY);
}

int acm_set_domainmaxmem(struct domain *dom)
{
	if(dom == DOMID_SELF)
		dom = current->domain->domain_id;
	if(current->domain->domain_id != dom){
		if(!acm_domain_control_op(dom, ACM_MEMORY, MEM_CONTROL))
			return 0;
	}
	return 1;
}

int acm_set_domainhandle(struct domain *dom)
{
	return 1;
}

int acm_set_debugging(struct domain *dom)
{
	return acm_domain_simple_op(dom, ACM_DEBUG, DEBUG_SET);
}

int acm_irq_permission(struct domain *dom, uint8_t pirq, int nr_pirq)
{
	return 1;
}

int acm_irq_permit_access(struct domain *dom, unsigned int start_pirq, unsigned int end_pirq)
{
	return 0;
}

int acm_send_guest_pirq(struct domain *dom, uint8_t pirq)
{
	return 1;
}

int acm_irq_status_query(uint32_t pirq)
{
	return 1;
}


int acm_iomem_permission(struct domain *dom, unsigned long first_mfn, unsigned long nr_mfns, uint8_t allow_access)
{
	return 1;
}


int acm_iomem_permit_access(struct domain *dom, unsigned long first_mfn, unsigned long end_mfn)
{
	return 0;
}

int acm_dma_request_permission(void)
{
	return 1;
}

int acm_dma_monitor_permission(unsigned long channel)
{
	return 1;
}

inline int acm_resource_simple_op(uint32_t obj_type, uint32_t req_type) 
{
	return 1;
}


int acm_settime(void)
{
	return acm_resource_simple_op(ACM_TIME, TIME_SET);
}

/* TODO: DOM0_READCONSOLE is currently not implemented in do_dom0_op()! */
int acm_readconsole(uint32_t clear)
{
	return 1;
}

int acm_tbuf_control(void)
{
	return acm_resource_simple_op(ACM_TRACEBUFFER, TRACE_CONTROL);
}

int acm_sched_id(void)
{
	return acm_resource_simple_op(ACM_SCHEDULER, SCHED_GET_ID);
}

int acm_perfc_control(void)
{
	return acm_resource_simple_op(ACM_PERFCOUNTER, PERFC_CONTROL);
}


int acm_evtchn_alloc_unbound(struct domain *dom, domid_t rdomid, evtchn_port_t port, uint32_t use)
{
	return 1;
}

int acm_evtchn_bind_interdomain(struct domain *dom, struct domain *rdom, evtchn_port_t port, uint32_t use)
{
	return 1;
}

int acm_evtchn_send(struct domain *dom, struct domain *rdom, evtchn_port_t port, uint32_t use)
{
	return 1;
}
/* don't think we need access control to this
int acm_evtchn_bindvirq(uint32_t virq, uint32_t vcpu)
{
	return 1;
}
*/
// AS LONG AS irq_access_permitted is used correctly, we don't need access control to below func.
int acm_evtchn_bindpirq(uint32_t pirq)
{
	return 1;
}

/* don't think we need access control to this
int acm_evtchn_bindvcpu(uint32_t vcpu, evtchn_port_t port)
{
	return 1;
}
*/
int acm_evtchn_status(struct domain *dom, evtchn_port_t port, uint32_t use)
{
	return 1;
}

int acm_evtchn_bindvirq(uint32_t virq, uint32_t vcpu)
{
	return 1;
}
int acm_evtchn_virq_status(struct domain *dom, evtchn_port_t port, uint32_t virq)
{
	return 1;
}
int acm_granttable_op(struct domain *subjdom, struct domain *objdom, uint32_t mfn, uint32_t use, uint32_t req_type)
{
	return 1;
}

int acm_granttable_share(struct domain *subjdom, struct domain *objdom, uint32_t mfn, uint32_t use, uint32_t flags)
{
	return acm_granttable_op(subjdom, objdom, mfn, use, GNTTAB_READ || GNTTAB_WRITE);
}

int acm_granttable_transfer(struct domain *subjdom, struct domain *objdom, uint32_t mfn, uint32_t use)
{
	return acm_granttable_op(subjdom, objdom, mfn, use, GNTTAB_TRANSFER);
}

int acm_granttable_setup(struct domain *dom)
{
	if(dom == current->domain->domain_id || dom == DOMID_SELF)
		return ACM_DECISION_PERMIT;
	return acm_domain_control_op(dom, ACM_GRANTTAB, GNTTAB_SETUP);
	//return acm_granttable_op(current->domain->domain_id, dom, 0, 0, GNTTAB_SETUP);
}

int acm_granttable_dumptab(struct domain *dom)
{
	if(dom == current->domain->domain_id || dom == DOMID_SELF)
		return ACM_DECISION_PERMIT;
	return acm_domain_simple_op(dom, ACM_GRANTTAB, GNTTAB_DUMP_TABLE);
	//return acm_granttable_op(current->domain->domain_id, dom, 0, 0, GNTTAB_DUMP_TABLE);
}


/* Controls privileges to reserving memory space for other domains
   do_memory_op is the only way to increase or decrease memory space allocated to a domain
   after dom creation.
   Domain's tot_pages = xenheap_pages +(-) # of transferred page via grant_table
*/
inline int acm_alloc_domheap(struct domain *dom, unsigned int pages, uint32_t req_type)
{

	return 1;
}


int acm_increase_reservation(struct domain *dom, unsigned int extent_order)
{
	return 1;
}

int acm_decrease_reservation(struct domain *dom)
{
	return acm_domain_simple_op(dom, ACM_MEMORY, MEM_DECREASE);
}

int acm_populate_physmap(struct domain *dom, unsigned int extent_order)
{
	return 1;
}

int acm_current_reservation(struct domain *dom)
{
	return acm_domain_simple_op(dom, ACM_MEMORY, MEM_GET_STAT);
}

int acm_translate_gpfn_list(struct domain *dom)
{
	return acm_domain_simple_op(dom, ACM_MEMORY, MEM_TRANSLATE_ADDR);
}

// controls how much memory space a domain can take.
int acm_alloc_chunk(struct domain *dom, unsigned int order)
{
	return 1;
}

int acm_set_guest_pages(struct domain *dom, unsigned int size)
{
	return 1;
}

/*refer public/xen.h */
int acm_modify_pte(pte_t nl1e)
{
	return 1;
}



int acm_modify_pde(pde_t nl2e)
{
	return 1;
}


int acm_mmu_update(unsigned long mfn)
{
	return 1;
}

int acm_mod_default_entry(unsigned long paddr)
{
	return 1;
}

int acm_mmuext_op(void)
{
	return 1;
/*
	int result;

	if(acm_belong_to_iomem(mfn))
		result = acm_iomem_permission(current->domain->domain_id, mfn, 1, 0);
	else
		result = 1;
	return result;
*/
}

/*
int acm_evtchn_bindvirq(uint32_t virq, uint32_t vcpu)
{
}
*/
int acm_update_va_mapping(struct domain *dom)
{
	return 1;
}

int acm_access_policy(int flag)
{
	return 1;
}


int acm_console_io(int cmd)
{
	return 1;
}

int acm_set_HID_irq(unsigned int irq)
{
	return 1;
}

void acm_update_domain_state(struct domain *domid)
{
//	prepare_evtchn_stat(domid);

}

void acm_weight_dom_cpu(struct domain *d)
{
	return;
}

int acm_check_battery_saving(struct domain *d)
{
	return 0;
}

