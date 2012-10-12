#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <public/xen.h>
#include <public/dom0_ops.h>

extern int get_guest_domain_address( dom0_op_t * dom0_op);
extern int create_guest_domain( dom0_op_t * dom0_op );

long arch_do_dom0_op(struct dom0_op *op, GUEST_HANDLE(dom0_op_t) u_dom0_op)
{
    long ret = 0;
		
    switch (op->cmd) {
            case DOM0_GETMEMLIST: 
            {
                    int i;
                    struct domain *d = NULL;
                    unsigned long max_pfns = op->u.getmemlist.max_pfns;
                    unsigned long mfn;
                    struct list_head *list_ent = NULL;

                    d = find_domain_by_id(op->u.getmemlist.domain);

                    ASSERT(d);

                    ret = -EINVAL;

                    if (d != NULL) {
                            ret = 0;

                            spin_lock(&d->page_alloc_lock);
                            list_ent = d->page_list.next;

                            for (i = 0; (i < max_pfns) && (list_ent != &d->page_list); i++) {
                                    mfn = page_to_pfn(list_entry(list_ent, struct page_info, list));

                                    if  (copy_to_guest_offset(op->u.getmemlist.buffer, i, &mfn, 1)) {
                                            ret = -EFAULT;
                                            break;
                                    }

                                    list_ent = pfn_to_page(mfn)->list.next;
                            }

                            spin_unlock(&d->page_alloc_lock);

                            op->u.getmemlist.num_pfns = i;
                            copy_to_guest(u_dom0_op, op, 1);

                            put_domain(d);
                    }
            }
   	    break;

            case DOM0_PHYSINFO:
            {
                    dom0_physinfo_t *pi = NULL;

                    pi = &op->u.physinfo;           

                    ASSERT(pi);

                    pi->threads_per_core = 1;
                    pi->cores_per_socket = 1; // FIXME
                    pi->sockets_per_node = num_online_cpus() / (pi->threads_per_core * pi->cores_per_socket);
                    pi->nr_nodes         = 1;
                    pi->free_pages       = avail_domheap_pages();
                    pi->cpu_khz          = 266000;
                    ret              = 0;

                    memset(pi->hw_cap, 0, sizeof(pi->hw_cap));

                    if ( copy_to_guest(u_dom0_op, op, 1) )
                            ret = -EFAULT;
            }
            break;

            case DOM0_GUEST_IMAGE_CTL:
            {
                    switch(op->u.guest_image_info.sub_cmd) {
                            case CMD_GUEST_COPY:
                            {
                                    get_guest_domain_address(op);

                                    if ( copy_to_guest(u_dom0_op, op, 1) )
                                        ret = -EFAULT;
                            }
                            break;

                            case CMD_GUEST_CREATE:
                            {
                                    create_guest_domain(op);

                                    if ( copy_to_guest(u_dom0_op, op, 1) )
                                        ret = -EFAULT;
                            }
                            break;
                    }

                    ret = 0;
            }
            break;

            default:
                    ret = 0;
                    break;
    }
    return ret;
}


void arch_getdomaininfo_ctxt(struct vcpu *v, vcpu_guest_context_t *c)
{ 
        /* this function haven't been embodied yet. */
	printk("arch_getdomaininfo_ctxt : Not Yet\n");
}


