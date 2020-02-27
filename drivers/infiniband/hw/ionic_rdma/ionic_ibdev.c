// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/mman.h>
#include <net/addrconf.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_user_verbs.h>

#include "ionic_fw.h"
#include "ionic_ibdev.h"

MODULE_AUTHOR("Pensando Systems, Inc");
MODULE_DESCRIPTION("Pensando RoCE HCA driver");
MODULE_LICENSE("Dual BSD/GPL");

#define DRIVER_DESCRIPTION "Pensando RoCE HCA driver"
#define DEVICE_DESCRIPTION "Pensando RoCE HCA"

/* work queue for handling network events, managing ib devices */
static struct workqueue_struct *ionic_dev_workq;

/* access single-threaded thru ionic_dev_workq */
static LIST_HEAD(ionic_ibdev_list);

static int ionic_qid_skip = 512;
static void ionic_resid_skip(struct ionic_resid_bits *bits)
{
	int i = ionic_qid_skip - 1;

	while (i < bits->inuse_size) {
		set_bit(i, bits->inuse);
		i += ionic_qid_skip;
	}
}

static int ionic_query_device(struct ib_device *ibdev,
			      struct ib_device_attr *attr,
			      struct ib_udata *udata)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);

	addrconf_ifid_eui48((u8 *)&attr->sys_image_guid, dev->ndev);
	attr->max_mr_size =
		((u64)dev->inuse_restbl.inuse_size * PAGE_SIZE / 2) <<
		(dev->cl_stride - dev->pte_stride);
	attr->page_size_cap = PAGE_SIZE;
	attr->vendor_id = to_pci_dev(dev->hwdev)->vendor;
	attr->vendor_part_id = to_pci_dev(dev->hwdev)->device;
	attr->hw_ver = dev->info->asic_rev;
	attr->fw_ver = 0;
	attr->max_qp = dev->size_qpid;
	attr->max_qp_wr = IONIC_MAX_DEPTH;
	attr->device_cap_flags =
		IB_DEVICE_LOCAL_DMA_LKEY |
		IB_DEVICE_MEM_WINDOW |
		IB_DEVICE_MEM_MGT_EXTENSIONS |
		IB_DEVICE_MEM_WINDOW_TYPE_2B |
		0;
	attr->max_send_sge =
		min(ionic_v1_send_wqe_max_sge(dev->max_stride, 0),
		    ionic_spec);
	attr->max_recv_sge =
		min3(ionic_v1_recv_wqe_max_sge(dev->max_stride, 0),
		     ionic_spec,
		     IONIC_SPEC_RD_RCV);
	attr->max_sge_rd = min(attr->max_send_sge, IONIC_SPEC_RD_RCV);
	attr->max_cq = dev->inuse_cqid.inuse_size;
	attr->max_cqe = IONIC_MAX_CQ_DEPTH;
	attr->max_mr = dev->inuse_mrid.inuse_size;
	attr->max_pd = ionic_max_pd;
	attr->max_qp_rd_atom = IONIC_MAX_RD_ATOM;
	attr->max_ee_rd_atom = 0;
	attr->max_res_rd_atom = IONIC_MAX_RD_ATOM;
	attr->max_qp_init_rd_atom = IONIC_MAX_RD_ATOM;
	attr->max_ee_init_rd_atom = 0;
	attr->atomic_cap = IB_ATOMIC_GLOB;
	attr->masked_atomic_cap = IB_ATOMIC_GLOB;
	attr->max_mw = dev->inuse_mrid.inuse_size;
	attr->max_mcast_grp = 0;
	attr->max_mcast_qp_attach = 0;
	attr->max_ah = dev->inuse_ahid.inuse_size;
	attr->max_fast_reg_page_list_len =
		(dev->inuse_restbl.inuse_size / 2) <<
		(dev->cl_stride - dev->pte_stride);
	attr->max_pkeys = IONIC_PKEY_TBL_LEN;

	return 0;
}

static int ionic_query_port(struct ib_device *ibdev, u8 port,
			    struct ib_port_attr *attr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);
	struct net_device *ndev = dev->ndev;

	if (port != 1)
		return -EINVAL;

	if (netif_running(ndev) && netif_carrier_ok(ndev)) {
		attr->state = IB_PORT_ACTIVE;
		attr->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	} else if (netif_running(ndev)) {
		attr->state = IB_PORT_DOWN;
		attr->phys_state = IB_PORT_PHYS_STATE_POLLING;
	} else {
		attr->state = IB_PORT_DOWN;
		attr->phys_state = IB_PORT_PHYS_STATE_DISABLED;
	}

	attr->max_mtu = ib_mtu_int_to_enum(ndev->max_mtu);
	attr->active_mtu = ib_mtu_int_to_enum(ndev->mtu);
	attr->gid_tbl_len = IONIC_GID_TBL_LEN;
	attr->ip_gids = true;
	attr->port_cap_flags = 0;
	attr->max_msg_sz = 0x80000000;
	attr->pkey_tbl_len = IONIC_PKEY_TBL_LEN;
	attr->max_vl_num = 1;
	attr->subnet_prefix = 0xfe80000000000000ull;

	return ib_get_eth_speed(ibdev, port,
				&attr->active_speed,
				&attr->active_width);
}

static enum rdma_link_layer ionic_get_link_layer(struct ib_device *ibdev,
						 u8 port)
{
	return IB_LINK_LAYER_ETHERNET;
}

static struct net_device *ionic_get_netdev(struct ib_device *ibdev, u8 port)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);

	if (port != 1)
		return ERR_PTR(-EINVAL);

	dev_hold(dev->ndev);

	return dev->ndev;
}

static int ionic_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
			    u16 *pkey)
{
	if (port != 1)
		return -EINVAL;

	if (index != 0)
		return -EINVAL;

	*pkey = 0xffff;

	return 0;
}

static int ionic_modify_device(struct ib_device *ibdev, int mask,
			       struct ib_device_modify *attr)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);

	if (mask & ~IB_DEVICE_MODIFY_NODE_DESC)
		return -EOPNOTSUPP;

	if (mask & IB_DEVICE_MODIFY_NODE_DESC)
		memcpy(dev->ibdev.node_desc, attr->node_desc,
		       IB_DEVICE_NODE_DESC_MAX);

	return 0;
}

static int ionic_get_port_immutable(struct ib_device *ibdev, u8 port,
				    struct ib_port_immutable *attr)
{
	if (port != 1)
		return -EINVAL;

	attr->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;

	attr->pkey_tbl_len = IONIC_PKEY_TBL_LEN;
	attr->gid_tbl_len = IONIC_GID_TBL_LEN;
	attr->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

static void ionic_get_dev_fw_str(struct ib_device *ibdev, char *str)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);
	size_t str_len = IB_FW_VERSION_NAME_MAX;

	strlcpy(str, dev->info->fw_version, str_len);
}

static const struct cpumask *ionic_get_vector_affinity(struct ib_device *ibdev,
						       int comp_vector)
{
	struct ionic_ibdev *dev = to_ionic_ibdev(ibdev);

	if (comp_vector < 0 || comp_vector >= dev->eq_count)
		return NULL;

	return irq_get_affinity_mask(dev->eq_vec[comp_vector]->irq);
}

void ionic_port_event(struct ionic_ibdev *dev, enum ib_event_type event)
{
	struct ib_event ev;

	ev.device = &dev->ibdev;
	ev.element.port_num = 1;
	ev.event = event;

	ib_dispatch_event(&ev);
}

static void ionic_destroy_ibdev(struct ionic_ibdev *dev)
{
	struct net_device *ndev = dev->ndev;

	list_del(&dev->driver_ent);

	ionic_kill_rdma_admin(dev, false);

	ionic_dcqcn_destroy(dev);

	ib_unregister_device(&dev->ibdev);

	ionic_destroy_rdma_admin(dev);

	ionic_api_clear_private(dev->handle);

	kfree(dev->stats);
	kfree(dev->stats_buf);
	kfree(dev->stats_hdrs);

	ionic_dbg_rm_dev(dev);

	ionic_resid_destroy(&dev->inuse_qpid);
	ionic_resid_destroy(&dev->inuse_cqid);
	ionic_resid_destroy(&dev->inuse_mrid);
	ionic_resid_destroy(&dev->inuse_ahid);
	ionic_resid_destroy(&dev->inuse_pdid);
	ionic_buddy_destroy(&dev->inuse_restbl);
	xa_destroy(&dev->qp_tbl);
	xa_destroy(&dev->cq_tbl);

	ib_dealloc_device(&dev->ibdev);

	dev_put(ndev);
}

static void ionic_kill_ibdev_cb(void *dev_ptr)
{
	struct ionic_ibdev *dev = dev_ptr;

	ibdev_warn(&dev->ibdev, "reset has been indicated\n");

	ionic_kill_ibdev(dev, true);
}

static const struct ib_device_ops ionic_dev_ops = {
	.owner			= THIS_MODULE,
	.driver_id		= RDMA_DRIVER_IONIC,
	.uverbs_abi_ver		= IONIC_ABI_VERSION,
	.query_device		= ionic_query_device,
	.query_port		= ionic_query_port,
	.get_link_layer		= ionic_get_link_layer,
	.get_netdev		= ionic_get_netdev,
	.query_pkey		= ionic_query_pkey,
	.modify_device		= ionic_modify_device,

	.get_port_immutable	= ionic_get_port_immutable,
	.get_dev_fw_str		= ionic_get_dev_fw_str,
	.get_vector_affinity	= ionic_get_vector_affinity,
};

static struct ionic_ibdev *ionic_create_ibdev(void *handle,
					      struct net_device *ndev)
{
	struct ib_device *ibdev;
	struct ionic_ibdev *dev;
	struct device *hwdev;
	const union ionic_lif_identity *ident;
	struct dentry *dbg_ctx;
	int rc, val, lif_index, version;

	dev_hold(ndev);

	ident = ionic_api_get_identity(handle, &lif_index);

	netdev_dbg(ndev, "rdma.version %d\n",
		ident->rdma.version);
	netdev_dbg(ndev, "rdma.qp_opcodes %d\n",
		ident->rdma.qp_opcodes);
	netdev_dbg(ndev, "rdma.admin_opcodes %d\n",
		ident->rdma.admin_opcodes);
	netdev_dbg(ndev, "rdma.npts_per_lif %d\n",
		ident->rdma.npts_per_lif);
	netdev_dbg(ndev, "rdma.nmrs_per_lif %d\n",
		ident->rdma.nmrs_per_lif);
	netdev_dbg(ndev, "rdma.nahs_per_lif %d\n",
		ident->rdma.nahs_per_lif);
	netdev_dbg(ndev, "rdma.aq.qtype %d rdma.aq.base %d rdma.aq.count %d\n",
		ident->rdma.aq_qtype.qtype,
		ident->rdma.aq_qtype.qid_base, ident->rdma.aq_qtype.qid_count);
	netdev_dbg(ndev, "rdma.sq.qtype %d rdma.sq.base %d rdma.sq.count %d\n",
		ident->rdma.sq_qtype.qtype,
		ident->rdma.sq_qtype.qid_base, ident->rdma.sq_qtype.qid_count);
	netdev_dbg(ndev, "rdma.rq.qtype %d rdma.rq.base %d rdma.rq.count %d\n",
		ident->rdma.rq_qtype.qtype,
		ident->rdma.rq_qtype.qid_base, ident->rdma.rq_qtype.qid_count);
	netdev_dbg(ndev, "rdma.cq.qtype %d rdma.cq.base %d rdma.cq.count %d\n",
		ident->rdma.cq_qtype.qtype,
		ident->rdma.cq_qtype.qid_base, ident->rdma.cq_qtype.qid_count);
	netdev_dbg(ndev, "rdma.eq.qtype %d rdma.eq.base %d rdma.eq.count %d\n",
		ident->rdma.eq_qtype.qtype,
		ident->rdma.eq_qtype.qid_base, ident->rdma.eq_qtype.qid_count);

	version = ident->rdma.version;

	if (version < IONIC_MIN_RDMA_VERSION) {
		netdev_err(ndev,
			   FW_INFO "ionic_rdma: Firmware RDMA Version %u\n",
			   version);
		netdev_err(ndev,
			   FW_INFO "ionic_rdma: Driver Min RDMA Version %u\n",
			   IONIC_MIN_RDMA_VERSION);
		rc = -EINVAL;
		goto err_dev;
	}

	if (version > IONIC_MAX_RDMA_VERSION) {
		netdev_err(ndev,
			   FW_INFO "ionic_rdma: Firmware RDMA Version %u\n",
			   version);
		netdev_err(ndev,
			   FW_INFO "ionic_rdma: Driver Max RDMA Version %u\n",
			   IONIC_MAX_RDMA_VERSION);
		rc = -EINVAL;
		goto err_dev;
	}

	hwdev = ionic_api_get_device(handle);

	/* Ensure that our parent is a true PCI device */
	if (!dev_is_pci(hwdev)) {
		netdev_err(ndev,
			   "ionic_rdma: Cannot bind to non-PCI device\n");
		rc = -ENXIO;
		goto err_dev;
	}

	dev = ib_alloc_device(ionic_ibdev, ibdev);
	if (!dev) {
		rc = -ENOMEM;
		goto err_dev;
	}
	ibdev = &dev->ibdev;

	dev->hwdev = hwdev;
	dev->ndev = ndev;
	dev->handle = handle;
	dev->lif_index = lif_index;
	dev->ident = ident;
	dev->info = ionic_api_get_devinfo(handle);

	ionic_api_kernel_dbpage(handle, &dev->intr_ctrl,
				&dev->dbid, &dev->dbpage);

	dev->rdma_version = version;
	dev->qp_opcodes = ident->rdma.qp_opcodes;
	dev->admin_opcodes = ident->rdma.admin_opcodes;

	/* base opcodes must be supported, extended opcodes are optional*/
	if (dev->qp_opcodes <= IONIC_V1_OP_BIND_MW) {
		netdev_dbg(ndev, "ionic_rdma: qp opcodes %d want min %d\n",
			   dev->qp_opcodes, IONIC_V1_OP_BIND_MW + 1);
		rc = -ENODEV;
		goto err_dev;
	}

	/* need at least one rdma admin queue (driver creates one) */
	val = le32_to_cpu(ident->rdma.aq_qtype.qid_count);
	if (!val) {
		netdev_dbg(ndev, "ionic_rdma: No RDMA Admin Queue\n");
		rc = -ENODEV;
		goto err_dev;
	}

	/* qp ids start at zero, and sq id == qp id */
	val = le32_to_cpu(ident->rdma.sq_qtype.qid_base);
	if (val) {
		netdev_dbg(ndev, "ionic_rdma: Nonzero sq qid base %u\n", val);
		rc = -EINVAL;
		goto err_dev;
	}

	/* qp ids start at zero, and rq id == qp id */
	val = le32_to_cpu(ident->rdma.rq_qtype.qid_base);
	if (val) {
		netdev_dbg(ndev, "ionic_rdma: Nonzero rq qid base %u\n", val);
		rc = -EINVAL;
		goto err_dev;
	}

	/* driver supports these qtypes starting at nonzero base */
	dev->aq_base = le32_to_cpu(ident->rdma.aq_qtype.qid_base);
	dev->cq_base = le32_to_cpu(ident->rdma.cq_qtype.qid_base);
	dev->eq_base = le32_to_cpu(ident->rdma.eq_qtype.qid_base);

	/*
	 * ionic_create_rdma_admin() may reduce aq_count or eq_count if
	 * it is unable to allocate all that were requested.
	 * aq_count is tunable; see ionic_rdma_aq_count
	 */
	dev->aq_count = le32_to_cpu(ident->rdma.aq_qtype.qid_count);
	dev->eq_count = le32_to_cpu(ident->rdma.eq_qtype.qid_count);

	dev->aq_qtype = ident->rdma.aq_qtype.qtype;
	dev->sq_qtype = ident->rdma.sq_qtype.qtype;
	dev->rq_qtype = ident->rdma.rq_qtype.qtype;
	dev->cq_qtype = ident->rdma.cq_qtype.qtype;
	dev->eq_qtype = ident->rdma.eq_qtype.qtype;

	dev->max_stride = ident->rdma.max_stride;
	dev->cl_stride = ident->rdma.cl_stride;
	dev->pte_stride = ident->rdma.pte_stride;
	dev->rrq_stride = ident->rdma.rrq_stride;
	dev->rsq_stride = ident->rdma.rsq_stride;

	xa_init(&dev->qp_tbl);
	xa_init(&dev->cq_tbl);

	mutex_init(&dev->inuse_lock);
	spin_lock_init(&dev->inuse_splock);

	rc = ionic_buddy_init(&dev->inuse_restbl,
			      le32_to_cpu(ident->rdma.npts_per_lif) >>
			      (dev->cl_stride - dev->pte_stride));
	if (rc)
		goto err_restbl;

	rc = ionic_resid_init(&dev->inuse_pdid, ionic_max_pd);
	if (rc)
		goto err_pdid;

	rc = ionic_resid_init(&dev->inuse_ahid,
			      le32_to_cpu(ident->rdma.nahs_per_lif));
	if (rc)
		goto err_ahid;

	rc = ionic_resid_init(&dev->inuse_mrid,
			      le32_to_cpu(ident->rdma.nmrs_per_lif));
	if (rc)
		goto err_mrid;

	/* skip reserved lkey */
	dev->inuse_mrid.next_id = 1;
	dev->next_mrkey = 1;

	rc = ionic_resid_init(&dev->inuse_cqid,
			      le32_to_cpu(ident->rdma.cq_qtype.qid_count));
	if (rc)
		goto err_cqid;

	dev->size_qpid = le32_to_cpu(ident->rdma.sq_qtype.qid_count);

	rc = ionic_resid_init(&dev->inuse_qpid, dev->size_qpid);
	if (rc)
		goto err_qpid;

	if (ionic_qid_skip > 0) {
		ionic_resid_skip(&dev->inuse_qpid);
		ionic_resid_skip(&dev->inuse_cqid);
	}

	/* skip reserved SMI and GSI qpids */
	dev->inuse_qpid.next_id = 2;

	if (ionic_dbg_enable)
		dbg_ctx = ionic_api_get_debug_ctx(handle);
	else
		dbg_ctx = NULL;

	ionic_dbg_add_dev(dev, dbg_ctx);

	rc = ionic_rdma_reset_devcmd(dev);
	if (rc)
		goto err_reset;

	rc = ionic_create_rdma_admin(dev);
	if (rc)
		goto err_register;

	ibdev->dev.parent = dev->hwdev;

	strlcpy(ibdev->node_desc, DEVICE_DESCRIPTION, IB_DEVICE_NODE_DESC_MAX);

	ibdev->node_type = RDMA_NODE_IB_CA;
	ibdev->phys_port_cnt = 1;

	/* the first eq is reserved for async events */
	ibdev->num_comp_vectors = dev->eq_count - 1;

	addrconf_ifid_eui48((u8 *)&ibdev->node_guid, ndev);

	ibdev->uverbs_cmd_mask =
		BIT_ULL(IB_USER_VERBS_CMD_GET_CONTEXT)		|
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_DEVICE)		|
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_PORT)		|
		0;
	ibdev->uverbs_ex_cmd_mask =
		0;

	ib_set_device_ops(&dev->ibdev, &ionic_dev_ops);
	ionic_datapath_setops(dev);
	ionic_controlpath_setops(dev);
	ionic_stats_setops(dev);

	rc = ib_register_device(ibdev, "ionic_%d");
	if (rc)
		goto err_register;

	rc = ionic_api_set_private(handle, dev, ionic_kill_ibdev_cb,
				   IONIC_PRSN_RDMA);
	if (rc)
		goto err_api;

	ionic_dcqcn_init(dev, ident->rdma.dcqcn_profiles);

	list_add(&dev->driver_ent, &ionic_ibdev_list);

	return dev;

err_api:
	ib_unregister_device(&dev->ibdev);
err_register:
	ionic_kill_rdma_admin(dev, false);
	ionic_destroy_rdma_admin(dev);
	kfree(dev->stats);
	kfree(dev->stats_buf);
	kfree(dev->stats_hdrs);
err_reset:
	ionic_dbg_rm_dev(dev);
	ionic_resid_destroy(&dev->inuse_qpid);
err_qpid:
	ionic_resid_destroy(&dev->inuse_cqid);
err_cqid:
	ionic_resid_destroy(&dev->inuse_mrid);
err_mrid:
	ionic_resid_destroy(&dev->inuse_ahid);
err_ahid:
	ionic_resid_destroy(&dev->inuse_pdid);
err_pdid:
	ionic_buddy_destroy(&dev->inuse_restbl);
err_restbl:
	xa_destroy(&dev->qp_tbl);
	xa_destroy(&dev->cq_tbl);
	ib_dealloc_device(ibdev);
err_dev:
	dev_put(ndev);
	return ERR_PTR(rc);
}

struct ionic_netdev_work {
	struct work_struct ws;
	unsigned long event;
	struct net_device *ndev;
	void *handle;
	u32 reset_cnt;
};

static void ionic_netdev_work(struct work_struct *ws)
{
	struct ionic_netdev_work *work =
		container_of(ws, struct ionic_netdev_work, ws);
	struct net_device *ndev = work->ndev;
	struct ionic_ibdev *dev;

	dev = ionic_api_get_private(work->handle, IONIC_PRSN_RDMA);

	switch (work->event) {
	case NETDEV_REGISTER:
		if (dev) {
			netdev_dbg(ndev, "already registered\n");
			break;
		}

		netdev_dbg(ndev, "register ibdev\n");

		dev = ionic_create_ibdev(work->handle, ndev);
		if (IS_ERR(dev)) {
			netdev_dbg(ndev, "error register ibdev %d\n",
				   (int)PTR_ERR(dev));
			break;
		}

		dev->reset_cnt = work->reset_cnt;
		ibdev_info(&dev->ibdev, "registered\n");
		break;

	case NETDEV_UNREGISTER:
		if (!dev) {
			netdev_dbg(ndev, "not registered\n");
			break;
		}

		/* Avoid spurious unregisters caused by ethernet LIF reset */
		if (!dev->reset_posted &&
		    ionic_api_stay_registered(work->handle)) {
			netdev_dbg(ndev, "stay registered\n");
			break;
		}

		netdev_dbg(ndev, "unregister ibdev\n");
		ionic_destroy_ibdev(dev);

		netdev_dbg(ndev, "unregistered\n");
		break;

	case NETDEV_UP:
		if (!dev)
			break;

		ionic_port_event(dev, IB_EVENT_PORT_ACTIVE);

		break;

	case NETDEV_DOWN:
		if (!dev)
			break;

		ionic_port_event(dev, IB_EVENT_PORT_ERR);

		break;

	case NETDEV_CHANGE:
		if (!dev)
			break;

		if (netif_running(ndev) && netif_carrier_ok(ndev))
			ionic_port_event(dev, IB_EVENT_PORT_ACTIVE);
		else
			ionic_port_event(dev, IB_EVENT_PORT_ERR);

		break;

	default:
		if (!dev)
			break;

		netdev_dbg(ndev, "unhandled event %lu\n", work->event);
	}

	dev_put(ndev);
	kfree(work);
}

static int ionic_netdev_event_post(struct net_device *ndev,
				   unsigned long event, u32 reset_cnt)
{
	struct ionic_netdev_work *work;
	void *handle;

	handle = get_netdev_ionic_handle(ndev, IONIC_API_VERSION,
					 IONIC_PRSN_RDMA);
	if (!handle) {
		pr_devel("unrecognized netdev: %s\n", netdev_name(ndev));
		return 0;
	}

	pr_devel("ionic netdev: %s\n", netdev_name(ndev));
	netdev_dbg(ndev, "event %lu\n", event);

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (WARN_ON_ONCE(!work))
		return -ENOMEM;

	dev_hold(ndev);

	INIT_WORK(&work->ws, ionic_netdev_work);
	work->event = event;
	work->ndev = ndev;
	work->handle = handle;

	/* Preserve reset_cnt in work struct since ibdev will be freed */
	work->reset_cnt = reset_cnt;

	queue_work(ionic_dev_workq, &work->ws);

	return 0;
}

static int ionic_netdev_event(struct notifier_block *notifier,
			      unsigned long event, void *ptr)
{
	struct net_device *ndev;
	int rc;

	ndev = netdev_notifier_info_to_dev(ptr);

	rc = ionic_netdev_event_post(ndev, event, 0);

	return rc ? notifier_from_errno(rc) : NOTIFY_DONE;
}

static struct notifier_block ionic_netdev_notifier = {
	.notifier_call = ionic_netdev_event,
};

void ionic_ibdev_reset(struct ionic_ibdev *dev)
{
	int rc;

	dev->reset_posted = true;
	dev->reset_cnt++;

	rc = ionic_netdev_event_post(dev->ndev, NETDEV_UNREGISTER, 0);
	if (rc) {
		ibdev_warn(&dev->ibdev,
			   "failed to post unregister event: %d\n", rc);
		return;
	}

	rc = ionic_netdev_event_post(dev->ndev, NETDEV_REGISTER,
				     dev->reset_cnt);
	if (rc)
		ibdev_warn(&dev->ibdev,
			   "failed to post register event: %d\n", rc);
}

static int __init ionic_mod_init(void)
{
	int rc;

	pr_info("%s : %s\n", DRIVER_NAME, DRIVER_DESCRIPTION);

	ionic_dev_workq = create_singlethread_workqueue(DRIVER_NAME "-dev");
	if (!ionic_dev_workq) {
		rc = -ENOMEM;
		goto err_dev_workq;
	}

	ionic_evt_workq = create_workqueue(DRIVER_NAME "-evt");
	if (!ionic_evt_workq) {
		rc = -ENOMEM;
		goto err_evt_workq;
	}

	rc = ionic_dbg_init();
	if (rc)
		goto err_dbg;

	rc = register_netdevice_notifier(&ionic_netdev_notifier);
	if (rc)
		goto err_notifier;

	return 0;

err_notifier:
	ionic_dbg_exit();
err_dbg:
	destroy_workqueue(ionic_evt_workq);
err_evt_workq:
	destroy_workqueue(ionic_dev_workq);
err_dev_workq:
	return rc;
}

static void __exit ionic_exit_work(struct work_struct *ws)
{
	struct ionic_ibdev *dev, *dev_next;

	list_for_each_entry_safe_reverse(dev, dev_next, &ionic_ibdev_list,
					 driver_ent) {
		ionic_destroy_ibdev(dev);
	}
}

static void __exit ionic_mod_exit(void)
{
	struct work_struct ws;

	unregister_netdevice_notifier(&ionic_netdev_notifier);

	INIT_WORK_ONSTACK(&ws, ionic_exit_work);
	queue_work(ionic_dev_workq, &ws);
	flush_work(&ws);
	destroy_work_on_stack(&ws);

	destroy_workqueue(ionic_evt_workq);
	destroy_workqueue(ionic_dev_workq);

	ionic_dbg_exit();

	BUILD_BUG_ON(sizeof(struct ionic_v1_cqe) != 32);
	BUILD_BUG_ON(sizeof(struct ionic_v1_base_hdr) != 16);
	BUILD_BUG_ON(sizeof(struct ionic_v1_recv_bdy) != 48);
	BUILD_BUG_ON(sizeof(struct ionic_v1_common_bdy) != 48);
	BUILD_BUG_ON(sizeof(struct ionic_v1_atomic_bdy) != 48);
	BUILD_BUG_ON(sizeof(struct ionic_v1_reg_mr_bdy) != 48);
	BUILD_BUG_ON(sizeof(struct ionic_v1_bind_mw_bdy) != 48);
	BUILD_BUG_ON(sizeof(struct ionic_v1_wqe) != 64);
	BUILD_BUG_ON(sizeof(struct ionic_v1_admin_wqe) != 64);
	BUILD_BUG_ON(sizeof(struct ionic_v1_eqe) != 4);
}

module_init(ionic_mod_init);
module_exit(ionic_mod_exit);
