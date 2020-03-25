/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#ifndef IONIC_IBDEV_H
#define IONIC_IBDEV_H

#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/xarray.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/uverbs_ioctl.h>

#include <rdma/ionic-abi.h>
#include <ionic_api.h>
#include <ionic_regs.h>

#include "ionic_fw.h"
#include "ionic_sysfs.h"
#include "ionic_queue.h"
#include "ionic_res.h"

#define DRIVER_NAME		"ionic_rdma"
#define DRIVER_SHORTNAME	"ionr"

#define IONIC_MIN_RDMA_VERSION	0
#define IONIC_MAX_RDMA_VERSION	1

#define IONIC_DBPAGE_SIZE	0x1000
#define IONIC_MAX_MRID		0xffffff
#define IONIC_MAX_QPID		0xffffff
#define IONIC_MAX_CMB_ORDER	15
#define IONIC_MAX_RD_ATOM	16
#define IONIC_GID_TBL_LEN	256
#define IONIC_PKEY_TBL_LEN	1

#define IONIC_SPEC_RD_RCV	4
#define IONIC_SPEC_LOW		8
#define IONIC_SPEC_HIGH		16

#define IONIC_META_LAST		((void *)1ul)
#define IONIC_META_POSTED	((void *)2ul)

#define IONIC_CQ_GRACE		100

#define IONIC_ROCE_UDP_SPORT	28272

/* resource is not reserved on the device, indicated in tbl_order */
#define IONIC_RES_INVALID	-1

struct dcqcn_root;
struct ionic_aq;
struct ionic_cq;
struct ionic_eq;

enum ionic_admin_state {
	IONIC_ADMIN_ACTIVE, /* submitting admin commands to queue */
	IONIC_ADMIN_PAUSED, /* not submitting, but may complete normally */
	IONIC_ADMIN_KILLED, /* not submitting, locally completed */
};

enum ionic_admin_flags {
	IONIC_ADMIN_F_BUSYWAIT  = BIT(0),	/* Don't sleep */
	IONIC_ADMIN_F_TEARDOWN  = BIT(1),	/* In destroy path */
	IONIC_ADMIN_F_INTERRUPT = BIT(2),	/* Interruptible w/timeout */
};

struct ionic_mmap_info {
	struct list_head ctx_ent;
	unsigned long offset;
	unsigned long size;
	unsigned long pfn;
	bool writecombine;
};

struct ionic_ibdev {
	struct ib_device	ibdev;

	struct list_head	driver_ent;

	struct device		*hwdev;
	struct net_device	*ndev;

	const struct ionic_devinfo	*info;
	const union ionic_lif_identity	*ident;

	void			*handle;
	int			lif_index;

	u32			dbid;
	u64			__iomem *dbpage;
	struct ionic_intr	__iomem *intr_ctrl;

	u16			rdma_version;
	u8			qp_opcodes;
	u8			admin_opcodes;

	u32			aq_base;
	u32			cq_base;
	u32			eq_base;

	u8			aq_qtype;
	u8			sq_qtype;
	u8			rq_qtype;
	u8			cq_qtype;
	u8			eq_qtype;

	u8			max_stride;
	u8			cl_stride;
	u8			pte_stride;
	u8			rrq_stride;
	u8			rsq_stride;

	/* These tables are used in the fast path.
	 * They are protected by RCU.
	 */
	struct xarray		qp_tbl;
	struct xarray		cq_tbl;

	/* These lists are used for debugging only.
	 * They are protected by the dev_lock.
	 */
	struct list_head	qp_list;
	struct list_head	cq_list;
	spinlock_t		dev_lock;

	struct mutex		inuse_lock; /* for id reservation */
	spinlock_t		inuse_splock; /* for ahid reservation */

	struct ionic_buddy_bits	inuse_restbl;
	struct ionic_resid_bits	inuse_pdid;
	struct ionic_resid_bits	inuse_ahid;
	struct ionic_resid_bits	inuse_mrid;
	u8			next_mrkey;
	struct ionic_resid_bits	inuse_cqid;
	struct ionic_resid_bits	inuse_qpid;
	int			size_qpid;

	struct work_struct	reset_work;
	bool			reset_posted;
	u32			reset_cnt;

	struct delayed_work	admin_dwork;
	struct ionic_aq		**aq_vec;
	int			aq_count;

	enum ionic_admin_state	admin_state;

	struct ionic_eq		**eq_vec;
	int			eq_count;

	int			hw_stats_count;
	struct ionic_v1_stat	*hw_stats;
	void			*hw_stats_buf;
	const char		**hw_stats_hdrs;

	struct dcqcn_root	*dcqcn;

	struct dentry		*debug;
	struct dentry		*debug_aq;
	struct dentry		*debug_cq;
	struct dentry		*debug_eq;
	struct dentry		*debug_mr;
	struct dentry		*debug_qp;
};

struct ionic_eq {
	struct ionic_ibdev	*dev;

	u32			eqid;
	u32			intr;

	struct ionic_queue	q;

	bool			enable;
	bool			armed;

	struct work_struct	work;

	int			irq;
	char			name[32];

	struct dentry		*debug;
};

struct ionic_admin_wr {
	struct completion	work;
	struct list_head	aq_ent;
	struct ionic_v1_admin_wqe wqe;
	struct ionic_v1_cqe	cqe;
	struct ionic_aq		*aq;
	int			status;
};

struct ionic_aq {
	struct ionic_ibdev	*dev;
	struct ionic_cq		*cq;

	struct work_struct	work;

	unsigned long		stamp;
	bool			armed;

	u32			aqid;
	u32			cqid;

	spinlock_t		lock; /* for posting */
	struct ionic_queue	q;
	struct ionic_admin_wr	**q_wr;
	struct list_head	wr_prod;
	struct list_head	wr_post;

	struct dentry		*debug;
};

struct ionic_ctx {
	struct ib_ucontext	ibctx;

	u32			dbid;

	struct mutex		mmap_mut; /* for mmap_list */
	unsigned long long	mmap_off;
	struct list_head	mmap_list;
	struct ionic_mmap_info	mmap_dbell;
};

struct ionic_tbl_res {
	int			tbl_order;
	int			tbl_pos;
};

struct ionic_tbl_buf {
	u32			tbl_limit;
	u32			tbl_pages;
	size_t			tbl_size;
	__le64			*tbl_buf;
	dma_addr_t		tbl_dma;
	u8			page_size_log2;
};

struct ionic_pd {
	struct ib_pd		ibpd;

	u32			pdid;
};

struct ionic_cq {
	struct ib_cq		ibcq;

	u32			cqid;
	u32			eqid;

	spinlock_t		lock; /* for polling */
	struct list_head	poll_sq;
	bool			flush;
	struct list_head	flush_sq;
	struct list_head	flush_rq;
	struct list_head	cq_list_ent;

	struct ionic_queue	q;
	bool			color;
	int			reserve;
	u16			arm_any_prod;
	u16			arm_sol_prod;

	struct kref		cq_kref;
	struct completion	cq_rel_comp;

	/* infrequently accessed, keep at end */
	struct ib_umem		*umem;
	struct ionic_tbl_res	res;

	struct dentry		*debug;
};

struct ionic_sq_meta {
	u64			wrid;
	u32			len;
	u16			seq;
	u8			ibop;
	u8			ibsts;
	bool			remote;
	bool			signal;
	bool			local_comp;
};

struct ionic_rq_meta {
	struct ionic_rq_meta	*next;
	u64			wrid;
};

struct ionic_qp {
	struct ib_qp		ibqp;
	enum ib_qp_state	state;

	u32			qpid;
	u32			ahid;
	u32			sq_cqid;
	u32			rq_cqid;

	bool			has_ah;
	bool			has_sq;
	bool			has_rq;

	bool			sig_all;

	struct list_head	qp_list_ent;

	struct list_head	cq_poll_sq;
	struct list_head	cq_flush_sq;
	struct list_head	cq_flush_rq;

	spinlock_t		sq_lock; /* for posting and polling */
	bool			sq_flush;
	bool			sq_flush_rcvd;
	struct ionic_queue	sq;
	void		__iomem *sq_cmb_ptr;
	struct ionic_sq_meta	*sq_meta;
	u16			*sq_msn_idx;

	int			sq_spec;
	u16			sq_old_prod;
	u16			sq_msn_prod;
	u16			sq_msn_cons;
	u16			sq_cmb_prod;

	spinlock_t		rq_lock; /* for posting and polling */
	bool			rq_flush;
	struct ionic_queue	rq;
	void		__iomem *rq_cmb_ptr;
	struct ionic_rq_meta	*rq_meta;
	struct ionic_rq_meta	*rq_meta_head;

	int			rq_spec;
	u16			rq_old_prod;
	u16			rq_cmb_prod;

	struct kref		qp_kref;
	struct completion	qp_rel_comp;

	/* infrequently accessed, keep at end */
	int			sgid_index;
	bool			sq_is_cmb;
	int			sq_cmb_order;
	u32			sq_cmb_pgid;
	phys_addr_t		sq_cmb_addr;
	struct ionic_mmap_info	sq_cmb_mmap;

	struct ib_umem		*sq_umem;
	struct ionic_tbl_res	sq_res;

	bool			rq_is_cmb;
	int			rq_cmb_order;
	u32			rq_cmb_pgid;
	phys_addr_t		rq_cmb_addr;
	struct ionic_mmap_info	rq_cmb_mmap;

	struct ib_umem		*rq_umem;
	struct ionic_tbl_res	rq_res;

	struct ionic_tbl_res	rsq_res;
	struct ionic_tbl_res	rrq_res;

	int			dcqcn_profile;

	struct ib_ud_header	*hdr;

	struct dentry		*debug;
};

struct ionic_ah {
	struct ib_ah		ibah;
	u32			ahid;
	int			sgid_index;
	struct ib_ud_header	hdr;
};

struct ionic_mr {
	union {
		struct ib_mr	ibmr;
		struct ib_mw	ibmw;
	};

	u32			mrid;
	int			flags;

	struct ib_umem		*umem;
	struct ionic_tbl_res	res;
	struct ionic_tbl_buf	buf;
	bool			created;

	struct dentry		*debug;
};

static inline struct ionic_ibdev *to_ionic_ibdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct ionic_ibdev, ibdev);
}

static inline struct ionic_ctx *to_ionic_ctx(struct ib_ucontext *ibctx)
{
	if (!ibctx)
		return NULL;

	return container_of(ibctx, struct ionic_ctx, ibctx);
}

static inline struct ionic_ctx *to_ionic_ctx_uobj(struct ib_uobject *uobj)
{
	if (!uobj)
		return NULL;

	return to_ionic_ctx(uobj->context);
}

static inline struct ionic_pd *to_ionic_pd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct ionic_pd, ibpd);
}

static inline struct ionic_mr *to_ionic_mr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct ionic_mr, ibmr);
}

static inline struct ionic_mr *to_ionic_mw(struct ib_mw *ibmw)
{
	return container_of(ibmw, struct ionic_mr, ibmw);
}

static inline struct ionic_cq *to_ionic_cq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct ionic_cq, ibcq);
}

static inline struct ionic_qp *to_ionic_qp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct ionic_qp, ibqp);
}

static inline struct ionic_ah *to_ionic_ah(struct ib_ah *ibah)
{
	return container_of(ibah, struct ionic_ah, ibah);
}

static inline u32 ionic_ctx_dbid(struct ionic_ibdev *dev,
				 struct ionic_ctx *ctx)
{
	if (!ctx)
		return dev->dbid;

	return ctx->dbid;
}

static inline u32 ionic_obj_dbid(struct ionic_ibdev *dev,
				 struct ib_uobject *uobj)
{
	return ionic_ctx_dbid(dev, to_ionic_ctx_uobj(uobj));
}

static inline bool ionic_ibop_is_local(enum ib_wr_opcode op)
{
	return op == IB_WR_LOCAL_INV || op == IB_WR_REG_MR;
}

static inline int ionic_res_order(int count, int stride, int cl_stride)
{
	/* count becomes log2 of size in bytes */
	count = order_base_2(count) + stride;

	/* zero if less than one cache line */
	if (count < cl_stride)
		return 0;

	return count - cl_stride;
}

static inline void ionic_qp_complete(struct kref *kref)
{
	struct ionic_qp *qp = container_of(kref, struct ionic_qp, qp_kref);

	complete(&qp->qp_rel_comp);
}

static inline void ionic_cq_complete(struct kref *kref)
{
	struct ionic_cq *cq = container_of(kref, struct ionic_cq, cq_kref);

	complete(&cq->cq_rel_comp);
}

/* ionic_admin.c */
extern struct workqueue_struct *ionic_evt_workq;
void ionic_admin_post(struct ionic_ibdev *dev, struct ionic_admin_wr *wr);
int ionic_admin_wait(struct ionic_ibdev *dev, struct ionic_admin_wr *wr,
		     enum ionic_admin_flags);

int ionic_rdma_reset_devcmd(struct ionic_ibdev *dev);

int ionic_create_rdma_admin(struct ionic_ibdev *dev);
void ionic_destroy_rdma_admin(struct ionic_ibdev *dev);
void ionic_kill_rdma_admin(struct ionic_ibdev *dev, bool fatal_path);

void ionic_kill_ibdev(struct ionic_ibdev *dev, bool fatal_path);

/* ionic_controlpath.c */
void ionic_controlpath_setops(struct ionic_ibdev *dev);
int ionic_get_res(struct ionic_ibdev *dev, struct ionic_tbl_res *res);
bool ionic_put_res(struct ionic_ibdev *dev, struct ionic_tbl_res *res);
int ionic_create_cq_common(struct ionic_cq *cq,
			   struct ionic_tbl_buf *buf,
			   const struct ib_cq_init_attr *attr,
			   struct ionic_ctx *ctx,
			   struct ib_udata *udata);
void ionic_destroy_cq_common(struct ionic_ibdev *dev, struct ionic_cq *cq);
void ionic_flush_qp(struct ionic_qp *qp);
void ionic_notify_flush_cq(struct ionic_cq *cq);

/* ionic_datapath.c */
void ionic_datapath_setops(struct ionic_ibdev *dev);

/* ionic_hw_stats.c */
void ionic_hw_stats_setops(struct ionic_ibdev *dev);

/* ionic_pgtbl.c */
__le64 ionic_pgtbl_dma(struct ionic_tbl_buf *buf, u64 va);
__be64 ionic_pgtbl_off(struct ionic_tbl_buf *buf, u64 va);
int ionic_pgtbl_page(struct ionic_tbl_buf *buf, u64 dma);
int ionic_pgtbl_umem(struct ionic_tbl_buf *buf, struct ib_umem *umem);
int ionic_pgtbl_init(struct ionic_ibdev *dev, struct ionic_tbl_res *res,
		     struct ionic_tbl_buf *buf, struct ib_umem *umem,
		     dma_addr_t dma, int limit);
void ionic_pgtbl_unbuf(struct ionic_ibdev *dev, struct ionic_tbl_buf *buf);

/* ionic_dcqcn.c */
int ionic_dcqcn_init(struct ionic_ibdev *dev, int prof_count);
void ionic_dcqcn_destroy(struct ionic_ibdev *dev);
int ionic_dcqcn_select_profile(struct ionic_ibdev *dev,
			       struct rdma_ah_attr *attr);

/* ionic_ibdev.c */
void ionic_ibdev_reset(struct ionic_ibdev *dev);
void ionic_port_event(struct ionic_ibdev *dev, enum ib_event_type event);

/* Global config knobs */
extern bool ionic_dbg_enable;

extern int ionic_sqcmb_order;
extern bool ionic_sqcmb_inline;
extern int ionic_rqcmb_order;

extern u16 ionic_aq_depth;
extern int ionic_aq_count;
extern u16 ionic_eq_depth;
extern u16 ionic_eq_isr_budget;
extern u16 ionic_eq_work_budget;
extern int ionic_max_pd;
extern int ionic_spec;

#endif /* IONIC_IBDEV_H */
