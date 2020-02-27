// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2019 Pensando Systems, Inc */

#include <linux/kernel.h>

#include "ionic.h"
#include "ionic_bus.h"
#include "ionic_dev.h"
#include "ionic_lif.h"
#include "ionic_txrx.h"

void *get_netdev_ionic_handle(struct net_device *netdev,
			      const char *api_version,
			      enum ionic_api_prsn prsn)
{
	struct ionic_lif *lif;

	if (strcmp(api_version, IONIC_API_VERSION))
		return NULL;

	lif = ionic_netdev_lif(netdev);

	if (!lif || lif->ionic->is_mgmt_nic)
		return NULL;

	/* TODO: Rework if supporting more than one slave */
	if (lif->slave_lif_cfg.prsn != IONIC_PRSN_NONE &&
	    lif->slave_lif_cfg.prsn != prsn)
		return NULL;

	return lif;
}
EXPORT_SYMBOL_GPL(get_netdev_ionic_handle);

bool ionic_api_stay_registered(void *handle)
{
	/* TODO: Implement when eth driver reset is implemented */
	return false;
}
EXPORT_SYMBOL_GPL(ionic_api_stay_registered);

void ionic_api_request_reset(void *handle)
{
	struct ionic_lif *lif = handle;

	dev_warn(&lif->netdev->dev, "request_reset: not implemented\n");
}
EXPORT_SYMBOL_GPL(ionic_api_request_reset);

void *ionic_api_get_private(void *handle, enum ionic_api_prsn prsn)
{
	struct ionic_lif *lif = handle;

	if (lif->slave_lif_cfg.prsn != prsn)
		return NULL;

	return lif->slave_lif_cfg.priv;
}
EXPORT_SYMBOL_GPL(ionic_api_get_private);

int ionic_api_set_private(void *handle, void *priv,
			  void (*reset_cb)(void *priv),
			  enum ionic_api_prsn prsn)
{
	struct ionic_lif *lif = handle;
	struct ionic_lif_cfg *cfg = &lif->slave_lif_cfg;

	if (priv && cfg->priv)
		return -EBUSY;

	if (lif->ionic->nlifs > 1) {
		if (priv) {
			/* Allocate a new slave LIF bit */
			cfg->index = ionic_slave_alloc(lif->ionic, prsn);
			if (cfg->index < 0)
				return -ENOSPC;
		} else if (cfg->priv) {
			/* Free the existing slave LIF bit */
			ionic_slave_free(lif->ionic, cfg->index);
		}
	}

	cfg->priv = priv;
	cfg->prsn = prsn;
	cfg->reset_cb = reset_cb;

	return 0;
}
EXPORT_SYMBOL_GPL(ionic_api_set_private);

struct device *ionic_api_get_device(void *handle)
{
	struct ionic_lif *lif = handle;

	return (lif->netdev->dev.parent);
}
EXPORT_SYMBOL_GPL(ionic_api_get_device);

const struct ionic_devinfo *ionic_api_get_devinfo(void *handle)
{
	struct ionic_lif *lif = handle;

	return &lif->ionic->idev.dev_info;
}
EXPORT_SYMBOL_GPL(ionic_api_get_devinfo);

struct dentry *ionic_api_get_debug_ctx(void *handle)
{
	struct ionic_lif *lif = handle;

	return lif->dentry;
}
EXPORT_SYMBOL_GPL(ionic_api_get_debug_ctx);

const union ionic_lif_identity *ionic_api_get_identity(void *handle, int *lif_index)
{
	struct ionic_lif *lif = handle;

	if (lif_index)
		*lif_index = lif->slave_lif_cfg.index;

	/* TODO: Do all LIFs have the same ident? */
	return &lif->ionic->ident.lif;
}
EXPORT_SYMBOL_GPL(ionic_api_get_identity);

int ionic_api_get_intr(void *handle, int *irq)
{
	struct ionic_lif *lif = handle;
	struct ionic_intr_info *intr_obj;
	int err;

	if (!lif->nrdma_eqs)
		return -ENOSPC;

	intr_obj = kzalloc(sizeof(*intr_obj), GFP_KERNEL);
	if (!intr_obj)
		return -ENOSPC;

	err = ionic_intr_alloc(lif->ionic, intr_obj);
	if (err)
		goto done;

	err = ionic_bus_get_irq(lif->ionic, intr_obj->index);
	if (err < 0) {
		ionic_intr_free(lif->ionic, intr_obj->index);
		goto done;
	}

	--lif->nrdma_eqs;

	*irq = err;
	err = intr_obj->index;
done:
	kfree(intr_obj);
	return err;
}
EXPORT_SYMBOL_GPL(ionic_api_get_intr);

void ionic_api_put_intr(void *handle, int intr)
{
	struct ionic_lif *lif = handle;

	ionic_intr_free(lif->ionic, intr);

	++lif->nrdma_eqs;
}
EXPORT_SYMBOL_GPL(ionic_api_put_intr);

int ionic_api_get_cmb(void *handle, u32 *pgid, phys_addr_t *pgaddr, int order)
{
	struct ionic_lif *lif = handle;
	struct ionic_dev *idev = &lif->ionic->idev;
	int ret;

	mutex_lock(&idev->cmb_inuse_lock);
	ret = bitmap_find_free_region(idev->cmb_inuse, idev->cmb_npages,
				      order);
	mutex_unlock(&idev->cmb_inuse_lock);

	if (ret < 0)
		return ret;

	*pgid = (u32)ret;
	*pgaddr = idev->phy_cmb_pages + ret * PAGE_SIZE;

	return 0;
}
EXPORT_SYMBOL_GPL(ionic_api_get_cmb);

void ionic_api_put_cmb(void *handle, u32 pgid, int order)
{
	struct ionic_lif *lif = handle;
	struct ionic_dev *idev = &lif->ionic->idev;

	mutex_lock(&idev->cmb_inuse_lock);
	bitmap_release_region(idev->cmb_inuse, pgid, order);
	mutex_unlock(&idev->cmb_inuse_lock);
}
EXPORT_SYMBOL_GPL(ionic_api_put_cmb);

void ionic_api_kernel_dbpage(void *handle,
			     struct ionic_intr __iomem **intr_ctrl,
			     u32 *dbid, u64 __iomem **dbpage)
{
	struct ionic_lif *lif = handle;

	*intr_ctrl = lif->ionic->idev.intr_ctrl;

	*dbid = lif->kern_pid;
	*dbpage = lif->kern_dbpage;
}
EXPORT_SYMBOL_GPL(ionic_api_kernel_dbpage);

int ionic_api_get_dbid(void *handle, u32 *dbid, phys_addr_t *addr)
{
	struct ionic_lif *lif = handle;
	int id, dbpage_num;

	mutex_lock(&lif->dbid_inuse_lock);

	id = find_first_zero_bit(lif->dbid_inuse, lif->dbid_count);
	if (id == lif->dbid_count) {
		mutex_unlock(&lif->dbid_inuse_lock);
		return -ENOMEM;
	}

	set_bit(id, lif->dbid_inuse);

	mutex_unlock(&lif->dbid_inuse_lock);

	dbpage_num = ionic_db_page_num(lif, id);

	*dbid = id;
	*addr = ionic_bus_phys_dbpage(lif->ionic, dbpage_num);

	return 0;
}
EXPORT_SYMBOL_GPL(ionic_api_get_dbid);

void ionic_api_put_dbid(void *handle, int dbid)
{
	struct ionic_lif *lif = handle;

	clear_bit(dbid, lif->dbid_inuse);
}
EXPORT_SYMBOL_GPL(ionic_api_put_dbid);

int ionic_api_adminq_post(void *handle, struct ionic_admin_ctx *ctx)
{
	struct ionic_lif *lif = handle;

	return ionic_adminq_post(lif, ctx);
}
EXPORT_SYMBOL_GPL(ionic_api_adminq_post);
