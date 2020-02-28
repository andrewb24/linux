# SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

ccflags-y :=  -I $(srctree)/drivers/net/ethernet/pensando/ionic

obj-$(CONFIG_INFINIBAND_IONIC)	+= ionic_rdma.o

ionic_rdma-y :=	\
	ionic_ibdev.o ionic_queue.o ionic_sysfs.o \
	ionic_controlpath.o ionic_datapath.o \
	ionic_admin.o ionic_pgtbl.o ionic_hw_stats.o \
	ionic_dcqcn.o ionic_res.o
