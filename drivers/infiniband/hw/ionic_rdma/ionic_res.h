/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2020 Pensando Systems, Inc.  All rights reserved.
 */

#ifndef IONIC_RES_H
#define IONIC_RES_H

/** struct ionic_resid_bits - Number allocator based on find_first_zero_bit.
 *
 * The allocator find_first_zero_bit suffers O(N^2) search time complexity,
 * for N allocations.  This is because it starts from the beginning of the
 * bitmap each time.  To find a free bit in the bitmap, the search time
 * increases for each allocation as the beginning of the bitmap is filled.  On
 * the other hand, it is desirable for O(1) memory size complexity, assuming
 * the capacity is constant.
 *
 * This allocator is intended to keep the desired memory size complexity, but
 * improve the search time complexity for typical workloads.  The search time
 * complexity is expected to be closer N, for N allocations, although it
 * remains bounded by O(N^2) in the worst case.
 */
struct ionic_resid_bits {
	int next_id;
	int inuse_size;
	unsigned long *inuse;
};

/** ionic_resid_init() - Initialize a resid allocator.
 * @resid:	Uninitialized resid allocator.
 * @size:	Capacity of the allocator.
 *
 * Return: Zero on success, or negative error number.
 */
int ionic_resid_init(struct ionic_resid_bits *resid, int size);

/** ionic_resid_destroy() - Destroy a resid allocator.
 * @resid:	Resid allocator.
 */
static inline void ionic_resid_destroy(struct ionic_resid_bits *resid)
{
	kfree(resid->inuse);
}

/** ionic_resid_get_shared() - Allocate an available shared resource id.
 * @resid:	Resid allocator.
 * @wrap_id:	Smallest valid resource id.
 * @next_id:	Start the search at resource id.
 * @size_id:	One after largest valid resource id.
 *
 * This does not update the next_id.  Caller should update the next_id for for
 * the resource that shares the id space, and/or the shared resid->next_id as
 * appropriate.
 *
 * Return: Resource id, or negative error number.
 */
int ionic_resid_get_shared(struct ionic_resid_bits *resid, int wrap_id,
			   int next_id, int size);

/** ionic_resid_get_wrap() - Allocate an available resource id, wrap to nonzero
 * @resid:	Resid allocator.
 * @wrap_id:	Smallest valid resource id.
 *
 * Return: Resource id, or negative error number.
 */
static inline int ionic_resid_get_wrap(struct ionic_resid_bits *resid,
				       int wrap_id)
{
	int rc;

	rc = ionic_resid_get_shared(resid, wrap_id,
				    resid->next_id,
				    resid->inuse_size);
	if (rc >= 0)
		resid->next_id = rc + 1;

	return rc;
}

/** ionic_resid_get() - Allocate an available resource id.
 * @resid:	Resid allocator.
 *
 * Return: Resource id, or negative error number.
 */
static inline int ionic_resid_get(struct ionic_resid_bits *resid)
{
	return ionic_resid_get_wrap(resid, 0);
}

/** ionic_resid_put() - Free a resource id.
 * @resid:	Resid allocator.
 * @id:		Resource id.
 */
static inline void ionic_resid_put(struct ionic_resid_bits *resid, int id)
{
	clear_bit(id, resid->inuse);
}

/** struct ionic_buddy_bits - Buddy allocator based on bitmap_find_free_region
 *
 * The allocator bitmap_find_free_region suffers O(N^2) search time complexity,
 * for N allocations.  This is because it starts from the beginning of the
 * bitmap each time.  To find a free range of bits in the bitmap, the search
 * time increases for each allocation as the beginning of the bitmap is filled.
 * On the other hand, it is desirable for O(1) memory size complexity, assuming
 * the capacity is constant.
 *
 * This allocator is intended to keep the desired memory size complexity, but
 * improve the search time complexity for typical workloads.  The search time
 * complexity is expected to be closer N, for N allocations, although it
 * remains bounded by O(N^2) in the worst case.
 */
struct ionic_buddy_bits {
	int inuse_size;
	int inuse_longs;
	unsigned long *inuse;
	int order_max;
	int *order_next;
};

/** ionic_buddy_init() - Initialize a buddy allocator.
 * @buddy:	Uninitialized buddy allocator.
 * @size:	Capacity of the allocator.
 *
 * Return: Zero on success, or negative error number.
 */
int ionic_buddy_init(struct ionic_buddy_bits *buddy, int size);

/** ionic_buddy_destroy() - Destroy a buddy allocator.
 * @buddy:	Buddy allocator.
 */
static inline void ionic_buddy_destroy(struct ionic_buddy_bits *buddy)
{
	kfree(buddy->order_next);
	kfree(buddy->inuse);
}

/** ionic_buddy_get() - Allocate an order-sized range.
 * @buddy:	Buddy allocator.
 * @order:	Log size of the range to get.
 *
 * Return: Position of the start of the range, or negative error number.
 */
int ionic_buddy_get(struct ionic_buddy_bits *buddy, int order);

/** ionic_buddy_put() - Free an order-sized range.
 * @buddy:	Buddy allocator.
 * @pos:	Position of the start of the range.
 * @order:	Log size of the range to put.
 */
void ionic_buddy_put(struct ionic_buddy_bits *buddy, int pos, int order);

#endif /* IONIC_RES_H */
