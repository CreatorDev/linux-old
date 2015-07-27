/*
 * File Name  : mem_region.h
 *
 * File Description: Memory regions manipulation - interface declaration
 *
 * Copyright (c) 2011, 2012, 2013, 2014 Imagination Technologies Ltd.
 * All rights reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef _MEM_REGION_H_
#define _MEM_REGION_H_

#include <linux/kernel.h>

struct mem_region {
	u32 from;
	u32 to;
};

typedef bool (*mr_relation_fn)(struct mem_region *, struct mem_region *);

bool legal(struct mem_region *r);
bool within(struct mem_region *legal, struct mem_region *r);
bool overlaps(struct mem_region *legal, struct mem_region *r);
bool within_any(struct mem_region rs[], unsigned int n, struct mem_region *r);
bool overlaps_any(struct mem_region rs[], unsigned int n, struct mem_region *r);

#endif
