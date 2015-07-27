/*
 * File Name  : mem-region.c
 *
 * File Description : Memory regions manipulation - implementation
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

#include "mem-region.h"

static bool any(struct mem_region haystack[], unsigned int n,
						mr_relation_fn predicate,
						struct mem_region *needle)
{
	int i;
	for (i = 0; i < n; i++) {
		if (predicate(haystack + i, needle))
			return true;
	}
	return false;
}

static bool addr_within(struct mem_region *r, u32 addr)
{
	return addr >= r->from && addr <= r->to;
}

static bool addr_beyond(struct mem_region *r, u32 addr)
{
	return addr > r->to;
}

static bool addr_before(struct mem_region *r, u32 addr)
{
	return addr < r->from;
}

bool legal(struct mem_region *r)
{
	return r->from <= r->to;
}

bool within(struct mem_region *legal, struct mem_region *r)
{
	return (r->from >= legal->from) && (r->to <= legal->to);
}

bool overlaps(struct mem_region *legal, struct mem_region *r)
{
	return (addr_within(legal, r->from) && addr_beyond(legal, r->to)) ||
		(addr_before(legal, r->from) && addr_within(legal, r->to));
}

bool within_any(struct mem_region rs[], unsigned int n, struct mem_region *r)
{
	return any(rs, n, within, r);
}

bool overlaps_any(struct mem_region rs[], unsigned int n, struct mem_region *r)
{
	return any(rs, n, overlaps, r);
}

