/*HEADER**********************************************************************
 ******************************************************************************
 ***
 *** Copyright (c) 2011, 2012, 2013, 2014 Imagination Technologies Ltd.
 *** All rights reserved
 ***
 *** This program is free software; you can redistribute it and/or
 *** modify it under the terms of the GNU General Public License
 *** as published by the Free Software Foundation; either version 2
 *** of the License, or (at your option) any later version.
 ***
 *** This program is distributed in the hope that it will be useful,
 *** but WITHOUT ANY WARRANTY; without even the implied warranty of
 *** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *** GNU General Public License for more details.
 ***
 *** You should have received a copy of the GNU General Public License
 *** along with this program; if not, write to the Free Software
 *** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *** USA.
 ***
 *** File Name  : circ_buf_oneway.h
 ***
 *** File Description:
 *** This file contains interface and implementation of circular buffers
 *** which only maintain one read/write pointer and therefore use their
 *** full capacity.
 ***
 ******************************************************************************
 *END*************************************************************************/

#ifndef __CIRC_BUF_ONEWAY_H__
#define __CIRC_BUF_ONEWAY_H__ 1

#include <asm/atomic.h>

#include <linux/log2.h>

#define CIRC_BUF_CORE \
	u8 *base;\
	atomic_t cur;\
	size_t size

/*
 * Routines common for both types of buffer
 */

static inline size_t __pure offset_from_cur(size_t cur, size_t off,
								size_t buf_size)
{
	return (cur + off) & (buf_size - 1);
}

/*
 * Buffer for incoming data - no need to track available space.
 */

struct circ_buf_in {
	CIRC_BUF_CORE;
};

static inline int circ_buf_in_init(struct circ_buf_in *buf,
								u8 *base,
								size_t size)
{

	if (!is_power_of_2(size))
		return -1;
	buf->base = base;
	buf->size = size;
	atomic_set(&buf->cur, 0);
	return 0;
}

static inline void circ_buf_in_read_done(struct circ_buf_in *buf, size_t n)
{
	atomic_add(n, &buf->cur);
}

static inline u8 *circ_buf_in_read_offset(struct circ_buf_in *buf, size_t off)
{
	return buf->base + offset_from_cur(atomic_read(&buf->cur), off,
								buf->size);
}

/*
 * Buffer for outgoing data - tracking where to write next and how much can
 * be written.
 */

struct circ_buf_out {
	CIRC_BUF_CORE;
	atomic_t avail;
};

static inline int circ_buf_out_init(struct circ_buf_out *buf,
								u8 *base,
								size_t size)
{
	if (!is_power_of_2(size))
		return -1;
	buf->base = base;
	buf->size = size;
	atomic_set(&buf->cur, 0);
	atomic_set(&buf->avail, size);
	return 0;
}

static inline void circ_buf_out_write_done(struct circ_buf_out *buf,
								size_t n)
{
	atomic_add(n, &buf->cur);
	atomic_sub(n, &buf->avail);
}

static inline void circ_buf_out_write_rcvd(struct circ_buf_out *buf,
								size_t n)
{
	atomic_add(n, &buf->avail);
}

static inline u8 *circ_buf_out_write_offset(const struct circ_buf_out *buf,
								size_t off)
{
	return buf-> base + offset_from_cur(atomic_read(&buf->cur), off,
								buf->size);
}

static inline size_t circ_buf_out_space(const struct circ_buf_out *buf)
{
	return atomic_read(&buf->avail);
}

#endif
