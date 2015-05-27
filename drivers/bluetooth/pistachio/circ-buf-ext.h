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
 *** File Name  : circ_buf_ext.h
 ***
 *** File Description:
 *** This file contains interface and implementation of an extension to
 *** the Linux circ_buf module
 ***
 ******************************************************************************
 *END*************************************************************************/

#ifndef __CIRC_BUF_EXT_H__
#define __CIRC_BUF_EXT_H__ 1

#include <linux/circ_buf.h>

#define DEFINE_CIRC_BUF_EXT_TYPE(mem_type, name) \
	struct name {\
		mem_type *base;\
		int tail;\
		int head;\
		int size;\
	};

DEFINE_CIRC_BUF_EXT_TYPE(u8, circ_buf_ext);

#define circ_buf_ext_scroll(field, buf_ptr, by) \
	((buf_ptr)->field = ((buf_ptr)->field + (by)) & ((buf_ptr)->size - 1))
#define circ_buf_ext_take(buf, n) \
	circ_buf_ext_scroll(head, buf, n)
#define circ_buf_ext_give(buf, n) \
	circ_buf_ext_scroll(tail, buf, n)
#define circ_buf_ext_read_offset(buf, idx) \
	((buf)->base + (((buf)->tail + (idx)) & ((buf)->size - 1)))
#define circ_buf_ext_write_offset(buf, idx) \
	((buf)->base + (((buf)->head + (idx)) & ((buf)->size - 1)))

static inline void circ_buf_ext_io_to_krn(
		struct circ_buf_ext *to,
		struct circ_buf_ext *from,
		unsigned int n)
{
	unsigned int idx;
	u8 tmp;
	for (idx = 0; idx < n; idx++) {
		tmp = ioread8((u8 __iomem *)circ_buf_ext_read_offset(from,
						idx));
		*circ_buf_ext_write_offset(to, idx) = tmp;
	}
	circ_buf_ext_take(to, n);
	circ_buf_ext_give(from, n);
}

static inline void circ_buf_ext_krn_to_io(
		struct circ_buf_ext *to,
		struct circ_buf_ext *from,
		unsigned int n)
{
	unsigned int idx;
	u8 tmp;
	for (idx = 0; idx < n; idx++) {
		tmp = *circ_buf_ext_read_offset(from, idx);
		iowrite8(tmp, (u8 __iomem *)circ_buf_ext_write_offset(to, idx));
	}
	circ_buf_ext_take(to, n);
	circ_buf_ext_give(from, n);
}

static inline int circ_buf_ext_space(struct circ_buf_ext *buf)
{
	return CIRC_SPACE(buf->head, buf->tail, buf->size);
}

static inline int circ_buf_ext_count(struct circ_buf_ext *buf)
{
	return CIRC_CNT(buf->head, buf->tail, buf->size);
}

#endif
