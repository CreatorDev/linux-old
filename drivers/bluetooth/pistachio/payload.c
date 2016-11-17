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
 *** File Name  : payload.c
 ***
 *** File Description:
 *** This file contains implementation of payload module, which represents
 *** packets transferred between IMG Bluetooth device and Linux userspace.
 ***
 ******************************************************************************
 *END**************************************************************************/

#include <linux/err.h>
#include <linux/io.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "payload.h"

#define GUARDED_ALLOC(var, alloc_f, fail_action) \
	(var = ({\
		typeof(var) ptr;\
		ptr = (alloc_f);\
		if (IS_ERR_OR_NULL(ptr)) {\
			(void)(fail_action);\
			return ptr;\
		};\
		ptr;\
		}))

/*
 * *** Private storage ***
 */
struct payload {
	u8 *data;
	size_t length;
};

/*
 * *** Private API ***
 */
static struct payload *get_payload_obj(size_t length)
{
	struct payload *pld;
	void *blob_start;

	blob_start = kzalloc(length + sizeof(struct payload), GFP_KERNEL);
	if (IS_ERR_OR_NULL(blob_start))
		return ERR_PTR(-ENOMEM);

	pld = blob_start;
	pld->data = blob_start + sizeof(*pld);
	pld->length = length;
	return pld;
}

static void dispose_of_payload_obj(struct payload *pld)
{
	/*
	 * Note: there is no need to worry about the 'data'
	 * pointer, because it is allocated as a single blob,
	 * whose starting address is stored as pld
	 */
	kfree(pld);
}

/*
 * *** Public API ***
 */
struct payload *payload_from_io(size_t length, const void __iomem *data)
{
	struct payload *pld;
	GUARDED_ALLOC(pld, get_payload_obj(length), NULL);
	memcpy_fromio(pld->data, data, pld->length);
	return pld;
}

struct payload *payload_from_user(size_t length, const void __user *data)
{
	struct payload *pld;
	GUARDED_ALLOC(pld, get_payload_obj(length), NULL);
	if (copy_from_user(pld->data, data, pld->length)) {
		/*
		 * That means that some bytes could not be copied
		 * and buffer had to be zero padded.
		 */
		dispose_of_payload_obj(pld);
		return ERR_PTR(-EFAULT);
	}
	return pld;
}

struct payload *payload_from_string(
		size_t length,
		unsigned char (*one_char)(void *, unsigned int),
		void *arg)
{
	size_t p;
	struct payload *pld;
	if (IS_ERR_OR_NULL(one_char))
		return 0;
	GUARDED_ALLOC(pld, get_payload_obj(length),
			pr_err("failed to allocate payload obj\n"));
	for (p = 0; p < length; p++)
		pld->data[p] = one_char(arg, p);

	return pld;
}

void payload_to_io(struct payload *pld, void __iomem *data)
{
	memcpy_toio(data, pld->data, pld->length);
	dispose_of_payload_obj(pld);
}

int payload_to_user(struct payload *pld, void __user *data)
{
	if (copy_to_user(data, pld->data, pld->length))
		return -EFAULT;

	dispose_of_payload_obj(pld);
	return 0;
}

void payload_delete(struct payload *pld)
{
	dispose_of_payload_obj(pld);
}

const u8 *payload_raw(const struct payload *pld)
{
	return pld->data;
}

size_t payload_length(const struct payload *pld)
{
	return pld->length;
}

unsigned char payload_at(const struct payload *pld, unsigned int idx)
{
	return pld->data[idx];
}
