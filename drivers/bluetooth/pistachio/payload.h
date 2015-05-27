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
 *** File Name  : payload.h
 ***
 *** File Description:
 *** This file contains interface definition of payload module, which represents
 *** packets transferred between IMG Bluetooth device and Linux userspace.
 ***
 ******************************************************************************
 *END**************************************************************************/

#ifndef __PAYLOAD_H__
#define __PAYLOAD_H__ 1

#include <linux/types.h>

struct payload;

/*
 * *** Create/teardown ***
 */
struct payload *payload_from_io(size_t length,
		const void __iomem *data);
struct payload *payload_from_user(size_t length, const void __user *data);
struct payload *payload_from_raw(size_t length, const u8 *data);
struct payload *payload_from_string(size_t length,
		unsigned char (*one_char)(void *, unsigned int), void *arg);
void payload_to_io(struct payload *pld, void __iomem *data);
int payload_to_user(struct payload *pld, void __user *data);
void payload_delete(struct payload *pld);

/*
 * *** Data access ***
 */
const u8 *payload_raw(const struct payload *pld);
size_t payload_length(const struct payload *pld);
unsigned char payload_at(const struct payload *pld, unsigned int idx);

#endif /* __PAYLOAD_H__ */
