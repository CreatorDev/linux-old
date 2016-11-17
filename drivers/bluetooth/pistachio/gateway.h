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
 *** File Name  : gateway.h
 ***
 *** File Description:
 *** This file contains interface declarations for gateway to the userspace
 ***
 ******************************************************************************
 *END**************************************************************************/

#ifndef __GATEWAY_H__
#define __GATEWAY_H__

#include <linux/device.h>
#include <linux/list.h>

struct payload;

typedef void (*push_message)(struct payload *pld);

int gateway_init(push_message, struct device *pdev);
void gateway_exit(void);
int gateway_send(struct payload *pld);

#endif /* __GATEWAY_H__ */
