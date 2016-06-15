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
 *** File Name  : img-hostport-main.h
 ***
 *** File Description:
 *** This file contains private definitions specific to Host Port comms
 ***
 ******************************************************************************
 *END**************************************************************************/

#ifndef _IMGBT_HOSTPORT_H_
#define _IMGBT_HOSTPORT_H_

/* Include files */
#include <linux/types.h>

#include <soc/img/img-transport.h>

#define MAX_ENDPOINTS 3
#define MAX_ENDPOINT_ID (MAX_ENDPOINTS - 1)

struct img_hostport_endpoints {
	img_transport_handler f[MAX_ENDPOINTS];
	spinlock_t in_use[MAX_ENDPOINTS];
};

struct img_hostport {
	struct img_hostport_endpoints endpoints;
	/* RPU system bus remapped addresses */
	void __iomem *vbase;
	void __iomem *vmtx_int_en;
	void __iomem *vmtx_irq_en;
	/* DTS entries */
	struct resource *base;
	struct resource *mtx_int_en;
	struct resource *mtx_irq_en;
	unsigned int irq_line;
};

/* Register H2C_CMD */
#define H2C_CMD 0x0
#define H2C_CMD_ADDR(base) ((base) + H2C_CMD)
#define C_HOST_INT_SHIFT 31

/* Register C2H_CMD */
#define C2H_CMD 0x4
#define C2H_CMD_ADDR(base) ((base) + C2H_CMD)

/* Register H2C_ACK */
#define H2C_ACK 0x8
#define H2C_ACK_ADDR(base) ((base) + H2C_ACK)
#define C_INT_CLR_SHIFT 31

/* Register C2H_ACK */
#define C2H_ACK 0xC
#define C2H_ACK_ADDR(base) ((base) + C2H_ACK)

/* Register C_INT_ENABLE */
#define C_INT_EN_SHIFT 31
#define C_IRQ_EN_SHIFT 15

#endif

/* EOF */
