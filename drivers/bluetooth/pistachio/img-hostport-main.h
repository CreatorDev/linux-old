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

#include "img-transport.h"

struct img_hostport {
	img_transport_handler rcv_handler;
	/* RPU system bus remapped addresses */
	void __iomem *uccp_mem_addr;
	void __iomem *uccp_base_addr;
	/* DTS entries */
	phys_addr_t uccp_core_base;
	unsigned long uccp_core_len;
	unsigned int irq_line;
};

#define C_REG_OFFSET 0x400

/* Register H2C_CMD */
#define H2C_CMD 0x0030
#define H2C_CMD_ADDR(base) ((base) + H2C_CMD)
#define C_HOST_INT_SHIFT 31

/* Register C2H_CMD */
#define C2H_CMD 0x0034
#define C2H_CMD_ADDR(base) ((base) + C2H_CMD)

/* Register H2C_ACK */
#define H2C_ACK 0x0038
#define H2C_ACK_ADDR(base) ((base) + H2C_ACK)
#define C_INT_CLR_SHIFT 31

/* Register C2H_ACK */
#define C2H_ACK 0x003C
#define C2H_ACK_ADDR(base) ((base) + C2H_ACK)

/* Register C_INT_ENABLE */
#define C_INT_ENABLE 0x0044
#define C_INT_ENABLE_ADDR(base) ((base) + C_INT_ENABLE)
#define C_INT_EN_SHIFT 31

#define C_INT_ENAB 0x0000
#define C_INT_ENAB_ADDR(base) ((base) + C_INT_ENAB)
#define C_INT_IRQ_ENAB_SHIFT 15

#endif

/* EOF */
