/*
 * File Name  : img-connectivity-pistachio.h
 *
 * File Description: Platform specific definitions for Pistachio SoC
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

#ifndef _IMG_CONNECTIVITY_PISTACHIO_H_
#define _IMG_CONNECTIVITY_PISTACHIO_H_

#include <linux/io.h>

#define CR_MC_SYS_MEM_BASE0_OFFSET 0x38218

static inline void soc_set_uccp_extram_base(void __iomem *sbus,
							phys_addr_t addr)
{
	/*
	 * For Pistachio platform this setup is sufficient to use DRAM from
	 * UCCP. For other platforms additional registers inside the UCCP may
	 * need to be set up.
	 *
	 * For details of the bitshifts refer to Pistachio TRM p.481
	 *
	 */
	iowrite32((addr >> 12) << 10,
		(void __iomem *)((u32)sbus + CR_MC_SYS_MEM_BASE0_OFFSET));
}

#endif
