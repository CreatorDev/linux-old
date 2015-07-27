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
 *** File Name  : img-connectivity.h
 ***
 *** File Description:
 *** This file contains public definitions specific to UCCP base driver
 ***
 ******************************************************************************
 *END**************************************************************************/
#ifndef __IMG_CONNECTIVITY_H
#define __IMG_CONNECTIVITY_H 1

struct img_version_info {
	int bt;
	int wlan;
};

struct img_scratch_info {
	void *virt_addr;
	dma_addr_t bus_addr;
};

struct img_version_info img_connectivity_version(void);
struct img_scratch_info img_connectivity_scratch(void);

#endif /* __IMG_CONNECTIVITY_H */
