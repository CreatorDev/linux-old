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
 *** File Name  : img-transport.h
 ***
 *** File Description:
 *** This file contains interface definition of the low level IMG transport
 *** mechanism.
 ***
 ******************************************************************************
 *END**************************************************************************/


#ifndef __IMG_TRANSPORT_H__
#define __IMG_TRANSPORT_H__

#include <linux/types.h>

/*
 * Note that this procedure is going to be executed
 * in the interrupt context, so it has to be as lean
 * as possible and should preferably defer all heavy
 * lifting.
 */
typedef void (*img_transport_handler)(u16 user_data);

int img_transport_notify(u16 user_data);

/*
 * Possible return values:
 *  @ -ENOBUFS  : all handler slots in use
 *  @ -EBADSLT  : id unavailable
 *  @  0        : callback registered
 */
int img_transport_register_callback(img_transport_handler,
					unsigned int client_id);

/*
 * Possible return values:
 * @ -EIDRM    : client id not found
 * @  0        : callback removed
 */
int img_transport_remove_callback(unsigned int client_id);

#endif
