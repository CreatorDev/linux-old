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

/*
 * The following 4 procedures issue pokes to the RPU. They are guaranteed not
 * to sleep.
 */

/*
 * May spin forever when, for example, RPU is unable to respond. If you can't
 * afford that, use *_timeout variant.
 */
void img_transport_notify(u16 user_data, int user_id);

/*
 * Times out after jiffies_timeout kernel ticks have passed.
 *
 * Possible return values:
 * @ -ETIME	: request timed out
 * @ 0		: RPU has been notified
 */
int __must_check img_transport_notify_timeout(u16 user_data,
					int user_id,
					long jiffies_timeout);

/*
 * May spin forever when, for example, RPU is unable to respond. If you can't
 * afford that, use *_timeout variant.
 */
void img_transport_notify_callback(u16 user_data,
					int user_id,
					void (*poke_ready)(void *),
					void *poke_ready_arg);

/*
 * Times out after jiffies_timeout kernel ticks have passed. 'poke_ready' called
 * just before the poke is issued.
 *
 * Possible return values:
 * @ -ETIME	: request timed out
 * @ 0		: RPU has been notified
 */
int __must_check img_transport_notify_callback_timeout(u16 user_data,
					int user_id,
					long jiffies_timeout,
					void (*poke_ready)(void *),
					void *poke_ready_arg);

/*
 * Register a routine which will be invoked whenever a message for client_id
 * is received.
 *
 * Possible return values:
 *  @ -EBADSLT	: id unavailable
 *  @  0	: callback registered
 */
int img_transport_register_callback(img_transport_handler,
					unsigned int client_id);

/*
 * Remove previously registerd routine.
 *
 * Possible return values:
 *  @ -EBADSLT	: client id not found
 *  @  0	: callback removed
 */
int img_transport_remove_callback(unsigned int client_id);

#endif
