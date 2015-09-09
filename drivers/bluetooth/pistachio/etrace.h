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
 *** File Name  : etrace.h
 ***
 *** File Description:
 *** Declaration of trace events
 ***
 ******************************************************************************
 *END**************************************************************************/
#undef TRACE_SYSTEM
#define TRACE_SYSTEM img_bt

#if !defined(__IMG_BT_TRACE_H__) || defined(TRACE_HEADER_MULTI_READ)
#define __IMG_BT_TRACE_H__

#include <linux/tracepoint.h>

#define DEFINE_HOSTPORT_EVENT(name) \
	DEFINE_EVENT(hostport_event_template, name,\
		TP_PROTO(unsigned long id, unsigned long size),\
		TP_ARGS(id, size))

DECLARE_EVENT_CLASS(hostport_event_template,
		TP_PROTO(unsigned long id, unsigned long size),
		TP_ARGS(id, size),
		TP_STRUCT__entry(
			__field(	unsigned long,	time	)
			__field(	unsigned int,	id	)
			__field(	unsigned int,	size	)
			),
		TP_fast_assign(
			__entry->time = jiffies;
			__entry->id = id;
			__entry->size = size;
			),
		TP_printk("time=%lu id=%u size=%u",
			__entry->time,
			__entry->id,
			__entry->size)
	);

DEFINE_HOSTPORT_EVENT(ctl_ack_sched);
DEFINE_HOSTPORT_EVENT(ctl_ack_execd);

DEFINE_HOSTPORT_EVENT(ctl_req_sched);
DEFINE_HOSTPORT_EVENT(ctl_req_execd);

DEFINE_HOSTPORT_EVENT(hst_ack_sched);
DEFINE_HOSTPORT_EVENT(hst_ack_execd);

DEFINE_HOSTPORT_EVENT(hst_req_sched);
DEFINE_HOSTPORT_EVENT(hst_req_execd_sent);
DEFINE_HOSTPORT_EVENT(hst_req_execd_delayed);
DEFINE_HOSTPORT_EVENT(hst_req_execd_catchup);

#define DEFINE_CHARDEV_EVENT(name) \
	DEFINE_EVENT(chardev_event_template, name,\
		TP_PROTO(int dummy),\
		TP_ARGS(dummy))

DECLARE_EVENT_CLASS(chardev_event_template,
		TP_PROTO(int dummy),
		TP_ARGS(dummy),
		TP_STRUCT__entry(
			__field(unsigned long, time)
			__field(int, dummy)
			),
		TP_fast_assign(
			__entry->time = jiffies;
			__entry->dummy = dummy;
			),
		TP_printk("time=%lu data=%d",
			__entry->time, __entry->dummy)
	);

DEFINE_CHARDEV_EVENT(tty_flip_depleted);
DEFINE_CHARDEV_EVENT(tty_stop_rx_requested);
DEFINE_CHARDEV_EVENT(tty_request_port);
DEFINE_CHARDEV_EVENT(tty_release_port);
DEFINE_CHARDEV_EVENT(tty_start_tx);
DEFINE_CHARDEV_EVENT(tty_stop_tx);
DEFINE_CHARDEV_EVENT(tty_shutdown_port);
DEFINE_CHARDEV_EVENT(tty_startup_port);

#define DEFINE_PAYLOAD_EVENT(name) \
	DEFINE_EVENT(payload_event_template, name,\
		TP_PROTO(unsigned int size, const char *type),\
		TP_ARGS(size, type))

DECLARE_EVENT_CLASS(payload_event_template,
		TP_PROTO(unsigned int size, const char *type),
		TP_ARGS(size, type),
		TP_STRUCT__entry(
			__field(unsigned int, size)
			__field(const char *, type)
			),
		TP_fast_assign(
			__entry->size = size;
			__entry->type = type;
			),
		TP_printk("size=%u type=%s",
			__entry->size, __entry->type)
	);

DEFINE_PAYLOAD_EVENT(header_detected);
DEFINE_PAYLOAD_EVENT(header_parsed);
DEFINE_PAYLOAD_EVENT(length_detected);
DEFINE_PAYLOAD_EVENT(length_parsed);
DEFINE_PAYLOAD_EVENT(data_detected);
DEFINE_PAYLOAD_EVENT(data_parsed);

#endif /* __IMG_BT_TRACE_H__ */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE etrace
#include <trace/define_trace.h>

