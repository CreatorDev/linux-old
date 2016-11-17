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
 *** File Name  : img-bt-main.c
 ***
 *** File Description:
 *** This file contains the implementation of the IMG Bluetooth
 *** transport protocol.
 ***
 ******************************************************************************
 *END**************************************************************************/
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <soc/img/img-transport.h>

#include "circ-buf-oneway.h"
#include "etrace.h"
#include "gateway.h"
#include "payload.h"

static const char *client_name = "img-bt";
#define dbg(format, ...) pr_debug("%s: " format, client_name, ## __VA_ARGS__)
#define err(format, ...) pr_err("%s: " format, client_name, ## __VA_ARGS__)
#define dbgn(format, ...) dbg(format "\n", ## __VA_ARGS__)
#define errn(format, ...) err(format "\n", ## __VA_ARGS__)
#define diagerrn(format, ...) \
	errn("%s : %d : " format, __func__, __LINE__, ## __VA_ARGS__)
#define diagdbgn(format, ...) \
	dbgn("%s : %d : " format, __func__, __LINE__, ## __VA_ARGS__)

#define ACK 1
#define REQUEST 0
#define CONTENT_MASK 0x7fff
#define CONTENT(msg) (msg & CONTENT_MASK)
#define TYPE_MASK 0x8000
#define TYPE(msg) ((msg & TYPE_MASK) >> 15)
#define RPU_ACK(length) ((u16)(length | 0x8000))
#define RPU_REQ(length) ((u16)(length & 0x7FFF))

#define BLUETOOTH_ID 1

typedef void __iomem *ioaddr_t;

/*
 * TODO: parameterize buffer length through module params
 */
static const resource_size_t buffer_length = 0x800;

static struct workqueue_struct *img_bt_workqueue;

static struct {
	struct circ_buf_out tx;
	struct circ_buf_in rx;
	phys_addr_t phys_base;
	ioaddr_t virt_base;
	resource_size_t length;
} xmit_buffers;

/*
 * *** Work structures depot ***
 *
 * TODO: measure how many work_structs are actually needed
 * with ACLs, because for any other command there should
 * only be one msg in that ring buffer at any given time.
 *
 */

#define WORK_DEPOT_SIZE (1<<5)
#define TX_BACKLOG_SIZE (1<<5)
struct message_xfer {
	union {
		struct payload *pld;
		u16 req_length;
	};
	struct work_struct tbd;
};
static struct message_xfer work_store[WORK_DEPOT_SIZE];
static DEFINE_KFIFO(work_depot, struct message_xfer*, WORK_DEPOT_SIZE);
static DEFINE_KFIFO(tx_backlog, struct payload*, TX_BACKLOG_SIZE);

static int work_depot_init(void)
{
	int i = 0;
	for (i = 0; i < WORK_DEPOT_SIZE; i++) {
		kfifo_put(&work_depot, work_store + i);
	}
	return 0;
}

static struct message_xfer *prepare_work(work_func_t todo, unsigned long data)
{
	struct message_xfer *work;
	if (!kfifo_get(&work_depot, &work)) {
		errn("no free work structures");
		return NULL;
	}
	INIT_WORK(&work->tbd, todo);
	return work;
}

static void return_work(struct message_xfer *work)
{
	kfifo_put(&work_depot, work);
}

static unsigned char next_char(void *buffer, unsigned idx)
{
	struct circ_buf_in *rx;
	u8 retval;

	rx = (struct circ_buf_in *)buffer;

	retval = (u8)ioread8((void __iomem *)circ_buf_in_read_offset(rx, idx));

	return retval;
}

static void payload_to_circ_buf_out(
		const struct payload *pld,
		struct circ_buf_out *buf)
{
	char c;
	int i;
	int length = payload_length(pld);

	for (i = 0; i < length; i++) {
		c = payload_at(pld, i);
		iowrite8(c, (void __iomem *)circ_buf_out_write_offset(buf, i));
	}
	circ_buf_out_write_done(buf, length);
}

static void do_tx_backlog(void)
{
	struct payload *pld;
	int dummy, length_sum = 0;

	if (kfifo_is_empty(&tx_backlog))
		return;

	while (kfifo_peek(&tx_backlog, &pld) &&
		circ_buf_out_space(&xmit_buffers.tx) >= payload_length(pld)) {

		length_sum += payload_length(pld);
		/*
		 * The following call must succeed because we checked
		 * kfifo_peek and the fifo is managed only by this
		 * background thread.
		 *
		 * Dummy read just to make __must_check_helper satisfied
		 */
		dummy = kfifo_get(&tx_backlog, &pld);
		payload_to_circ_buf_out(pld, &xmit_buffers.tx);
		payload_delete(pld);
	}

	if (length_sum > 0) {
		img_transport_notify(RPU_REQ((u16)length_sum), BLUETOOTH_ID);
		trace_hst_req_execd_catchup(BLUETOOTH_ID, length_sum);
	}
}

/*
 * *** Worker procs ***
 */

static void ack_from_controller(struct work_struct *tbd)
{
	struct message_xfer *work = container_of(tbd, struct message_xfer, tbd);
	u16 payload_length = work->req_length;

	circ_buf_out_write_rcvd(&xmit_buffers.tx, payload_length);

	return_work(work);

	do_tx_backlog();

	trace_ctl_ack_execd(BLUETOOTH_ID, payload_length);
}

static void req_from_controller(struct work_struct *tbd)
{
	u16 user_data_length;
	struct payload *pld;

	struct message_xfer *work = container_of(tbd, struct message_xfer, tbd);
	/*
	 * This is the length of the data that has just arrived
	 */
	user_data_length = work->req_length;
	if (0 == user_data_length)
		goto exit;

	do_tx_backlog();
	/*
	 * Push messages going from the controller
	 */
	pld = payload_from_string(user_data_length, next_char,
		&xmit_buffers.rx);
	/* TODO: service this call's failure */
	gateway_send(pld);

	circ_buf_in_read_done(&xmit_buffers.rx, user_data_length);
	img_transport_notify(RPU_ACK(user_data_length), BLUETOOTH_ID);

exit:
	return_work(work);
	trace_ctl_req_execd(BLUETOOTH_ID, user_data_length);
}

static void req_to_controller(struct work_struct *tbd)
{
	int space_needed, space_available;
	struct payload *pld;

	struct message_xfer *work = container_of(tbd, struct message_xfer, tbd);
	pld = work->pld;
	if (IS_ERR_OR_NULL(pld)) {
		diagerrn("payload is not a valid pointer");
		goto exit;
	}

	space_needed = payload_length(pld);
	space_available = circ_buf_out_space(&xmit_buffers.tx);
	if (space_needed <= space_available) {
		/*
		 * Process message going to the controller
		 */
		payload_to_circ_buf_out(pld, &xmit_buffers.tx);
		payload_delete(pld);
		img_transport_notify(RPU_REQ(space_needed), BLUETOOTH_ID);
		trace_hst_req_execd_sent(BLUETOOTH_ID, space_needed);
	} else {
		/*
		 * Save for backlog processing, which should be fired on every
		 * poke confirmation and controller ACK
		 */
		if (!kfifo_put(&tx_backlog, pld)) {
			diagerrn("no space in backlog, dropping payload");
			payload_delete(pld);
		}
		trace_hst_req_execd_delayed(BLUETOOTH_ID, space_needed);
	}

exit:
	return_work(work);
}

/*
 * *** Message handlers ***
 */
static void handle_gateway_message(struct payload *pld)
{
	struct message_xfer *work = prepare_work(req_to_controller,
			(unsigned long)pld);
	if (NULL == work) {
		diagerrn(
			"no more free work structures, payload dropped");
		payload_delete(pld);
		return;
	}
	trace_hst_req_sched(BLUETOOTH_ID, payload_length(pld));
	work->pld = pld;
	if (!queue_work(img_bt_workqueue, &work->tbd)) {
		diagerrn("bug : work already scheduled");
	}
}

static void handle_controller_message(u16 user_data)
{
	struct message_xfer *work;
	unsigned int content;
	content = CONTENT(user_data);
	switch (TYPE(user_data)) {
	case ACK:
		/* An acknowledgment has been received */
		work = prepare_work(ack_from_controller, content);
		work->req_length = content;
		/* Process whatever may be pending in the TX backlog */
		if (NULL == work)
			diagerrn("no more free work structures");
		trace_ctl_ack_sched(BLUETOOTH_ID, work->req_length);
		queue_work(img_bt_workqueue, &work->tbd);
		break;
	case REQUEST:
		/* A data request has arrived */
		work = prepare_work(req_from_controller, content);
		work->req_length = content;
		trace_ctl_req_sched(BLUETOOTH_ID, work->req_length);
		queue_work(img_bt_workqueue, &work->tbd);
		break;
	default:
		errn("received unknown message type from controller");
	}
}

/*
 * *** Platform API ***
 */

static int img_bt_pltfr_memsetup(void)
{
	img_bt_workqueue = create_singlethread_workqueue("img_bt_workqueue");
	if (IS_ERR_OR_NULL(img_bt_workqueue))
		return PTR_ERR(img_bt_workqueue);

	return 0;
}

static void img_bt_pltfr_memsetup_rollback(void)
{
	memset(&xmit_buffers, 0 , sizeof(xmit_buffers));
	return;
}

static int img_bt_pltfr_dtsetup(struct platform_device *pdev)
{
	const struct resource *buffers_area = platform_get_resource(pdev,
			IORESOURCE_MEM, 0);
	if (NULL == buffers_area) {
		errn("no DTS entry for buffers base address");
		return -ENOENT;
	}
	xmit_buffers.phys_base =
		(phys_addr_t)buffers_area->start;
	xmit_buffers.length =
		(resource_size_t)(buffers_area->end - buffers_area->start + 1);

	return 0;
}

static void img_bt_pltfr_dtsetup_rollback(void)
{
	return;
}

static int img_bt_pltfr_bufsetup(void)
{
	ioaddr_t tx_base, rx_base;
	int result = 0;

	if (NULL == request_mem_region(xmit_buffers.phys_base,
				xmit_buffers.length, client_name)) {
		err("could not request memory region : %p - %p\n",
				(ioaddr_t)xmit_buffers.phys_base,
				(ioaddr_t)(xmit_buffers.phys_base +
					xmit_buffers.length - 1));
		result = -ENOMEM;
		goto request_failed;
	}

	xmit_buffers.virt_base =
		ioremap(xmit_buffers.phys_base, xmit_buffers.length);

	if (NULL == xmit_buffers.virt_base) {
		errn("could not remap memory region : %p + %x",
				(ioaddr_t)xmit_buffers.phys_base,
				xmit_buffers.length);
		result = -ENOMEM;
		goto remap_failed;
	}

	/*
	 * TODO: this assumes contiguous placement
	 */
	rx_base = (ioaddr_t)((resource_size_t)xmit_buffers.virt_base + 0);
	tx_base = (ioaddr_t)((resource_size_t)xmit_buffers.virt_base +
								buffer_length);
	dbgn("tx buffer at : 0x%p", tx_base);
	dbgn("rx buffer at : 0x%p", rx_base);
	if (circ_buf_out_init(&xmit_buffers.tx, tx_base, buffer_length)) {
		errn("<out> circular buffer init failed, size is not "
					"a power of 2: %d", buffer_length);
		goto buffer_alloc_failed;
	}
	if (circ_buf_in_init(&xmit_buffers.rx, rx_base, buffer_length)) {
		errn("<in> circular buffer init failed, size is not "
					"a power of 2: %d", buffer_length);
		goto buffer_alloc_failed;
	}

	result = work_depot_init();
	if (result) {
		errn("workqueue init failed");
		goto work_depot_init_failed;
	}

	return result;

work_depot_init_failed:
	(void)0;
buffer_alloc_failed:
	(void)0;
remap_failed:
	release_mem_region(xmit_buffers.phys_base, xmit_buffers.length);
request_failed:
	return result;
}

static void img_bt_pltfr_bufsetup_rollback(void)
{
	iounmap(xmit_buffers.virt_base);
	release_mem_region(xmit_buffers.phys_base, xmit_buffers.length);
}

static int img_bt_pltfr_reg_handler(unsigned int client_id)
{
	return img_transport_register_callback(handle_controller_message,
			client_id);
}

static void img_bt_pltfr_reg_handler_rollback(unsigned int client_id)
{
	img_transport_remove_callback(client_id);
}

static int __init img_bt_pltfr_probe(struct platform_device *pdev)
{
	int result = 0;

	result = img_bt_pltfr_memsetup();
	if (result) {
		err("memory setup failed\n");
		goto memsetup_failed;
	}

	result = img_bt_pltfr_dtsetup(pdev);
	if (result) {
		err("DT setup failed\n");
		goto dtsetup_failed;
	}

	result = img_bt_pltfr_bufsetup();
	if (result) {
		err("buffer setup failed\n");
		goto bufsetup_failed;
	}

	result = img_bt_pltfr_reg_handler(BLUETOOTH_ID);
	if (result) {
		err("failed to install callback in the transport interface\n");
		goto callback_regist_failed;
	}

	result = gateway_init(handle_gateway_message, &pdev->dev);
	if (result) {
		errn("could not initialize gateway");
		goto gateway_init_failed;
	}

	return result;

gateway_init_failed:
	img_bt_pltfr_reg_handler_rollback(0);
callback_regist_failed:
	img_bt_pltfr_bufsetup_rollback();
bufsetup_failed:
	img_bt_pltfr_dtsetup_rollback();
dtsetup_failed:
	img_bt_pltfr_memsetup_rollback();
memsetup_failed:
	return result;
}

static int img_bt_pltfr_remove(struct platform_device *pdev)
{
	gateway_exit();
	destroy_workqueue(img_bt_workqueue);
	img_bt_pltfr_reg_handler_rollback(0);
	img_bt_pltfr_bufsetup_rollback();
	img_bt_pltfr_dtsetup_rollback();
	img_bt_pltfr_memsetup_rollback();

	return 0;
}

static const struct of_device_id img_bt_dt_ids[] = {
	{ .compatible = "img,pistachio-uccp-bt" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, img_bt_dt_ids);

struct platform_driver img_bt_driver = {
	.remove = img_bt_pltfr_remove,
	.driver = {
		.name   = "img-bt",
		.owner  = THIS_MODULE,
		.of_match_table = of_match_ptr(img_bt_dt_ids),
	},
};

/*
 * *** Entry and exit points ***
 */

static int __init img_bt_init(void)
{
	return platform_driver_probe(&img_bt_driver, img_bt_pltfr_probe);
}

static void __exit img_bt_exit(void)
{
	platform_driver_unregister(&img_bt_driver);
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Bartosz Flis <bartosz.flis@imgtec.com>");
MODULE_DESCRIPTION("Imagination Technologies Bluetooth driver - www.imgtec.com");

module_init(img_bt_init);
module_exit(img_bt_exit);
