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
 *** File Name  : img-bt-chardev.h
 ***
 *** File Description:
 *** This file contains concrete implementation of gateway interface -
 *** - serial device.
 ***
 ******************************************************************************
 *END**************************************************************************/

#include <linux/device.h>
#include <linux/serial.h>
#include <linux/serial_core.h>
#include <linux/string.h>
#include <linux/tty_flip.h>

#include "circ-buf-ext.h"
#include "etrace.h"
#include "gateway.h"
#include "payload.h"

static const char *client_name = "img-bt";
#define dbg(format, ...) pr_debug("%s: " format, client_name, ## __VA_ARGS__)
#define err(format, ...) pr_err("%s: " format, client_name, ## __VA_ARGS__)
#define dbgn(format, ...) dbg(format "\n", ## __VA_ARGS__)
#define errn(format, ...) err(format "\n", ## __VA_ARGS__)

/*
 * *** Private storage ***
 */

static struct {
	push_message push_client_msg;
	struct uart_port port;
} gateway;

static struct uart_driver img_bt_uart_driver = {
	.driver_name    = "img-bt-uart",
	.dev_name       = "ttyHS",
	.nr             = 1,
};

/*
 * *** Private procs ***
 */

static unsigned char next_char(void *port, unsigned int idx)
{
	unsigned char c;
	struct uart_port *uport = (struct uart_port *)port;
	struct circ_buf *xmit = &uport->state->xmit;
	(void)idx;

	c = xmit->buf[xmit->tail];
	xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
	uport->icount.tx++;
	return c;
}

static unsigned int img_bt_tx_empty(struct uart_port *port) { return 0; }
static void img_bt_set_mctrl(struct uart_port *port, unsigned int mctrl) {}
static unsigned int img_bt_get_mctrl(struct uart_port *port) { return 0; }
static void img_bt_break_ctl(struct uart_port *port, int break_state) {}
static void img_bt_enable_ms(struct uart_port *port) {}
static void img_bt_release_port(struct uart_port *port) {trace_tty_release_port(0);}
static int img_bt_request_port(struct uart_port *port) { trace_tty_request_port(0);return 0; }
static void img_bt_config_port(struct uart_port *port, int flags) {}
static int img_bt_verify_port(struct uart_port *port,
		struct serial_struct *ser) { return 0; }
static void img_bt_set_termios(struct uart_port *port, struct ktermios *new,
		struct ktermios *old) {}

static const char *img_bt_type(struct uart_port *port)
{
	return client_name;
}

static void img_bt_stop_rx(struct uart_port *port)
{
	trace_tty_stop_rx_requested(0);
}

static void img_bt_start_tx(struct uart_port *port)
{
	struct payload *pld;
	/*
	 * As this driver is intended to be used with the HCI line
	 * discipline, whenever this is called it means
	 * that some data has arrived from the top. Effectively,
	 * this proc plays the role of a TX interrupt in a proper
	 * UART driver.
	 */

	/*
	 * Author doesn't like this. State structure is supposed to be private
	 * to serial_core. TODO: find another way.
	 */
	struct circ_buf *xmit = &port->state->xmit;

	trace_tty_start_tx(CIRC_CNT(xmit->head, xmit->tail, UART_XMIT_SIZE));

	if (uart_circ_empty(xmit))
		return;

	/*
	 * next_char is guaranteed not to be called
	 * if this function returns error
	 */
	pld = payload_from_string(uart_circ_chars_pending(xmit),
		next_char,
		port);
	if (IS_ERR_OR_NULL(pld))
		return;

	gateway.push_client_msg(pld);

}

static void img_bt_stop_tx(struct uart_port *port)
{
	trace_tty_stop_tx(0);
}

static void img_bt_shutdown(struct uart_port *port)
{
	trace_tty_shutdown_port(0);
}

static int img_bt_startup(struct uart_port *port)
{
	trace_tty_startup_port(0);
	return 0;
}

/* serial core callbacks */
static struct uart_ops img_bt_ops = {
	.tx_empty       = img_bt_tx_empty,
	.get_mctrl      = img_bt_get_mctrl,
	.set_mctrl      = img_bt_set_mctrl,
	.start_tx       = img_bt_start_tx,
	.stop_tx        = img_bt_stop_tx,
	.stop_rx        = img_bt_stop_rx,
	.enable_ms      = img_bt_enable_ms,
	.break_ctl      = img_bt_break_ctl,
	.startup        = img_bt_startup,
	.shutdown       = img_bt_shutdown,
	.set_termios    = img_bt_set_termios,
	.type           = img_bt_type,
	.release_port   = img_bt_release_port,
	.request_port   = img_bt_request_port,
	.config_port    = img_bt_config_port,
	.verify_port    = img_bt_verify_port,
};

/*
 * *** Public API ***
 */

int gateway_init(push_message push_f, struct device *pdev)
{
	int ret;

	ret = uart_register_driver(&img_bt_uart_driver);
	if (ret) {
		errn("failed to register serial driver : errno %d", ret);
		goto uart_register_driver_failed;
	}

	gateway.push_client_msg = push_f;

	memset(&gateway.port, 0, sizeof(gateway.port));
	gateway.port.dev = pdev;
	gateway.port.ops = &img_bt_ops;
	gateway.port.type = PORT_HOSTPORT;
	ret = uart_add_one_port(&img_bt_uart_driver, &gateway.port);
	if (ret) {
		errn("adding uart port failed");
		goto uart_add_one_port_failed;
	}
	return 0;

uart_add_one_port_failed:
	uart_unregister_driver(&img_bt_uart_driver);
uart_register_driver_failed:
	return ret;
}

void gateway_exit(void)
{
	uart_remove_one_port(&img_bt_uart_driver, &gateway.port);
	uart_unregister_driver(&img_bt_uart_driver);
}

int gateway_send(struct payload *pld)
{
	trace_tty_flip_depleted(tty_buffer_space_avail(&gateway.port.state->port));
	tty_insert_flip_string(&gateway.port.state->port,
		payload_raw(pld),
		payload_length(pld));
	tty_flip_buffer_push(&gateway.port.state->port);
	payload_delete(pld);

	return 0;
}
