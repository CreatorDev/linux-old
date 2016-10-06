/*
 * File Name  : hal_hostport.c
 *
 * This file contains the source functions of HAL IF for hostport+shared
 * memmory based communications
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
#include <asm/unaligned.h>

#include <linux/clk.h>
#include <linux/etherdevice.h>
#include <linux/iio/consumer.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/of_device.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/syscore_ops.h>
#include <linux/time.h>


#include "core.h"
#include "fwldr.h"
#include "hal.h"
#include "hal_hostport.h"


#define COMMAND_START_MAGIC 0xDEAD

static int is_mem_dma(void *virt_addr, int len);
static int init_rx_buf(int pkt_desc,
		       unsigned int max_data_size,
		       dma_addr_t *dma_buf,
		       struct sk_buff *new_skb);

static int is_mem_bounce(void *virt_addr, int len);

static struct hal_priv *hpriv;
static const char *hal_name = "UCCP420_WIFI_HAL";

static unsigned long shm_offset = HAL_SHARED_MEM_OFFSET;
module_param(shm_offset, ulong, S_IRUSR|S_IWUSR);

unsigned int hal_cmd_sent;
unsigned int hal_event_recv;
struct timer_list stats_timer;
unsigned int alloc_skb_failures;
unsigned int alloc_skb_dma_region;
unsigned int alloc_skb_priv_tx_region;
unsigned int alloc_skb_priv_rx_region;
unsigned int alloc_skb_priv_runtime;

static unsigned int uccp_ddr_base;

#ifdef PERF_PROFILING
/* The timing markers */
unsigned long irq_timestamp[20] = {0};
unsigned long rcv_hdlr_time[20] = {0};
unsigned long rx_pkts_halint_event[20] = {0};
unsigned long halint_event_handling_time[20] = {0};
unsigned long pflags;

/*Indexs for current sample*/
unsigned int halint_handling_index;
unsigned int rx_pkt_index;
unsigned int rcv_hdlr_index;
unsigned int irq_ts_index;
spinlock_t  timing_lock;
#endif

#ifdef HAL_DEBUG
#define _HAL_DEBUG(fmt, args...) pr_debug(fmt, ##args)
#else /* CONFIG_HAL_DEBUG */
#define _HAL_DEBUG(...) do { } while (0)
#endif /* CONFIG_HAL_DEBUG */

#define UCCP_DEBUG_HAL(fmt, ...)                           \
do {							\
	if ((uccp_debug & UCCP_DEBUG_HAL) && net_ratelimit()) \
		pr_debug(fmt, ##__VA_ARGS__);	 \
} while (0)

#define UCCP_DEBUG_DUMP_HAL(fmt, ...)                           \
do {							\
	if (uccp_debug & UCCP_DEBUG_DUMP_HAL)			\
		print_hex_dump(KERN_DEBUG, fmt, ##__VA_ARGS__);	 \
} while (0)

#define DUMP_HAL (uccp_debug & UCCP_DEBUG_DUMP_HAL)

/* for send and receive count. */
static unsigned long tx_cnt;
static unsigned long rx_cnt;
/*UCCP_DEBUG_HAL */

unsigned char vif_macs[2][ETH_ALEN];

static char *mac_addr;
module_param(mac_addr, charp, 0000);
MODULE_PARM_DESC(mac_addr, "Configure wifi base mac address");

#define RF_PARAMS_SIZE 369
unsigned char rf_params[RF_PARAMS_SIZE];
unsigned char *rf_params_vpd;
int num_streams_vpd = -1;

/* Range check */
#define CHECK_EVENT_ADDR_UCCP(x) ((x) >= HAL_UCCP_GRAM_BASE && (x) <=\
				  (HAL_UCCP_GRAM_BASE + \
				  hpriv->uccp_pkd_gram_len))

#define CHECK_EVENT_STATUS_ADDR_UCCP(x) ((x) >= HAL_UCCP_GRAM_BASE && (x) <=\
					 (HAL_UCCP_GRAM_BASE + \
					 hpriv->uccp_pkd_gram_len))

#define CHECK_EVENT_LEN(x) ((x) < 0x5000)
#define CHECK_RX_PKT_CNT(x) ((x) >= 1 && (x) <= 16)
/* #define CHECK_SRC_PTR(x, y) ((x) >= (y) && (x) <= (y) +
 * HAL_HOST_BOUNCE_BUF_LEN)
 */
#define CHECK_PKT_DESC(x) ((x) < (hpriv->rx_bufs_2k + hpriv->rx_bufs_12k))
/* MAX_RX_BUFS */

#define DEFAULT_MAC_ADDRESS "001122334455"

static void __iomem *get_base_address_64mb(unsigned int bounce_addr)
{
	int boundary = 0x4000000 /*64MB*/;
	unsigned int chunk_start_offset;
	unsigned int chunk_start, next_chunk_start;

	/* divide the DDR in to 64MB chunks.
	 * and return the chuunk address base corresponding to the
	 * 4mb_addr.
	 */
	chunk_start_offset = (unsigned int) bounce_addr/boundary;
	chunk_start = chunk_start_offset * boundary;
	next_chunk_start = (chunk_start_offset + 1) * boundary;

	/* 4MB region spans across chunks, program
	 * bounce_addr-60MB as start of 64MB region.
	 */
	if (bounce_addr + HAL_HOST_BOUNCE_BUF_LEN > next_chunk_start) {
		pr_info("%s: bounce_addr spans across chunks\n", __func__);
		chunk_start = bounce_addr - HAL_HOST_NON_BOUNCE_BUF_LEN;
	}

	pr_info("bounce_addr: 0x%x chunk_start: 0x%x\n",
		(unsigned int) bounce_addr,
		chunk_start_offset);

	return (void __iomem *) (chunk_start);
}


int hal_get_dump_len(unsigned long dump_type)
{
	unsigned int dump_len = 0;

	switch (dump_type) {
	case HAL_RPU_TM_CMD_GRAM:
		dump_len = hpriv->uccp_pkd_gram_len;
	break;
	case HAL_RPU_TM_CMD_COREA:
		dump_len = UCCP_COREA_REGION_LEN;
	break;
	case HAL_RPU_TM_CMD_COREB:
		dump_len = UCCP_COREB_REGION_LEN;
	break;
	case HAL_RPU_TM_CMD_PERIP:
		dump_len = hpriv->uccp_perip_len;
	break;
	case HAL_RPU_TM_CMD_SYSBUS:
		dump_len = hpriv->uccp_sysbus_len;
	break;
	default:
		dump_len = 0;
	}
	return dump_len;
}

int hal_get_dump_gram(long *dump_start)
{
	char *gram_dump;

	gram_dump = kzalloc(hpriv->uccp_pkd_gram_len, GFP_KERNEL);

	if (!dump_start)
		return -ENOMEM;

	memcpy(gram_dump,
	       (char *)hpriv->gram_base_addr,
	       hpriv->uccp_pkd_gram_len);

	*dump_start = (long) gram_dump;

	return 0;
}

int hal_get_dump_core(unsigned long  *dump_start, unsigned char region_type)
{
	unsigned int *core_dump;
	unsigned long len = 0;
	unsigned long region_start = 0;

	if (region_type == UCCP_REGION_TYPE_COREA) {
		len = UCCP_COREA_REGION_LEN;
		region_start = UCCP_COREA_REGION_START;
	} else if (region_type  == UCCP_REGION_TYPE_COREB) {
		len = UCCP_COREB_REGION_LEN;
		region_start = UCCP_COREB_REGION_START;
	}

	core_dump = kzalloc(len, GFP_KERNEL);

	if (!core_dump)
		return -ENOMEM;

	if (len % 4)
		len = len/4 + 1;
	else
		len = len/4;

	rpudump_init();

	core_mem_read(region_start, core_dump, len);

	*dump_start = (unsigned long) core_dump;

	return 0;

}

int hal_get_dump_perip(unsigned long  *dump_start)
{
	unsigned int *perip_dump;

	perip_dump = kzalloc(hpriv->uccp_perip_len, GFP_KERNEL);

	if (!perip_dump)
		return -ENOMEM;

	memcpy(perip_dump,
	       (char *)hpriv->uccp_perip_base_addr,
	       hpriv->uccp_perip_len);

	*dump_start = (unsigned long) perip_dump;

	return 0;
}

int hal_get_dump_sysbus(unsigned long  *dump_start)
{
	unsigned int *sysbus_dump;

	sysbus_dump = kzalloc(hpriv->uccp_sysbus_len, GFP_KERNEL);

	if (!sysbus_dump)
		return -ENOMEM;

	memcpy(sysbus_dump,
	       (char *)hpriv->uccp_sysbus_base_addr,
	       hpriv->uccp_sysbus_len);

	*dump_start = (unsigned long) sysbus_dump;
	return 0;

}

static int hal_reset_hal_params(void)
{
	hpriv->cmd_cnt = COMMAND_START_MAGIC;
	hpriv->event_cnt = 0;
	return 0;
}


static int hal_ready(struct hal_priv *priv)
{
	unsigned int value = 0;

	/* Check the ACK register bit */
	value =  readl((void __iomem *)(HOST_TO_UCCP_CORE_CMD_ADDR));

	if (value & BIT(UCCP_CORE_HOST_INT_SHIFT))
		return 0;
	else
		return 1;
}


static void tx_tasklet_fn(unsigned long data)
{
	struct hal_priv *priv = (struct hal_priv *)data;
	struct sk_buff *skb;
	unsigned int value = 0;
	unsigned long start_addr;
	unsigned long start = 0;

	while ((skb = skb_dequeue(&priv->txq))) {
		tx_cnt++;
		UCCP_DEBUG_HAL("%s: tx_cnt=%ld cmd_cnt=0x%X event_cnt=0x%X\n",
				hal_name,
				tx_cnt,
				priv->cmd_cnt,
				priv->event_cnt);
		if (DUMP_HAL) {
			UCCP_DEBUG_HAL("%s: xmit dump\n", hal_name);
			UCCP_DEBUG_DUMP_HAL(" ", DUMP_PREFIX_NONE, 16, 1,
					 skb->data, skb->len, 1);
		}

		start = jiffies;

		while (!hal_ready(priv) &&
		     time_before(jiffies, start + msecs_to_jiffies(1000))) {
			cpu_relax();
		}

		if (!hal_ready(priv)) {
			pr_err("%s: Intf not ready for 1000ms, dropping cmd\n",
			       hal_name);
			dev_kfree_skb_any(skb);
			skb = NULL;
		}

		if (!skb)
			continue;

		if (priv->hal_disabled)
			break;

		/* Write the command buffer in GRAM */
		start_addr = readl((void __iomem *)HAL_GRAM_CMD_START);

		UCCP_DEBUG_HAL("%s: Command address = 0x%08x\n",
			 hal_name, (unsigned int)start_addr);

		start_addr -= HAL_UCCP_GRAM_BASE;
		start_addr += ((priv->gram_mem_addr)-(priv->shm_offset));

		if ((start_addr < priv->gram_mem_addr) ||
		    (start_addr > (priv->gram_mem_addr + HAL_WLAN_GRAM_LEN))) {
			pr_err("%s: Invalid cmd addr 0x%08x, dropping cmd\n",
			       hal_name, (unsigned int)start_addr);
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		memcpy((unsigned char *)start_addr, skb->data, skb->len);

		writel(skb->len, (void __iomem *)HAL_GRAM_CMD_LEN);

		value = (unsigned int) (priv->cmd_cnt);
		value |= 0x7fff0000;
		writel(value, (void __iomem *)(HOST_TO_UCCP_CORE_CMD_ADDR));
		priv->cmd_cnt++;
		hal_cmd_sent++;

		dev_kfree_skb_any(skb);
	}
}


static void hostport_send(struct hal_priv  *priv,
			  struct sk_buff   *skb)
{
	skb_queue_tail(&priv->txq, skb);
	tasklet_schedule(&priv->tx_tasklet);
}

static void hostport_send_head(struct hal_priv  *priv,
			  struct sk_buff   *skb)
{
	skb_queue_head(&priv->txq, skb);
	tasklet_schedule(&priv->tx_tasklet);
}


static void hal_send(void *nwb,
		     unsigned char rcv_mod_id,
		     unsigned char send_mod_id,
		     void *dataptr)
	{
	struct sk_buff *cmd = (struct sk_buff *)nwb, *skb, *tmp;
	struct sk_buff_head *skb_list;
	struct hal_hdr *hdr;
	unsigned long dcp_start_addr;
	unsigned int pkt = 0, desc_id = 0, frame_id = 0;
	struct hal_tx_data *hal_tx_data = NULL;
	struct buf_info *tx_buf_info = NULL;
	dma_addr_t dma_buf;

	if (dataptr) {
		hdr = (struct hal_hdr *)cmd->data;
		skb_list = (struct sk_buff_head *)dataptr;

		/* Struct of CMD's are hal_data + desc_id + payload_len*/
		desc_id = (*(unsigned int *)(cmd->data + HAL_PRIV_DATA_SIZE)) &
			   0x0000FFFF;

		skb_queue_walk_safe(skb_list, skb, tmp)
			{
			frame_id = (desc_id * NUM_FRAMES_IN_TX_DESC) + pkt;
			hal_tx_data = &hpriv->hal_tx_data[frame_id];
			tx_buf_info = &hpriv->tx_buf_info[frame_id];

			hal_tx_data->data_len = tx_buf_info->dma_buf_len;

			dma_buf = tx_buf_info->dma_buf;
			dma_buf -= uccp_ddr_base;

			hal_tx_data->address = dma_buf >> 2;
			hal_tx_data->offset = dma_buf & 0x00000003;
			pkt++;
			}

		dcp_start_addr = HAL_GRAM_TX_DATA_START +
				 (desc_id * TX_DESC_HAL_SIZE);

		memcpy((void *)dcp_start_addr,
		       &hpriv->hal_tx_data[(desc_id * NUM_FRAMES_IN_TX_DESC)],
		       TX_DESC_HAL_SIZE);
	}

	hostport_send(hpriv, nwb);

}

static void recv_tasklet_fn(unsigned long data)
{

	struct hal_priv *priv = (struct hal_priv *)data;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&priv->refillq))) {
		/* As we refilled the buffers, now pass them UP */
		priv->rcv_handler(skb, LMAC_MOD_ID);
	}
}

static void rx_tasklet_fn(unsigned long data)
{
	struct hal_priv *priv = (struct hal_priv *)data;
	struct sk_buff  *skb;
	unsigned char *buf;
	unsigned long temp;
	unsigned char *nbuff;
	struct event_hal *evnt;
	struct cmd_hal cmd_rx;
	struct sk_buff *nbuf, *rx_skb;
	unsigned char *cmd_data;
	unsigned int payload_length, length, data_length;
	void __iomem *src_ptr;
	int count = 0;
	unsigned int pkt_desc = 0, max_data_size = MAX_DATA_SIZE_2K;
	dma_addr_t dma_buf = 0;
	unsigned long event_addr, event_status_addr, event_len;
#ifdef PERF_PROFILING
	struct timeval  tv_start, tv_now, full_tv_start, full_tv_now;
	long usec_diff = 0, full_usec_diff = 0;
#endif
	struct buf_info *rx_buf_info = NULL;
	struct buf_info temp_rx_buf_info;
	struct sk_buff *new_skb;

	while ((skb = skb_dequeue(&priv->rxq))) {
		event_addr = *((unsigned long *)(skb->cb));
		event_status_addr = *((unsigned long *)(skb->cb + 4));
		event_len = *(unsigned long *)(skb->cb + 8);

		/* Range check */
		if (skb->len > event_len) {
			pr_err("%s: Err! skb->len=%d, event_len =%d\n",
			       __func__, skb->len, (int)event_len);
			dev_kfree_skb_any(skb);
			continue;
		}

		temp = event_addr;
		buf = skb_put(skb, event_len);
		memcpy(buf, (unsigned char *)temp, skb->len);

		/* Mark the buffer free */
		temp = event_status_addr;

		UCCP_DEBUG_HAL("%s: Freeing event buffer at 0x%08x\n",
			 hal_name, (unsigned int)temp);

		*((unsigned long *)temp) = 0;

		rx_cnt++;
		UCCP_DEBUG_HAL("%s:rx_cnt=%ld cmd_cnt=0x%X event_cnt=0x%X\n",
			 hal_name, rx_cnt, priv->cmd_cnt, priv->event_cnt);
		if (DUMP_HAL) {
			UCCP_DEBUG_HAL("%s: recv dump\n", hal_name);
			UCCP_DEBUG_DUMP_HAL(" ", DUMP_PREFIX_NONE, 16, 1,
						skb->data, skb->len, 1);
		}
		nbuff = skb->data;
		evnt = (struct event_hal *)nbuff;

		/* Message from HAL after the DMA completion,
		 * Fetch the buffer addrs from UCCP HOST RAM
		 * Copy them to the skb
		 * Pass them up
		 * Refresh the RX descriptor in firmware
		 */
		if (evnt->hdr.id == 0xffffffff) {
			/* HAL_INTERNAL CMD */
			memset(&cmd_rx, 0, sizeof(struct cmd_hal));

			if (!CHECK_RX_PKT_CNT(evnt->rx_pkt_cnt)) {
				/* Range check */
				pr_err("%s: Error!!! rx_pkt_cnt = %d\n",
				       __func__, evnt->rx_pkt_cnt);
				dev_kfree_skb_any(skb);
				continue;
			}

#ifdef PERF_PROFILING
			do_gettimeofday(&full_tv_start);

			/* HAL Profile Stat: Rx Pkts per HAL internal Event */
			rx_pkts_halint_event[rx_pkt_index] = evnt->rx_pkt_cnt;
			rx_pkt_index = (rx_pkt_index + 1) % 20;
#endif
			for (count = 0; count < evnt->rx_pkt_cnt; count++) {
				pkt_desc = evnt->rx_pkt_desc[count];

				/* Range check */
				if (!CHECK_PKT_DESC(pkt_desc)) {
					pr_err("%s: Error!!! pkt_desc = %d\n",
					       __func__, pkt_desc);

					/* Drop all the remaining buffers: As
					 * per Design They will not be reclaimed
					 * by FW.
					 */
					break;
				}

				if (pkt_desc < hpriv->rx_bufs_12k)
					max_data_size = MAX_DATA_SIZE_12K;

				if (hpriv->rx_buf_info == NULL)
					break;

				rx_buf_info = hpriv->rx_buf_info + pkt_desc;

				memcpy(&temp_rx_buf_info,
				       rx_buf_info,
				       sizeof(struct buf_info));

				dma_unmap_single(NULL,
						 rx_buf_info->dma_buf,
						 rx_buf_info->dma_buf_len,
						 DMA_FROM_DEVICE);

				dma_buf = rx_buf_info->dma_buf;
				src_ptr = rx_buf_info->src_ptr;


				UCCP_DEBUG_HAL("%s: dma_buf = 0x%08X\n",
						hal_name,
						(unsigned int)dma_buf);

				UCCP_DEBUG_HAL("%s: src_ptr = 0x%08X\n",
					       hal_name,
					       (unsigned int)src_ptr);

				if (DUMP_HAL) {
					UCCP_DEBUG_HAL("DMA data dump:");
					UCCP_DEBUG_HAL(" size=200\n");
					UCCP_DEBUG_DUMP_HAL(" ",
							DUMP_PREFIX_NONE, 16,
							1, src_ptr, 200, 1);
				}

				/* Offset in UMAC_LMAC_MSG_HDR, points to
				 * payload_length
				 */

				/* 802.11hdr + payload Len*/
				payload_length = *(((unsigned int *)src_ptr) +
						   3);
				length = *(((unsigned int *)src_ptr) + 5);

				/* Control Info Len*/
				data_length = payload_length + length;

				/* Complete data length to be copied */
				UCCP_DEBUG_HAL("%s: Payload Len =%d(0x%x), ",
					   hal_name,
					   payload_length,
					   payload_length);

				UCCP_DEBUG_HAL("Len=%d(0x%x), ",
					   length,
					   length);

				UCCP_DEBUG_HAL("Data Len = %d(0x%x)\n",
					   data_length,
					   data_length);

				if (data_length > max_data_size) {
					pr_err("Max length exceeded:");
					pr_err(" payload_len: %d len:%d",
						payload_length,
						length);
					pr_err(" data_len:%d desc:%d\n",
						data_length,
						pkt_desc);


					pr_err("Event from LMAC:");
					print_hex_dump(KERN_DEBUG,
						       "",
						       DUMP_PREFIX_NONE,
						       16,
						       1,
						       skb->data,
						       skb->len,
						       1);

					pr_err("DMA Data from LMAC:");
					print_hex_dump(KERN_DEBUG,
						       "",
						       DUMP_PREFIX_NONE,
						       16,
						       1,
						       src_ptr,
						       200,
						       1);

					/* Do not send the packet UP,
					 * just refill the buffer
					 * and give it to HW, for
					 * non-DMA case give the same
					 * buffer.
					 */
					dma_map_single(NULL,
						       rx_buf_info->src_ptr,
						       max_data_size,
						       DMA_FROM_DEVICE);
					cmd_rx.rx_pkt_data.rx_pkt_cnt++;
					cmd_rx.rx_pkt_data.rx_pkt[count].desc =
						evnt->rx_pkt_desc[count];
					cmd_rx.rx_pkt_data.rx_pkt[count].ptr  =
						dma_buf - uccp_ddr_base;
					continue;
				}

				new_skb = alloc_skb(max_data_size, GFP_ATOMIC);

				if (!new_skb) {
					/* If allocation fails, drop the packet,
					 * continue
					 */
					memcpy(rx_buf_info,
					       &temp_rx_buf_info,
					       sizeof(struct buf_info));

					dma_map_single(NULL,
						       rx_buf_info->src_ptr,
						       max_data_size,
						       DMA_FROM_DEVICE);

					dma_buf = rx_buf_info->dma_buf;
				} else {
					rx_skb = temp_rx_buf_info.skb;

					if (temp_rx_buf_info.dma_buf_priv) {
						memcpy(skb_put(rx_skb,
						       data_length),
						       src_ptr,
						       data_length);

					} else {
						skb_put(rx_skb, data_length);
					}

					init_rx_buf(pkt_desc, max_data_size,
						    &dma_buf, new_skb);
					skb_queue_tail(&hpriv->refillq, rx_skb);
				}

				cmd_rx.rx_pkt_data.rx_pkt_cnt++;
				cmd_rx.rx_pkt_data.rx_pkt[count].desc =
					evnt->rx_pkt_desc[count];
				cmd_rx.rx_pkt_data.rx_pkt[count].ptr =
					dma_buf - uccp_ddr_base;

			}

			if (cmd_rx.rx_pkt_data.rx_pkt_cnt != 0) {
				cmd_rx.hdr.id = 0xffffffff;

				/* Inform HAL about the newly allocated
				 * buffers
				 */
				nbuf = alloc_skb(sizeof(struct cmd_hal),
						 GFP_ATOMIC);
				if (nbuf) {
					cmd_data = skb_put(nbuf,
						   sizeof(struct cmd_hal));

					memcpy(cmd_data,
					       (unsigned char *)&cmd_rx,
					       sizeof(struct cmd_hal));
					hal_cmd_sent--;
					hostport_send_head(hpriv, nbuf);

				}
			}

#ifdef PERF_PROFILING
			do_gettimeofday(&full_tv_now);

			if ((full_tv_now.tv_sec - full_tv_start.tv_sec) == 0) {
				full_usec_diff = full_tv_now.tv_usec -
						 full_tv_start.tv_usec;
			} else {
				/* Exceeding the second */
				full_usec_diff = full_tv_now.tv_usec +
						 (((1000 * 1000) -
						  full_tv_start.tv_usec) + 1);
			}

			spin_lock_irqsave(&timing_lock, pflags);

			halint_event_handling_time[halint_handling_index] =
			full_usec_diff;

			halint_handling_index = (halint_handling_index +
						 1) % 20;

			spin_unlock_irqrestore(&timing_lock, pflags);

			/* Start the Timer for RCV Handler Profiling */
			do_gettimeofday(&tv_start);
#endif
			tasklet_schedule(&priv->recv_tasklet);
#ifdef PERF_PROFILING
			do_gettimeofday(&tv_now);

			if ((tv_now.tv_sec - tv_start.tv_sec) == 0) {
				usec_diff = tv_now.tv_usec - tv_start.tv_usec;
			} else {
				/* exceeding the second */
				usec_diff = tv_now.tv_usec +
					    (((1000 * 1000) -
					      tv_start.tv_usec) + 1);
			}

			spin_lock_irqsave(&timing_lock, pflags);

			rcv_hdlr_time[rcv_hdlr_index] = usec_diff;
			rcv_hdlr_index = (rcv_hdlr_index + 1)%20;

			spin_unlock_irqrestore(&timing_lock, pflags);
#endif
			/* Internal CMD, Free it */
			dev_kfree_skb_any(skb);

		} else	{
			/* MSG from LMAC, non-data*/
			hal_event_recv++;
			priv->rcv_handler(skb, LMAC_MOD_ID);
		}
	}
}


static void hal_register_callback(msg_handler handler,
				  unsigned char mod_id)
{
	hpriv->rcv_handler = handler;
}


static irqreturn_t hal_irq_handler(int    irq, void  *p)
{

	unsigned int value;
	unsigned long event_addr, event_status_addr, event_len;
	unsigned char spurious;
	struct sk_buff *skb;
	struct hal_priv *priv = (struct hal_priv *)p;
#ifdef PERF_PROFILING
	long usec_diff;
	struct timeval tv_start, tv_now;
#endif
	int is_err = 0;

	spurious = 0;

	value = readl((void __iomem *)(UCCP_CORE_TO_HOST_CMD_ADDR)) &
		0x7fffffff;
	if (value == (0x7fff0000 | priv->event_cnt)) {
#ifdef PERF_PROFILING
		do_gettimeofday(&tv_start);
#endif
#ifdef CONFIG_PM
		rx_interrupt_status = 1;
#endif
		event_addr = readl((void __iomem *)HAL_GRAM_EVENT_START);
		event_status_addr = readl((void __iomem *)(HAL_GRAM_EVENT_START
							   + 4));
		event_len = readl((void __iomem *)(HAL_GRAM_EVENT_START + 8));

		/* Range check */
		if (!(CHECK_EVENT_ADDR_UCCP(event_addr)) ||
		    !(CHECK_EVENT_STATUS_ADDR_UCCP(event_status_addr)) ||
		    !CHECK_EVENT_LEN(event_len)) {
			pr_err("%s: Error!!! event_addr = 0x%08x\n",
			       __func__,
			       (unsigned int)event_addr);

			pr_err("%s: Error!!! event_len =%d\n",
			       __func__,
			       (int)event_len);

			pr_err("%s: Error!!! event_status_addr = 0x%08x\n",
			       __func__,
			       (unsigned int)event_status_addr);

			is_err = 1;
		}
		UCCP_DEBUG_HAL("%s: event address = 0x%08x\n",
			hal_name,
			(unsigned int)event_addr);
		UCCP_DEBUG_HAL("%s: event status address = 0x%08x\n",
			hal_name,
			(unsigned int)event_status_addr);
		UCCP_DEBUG_HAL("%s: event len = %d\n",
			hal_name,
			(int)event_len);

		if (unlikely(is_err)) {
			/* If addr is valid try to clear */
			if (CHECK_EVENT_STATUS_ADDR_UCCP(event_status_addr)) {
				event_status_addr -= HAL_UCCP_GRAM_BASE;
				event_status_addr += ((priv->gram_mem_addr) -
						      (priv->shm_offset));
				*((unsigned long *)event_status_addr) = 0;
			} else
				pr_err("%s: UCCP status addr invalid, not clearing it\n",
				       hal_name);

			return IRQ_HANDLED;
		}

		event_addr -= HAL_UCCP_GRAM_BASE;
		event_status_addr -= HAL_UCCP_GRAM_BASE;
		event_addr += ((priv->gram_mem_addr) - (priv->shm_offset));
		event_status_addr += ((priv->gram_mem_addr) -
				      (priv->shm_offset));

		skb = dev_alloc_skb(event_len);

		if (!skb) {
			*((unsigned long *)event_status_addr) = 0;
		} else {
			*(unsigned long *)(skb->cb) = event_addr;

			/* Address of event payload */
			*(unsigned long *)(skb->cb + 4) = event_status_addr;

			/* Address to mark free */
			*(unsigned long *)(skb->cb + 8) = event_len;

			/* Length of event payload */
			skb_queue_tail(&priv->rxq, skb);
			tasklet_schedule(&priv->rx_tasklet);
		}

		priv->event_cnt++;
	} else {
		spurious = 1;
	}

	if (!spurious) {
		/* Clear the uccp interrupt */
		value = 0;
		value |= BIT(UCCP_CORE_INT_CLR_SHIFT);
		writel(*((unsigned long   *)&(value)),
		(void __iomem *)(HOST_TO_UCCP_CORE_ACK_ADDR));
	} else {
		pr_warn("%s: Spurious interrupt received\n", hal_name);

	}

#ifdef PERF_PROFILING
	do_gettimeofday(&tv_now);

	if ((tv_now.tv_sec - tv_start.tv_sec) == 0) {
		usec_diff = tv_now.tv_usec - tv_start.tv_usec;
	} else {
		/* Exceeding the second */
		usec_diff = tv_now.tv_usec +
			    (((1000 * 1000) - tv_start.tv_usec) + 1);
	}

	spin_lock_irqsave(&timing_lock, pflags);

	irq_timestamp[irq_ts_index] = usec_diff;
	irq_ts_index = (irq_ts_index + 1)%20;

	spin_unlock_irqrestore(&timing_lock, pflags);
#endif
	return IRQ_HANDLED;
}


static void hal_enable_int(void  *p)
{
	unsigned int   value = 0;

	/* Set external pin irq enable for host_irq and uccp_irq */
	value = readl((void __iomem *)UCCP_CORE_INT_ENAB_ADDR);
	value |= BIT(UCCP_CORE_INT_IRQ_ENAB_SHIFT);

	writel(*((unsigned long   *)&(value)),
	       (void __iomem *)(UCCP_CORE_INT_ENAB_ADDR));

	/* Enable raising uccp_int when UCCP_INT = 1 */
	value = 0;
	value |= BIT(UCCP_CORE_INT_EN_SHIFT);
	writel(*((unsigned long *)&(value)),
	       (void __iomem *)(UCCP_CORE_INT_ENABLE_ADDR));
}


static void hal_disable_int(void  *p)
{
	unsigned int value = 0;

	/* Reset external pin irq enable for host_irq and uccp_irq */
	value = readl((void __iomem *)UCCP_CORE_INT_ENAB_ADDR);
	value &= ~(BIT(UCCP_CORE_INT_IRQ_ENAB_SHIFT));
	writel(*((unsigned long   *)&(value)),
	       (void __iomem *)(UCCP_CORE_INT_ENAB_ADDR));

	/* Disable raising uccp_int when UCCP_INT = 1 */
	value = 0;
	value &= ~(BIT(UCCP_CORE_INT_EN_SHIFT));
	writel(*((unsigned long *)&(value)),
	       (void __iomem *)(UCCP_CORE_INT_ENABLE_ADDR));
}


#ifdef PERF_PROFILING
static int ulong_cmp(const void *a, const void *b)
{
	return *(unsigned long *)a - *(unsigned long *)b;
}


static int avg_array(unsigned long *arr, unsigned int max_index)
{
	unsigned int index;
	unsigned int avg = 0;

	if (!max_index)
		return 0;

	for (index = 0; index < max_index; index++)
		avg += arr[index];

	return avg/max_index;
}


static int max_array(unsigned long *arr, unsigned int max_index)
{
	sort(arr, max_index, sizeof(unsigned long), ulong_cmp, NULL);
	return arr[max_index-1];
}
#endif


static int proc_write_hal_stats(struct file          *file,
		const char __user    *buffer,
		size_t		     count,
		loff_t               *ppos)
{
	char buf[50];
	unsigned long val;

	if (count >= sizeof(buf))
		count = sizeof(buf)-1;

	if (copy_from_user(buf, buffer, count))
		return -EFAULT;
	buf[count] = '\0';

	if (param_get_val(buf, "get_gram_dump=", &val))
		hal_get_dump_gram(&val);
	else if (param_get_val(buf, "get_core_dump=", &val))
		hal_get_dump_core(&val, 0);
	else if (param_get_val(buf, "get_perip_dump=", &val))
		hal_get_dump_perip(&val);
	else if (param_get_val(buf, "get_sysbus_dump=", &val))
		hal_get_dump_sysbus(&val);
	return count;
}

static int proc_read_hal_stats(struct seq_file *m, void *v)
{
#ifdef PERF_PROFILING
	int index, max_index = 20;

	seq_puts(m, "************* Host HAL Stats ***********\n");

	seq_printf(m, "IRQ TIME: AVG: %d, MAX: %d\n",
		   avg_array(irq_timestamp, 20),
		   max_array(irq_timestamp, 20));

	for (index = 0; index < max_index; index++)
		seq_printf(m, "IRQ[%d] = %ld\n",
			   index,
			   irq_timestamp[index]);

	seq_printf(m, "RCV Handler TIME: AVG: %d, MAX: %d\n",
		   avg_array(rcv_hdlr_time, 20),
		   max_array(rcv_hdlr_time, 20));

	for (index = 0; index < max_index; index++)
		seq_printf(m, "RH[%d] = %ld\n",
			   index,
			   rcv_hdlr_time[index]);

	seq_printf(m, "Packetx Rx with HAL Internal: AVG: %d, MAX: %d\n",
		   avg_array(rx_pkts_halint_event, 20),
		   max_array(rx_pkts_halint_event, 20));

	for (index = 0; index < max_index; index++)
		seq_printf(m, "RXPKT[%d] = %ld\n",
			   index,
			   rx_pkts_halint_event[index]);

	seq_printf(m, "HAL Internal Event Handling Time: AVG: %d, MAX: %d\n",
		   avg_array(halint_event_handling_time, 20),
		   max_array(halint_event_handling_time, 20));

	for (index = 0; index < max_index; index++)
		seq_printf(m, "HALINT[%d] = %ld\n",
			   index,
			   halint_event_handling_time[index]);

#endif

	seq_printf(m, "Alloc SKB Failures: %d\n",
		   alloc_skb_failures);

	seq_printf(m, "Alloc SKB in 60 MB DMA Region  %d\n",
		   alloc_skb_dma_region);

	seq_printf(m, "Alloc SKB in Priv 4 MB TX Region: %d\n",
		   alloc_skb_priv_tx_region);

	seq_printf(m, "Alloc SKB in Priv 4 MB RX Region: %d\n",
		   alloc_skb_priv_rx_region);

	seq_printf(m, "Alloc SKB Run time: %d\n", alloc_skb_priv_runtime);

	seq_printf(m, "hal_cmd_sent_cnt: %d\n",
		   hal_cmd_sent);

	seq_printf(m, "hal_event_recv_cnt: %d\n",
		   hal_event_recv);

	return 0;
}


static int proc_open_hal_stats(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_hal_stats, NULL);
}


static const struct file_operations params_fops_hal_stats = {
	.open = proc_open_hal_stats,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = proc_write_hal_stats,
	.release = single_release
};


static int hal_proc_init(struct proc_dir_entry *hal_proc_dir_entry)
{
	struct proc_dir_entry *entry;
	int err = 0;

	entry = proc_create("hal_stats",
			    0444,
			    hal_proc_dir_entry,
			    &params_fops_hal_stats);

	if (!entry) {
		pr_err("Failed to create HAL proc entry\n");
		err = -ENOMEM;
	}

	return err;
}


#ifdef PERF_PROFILING
static void stats_timer_expiry(unsigned long data)
{
	if (alloc_skb_dma_region) {
		pr_info("Alloc SKB in 60 MB DMA Region  %d\n",
			alloc_skb_dma_region);

		alloc_skb_dma_region = 0;
	}

	if (alloc_skb_priv_rx_region) {
		pr_info("Alloc SKB in Priv 4 MB Region: %d\n",
			alloc_skb_priv_rx_region);
		alloc_skb_priv_rx_region = 0;
	}

	if (alloc_skb_failures) {
		pr_info("Alloc SKB Failures: %d\n",
			alloc_skb_failures);
		alloc_skb_failures = 0;
	}

	if (alloc_skb_priv_runtime) {
		pr_info("Alloc SKB Run time: %d\n",
			alloc_skb_priv_runtime);
		alloc_skb_priv_runtime = 0;
	}

	mod_timer(&stats_timer, jiffies + msecs_to_jiffies(1000));
}
#endif


int hal_start(void)
{

#ifdef PERF_PROFILING
	init_timer(&stats_timer);
	stats_timer.function = stats_timer_expiry;
	stats_timer.data = (unsigned long) NULL;
	mod_timer(&stats_timer, jiffies + msecs_to_jiffies(1000));
#endif
	hpriv->hal_disabled = 0;

	/* Enable host_int and uccp_int */
	hal_enable_int(NULL);

	return 0;
}


int hal_stop(void)
{
	/* Disable host_int and uccp_irq */
	hal_disable_int(NULL);
	return 0;
}


static int chg_irq_register(int val)
{
	UCCP_DEBUG_HAL("%s: change irq regist state %s.\n",
		 hal_name, ((val == 1) ? "ON" : "OFF"));

	if (val == 0) {
		/* Unregister irq handler */
		free_irq(hpriv->irq, hpriv);

	} else if (val == 1) {
		/* Register irq handler */
		if (request_irq(hpriv->irq,
				hal_irq_handler,
				IRQF_NO_SUSPEND,
				"wlan",
				hpriv) != 0) {
			return -1;
		}
	}

	return 0;
}

static inline int conv_str_to_byte(unsigned char *byte,
		     unsigned char *str,
		     int len)
{
	int  i, j = 0;
	unsigned char ch, val = 0;

	for (i = 0; i < (len * 2); i++) {
		/*convert to lower*/
		ch = ((str[i] >= 'A' && str[i] <= 'Z') ? str[i] + 32 : str[i]);

		if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f'))
			return -1;

		if (ch >= '0' && ch <= '9')  /*check is digit*/
			ch = ch - '0';
		else
			ch = ch - 'a' + 10;

		val += ch;

		if (!(i%2))
			val <<= 4;
		else {
			byte[j] = val;
			j++;
			val = 0;
		}
	}

	return 0;
}

/* Unmap and release all resoruces*/
static int cleanup_all_resources(void)
{
	/* Unmap UCCP sysbus memory */
	iounmap((void __iomem *)hpriv->uccp_sysbus_base_addr);
	release_mem_region(hpriv->uccp_sysbus_base, hpriv->uccp_sysbus_len);

	/* Unmap UCCP perip memory */
	iounmap((void __iomem *)hpriv->uccp_perip_base_addr);
	release_mem_region(hpriv->uccp_perip_base, hpriv->uccp_perip_len);

	/* Unmap GRAM */
	if (hpriv->gram_b4_addr)
		iounmap((void __iomem *)hpriv->gram_b4_addr);
	if (hpriv->uccp_gram_base) {
		release_mem_region(hpriv->uccp_gram_base,
				   hpriv->uccp_gram_len);
	}
	iounmap((void __iomem *)hpriv->gram_base_addr);
	release_mem_region(hpriv->uccp_pkd_gram_base,
			   hpriv->uccp_pkd_gram_len);

	/* Free UCCP Host RAM */
	kfree(hpriv->base_addr_uccp_host_ram);
	hpriv->base_addr_uccp_host_ram = NULL;

	/* Free UCCP HAL TX data */
	kfree(hpriv->hal_tx_data);
	hpriv->hal_tx_data = NULL;

	/* Free private structure */
	kfree(hpriv);
	hpriv = NULL;

	return 0;
}

static int uccp420_pltfr_probe(struct platform_device *pdev)
{
	struct resource *res;
	int irq;
	struct device_node *np = pdev->dev.of_node;
	struct property *pp = NULL;
	struct iio_channel *channels;
	int ret;
	int size;

	channels = iio_channel_get_all(&pdev->dev);
	if (IS_ERR(channels))
		return PTR_ERR(channels);

	hpriv = kzalloc(sizeof(struct hal_priv), GFP_KERNEL);
	if (!hpriv)
		return -ENOMEM;

	irq = platform_get_irq_byname(pdev, "uccpirq");

	hpriv->irq = irq;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM,
					   "uccp_sysbus_base");
	if (res == NULL)
		return pr_err("No dts entry : uccp_sysbus_base");

	hpriv->uccp_sysbus_base = res->start;
	hpriv->uccp_sysbus_len = res->end - res->start + 1;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM,
					   "uccp_perip_base");
	if (res == NULL)
		return pr_err("No dts entry : uccp_perip_base");

	hpriv->uccp_perip_base = res->start;
	hpriv->uccp_perip_len = res->end - res->start + 1;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM,
					   "uccp_pkd_gram_base");

	if (res == NULL)
		return pr_err("No dts entry : uccp_pkd_gram_base");

	hpriv->uccp_pkd_gram_base = res->start;
	hpriv->uccp_pkd_gram_len = res->end - res->start + 1;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM,
					   "uccp_gram_base");

	if (res) {
		hpriv->uccp_gram_base = res->start;
		hpriv->uccp_gram_len = res->end - res->start + 1;
	}

	pp = of_find_property(np, "mac-address0", NULL);

	if (pp && (pp->length == ETH_ALEN) && pp->value)
		memcpy(&vif_macs[0], (void *)pp->value, ETH_ALEN);
	else if (mac_addr == NULL)
		mac_addr = DEFAULT_MAC_ADDRESS;

	pp = of_find_property(np, "mac-address1", NULL);

	if (pp && (pp->length == ETH_ALEN) && pp->value)
		memcpy(&vif_macs[1], (void *)pp->value, ETH_ALEN);

	if (mac_addr != NULL) {

		conv_str_to_byte(vif_macs[0], mac_addr, ETH_ALEN);

		ether_addr_copy(vif_macs[1], vif_macs[0]);

		/* Set the Locally Administered bit*/
		vif_macs[1][0] |= 0x02;

		/* Increment the MSB by 1 (excluding 2 special bits)*/
		vif_macs[1][0] += (1 << 2);
	}

	pp = of_find_property(np, "rf-params", &size);

	if (pp && pp->value) {
		memcpy(rf_params, pp->value, size);
		rf_params_vpd = rf_params;
	}

	pp = of_find_property(np, "num_streams", &size);

	if (pp && pp->value)
		num_streams_vpd = *((int *)pp->value);

	clk_prepare_enable(devm_clk_get(&pdev->dev, "rpu_core"));
	clk_prepare_enable(devm_clk_get(&pdev->dev, "rpu_l"));
	clk_prepare_enable(devm_clk_get(&pdev->dev, "rpu_v"));
	clk_prepare_enable(devm_clk_get(&pdev->dev, "rpu_sleep"));
	clk_prepare_enable(devm_clk_get(&pdev->dev, "wifi_adc"));
	clk_prepare_enable(devm_clk_get(&pdev->dev, "wifi_dac"));

	clk_prepare_enable(devm_clk_get(&pdev->dev, "event_timer"));
	clk_prepare_enable(devm_clk_get(&pdev->dev, "sys_event_timer"));
	clk_prepare_enable(devm_clk_get(&pdev->dev, "aux_adc"));
	clk_prepare_enable(devm_clk_get(&pdev->dev, "aux_adc_internal"));

	/* To support suspend/resume (economy mode)
	 * during probe a wake up capable device will invoke
	 * the below routine with second parameter("can_wakeup" flag)
	 * set to 1.
	 */
	device_init_wakeup(&pdev->dev, 1);


	ret = hal_ops.init(&pdev->dev);

	if (!ret)
		UCCP_DEBUG_HAL("uccp420 wlan driver registration completed");

	return ret;
}

static int uccp420_pltfr_remove(struct platform_device *pdev)
{
	clk_disable_unprepare(devm_clk_get(&pdev->dev, "rpu_core"));
	clk_disable_unprepare(devm_clk_get(&pdev->dev, "rpu_l"));
	clk_disable_unprepare(devm_clk_get(&pdev->dev, "rpu_v"));
	clk_disable_unprepare(devm_clk_get(&pdev->dev, "rpu_sleep"));
	clk_disable_unprepare(devm_clk_get(&pdev->dev, "wifi_adc"));
	clk_disable_unprepare(devm_clk_get(&pdev->dev, "wifi_dac"));

	clk_disable_unprepare(devm_clk_get(&pdev->dev, "event_timer"));
	clk_disable_unprepare(devm_clk_get(&pdev->dev, "sys_event_timer"));
	clk_disable_unprepare(devm_clk_get(&pdev->dev, "aux_adc"));
	clk_disable_unprepare(devm_clk_get(&pdev->dev, "aux_adc_internal"));

	/* To support suspend/resume feature (economy mode)
	 * during remove a wake up capable device will invoke
	 * the below routine with second parameter("can_wakeup" flag)
	 * set to 0.
	 */
	device_init_wakeup(&pdev->dev, 0);

	return 0;
}

static const struct of_device_id uccp420_dt_ids[] = {
	{ .compatible = "img,pistachio-uccp"},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, uccp420_dt_ids);

struct platform_driver img_uccp_driver = {
	.probe = uccp420_pltfr_probe,
	.remove = uccp420_pltfr_remove,
	.driver = {
		.name     = "uccp420",
		.owner    = THIS_MODULE,
		.of_match_table = of_match_ptr(uccp420_dt_ids),
	},
};




static int hal_deinit(void *dev)
{
	struct sk_buff *skb;

	(void)(dev);

	_uccp420wlan_80211if_exit();
	platform_driver_unregister(&img_uccp_driver);

	/* Free irq line */
	chg_irq_register(0);

	/* Kill the HAL tasklet */
	tasklet_kill(&hpriv->tx_tasklet);
	tasklet_kill(&hpriv->rx_tasklet);
	tasklet_kill(&hpriv->recv_tasklet);
	while ((skb = skb_dequeue(&hpriv->rxq)))
		dev_kfree_skb_any(skb);

	while ((skb = skb_dequeue(&hpriv->refillq)))
		dev_kfree_skb_any(skb);

	while ((skb = skb_dequeue(&hpriv->txq)))
		dev_kfree_skb_any(skb);

	cleanup_all_resources();

	return 0;
}


static int hal_init(void *dev)
{
	struct proc_dir_entry *main_dir_entry;
	int err = 0;
	unsigned int value = 0;
	unsigned char *rpusocwrap;
	void __iomem *sixfour_mb_base;
	unsigned int phys_64mb;

	(void) (dev);

	hpriv->shm_offset =  shm_offset;

	if (hpriv->shm_offset != HAL_SHARED_MEM_OFFSET)
		UCCP_DEBUG_HAL("%s: Using shared memory offset 0x%lx\n",
			 hal_name, hpriv->shm_offset);

	/* Map UCCP core memory */
	if (!(request_mem_region(hpriv->uccp_sysbus_base,
				 hpriv->uccp_sysbus_len,
				 "uccp"))) {
		pr_err("%s: request_mem_region failed for UCCP core region\n",
		       hal_name);
		err = -ENOMEM;
		goto free_hpriv;
	}

	hpriv->uccp_sysbus_base_addr = (unsigned long)devm_ioremap(dev,
							hpriv->uccp_sysbus_base,
							hpriv->uccp_sysbus_len);

	if (!hpriv->uccp_sysbus_base_addr) {
		pr_err("%s: Ioremap failed for UCCP core mem region\n",
			hal_name);
		err = -ENOMEM;
		goto uccp_sysbus_release;
	}

	hpriv->uccp_mem_addr = hpriv->uccp_sysbus_base_addr +
			       HAL_UCCP_CORE_REG_OFFSET;

	/* Map UCCP Perip memory */
	if (!(request_mem_region(hpriv->uccp_perip_base,
				 hpriv->uccp_perip_len,
				 "uccp"))) {
		pr_err("%s: request_mem_region failed for UCCP perip region\n",
		       hal_name);
		err = -ENOMEM;
		goto uccp_sysbus_unmap;
	}

	hpriv->uccp_perip_base_addr =
	(unsigned long) devm_ioremap(dev, hpriv->uccp_perip_base,
				     hpriv->uccp_perip_len);

	if (!hpriv->uccp_perip_base_addr) {
		pr_err("%s: Ioremap failed for UCCP perip mem region\n",
			hal_name);
		err = -ENOMEM;
		goto uccp_perip_release;
	}

	/* Map GRAM */
	if (!request_mem_region(hpriv->uccp_pkd_gram_base,
				hpriv->uccp_pkd_gram_len,
				"wlan_gram")) {
		pr_err("%s: request_mem_region failed for GRAM\n",
		       hal_name);
		err = -ENOMEM;
		goto uccp_perip_unmap;
	}

	hpriv->gram_base_addr =
		(unsigned long)devm_ioremap(dev, hpriv->uccp_pkd_gram_base,
				       hpriv->uccp_pkd_gram_len);
	if (!hpriv->gram_base_addr) {
		pr_err("%s: Ioremap failed for gram region.\n",
		       hal_name);
		err = -ENOMEM;
		goto uccp_gram_pkd_release;
	}

	hpriv->gram_mem_addr = hpriv->gram_base_addr + hpriv->shm_offset;

	/* Try GFP_DMA, to get the buffer in ZONE_DMA.
	 */
	hpriv->base_addr_uccp_host_ram = kmalloc(HAL_HOST_BOUNCE_BUF_LEN,
						 GFP_DMA);

	if (!hpriv->base_addr_uccp_host_ram) {
		pr_err("%s: uccp host ram: failed to allocate memory\n",
			       hal_name);
		err = -ENOMEM;
		goto uccp_gram_unmap;
	}

	phys_64mb = virt_to_phys(hpriv->base_addr_uccp_host_ram);

	pr_err("%s: kmalloc success: %p an phy: 0x%x end: %p\n",
	       __func__,
	       hpriv->base_addr_uccp_host_ram,
	       phys_64mb,
	       hpriv->base_addr_uccp_host_ram + HAL_HOST_ZONE_DMA_LEN);

	/* Program the 64MB base address to the RPU.
	 * RPU can access only 64MB starting from this
	 * address.
	 */
	sixfour_mb_base = get_base_address_64mb(phys_64mb);


	rpusocwrap = (unsigned char *)(hpriv->uccp_sysbus_base_addr + 0x38000);

	value = ((unsigned int)sixfour_mb_base) / (4 * 1024);
	uccp_ddr_base = value * (4 * 1024);
	value = value << 10;
	writel(value, rpusocwrap + 0x218);

	pr_err("%s: kmalloc success: %x\n", __func__, uccp_ddr_base);

	if (hpriv->uccp_gram_base) {

		/* gram_b4_addr */
		if (!(request_mem_region(hpriv->uccp_gram_base,
				 hpriv->uccp_gram_len,
				 "uccp_gram_base"))) {
			pr_err("%s:uccp_gram_base: request_mem_region failed\n",
			       hal_name);
			err = -ENOMEM;
			goto free_host_ram;
		}

		hpriv->gram_b4_addr =
			(unsigned long)devm_ioremap(dev, hpriv->uccp_gram_base,
					       hpriv->uccp_gram_len);

		if (!hpriv->gram_b4_addr) {
			pr_err("%s: Ioremap failed for UCCP mem region\n",
				hal_name);
			err = -ENOMEM;
			goto uccp_gram_release;
		}
	}

	/* Register irq handler */
	if (chg_irq_register(1)) {
		pr_err("%s: Unable to register Interrupt handler with kernel\n",
		       hal_name);
		err = -ENOMEM;
		goto uccp_gram_b4_unmap;
	}

	/*Allocate space do update data pointers to DCP*/
	hpriv->hal_tx_data = kzalloc((NUM_TX_DESC * NUM_FRAMES_IN_TX_DESC *
				      sizeof(struct hal_tx_data)), GFP_KERNEL);

	if (!hpriv->hal_tx_data) {
		pr_err("%s: hal_tx_data: unable to allocate memory\n",
		       hal_name);
		err = -ENOMEM;
		goto uccp_gram_b4_unmap;
	}

	/* Intialize HAL tasklets */
	tasklet_init(&hpriv->tx_tasklet,
		     tx_tasklet_fn,
		     (unsigned long)hpriv);
	tasklet_init(&hpriv->rx_tasklet,
		     rx_tasklet_fn,
		     (unsigned long)hpriv);
	tasklet_init(&hpriv->recv_tasklet,
		     recv_tasklet_fn,
		     (unsigned long)hpriv);
	skb_queue_head_init(&hpriv->rxq);
	skb_queue_head_init(&hpriv->txq);
	skb_queue_head_init(&hpriv->refillq);
#ifdef PERF_PROFILING
	spin_lock_init(&timing_lock);
#endif

	if (_uccp420wlan_80211if_init(&main_dir_entry) < 0) {
		pr_err("%s: wlan_init failed\n", hal_name);
		hal_deinit(NULL);
		return -ENOMEM;
	}

	err = hal_proc_init(main_dir_entry);

	if (err)
		return err;

	hpriv->cmd_cnt = COMMAND_START_MAGIC;
	hpriv->event_cnt = 0;

	return 0;

uccp_gram_b4_unmap:
	if (hpriv->gram_b4_addr)
		iounmap((void __iomem *)hpriv->gram_b4_addr);
uccp_gram_release:
	if (hpriv->uccp_gram_base)
		release_mem_region(hpriv->uccp_gram_base,
				   hpriv->uccp_gram_len);
free_host_ram:
	kfree(hpriv->base_addr_uccp_host_ram);
	hpriv->base_addr_uccp_host_ram = NULL;
uccp_gram_unmap:
	iounmap((void __iomem *)hpriv->gram_base_addr);
uccp_gram_pkd_release:
	release_mem_region(hpriv->uccp_pkd_gram_base,
			   hpriv->uccp_pkd_gram_len);
uccp_perip_unmap:
	iounmap((void __iomem *)hpriv->uccp_perip_base_addr);
uccp_perip_release:
	release_mem_region(hpriv->uccp_perip_base,
			   hpriv->uccp_perip_len);
uccp_sysbus_unmap:
	iounmap((void __iomem *)hpriv->uccp_sysbus_base_addr);
uccp_sysbus_release:
	release_mem_region(hpriv->uccp_sysbus_base,
			   hpriv->uccp_sysbus_len);
free_hpriv:
	kfree(hpriv);
	hpriv = NULL;

	return err;
}

static void hal_deinit_bufs(void)
{
	int i = 0, j = 0;
	struct buf_info *info = NULL;

	tasklet_disable(&hpriv->rx_tasklet);
	tasklet_disable(&hpriv->recv_tasklet);

	if (hpriv->rx_buf_info) {
		for (i = 0; i < hpriv->rx_bufs_2k + hpriv->rx_bufs_12k; i++) {
			info = &hpriv->rx_buf_info[i];

			if (info->dma_buf) {
				dma_unmap_single(NULL,
						 info->dma_buf,
						 info->dma_buf_len,
						 DMA_FROM_DEVICE);

				info->dma_buf = 0;
				info->dma_buf_len = 0;
			}

			if (hpriv->rx_buf_info[i].skb) {
				kfree_skb(hpriv->rx_buf_info[i].skb);
				hpriv->rx_buf_info[i].skb = NULL;
			}
		}

		kfree(hpriv->rx_buf_info);
		hpriv->rx_buf_info = NULL;
	}

	if (hpriv->tx_buf_info) {
		for (i = 0; i < hpriv->tx_bufs; i++) {
			for (j = 0; i < NUM_FRAMES_IN_TX_DESC; i++) {
				info = &hpriv->tx_buf_info[i + j];

				if (info->dma_buf) {
					dma_unmap_single(NULL,
							 info->dma_buf,
							 info->dma_buf_len,
							 DMA_TO_DEVICE);

					info->dma_buf = 0;
					info->dma_buf_len = 0;
				}
			}
		}

		kfree(hpriv->tx_buf_info);
		hpriv->tx_buf_info = NULL;
	}

	hpriv->hal_disabled = 1;
	tasklet_enable(&hpriv->rx_tasklet);
	tasklet_enable(&hpriv->recv_tasklet);
}


static int hal_init_bufs(unsigned int tx_bufs,
			 unsigned int rx_bufs_2k,
			 unsigned int rx_bufs_12k,
			 unsigned int tx_max_data_size)
{
	struct cmd_hal cmd_rx;
	struct sk_buff *nbuf = NULL;
	unsigned int count = 0, cmd_count = 0, pkt_desc = 0;
	unsigned int rx_max_data_size;
	dma_addr_t dma_buf = 0;
	unsigned int cmd_buf_count = ((rx_bufs_2k + rx_bufs_12k) /
				      MAX_RX_BUF_PTR_PER_CMD);
	int result = -1;

	hpriv->tx_bufs = tx_bufs;
	hpriv->rx_bufs_2k = rx_bufs_2k;
	hpriv->rx_bufs_12k = rx_bufs_12k;
	hpriv->max_data_size = tx_max_data_size;
	hpriv->tx_base_addr_uccp_host_ram = hpriv->base_addr_uccp_host_ram;
	hpriv->rx_base_addr_uccp_host_ram = hpriv->base_addr_uccp_host_ram +
		(tx_bufs * NUM_FRAMES_IN_TX_DESC * tx_max_data_size);

	if (((tx_bufs * NUM_FRAMES_IN_TX_DESC * tx_max_data_size) +
	     ((rx_bufs_2k * MAX_DATA_SIZE_2K + rx_bufs_12k *
	       MAX_DATA_SIZE_12K))) > HAL_HOST_BOUNCE_BUF_LEN) {
		pr_err("%s Cannot accomodate tx_bufs: %d, frames/desc: %d and rx_bufs_2k: %d rx_bufs_12k: %d in %d UCCP Host RAM\n",
		       hal_name, tx_bufs, NUM_FRAMES_IN_TX_DESC,
		       rx_bufs_2k, rx_bufs_12k, HAL_HOST_BOUNCE_BUF_LEN);

		goto err;
	}

	hpriv->rx_buf_info = kzalloc(((rx_bufs_2k + rx_bufs_12k) *
				      sizeof(struct buf_info)), GFP_KERNEL);

	if (!hpriv->rx_buf_info) {
		pr_err("%s out of memory\n", hal_name);
		goto err;
	}

	hpriv->tx_buf_info = kzalloc((tx_bufs * NUM_FRAMES_IN_TX_DESC *
				      sizeof(struct buf_info)),
				     GFP_KERNEL);

	if (!hpriv->tx_buf_info) {
		pr_err("%s out of memory\n", hal_name);
		goto err;
	}


	for (cmd_count = 0; cmd_count < cmd_buf_count; cmd_count++) {
		memset(&cmd_rx, 0, sizeof(struct cmd_hal));


		for (count = 0; count < MAX_RX_BUF_PTR_PER_CMD; count++,
		     pkt_desc++) {

			if (pkt_desc < hpriv->rx_bufs_12k)
				rx_max_data_size = MAX_DATA_SIZE_12K;
			else
				rx_max_data_size = MAX_DATA_SIZE_2K;

			UCCP_DEBUG_HAL("%s: Loop :%d: rx_max_data_size: %d\n",
				 hal_name, cmd_count, rx_max_data_size);

			result = init_rx_buf(pkt_desc,
					     rx_max_data_size,
					     &dma_buf,
					     NULL);

			if (result) {
				pr_err("%s Failed to initialize RX buf %d\n",
				       hal_name, pkt_desc);
				goto err;
			}

			cmd_rx.rx_pkt_data.rx_pkt_cnt++;
			cmd_rx.rx_pkt_data.rx_pkt[count].desc = pkt_desc;
			cmd_rx.rx_pkt_data.rx_pkt[count].ptr = dma_buf -
							       uccp_ddr_base;
		}

		cmd_rx.hdr.id = 0xFFFFFFFF;

		nbuf = alloc_skb(sizeof(struct cmd_hal), GFP_ATOMIC);

		if (!nbuf)
			goto err;

		memcpy(skb_put(nbuf, sizeof(struct cmd_hal)),
		       (unsigned char *)&cmd_rx, sizeof(struct cmd_hal));
		hal_cmd_sent--;
		hostport_send_head(hpriv, nbuf);
	}

	return 0;
err:
	if (nbuf) {
		kfree_skb(nbuf);
		nbuf = NULL;
	}

	hal_deinit_bufs();

	return -1;
}


int hal_map_tx_buf(int pkt_desc, int frame_id, unsigned char *data, int len)
{
	unsigned int index = (pkt_desc * NUM_FRAMES_IN_TX_DESC) + frame_id;
	void __iomem  *tx_address = NULL;
	int i, j;
	dma_addr_t dma_buf = 0;
	dma_addr_t curr_buf = 0;

	/* For QoS Null frames we dont try to map the frame since the data len
	 * will be 0 and there is nothing for the FW to process
	 */
	if (len == 0)
		return 0;

	/* Sanity check */
	dma_buf = ((struct buf_info)(hpriv->tx_buf_info[index])).dma_buf;

	if (dma_buf) {
		pr_err("%s: Already mapped pkt descriptor: %d and frame: %d dma_buf: 0x%x dma_buf: 0x%x index: %d\n",
		       __func__,
		       pkt_desc,
		       frame_id,
		       (unsigned int)hpriv->tx_buf_info[index].dma_buf,
		       (unsigned int)dma_buf,
		       index);

		for (i = 0; i < NUM_TX_DESC; i++) {
			for (j = 0; j < NUM_FRAMES_IN_TX_DESC; j++) {
				UCCP_DEBUG_HAL("%s: TX: descriptor: %d ",
					       __func__, i);
				curr_buf = hpriv->tx_buf_info[i + j].dma_buf;
				UCCP_DEBUG_HAL("and frame: %d dma_buf: 0x%x\n",
					       j,
					       curr_buf);
			}
		}

		for (i = 0; i < 80; i++) {
			UCCP_DEBUG_HAL("%s: RX: descriptor: %d dma_buf: 0x%x\n",
				       __func__,
				       i,
				       hpriv->rx_buf_info[i].dma_buf);
		}

		return -1;
	}

	if (!is_mem_dma(data, len)) {
		/* Copy SKB to the UCCP Private Area */
		tx_address = hpriv->tx_base_addr_uccp_host_ram +
			     (index * hpriv->max_data_size);

		memcpy(tx_address, data, len);
		alloc_skb_priv_tx_region++;
	} else {
		tx_address = data;
		alloc_skb_dma_region++;
	}

	dma_buf = dma_map_single(NULL,
				 tx_address,
				 len,
				 DMA_TO_DEVICE);

	if (unlikely(dma_mapping_error(NULL,
				       dma_buf))) {
		pr_err("%s Unable to map DMA on TX\n", hal_name);
		return -1;
	}

	hpriv->tx_buf_info[index].dma_buf = dma_buf;

	hpriv->tx_buf_info[index].dma_buf_len = len;

	return 0;
}


int hal_unmap_tx_buf(int pkt_desc, int frame_id)
{
	unsigned int index = (pkt_desc * NUM_FRAMES_IN_TX_DESC) + frame_id;

	/* For QoS Null frames we did not map the frame (since the data len
	 * will be 0 and there is nothing for the FW to process), hence no need
	 * to try and unmap
	 */
	if (!hpriv->tx_buf_info[index].dma_buf_len)
		return 0;

	/* Sanity check */
	if (!hpriv->tx_buf_info[index].dma_buf) {
		pr_err("%s called for unmapped pkt desc: %d , frame: %d\n",
		       __func__, pkt_desc, frame_id);
		return -1;
	}

	dma_unmap_single(NULL,
			 hpriv->tx_buf_info[index].dma_buf,
			 hpriv->tx_buf_info[index].dma_buf_len,
			 DMA_TO_DEVICE);

	memset(&hpriv->tx_buf_info[index], 0, sizeof(struct buf_info));

	return 0;
}


static int is_mem_dma(void *virt_addr, int len)
{
	phys_addr_t phy_addr = 0;

	phy_addr = virt_to_phys(virt_addr);

	if (phy_addr >= uccp_ddr_base &&
	    (phy_addr + len) < (uccp_ddr_base +
				HAL_HOST_ZONE_DMA_LEN))
		return 1;

	return 0;
}


static int is_mem_bounce(void *virt_addr, int len)
{
	phys_addr_t phy_addr_start = 0;
	phys_addr_t phy_addr = 0;

	phy_addr = virt_to_phys(virt_addr);
	phy_addr_start = virt_to_phys(hpriv->base_addr_uccp_host_ram);

	if (phy_addr >= phy_addr_start &&
	   (phy_addr + len) < (phy_addr_start +
			       HAL_HOST_BOUNCE_BUF_LEN))
		return 1;

	pr_warn("%s: Warning:Address is out of Bounce memory region\n",
		hal_name);

	return 0;
}


static int init_rx_buf(int pkt_desc,
		       unsigned int max_data_size,
		       dma_addr_t *dma_buf,
		       struct sk_buff *new_skb)
{
	struct sk_buff *rx_skb = NULL;
	void __iomem *src_ptr = NULL;

	memset(&hpriv->rx_buf_info[pkt_desc], 0, sizeof(struct buf_info));

	if (new_skb == NULL) {

		rx_skb = alloc_skb(max_data_size, GFP_ATOMIC);

		if (!rx_skb) {
			alloc_skb_failures++;
			return -1;
		}
	} else
		rx_skb = new_skb;

	if ((is_mem_dma(rx_skb->data, max_data_size))) {
		src_ptr = rx_skb->data;
		alloc_skb_dma_region++;
	} else {
		if (pkt_desc < hpriv->rx_bufs_12k) {
			src_ptr = hpriv->rx_base_addr_uccp_host_ram +
				  (pkt_desc * MAX_DATA_SIZE_12K);
		} else {
			src_ptr = hpriv->rx_base_addr_uccp_host_ram +
				  (hpriv->rx_bufs_12k * MAX_DATA_SIZE_12K) +
				  ((pkt_desc - hpriv->rx_bufs_12k) *
				   MAX_DATA_SIZE_2K);
		}

		if (!is_mem_bounce(src_ptr, max_data_size)) {
			if (rx_skb)
				dev_kfree_skb_any(rx_skb);
			return -1;
		}

		hpriv->rx_buf_info[pkt_desc].dma_buf_priv = 1;
		alloc_skb_priv_rx_region++;
	}

	*dma_buf = dma_map_single(NULL,
				  src_ptr,
				  max_data_size,
				  DMA_FROM_DEVICE);

	if (unlikely(dma_mapping_error(NULL,
				       *dma_buf))) {
		pr_err("%s Unable to map DMA on RX\n", hal_name);

		if (rx_skb)
			dev_kfree_skb_any(rx_skb);

		return -1;
	}

	hpriv->rx_buf_info[pkt_desc].skb = rx_skb;
	hpriv->rx_buf_info[pkt_desc].src_ptr = src_ptr;
	hpriv->rx_buf_info[pkt_desc].dma_buf = *dma_buf;
	hpriv->rx_buf_info[pkt_desc].dma_buf_len = max_data_size;

	return 0;
}

void hal_set_mem_region(unsigned int addr)
{

}

void hal_request_mem_regions(unsigned char **gram_addr,
			     unsigned char **sysbus_addr,
			     unsigned char **gram_b4_addr)
{
	*gram_addr = (unsigned char *)hpriv->gram_base_addr;
	*sysbus_addr = (unsigned char *)hpriv->uccp_sysbus_base_addr;
	*gram_b4_addr = (unsigned char *)hpriv->gram_b4_addr;
}

void hal_enable_irq_wake(void)
{
	enable_irq_wake(hpriv->irq);
}

void hal_disable_irq_wake(void)
{
	disable_irq_wake(hpriv->irq);
}


struct hal_ops_tag hal_ops = {
	.init = hal_init,
	.deinit	= hal_deinit,
	.start = hal_start,
	.stop = hal_stop,
	.register_callback = hal_register_callback,
	.send = hal_send,
	.init_bufs = hal_init_bufs,
	.deinit_bufs = hal_deinit_bufs,
	.map_tx_buf = hal_map_tx_buf,
	.unmap_tx_buf = hal_unmap_tx_buf,
	.reset_hal_params	= hal_reset_hal_params,
	.set_mem_region	= hal_set_mem_region,
	.request_mem_regions	= hal_request_mem_regions,
	.enable_irq_wake = hal_enable_irq_wake,
	.disable_irq_wake = hal_disable_irq_wake,
	.get_dump_gram		= hal_get_dump_gram,
	.get_dump_core		= hal_get_dump_core,
	.get_dump_perip		= hal_get_dump_perip,
	.get_dump_sysbus	= hal_get_dump_sysbus,
	.get_dump_len		= hal_get_dump_len,
};

#ifdef CONFIG_PM
static int host_suspend(void)
{
	if ((img_suspend_status == 1) && (rx_interrupt_status == 1)) {
		pr_err("%s: Interrupt raised during Suspend, cancel suspend",
				hal_name);
		return -EBUSY;
	} else {
		return 0;
	}
}
#else
	#define host_suspend		NULL
#endif

static struct syscore_ops host_syscore_ops = {
	.suspend = host_suspend,
};

static int __init hostport_init(void)
{
	int ret = 0;

	ret = platform_driver_register(&img_uccp_driver);
	register_syscore_ops(&host_syscore_ops);

	return ret;
}

static void __exit hostport_exit(void)
{
	unregister_syscore_ops(&host_syscore_ops);
	hal_ops.deinit(NULL);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Imagination Technologies");
MODULE_DESCRIPTION("Driver for IMG UCCP420 WiFi solution");

module_init(hostport_init);
module_exit(hostport_exit);
