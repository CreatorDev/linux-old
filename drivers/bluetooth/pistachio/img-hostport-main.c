/*HEADER**********************************************************************
 ******************************************************************************
 ***
 *** Copyright (c) 2011, 2012, 2013, 2014 Imagination Technologies Ltd.
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
 *** File Name  : img-hostport-main.c
 ***
 *** File Description:
 *** This file contains the implementation of the IMG low level
 *** shared memory based transport.
 ***
 ******************************************************************************
 *END**************************************************************************/

#include <asm/unaligned.h>

#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/clk.h>

#include "img-hostport-main.h"

static struct img_hostport *module;
static const char *hal_name = "img-hostport";
#define dbg(format, ...) pr_debug("%s: " format, hal_name, ## __VA_ARGS__)
#define err(format, ...) pr_err("%s: " format, hal_name, ## __VA_ARGS__)
#define dbgn(format, ...) dbg(format "\n", ## __VA_ARGS__)
#define errn(format, ...) err(format "\n", ## __VA_ARGS__)
#define diagerrn(format, ...) \
	errn("%s : %d : " format, __func__, __LINE__, ## __VA_ARGS__)
#define diagdbgn(format, ...) \
	dbgn("%s : %d : " format, __func__, __LINE__, ## __VA_ARGS__)

#define COMMON_HOST_ID 0
#define CALLEE_MASK 0x000000f0
#define CALLEE_SHIFT 4
#define CALLER_MASK 0x0000000f
#define USERMSG_MASK 0x00ffff00
#define USERMSG_SHIFT 8
#define CALLEE(reg) ((reg & CALLEE_MASK) >> CALLEE_SHIFT)
#define CALLER(reg) (reg & CALLER_MASK)
#define USERMSG(reg) ((reg & USERMSG_MASK) >> USERMSG_SHIFT)

DEFINE_SEMAPHORE(host_to_uccp_core_lock);

enum {
	CLK_RPU_CORE = 0, CLK_BT, CLK_BT_DIV4, CLK_BT_DIV8, CLK_QTY
};
static const char * const clock_names[] = {"rpu_core", "bt", "bt_div4",
	"bt_div8"};
static struct clk *clocks[CLK_QTY];

/*
 * Forward declarations
 */
static void notify_common(u16 user_data, int user_id);

/*
 * Public interface procs
 */

int img_transport_register_callback(
		img_transport_handler poke,
		unsigned int client_id)
{
	if (client_id > MAX_ENDPOINT_ID || module->endpoints.f[client_id])
		return -EBADSLT;

	spin_lock(module->endpoints.in_use + client_id);
	module->endpoints.f[client_id] = poke;
	spin_unlock(module->endpoints.in_use + client_id);

	return 0;
}
EXPORT_SYMBOL(img_transport_register_callback);

void img_transport_notify(u16 user_data, int user_id)
{
	down(&host_to_uccp_core_lock);
	notify_common(user_data, user_id);
}
EXPORT_SYMBOL(img_transport_notify);

int __must_check img_transport_notify_timeout(u16 user_data,
					int user_id,
					long jiffies_timeout)
{
	if (-ETIME == down_timeout(&host_to_uccp_core_lock, jiffies_timeout)) {
		return -ETIME;
	}
	notify_common(user_data, user_id);
	return 0;
}
EXPORT_SYMBOL(img_transport_notify_timeout);

int img_transport_remove_callback(unsigned int client_id)
{
	if (client_id > MAX_ENDPOINT_ID || !module->endpoints.f[client_id])
		return -EBADSLT;

	spin_lock(module->endpoints.in_use + client_id);
	module->endpoints.f[client_id] = NULL;
	spin_unlock(module->endpoints.in_use + client_id);

	return 0;
}
EXPORT_SYMBOL(img_transport_remove_callback);

/*
 * Private procs
 */

static u8 id_to_field(int id)
{
	id &= 0xF;
	return (id << 4) | id;
}

static void notify_common(u16 user_data, int user_id)
{
	iowrite32(0x87 << 24 | user_data << 8 | id_to_field(user_id),
			(void __iomem *)H2C_CMD_ADDR(module->uccp_mem_addr));
}

static irqreturn_t hal_irq_handler(int    irq, void  *p)
{
	/* p is module here! */
	unsigned long flags;
	unsigned int reg_value;
	unsigned int value, caller_id, callee_id, user_message, first_bit;
	img_transport_handler handler;
	spinlock_t *handler_in_use;

	reg_value =
		readl((void __iomem *)(C2H_CMD_ADDR(module->uccp_mem_addr)));

	/* TODO: need to change that to support platforms other that 32 bit */
	first_bit = (reg_value & (1 << 31)) >> 31;
	if (0 == first_bit) {
		err("unexpected spurious interrupt detected!\n");
		return IRQ_HANDLED;
	}

	/* Clear the uccp interrupt */
	value = 0;
	value |= BIT(C_INT_CLR_SHIFT);
	writel(value, (void __iomem *)(H2C_ACK_ADDR(module->uccp_mem_addr)));

	callee_id = CALLEE(reg_value);
	caller_id = CALLER(reg_value);
	user_message = USERMSG(reg_value);
	/*
	 * We are ready to release the spinlock
	 * once we get the all zeros message.
	 *
	 * callee_id is tainted, therefore must be checked.
	 */
	if (callee_id > MAX_ENDPOINT_ID) {
		errn("endpoint with id = %u doesn't exist", callee_id);
		return IRQ_HANDLED;
	}

	if (COMMON_HOST_ID == callee_id) {
		switch (user_message) {
		case 0:
			/*
			 * now H2C_CMD_ADDR can
			 * be written to again
			 */
			up(&host_to_uccp_core_lock);
			break;
		default:
			errn("unexpected controller message, dropping :");
			errn("\tcallee_id : %d", callee_id);
			errn("\tcaller_id : %d", caller_id);
			errn("\tuser_message : %d", user_message);
		}
	} else {
		handler = module->endpoints.f[callee_id];
		handler_in_use = module->endpoints.in_use + callee_id;
		if (NULL != handler) {
			spin_lock_irqsave(handler_in_use, flags);
			handler((u16)user_message);
			spin_unlock_irqrestore(handler_in_use, flags);
		} else
			errn("endpoint with id = %u not registered", callee_id);
	}

	return IRQ_HANDLED;
}

static void img_hostport_irq_on(void)
{
	unsigned int value = 0;

	/* Set external pin irq enable for host_irq and uccp_irq */
	value = readl((void __iomem *)C_INT_ENAB_ADDR(module->uccp_mem_addr));
	value |= BIT(C_INT_IRQ_ENAB_SHIFT);
	writel(value,
		(void __iomem *)(C_INT_ENAB_ADDR(module->uccp_mem_addr)));

	/* Enable raising uccp_int when UCCP_INT = 1 */
	value = 0;
	value |= BIT(C_INT_EN_SHIFT);
	writel(value,
		(void __iomem *)(C_INT_ENABLE_ADDR(module->uccp_mem_addr)));
}

static void img_hostport_irq_off(void)
{
	unsigned int value = 0;

	/* Reset external pin irq enable for host_irq and uccp_irq */
	value = readl((void __iomem *)C_INT_ENAB_ADDR(module->uccp_mem_addr));
	value &= ~(BIT(C_INT_IRQ_ENAB_SHIFT));
	writel(value,
		(void __iomem *)(C_INT_ENAB_ADDR(module->uccp_mem_addr)));

	/* Disable raising uccp_int when UCCP_INT = 1 */
	value = 0;
	value &= ~(BIT(C_INT_EN_SHIFT));
	writel(value,
		(void __iomem *)(C_INT_ENABLE_ADDR(module->uccp_mem_addr)));
}

static int img_hostport_pltfr_irqregist(int irq_line)
{
	dbg("requesting interrupt line %d\n", irq_line);

	return request_irq(irq_line, hal_irq_handler, 0, hal_name, module);
}

static int img_hostport_pltfr_irqregist_rollback(int irq_line)
{
	dbg("releasing interrupt line %d\n", irq_line);

	free_irq(irq_line, module);

	return 0;
}

static int img_hostport_pltfr_dtsetup(struct platform_device *pdev)
{
	/* struct resource *res; */
	int irq_or_error, i;
	const struct resource *rpu_sbus;
	/* Get resources from platform device */
	irq_or_error = platform_get_irq(pdev, 0);
	if (irq_or_error < 0) { /* it's an error */
		err("cannot find IRQ resource\n");
		return irq_or_error; /* it's now error code */
	}
	module->irq_line = irq_or_error; /* it's now a valid IRQ line */

	rpu_sbus = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (rpu_sbus == NULL) {
		err("no dts entry : reg with index 0\n");
		return -ENOENT;
	}

	module->uccp_core_base = rpu_sbus->start;
	module->uccp_core_len = (rpu_sbus->end) - (rpu_sbus->start) + 1;

	/* Retrieve clocks */
	for (i = 0; i < CLK_QTY; i++) {
		clocks[i] = devm_clk_get(&pdev->dev, clock_names[i]);
		if (IS_ERR(clocks[i])) {
			errn("could not get %s clock", clock_names[i]);
			return -ENOENT;
		}
	}

	return 0;
}

static void img_hostport_pltfr_dtsetup_rollback(void)
{
	module->uccp_core_base = 0;
	module->uccp_core_len = 0;
	module->irq_line = 0;
	memset(clocks, 0, CLK_QTY*sizeof(clocks[0]));
}

static int img_hostport_pltfr_memmap(void)
{
#define REQUEST_MEM_FAILED_MSG "request_mem_region failed for UCCP region"
	/* Map UCCP memory */
	if (NULL == (request_mem_region(module->uccp_core_base,
					module->uccp_core_len, "uccp"))) {
		errn(REQUEST_MEM_FAILED_MSG ". base = %p, length = %lx\n",
				(void *)module->uccp_core_base,
				module->uccp_core_len);
		goto uccp_memory_request_error;
	}

	module->uccp_base_addr = ioremap(module->uccp_core_base,
			module->uccp_core_len);
	if (module->uccp_base_addr == 0) {
		errn("ioremap failed for UCCP mem region\n");
		goto uccp_memory_remap_error;
	}
	module->uccp_mem_addr = module->uccp_base_addr + C_REG_OFFSET;

	return 0;

uccp_memory_remap_error:
	release_mem_region(module->uccp_core_base, module->uccp_core_len);
uccp_memory_request_error:
	return -ENOMEM;
}

static void img_hostport_pltfr_memmap_rollback(void)
{
	iounmap((void __iomem *)module->uccp_base_addr);
	release_mem_region(module->uccp_core_base, module->uccp_core_len);
}

static int img_hostport_pltfr_memsetup(void)
{
	int i;

	module = kzalloc(sizeof(struct img_hostport), GFP_KERNEL);

	if (IS_ERR_OR_NULL(module))
		return PTR_ERR(module);

	for (i = 0; i < MAX_ENDPOINTS; i++)
		spin_lock_init(module->endpoints.in_use + i);
	return 0;
}

static void img_hostport_pltfr_memsetup_rollback(void)
{
	kfree(module);
}

static int img_hostport_pltfr_clksetup(struct platform_device *pdev)
{
	int i;

	for (i = 0; i < CLK_QTY; i++)
		clk_prepare_enable(clocks[i]);

	return 0;
}

static void img_hostport_pltfr_clksetup_rollback(void)
{
	int i;

	for (i = 0; i < CLK_QTY; i++)
		clk_disable_unprepare(clocks[i]);

}

static int __init img_hostport_pltfr_probe(struct platform_device *pdev)
{
	int result = 0;

	result = img_hostport_pltfr_memsetup();
	if (result) {
		err("Memory setup failed");
		goto memsetup_failed;
	}

	result = img_hostport_pltfr_dtsetup(pdev);
	if (result) {
		err("DT setup failed");
		goto dtsetup_failed;
	}

	result = img_hostport_pltfr_memmap();
	if (result) {
		errn("Memory remapping failed");
		goto memmap_failed;
	}

	result = img_hostport_pltfr_clksetup(pdev);
	if (result) {
		err("Clock setup failed");
		goto clksetup_failed;
	}

	/* Register irq handler, irq_line comes from dtsetup */
	result = img_hostport_pltfr_irqregist(module->irq_line);
	if (result) {
		err("Unable to register IRQ handler\n");
		goto irqsetup_failed;
	}

	dbg("activating hostport interrupt");
	img_hostport_irq_on();

	dbg("hostport driver registration completed");
	return result;

irqsetup_failed:
	img_hostport_pltfr_clksetup_rollback();
clksetup_failed:
	img_hostport_pltfr_memmap_rollback();
memmap_failed:
	img_hostport_pltfr_dtsetup_rollback();
dtsetup_failed:
	img_hostport_pltfr_memsetup_rollback();
memsetup_failed:
	return result;
}

static int img_hostport_pltfr_remove(struct platform_device *pdev)
{
	img_hostport_irq_off();
	img_hostport_pltfr_irqregist_rollback(module->irq_line);
	img_hostport_pltfr_clksetup_rollback();
	img_hostport_pltfr_memmap_rollback();
	img_hostport_pltfr_dtsetup_rollback();
	img_hostport_pltfr_memsetup_rollback();

	return 0;
}

static const struct of_device_id img_hostport_dt_ids[] = {
	{ .compatible = "img,pistachio-uccp-base" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, img_hostport_dt_ids);

struct platform_driver img_uccp_driver = {
	.probe = img_hostport_pltfr_probe,
	.remove = img_hostport_pltfr_remove,
	.driver = {
		.name     = "uccp420",
		.of_match_table = of_match_ptr(img_hostport_dt_ids),
	},
};

static void __exit img_hostport_leave(void)
{
	platform_driver_unregister(&img_uccp_driver);
}

static int __init img_hostport_entry(void)
{
	return platform_driver_probe(&img_uccp_driver,
					img_hostport_pltfr_probe);
}

module_init(img_hostport_entry);
module_exit(img_hostport_leave);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Bartosz Flis <bartosz.flis@imgtec.com>");
MODULE_DESCRIPTION("Imagination Technologies Host Port driver - www.imgtec.com");
