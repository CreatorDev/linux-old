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
#include <linux/jiffies.h>
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

#include <soc/img/img-connectivity.h>

#include "img-hostport.h"

typedef void (*gen_handler)(void *);

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
#define IS_BUSY(reg) (ioread32(reg) & 0x80000000)
#define mtx_int_en_WIDTH 4

DEFINE_SPINLOCK(host_to_uccp_core_lock);

/*
 * Forward declarations
 */
static void notify_common(u16 user_data, int user_id, gen_handler poke_ready,
							void *poke_ready_arg);

/*
 * Public interface procs
 */

void img_transport_notify(u16 user_data, int user_id)
{
	img_transport_notify_callback(user_data, user_id, NULL, NULL);
}
EXPORT_SYMBOL(img_transport_notify);

int __must_check img_transport_notify_timeout(u16 user_data,
					int user_id,
					long jiffies_timeout)
{
	return img_transport_notify_callback_timeout(user_data, user_id,
						jiffies_timeout, NULL, NULL);
}
EXPORT_SYMBOL(img_transport_notify_timeout);

void img_transport_notify_callback(u16 user_data,
					int user_id,
					gen_handler poke_ready,
					void *poke_ready_arg)
{
	unsigned long flags;
	spin_lock_irqsave(&host_to_uccp_core_lock, flags);
	while(IS_BUSY(H2C_CMD_ADDR(module->vbase)))
		continue;
	notify_common(user_data, user_id, poke_ready, poke_ready_arg);
	spin_unlock_irqrestore(&host_to_uccp_core_lock, flags);
}
EXPORT_SYMBOL(img_transport_notify_callback);

int __must_check img_transport_notify_callback_timeout(u16 user_data,
					int user_id,
					long jiffies_timeout,
					gen_handler poke_ready,
					void *poke_ready_arg)
{
	unsigned long start_time = jiffies, flags;
	spin_lock_irqsave(&host_to_uccp_core_lock, flags);
	while(IS_BUSY(H2C_CMD_ADDR(module->vbase))) {
		if (time_after_eq(start_time + jiffies_timeout, jiffies)) {
			spin_unlock_irqrestore(&host_to_uccp_core_lock, flags);
			return -ETIME;
		}
	}

	notify_common(user_data, user_id, poke_ready, poke_ready_arg);
	spin_unlock_irqrestore(&host_to_uccp_core_lock, flags);
	return 0;
}
EXPORT_SYMBOL(img_transport_notify_callback_timeout);

int img_transport_register_callback(
		img_transport_handler poke,
		unsigned int client_id)
{
	/*
	 * Make sure that the slot is free, i.e. null
	 */
	if (0 == client_id || client_id > MAX_ENDPOINT_ID || module->endpoints.f[client_id])
		return -EBADSLT;

	spin_lock(module->endpoints.in_use + client_id);
	module->endpoints.f[client_id] = poke;
	spin_unlock(module->endpoints.in_use + client_id);

	return 0;
}
EXPORT_SYMBOL(img_transport_register_callback);

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

static void notify_common(u16 user_data, int user_id, gen_handler poke_ready,
							void *poke_ready_arg)
{
	trace_printk("img-hostport: snd -- %d:%d:%02X\n", user_id, user_id, user_data);
	if (poke_ready)
		poke_ready(poke_ready_arg);
	iowrite32(0x87 << 24 | user_data << 8 | id_to_field(user_id),
			(void __iomem *)H2C_CMD_ADDR(module->vbase));
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
		readl((void __iomem *)(C2H_CMD_ADDR(module->vbase)));

	/* TODO: need to change that to support platforms other that 32 bit */
	first_bit = (reg_value & (1 << 31)) >> 31;
	if (0 == first_bit) {
		trace_printk("img-hostport: unexpected spurious interrupt detected (0x%08X)!\n",
			reg_value);
		goto exit;
	}

	callee_id = CALLEE(reg_value);
	caller_id = CALLER(reg_value);
	user_message = USERMSG(reg_value);
	trace_printk("img-hostport: rcv -%c %d:%d:%02X\n", first_bit ? '-' : '*', callee_id, caller_id, user_message);

	/*
	 * callee_id is tainted, therefore must be checked.
	 */
	if (callee_id > MAX_ENDPOINT_ID) {
		trace_printk("img-hostport: endpoint with id = %u doesn't exist\n", callee_id);
		goto deassert;
	}

	handler = module->endpoints.f[callee_id];
	handler_in_use = module->endpoints.in_use + callee_id;
	if (NULL == handler) {
		trace_printk("img-hostport: endpoint with id = %u not registered\n", callee_id);
		goto deassert;
	}
	spin_lock_irqsave(handler_in_use, flags);
	handler((u16)user_message);
	spin_unlock_irqrestore(handler_in_use, flags);

deassert:
	/* Clear the uccp interrupt */
	value = 0;
	value |= BIT(C_INT_CLR_SHIFT);
	writel(value, (void __iomem *)(H2C_ACK_ADDR(module->vbase)));

	/*
	 * Send ACK to the RPU
	 */
	img_transport_notify(0, COMMON_HOST_ID);
exit:
	return IRQ_HANDLED;
}

static void img_hostport_irq_on(void)
{
	unsigned int value = 0;

	/*
	 * Both mtx_irq and mtx_int must be asserted in order to
	 * receive inerrupts on the host
	 */

	iowrite32(0x80000000, H2C_ACK_ADDR(module->vbase));
	iowrite32(0x80000000, C2H_ACK_ADDR(module->vbase));

	value = readl(module->vmtx_irq_en);
	value |= BIT(C_IRQ_EN_SHIFT);
	writel(value, module->vmtx_irq_en);

	value = 0;
	value |= BIT(C_INT_EN_SHIFT);
	writel(value, module->vmtx_int_en);
}

static void img_hostport_irq_off(void)
{
	unsigned int value = 0;

	value = 0;
	value &= ~(BIT(C_INT_EN_SHIFT));
	writel(value, module->vmtx_int_en);

	value = readl(module->vmtx_irq_en);
	value &= ~(BIT(C_IRQ_EN_SHIFT));
	writel(value, module->vmtx_irq_en);
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
	int irq_or_error;
	/* Get resources from platform device */
	irq_or_error = platform_get_irq(pdev, 0);
	if (irq_or_error < 0) { /* it's an error */
		err("cannot find IRQ resource\n");
		return irq_or_error; /* it's now error code */
	}
	module->irq_line = irq_or_error; /* it's now a valid IRQ line */

	module->base = platform_get_resource_byname(pdev, IORESOURCE_MEM,
						"Hostport control block");
	if (IS_ERR_OR_NULL(module->base)) {
		errn("hostport base address not found");
		return PTR_ERR(module->base);
	}

	module->mtx_int_en = platform_get_resource_byname(pdev, IORESOURCE_MEM,
						"Hostport mtx_int enable");
	if (IS_ERR_OR_NULL(module->mtx_int_en)) {
		errn("mtx_int enable address not found");
		return PTR_ERR(module->base);
	}

	module->mtx_irq_en = platform_get_resource_byname(pdev, IORESOURCE_MEM,
						"Hostport mtx_irq enable");
	if (IS_ERR_OR_NULL(module->mtx_irq_en)) {
		errn("mtx_irq enable address not found");
		return PTR_ERR(module->mtx_irq_en);
	}

	return 0;
}

static void img_hostport_pltfr_dtsetup_rollback(void)
{
	module->base = 0;
	module->mtx_int_en = 0;
	module->irq_line = 0;
}

static int img_hostport_pltfr_memmap(struct platform_device *d)
{
	/* Map RPU sbus */
	module->vbase = devm_ioremap_resource(&d->dev, module->base);
	if (NULL == module->vbase) {
		errn("failed to remap Hostport control block");
		return -ENOMEM;
	}

	module->vmtx_int_en = devm_ioremap_resource(&d->dev,
							module->mtx_int_en);
	if (module->vmtx_int_en == 0) {
		errn("failed to remap mtx_int enable register");
		return -ENOMEM;
	}

	module->vmtx_irq_en = devm_ioremap_resource(&d->dev,
							module->mtx_irq_en);
	if (module->vmtx_irq_en == 0) {
		errn("faield to remap mtx_irq enable register");
		return -ENOMEM;
	}

	return 0;
}

static void img_hostport_pltfr_memmap_rollback(void)
{
	module->vmtx_int_en = module->vbase = 0;
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

static int img_hostport_pltfr_probe(struct platform_device *pdev)
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

	result = img_hostport_pltfr_memmap(pdev);
	if (result) {
		errn("Memory remapping failed");
		goto memmap_failed;
	}

	/* Register irq handler, irq_line comes from dtsetup */
	result = img_hostport_pltfr_irqregist(module->irq_line);
	if (result) {
		err("Unable to register IRQ handler\n");
		goto irqsetup_failed;
	}

	dbg("activating hostport interrupt");
	img_hostport_irq_on();

	dbg("releasing C2H register");
	img_transport_notify(0, COMMON_HOST_ID);

	dbg("hostport driver registration completed");
	return result;

irqsetup_failed:
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
	img_hostport_pltfr_memmap_rollback();
	img_hostport_pltfr_dtsetup_rollback();
	img_hostport_pltfr_memsetup_rollback();

	return 0;
}

static const struct of_device_id img_hostport_dt_ids[] = {
	{ .compatible = "img,pistachio-uccp-hostport" },
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
	/*
	 * The following line is here purely to make sure that the current
	 * module depends on img-connectivity when it's loaded as a module.
	 */
	 img_connectivity_version();

	return platform_driver_probe(&img_uccp_driver,
					img_hostport_pltfr_probe);
}

module_init(img_hostport_entry);
module_exit(img_hostport_leave);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Bartosz Flis <bartosz.flis@imgtec.com>");
MODULE_DESCRIPTION("Imagination Technologies Host Port driver - www.imgtec.com");
