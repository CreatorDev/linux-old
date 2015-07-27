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
 *** File Name  : img-connectivity.c
 ***
 *** File Description:
 *** This file contains the implementation of the UCCP base driver.
 ***
 ******************************************************************************
 *END**************************************************************************/
#include <linux/clk.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>

#include <soc/img/img-connectivity.h>

#include "devres-ext.h"
#include "img-fwldr.h"

#define MOD_NAME "img-connectivity"
#define mod_err(format, ...) pr_err(MOD_NAME ": " format "\n", ##__VA_ARGS__)
#define mod_info(format, ...) pr_info(MOD_NAME ": " format "\n", ##__VA_ARGS__)

#define MAX_LOADERS 2
#define MB (1024*1024)
#define SCRATCHBUF_SIZE (4*MB)

enum {
	BOOT_OFF = 0,
	BOOT_MTX = 1,
	BOOT_MCP = 2,
};
static uint boot = BOOT_MTX;
module_param(boot, uint, 0400);
MODULE_PARM_DESC(boot,
	"Boot flag: \n\t0 - skip booting altogether"
	"\n\t1 - boot META"
	"\n\t2 - boot META and MCP");

/*
 * The following assumes BT configuration, i.e. one loader file and two
 * META threads.
 * # modprobe img-connectivity
 *
 * WIFI only configuration is two loaders (MCP, META) and one META thread.
 * Though binaries' names are just examples, remember that they must be relative
 * to [/usr]/lib/firmware/.
 * # modprobe img-connectivity mtx_threads=1 mcp_ldr="img/mcp.ldr"
 * mtx_ldr="img/mtx.ldr" boot=2
 *
 * Combo configuration is the best of both worlds: two loaders (MCP, META)
 * and two META threads. You use it like that:
 * # modprobe img-connectivity mcp_ldr="img/mcp.ldr" mtx_ldr="img/mtx.ldr"
 * boot=2
 */

static unsigned int mtx_threads = 2;
module_param(mtx_threads, uint, 0400);
MODULE_PARM_DESC(mtx_threads, "Number of available meta threads");

static char *mtx_ldr = "img/connectivity-mtx.ldr";
module_param(mtx_ldr, charp, 0400);
MODULE_PARM_DESC(mtx_ldr, "META loader binary");

static char *mcp_ldr = NULL;
module_param(mcp_ldr, charp, 0400);
MODULE_PARM_DESC(mcp_ldr, "MCP loader binary");

struct img_connectivity {
	void *scratch;
	dma_addr_t scratch_bus;
	unsigned char __iomem *uccp_sbus_v;
	unsigned char __iomem *uccp_gram_v;
	struct resource *uccp_sbus;
	struct resource *uccp_gram;
};
static struct img_connectivity *module;

struct clock {
	struct list_head xs;
	struct clk *p;
};
static LIST_HEAD(clocks);

/*
 * *** Public API ***
 */
struct img_version_info img_connectivity_version(void)
{
	struct img_version_info vi = { .bt = 0, .wlan = 0 };
	return vi;
}
EXPORT_SYMBOL(img_connectivity_version);

struct img_scratch_info img_connectivity_scratch(void)
{
	struct img_scratch_info si = {
		.virt_addr = module->scratch,
		.bus_addr = module->scratch_bus
	};
	return si;
}
EXPORT_SYMBOL(img_connectivity_scratch);

/*
 * *** Private API ***
 */
static int img_connectivity_memsetup(struct platform_device *d)
{
	module = devm_kzalloc(&d->dev, sizeof(struct img_connectivity),
								GFP_KERNEL);
	if (NULL == module) {
		return -ENOMEM;
	}

	module->scratch = dmam_alloc_coherent(&d->dev, SCRATCHBUF_SIZE,
					&module->scratch_bus, GFP_KERNEL);
	if (NULL == module->scratch)
		return -ENOMEM;

	return 0;
}

static void img_connectivity_memsetup_rollback(struct platform_device *d)
{}

#define until(i, max) for (i = 0; i < max; i++)
static int boot_cpu(struct device *d, const char *fw_name,
						unsigned int num_threads)
{
	int err, t_idx;
	const struct firmware *fw = NULL;

	err = request_firmware(&fw, fw_name, d);
	if (err) {
		mod_err("firmware request failed for %s", fw_name);
		return err;
	}

	until(t_idx, num_threads)
		fwldr_soft_reset(t_idx);

	err = fwldr_load_fw(fw->data);
	if (!err)
		mod_info("firmware %s loaded", fw_name);
	else
		mod_err("firmware %s load failed", fw_name);

	release_firmware(fw);
	return 0;
}

static int img_connectivity_boot(struct platform_device *d)
{
	int err, t_idx;

	if (BOOT_OFF == boot) {
		mod_info("skipping boot");
		return 0;
	}

	module->uccp_sbus_v = devm_ioremap_resource(&d->dev, module->uccp_sbus);
	if (IS_ERR(module->uccp_sbus_v))
		return PTR_ERR(module->uccp_sbus_v);

	module->uccp_gram_v = devm_ioremap_resource(&d->dev, module->uccp_gram);
	if (IS_ERR(module->uccp_gram_v))
		return PTR_ERR(module->uccp_gram_v);

	fwldr_init(module->uccp_sbus_v, module->uccp_gram_v, NULL);

	/*
	 * MCP code, if provided, has to be loaded first. After that it is
	 * necessary to stop all META threads.
	 */
	if(BOOT_MCP == boot) {
		if (!mcp_ldr) {
			mod_err("MCP boot requested, but MCP loader binary "
							"not specified");
			return -ENOENT;
		}

		err = boot_cpu(&d->dev, mcp_ldr, mtx_threads);
		if (err) {
			return err;
		}

		until(t_idx, mtx_threads)
			fwldr_stop_thrd(t_idx);
	}

	err = boot_cpu(&d->dev, mtx_ldr, mtx_threads);
	if (err) {
		return err;
	}

	devm_iounmap_resource(&d->dev, module->uccp_gram, module->uccp_gram_v);
	devm_iounmap_resource(&d->dev, module->uccp_sbus, module->uccp_sbus_v);

	return 0;
}

static void img_connectivity_boot_rollback(struct platform_device *d)
{}

static int img_connectivity_clock_setup(struct platform_device *d)
{
	int ret;
	struct clock *clock;

	list_for_each_entry(clock, &clocks, xs) {
		ret = clk_prepare_enable(clock->p);
		if (ret) {
			list_for_each_entry_continue_reverse(clock, &clocks, xs)
				clk_disable_unprepare(clock->p);
			return ret;
		}
	}

	return 0;
}

static void img_connectivity_clock_setup_rollback(struct platform_device *d)
{
	struct clock *clock;

	list_for_each_entry(clock, &clocks, xs)
		clk_disable_unprepare(clock->p);
}

static struct clock *alloc_single_clock(struct device *d, int index)
{
	struct clock *tmp;
	struct clk *tmpclk;

	tmpclk = of_clk_get(d->of_node, index);
	if (IS_ERR(tmpclk)) {
		return ERR_PTR(-ENODEV);
	}

	tmp = devm_kzalloc(d, sizeof(struct clock), GFP_KERNEL);
	if (NULL == tmp) {
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&tmp->xs);
	tmp->p = tmpclk;
	return tmp;
}

static int img_connectivity_dtsetup(struct platform_device *d)
{
	int i;
	struct clock *tmp;
	int clocks_no;

	/*
	 * Check how many clocks we have defined.
	 *
	 * Note that 'clocks' is an optional property.
	 */
	if (of_property_read_u32(d->dev.of_node, "clocks-number", &clocks_no)) {
		mod_info("img-connectivity: could not find 'clocks-number' "
			"dt property");
		return 0;
	}

	mod_info("img-connectivity: detected %d clocks", clocks_no);

	INIT_LIST_HEAD(&clocks);
	for (i = 0; i < clocks_no; i++) {
		tmp = alloc_single_clock(&d->dev, i);
		if (!IS_ERR(tmp)) {
			list_add(&tmp->xs, &clocks);
		} else if (ERR_PTR(-ENODEV) == tmp) {
			mod_err("img-connectivity: invalid clock reference %d",
					i);
			return PTR_ERR(tmp);
		} else if (ERR_PTR(-ENOMEM) == tmp) {
			mod_err("img-connectivity: failed to allocate "
					"clock descriptor");
			return PTR_ERR(tmp);
		} else {
			mod_err("img-connectivity: BUG: unknown return value "
					"%ld", PTR_ERR(tmp));
			return PTR_ERR(tmp);
		}
	}

	/*
	 * Parse 'reg' property
	 */
	module->uccp_sbus = platform_get_resource_byname(d, IORESOURCE_MEM,
							"UCCP system bus");
	if (IS_ERR(module->uccp_sbus))
		return -ENOENT;

	module->uccp_gram = platform_get_resource_byname(d, IORESOURCE_MEM,
							"UCCP packed GRAM");
	if (IS_ERR(module->uccp_gram))
		return -ENOENT;

	return 0;
}

static void img_connectivity_dtsetup_rollback(struct platform_device *d)
{}

static int img_connectivity_memmap(struct platform_device *d)
{
	return 0;
}

static void img_connectivity_memmap_rollback(struct platform_device *d)
{}

/*
 * * platform driver code & data
 */
static int __init img_connectivity_probe(struct platform_device *d)
{
	int ret;

	ret = img_connectivity_memsetup(d);
	if (ret)
		goto memsetup_failed;

	ret = img_connectivity_dtsetup(d);
	if (ret)
		goto dtsetup_failed;

	ret = img_connectivity_memmap(d);
	if (ret)
		goto memmap_failed;

	ret = img_connectivity_clock_setup(d);
	if (ret)
		goto clock_setup_failed;

	ret = img_connectivity_boot(d);
	if (ret)
		goto boot_failed;

	return 0;
boot_failed:
	img_connectivity_clock_setup_rollback(d);
clock_setup_failed:
	img_connectivity_memmap_rollback(d);
memmap_failed:
	img_connectivity_dtsetup_rollback(d);
dtsetup_failed:
	img_connectivity_memsetup_rollback(d);
memsetup_failed:
	return ret;
}

static int img_connectivity_remove(struct platform_device *d)
{
	img_connectivity_boot_rollback(d);
	img_connectivity_clock_setup_rollback(d);
	img_connectivity_dtsetup_rollback(d);
	img_connectivity_memsetup_rollback(d);
	return 0;
}

static const struct of_device_id img_connectivity_dt_ids[] = {
	{ .compatible = "img,pistachio-uccp-system" },
	{}
};
MODULE_DEVICE_TABLE(of, img_connectivity_dt_ids);

static struct platform_driver img_connectivity_pd = {
	.remove = img_connectivity_remove,
	.driver = {
		.name = "img-connectivity",
		.of_match_table = of_match_ptr(img_connectivity_dt_ids),
	},
};

/*
 * * .ko entry and exit points
 */
static int __init img_connectivity_entry(void)
{
	return platform_driver_probe(&img_connectivity_pd, img_connectivity_probe);
}

static void __exit img_connectivity_leave(void)
{
	platform_driver_unregister(&img_connectivity_pd);
}

module_init(img_connectivity_entry);
module_exit(img_connectivity_leave);

/*
 * * module metadata
 */
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Bartosz Flis <bartosz.flis@imgtec.com>");
MODULE_DESCRIPTION("Imagination Technologies RPU base driver - www.imgtec.com");
