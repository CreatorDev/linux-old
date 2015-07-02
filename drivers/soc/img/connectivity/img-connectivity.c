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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>

#include <soc/img/img-connectivity.h>

struct img_connectivity {
	phys_addr_t rpu_sbus;
};

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

/*
 * *** Private API ***
 */
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
		pr_info("img-connectivity: could not find 'clocks-number' "
			"dt property\n");
		return 0;
	}

	pr_info("img-connectivity: detected %d clocks\n", clocks_no);

	INIT_LIST_HEAD(&clocks);
	for (i = 0; i < clocks_no; i++) {
		tmp = alloc_single_clock(&d->dev, i);
		if (!IS_ERR(tmp)) {
			list_add(&tmp->xs, &clocks);
		} else if (ERR_PTR(-ENODEV) == tmp) {
			pr_err("img-connectivity: invalid clock reference %d\n",
					i);
			return PTR_ERR(tmp);
		} else if (ERR_PTR(-ENOMEM) == tmp) {
			pr_err("img-connectivity: failed to allocate "
					"clock descriptor\n");
			return PTR_ERR(tmp);
		} else {
			pr_err("img-connectivity: BUG: unknown return value "
					"%ld\n", PTR_ERR(tmp));
			return PTR_ERR(tmp);
		}
	}

	return 0;
}

static void img_connectivity_dtsetup_rollback(struct platform_device *d)
{}
/*
 * * platform driver code & data
 */
static int __init img_connectivity_probe(struct platform_device *d)
{
	int ret;

	ret = img_connectivity_dtsetup(d);
	if (ret)
		goto dtsetup_failed;

	ret = img_connectivity_clock_setup(d);
	if (ret)
		goto clock_setup_failed;

	/*
	 * TODO: request and load the code
	 */
	return 0;
clock_setup_failed:
	img_connectivity_dtsetup_rollback(d);
dtsetup_failed:
	return ret;
}

static int img_connectivity_remove(struct platform_device *d)
{
	img_connectivity_clock_setup_rollback(d);
	img_connectivity_dtsetup_rollback(d);
	/*
	 * Quiesce the RPU (?)
	 */
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
