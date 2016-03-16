/*
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This driver gives access(read/write) to the bootcounter used by u-boot.
 * Access is supported via sysfs.
 *
 * Based on work from: Steffen Rumler  <Steffen.Rumler@siemens.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
*/

#include <linux/fs.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/regmap.h>
#include <linux/mfd/syscon.h>

#define UBOOT_BOOTCOUNT_MAGIC		0xB001C041 /* magic number value */
#define UBOOT_BOOTCOUNT_MAGIC_MASK	0xFFFF0000 /* magic, when combined */
#define UBOOT_BOOTCOUNT_COUNT_MASK	0x0000FFFF /* value, when combined */


struct bootcount_device {
	struct regmap *regmap;
	unsigned int regmap_offset;
};

static const struct regmap_config regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
};

static int bootcount_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	int ret;
	unsigned int bootcount;
	struct bootcount_device *priv = dev_get_drvdata(dev);

	ret = regmap_read(priv->regmap, priv->regmap_offset, &bootcount);
	if (ret)
		return ret;

	if ((bootcount & UBOOT_BOOTCOUNT_MAGIC_MASK) !=
		(UBOOT_BOOTCOUNT_MAGIC & UBOOT_BOOTCOUNT_MAGIC_MASK)) {
		return -EINVAL;
	}
	bootcount &= UBOOT_BOOTCOUNT_COUNT_MASK;
	return sprintf(buf, "%u\n", bootcount);
}

static int bootcount_store(struct device *dev,
			struct device_attribute *attr,
			const char *buf,
			size_t count)
{
	int ret;
	u32 value;
	struct bootcount_device *priv = dev_get_drvdata(dev);

	ret = kstrtou32(buf, 0, &value);
	if (ret < 0)
		return ret;

	value = (UBOOT_BOOTCOUNT_MAGIC & UBOOT_BOOTCOUNT_MAGIC_MASK) |
		(value & UBOOT_BOOTCOUNT_COUNT_MASK);
	ret = regmap_write(priv->regmap, priv->regmap_offset, value);
	if (ret)
		return ret;

	return count;
}

static DEVICE_ATTR_RW(bootcount);

static int bootcount_probe(struct platform_device *ofdev)
{
	unsigned int magic;
	struct bootcount_device *priv;
	struct resource *res;
	int status, ret;

	priv = devm_kzalloc(&ofdev->dev, sizeof(struct bootcount_device), GFP_KERNEL);
	if (!priv) {
		dev_err(&ofdev->dev, "Unable to allocate device private data\n");
		return -ENOMEM;
	}

	res = platform_get_resource(ofdev, IORESOURCE_MEM, 0);
	if (res) {
		void __iomem *reg;

		reg = devm_ioremap_resource(&ofdev->dev, res);
		if (IS_ERR(reg)) {
			dev_err(&ofdev->dev, "Unable to map register\n");
			return PTR_ERR(reg);
		}
		priv->regmap = devm_regmap_init_mmio(&ofdev->dev, reg,
						     &regmap_config);
		if (IS_ERR(priv->regmap)) {
			dev_err(&ofdev->dev, "Unable to get regmap\n");
			return PTR_ERR(priv->regmap);
		}

		priv->regmap_offset = 0;
	} else {
		struct of_phandle_args args;

		ret = of_parse_phandle_with_fixed_args(ofdev->dev.of_node,
						"syscon-reg", 1, 0,
						&args);
		if (ret)
			return ret;
		priv->regmap = syscon_node_to_regmap(args.np);
		if (IS_ERR(priv->regmap)) {
			dev_err(&ofdev->dev, "Unable to get regmap\n");
			return PTR_ERR(priv->regmap);
		}
		priv->regmap_offset = args.args[0];
	}

	ret = regmap_read(priv->regmap, priv->regmap_offset, &magic);
	if (ret)
		return ret;

	if ((magic & UBOOT_BOOTCOUNT_MAGIC_MASK) !=
	    (UBOOT_BOOTCOUNT_MAGIC & UBOOT_BOOTCOUNT_MAGIC_MASK)) {
		dev_err(&ofdev->dev, "bad magic\n");
		return -EINVAL;
	}

	status = device_create_file(&ofdev->dev, &dev_attr_bootcount);
	if (status) {
		dev_err(&ofdev->dev, "unable to register sysfs entry\n");
		return status;
	}
	dev_set_drvdata(&ofdev->dev, priv);
	return 0;
}

static int bootcount_remove(struct platform_device *ofdev)
{
	device_remove_file(&ofdev->dev, &dev_attr_bootcount);
	return 0;
}

static const struct of_device_id bootcount_match[] = {
	{ .compatible = "uboot,bootcount", },
	{},
};

MODULE_DEVICE_TABLE(of, bootcount_match);

static struct platform_driver bootcount_driver = {
	.driver = {
		.name = "bootcount",
		.of_match_table = bootcount_match,
	},
	.probe = bootcount_probe,
	.remove = bootcount_remove,
};

module_platform_driver(bootcount_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Avinash Tahakik <avinash.tahakik@imgtec.com>");
MODULE_DESCRIPTION("Provide (read/write) access to the U-Boot bootcounter via sysfs");
