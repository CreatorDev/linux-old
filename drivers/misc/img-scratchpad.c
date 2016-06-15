/*
 * Copyright (C) 2016 Imagination Technologies Ltd.
 *
 * This driver provides sysfs read/write access to the scratchpad
 * registers, these registers are soft reset protected registers.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
*/

#include <linux/clk.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>


#define MAX_NUM_REG	8
#define REG_SIZE	4
#define FILE_PREFIX	"reg"

struct scratchpad_device {
	struct clk *wdt_clk;
	struct clk *sys_clk;
	struct regmap *regmap;
	struct attribute_group attr_group;
	struct device_attribute *attr;
	struct attribute **attrs;
};

static int reg_show(struct device *dev, struct device_attribute *attr,
		    char *buf)
{
	unsigned int value;
	unsigned int index;
	int ret;
	struct scratchpad_device *priv = dev_get_drvdata(dev);

	/* find out reg number based on name of attr */
	if (sscanf(attr->attr.name, FILE_PREFIX"%u", &index) != 1)
		return -EINVAL;

	if (index > MAX_NUM_REG)
		return -EINVAL;

	ret = regmap_read(priv->regmap, index*REG_SIZE, &value);
	if (ret)
		return ret;

	return sprintf(buf, "0x%x\n", value);
}

static int reg_store(struct device *dev, struct device_attribute *attr,
		     const char *buf, size_t count)
{
	int ret;
	u32 value;
	unsigned int index;
	struct scratchpad_device *priv = dev_get_drvdata(dev);

	/* find out reg number based on name of attr */
	if (sscanf(attr->attr.name, FILE_PREFIX"%u", &index) != 1)
		return -EINVAL;

	if (index > MAX_NUM_REG)
		return -EINVAL;

	ret = kstrtou32(buf, 0, &value);
	if (ret < 0)
		return ret;

	ret = regmap_write(priv->regmap, index*REG_SIZE, value);
	if (ret)
		return ret;

	return count;
}

static int enable_wdt_clk(struct device *dev)
{
	int ret;
	struct scratchpad_device *priv = dev_get_drvdata(dev);

	priv->sys_clk = devm_clk_get(dev, "sys");
	if (IS_ERR(priv->sys_clk)) {
		dev_err(dev, "failed to get the sys clock\n");
		return PTR_ERR(priv->sys_clk);
	}

	priv->wdt_clk = devm_clk_get(dev, "wdt");
	if (IS_ERR(priv->wdt_clk)) {
		dev_err(dev, "failed to get the wdt clock\n");
		return PTR_ERR(priv->wdt_clk);
	}

	ret = clk_prepare_enable(priv->sys_clk);
	if (ret) {
		dev_err(dev, "could not prepare or enable sys clock\n");
		return ret;
	}

	ret = clk_prepare_enable(priv->wdt_clk);
	if (ret) {
		dev_err(dev, "could not prepare or enable wdt clock\n");
		clk_disable_unprepare(priv->sys_clk);
	}

	return ret;
}

static void disable_wdt_clk(struct device *dev)
{
	struct scratchpad_device *priv = dev_get_drvdata(dev);

	clk_disable_unprepare(priv->wdt_clk);
	clk_disable_unprepare(priv->sys_clk);
}

static int create_sysfs_files(struct device *dev, unsigned long sysfs_mask)
{
	int i, attr_index = 0;
	unsigned int num_regs = 0;
	int ret;
	struct scratchpad_device *priv = dev_get_drvdata(dev);

	/* If no files to be created, just return */
	if (!sysfs_mask)
		return 0;

	for_each_set_bit(i, &sysfs_mask, BITS_PER_BYTE)
		num_regs++;

	/* Allocate memory for sysfs attributes based on number
	 * of registers to be exposed
	 * +1 for NULL termination in the end
	 */
	priv->attrs = devm_kzalloc(dev,
			sizeof(struct attribute *) * (num_regs+1),
			GFP_KERNEL);
	if (!priv->attrs)
		return -ENOMEM;

	priv->attr = devm_kzalloc(dev,
			sizeof(struct device_attribute) * num_regs,
			GFP_KERNEL);
	if (!priv->attr)
		return -ENOMEM;

	/* create sysfs attributes */
	for_each_set_bit(i, &sysfs_mask, BITS_PER_BYTE) {
		char *name;
		const int name_len = sizeof(FILE_PREFIX) + 2;

		name = devm_kmalloc(dev, name_len, GFP_KERNEL);
		if (!name)
			return -ENOMEM;

		/* specify file name based on the actual reg index */
		snprintf(name, name_len, FILE_PREFIX"%01u", i);

		sysfs_attr_init(&priv->attr[attr_index].attr);
		priv->attr[attr_index].attr.name = name;
		priv->attr[attr_index].attr.mode = (S_IWUSR | S_IRUGO);
		priv->attr[attr_index].show = reg_show;
		priv->attr[attr_index].store = reg_store;
		priv->attrs[attr_index] = &priv->attr[attr_index].attr;
		attr_index++;
	}

	priv->attr_group.attrs = priv->attrs;
	ret = sysfs_create_group(&dev->kobj, &priv->attr_group);
	if (ret)
		dev_err(dev, "Error in creating sysfs group\n");

	return ret;
}

static int scratchpad_probe(struct platform_device *ofdev)
{
	struct device *dev = &ofdev->dev;
	struct scratchpad_device *priv;
	int ret;
	u8 sysfs_mask = 0xFF;

	priv = devm_kzalloc(dev, sizeof(struct scratchpad_device),
			    GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	dev_set_drvdata(dev, priv);

	priv->regmap = syscon_node_to_regmap(dev->of_node);
	if (IS_ERR(priv->regmap)) {
		dev_err(dev, "Unable to get regmap\n");
		return PTR_ERR(priv->regmap);
	}

	if (of_property_read_u8(dev->of_node, "sysfs-mask", &sysfs_mask))
		dev_info(dev, "sysfs-mask property not specified\n");

	ret = enable_wdt_clk(dev);
	if (ret)
		return ret;

	ret = create_sysfs_files(dev, sysfs_mask);
	if (ret)
		goto clk_unprepare;

	return 0;

clk_unprepare:
	disable_wdt_clk(dev);
	return ret;
}

static int scratchpad_remove(struct platform_device *ofdev)
{
	struct scratchpad_device *priv = dev_get_drvdata(&ofdev->dev);

	sysfs_remove_group(&ofdev->dev.kobj, &priv->attr_group);

	disable_wdt_clk(&ofdev->dev);

	return 0;
}

static const struct of_device_id scratchpad_match[] = {
	{ .compatible = "img,pistachio-scratchpad", },
	{},
};

MODULE_DEVICE_TABLE(of, scratchpad_match);

static struct platform_driver scratchpad_driver = {
	.driver = {
		.name = "img-scratchpad",
		.of_match_table = scratchpad_match,
	},
	.probe = scratchpad_probe,
	.remove = scratchpad_remove,
};

module_platform_driver(scratchpad_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shraddha Chaudhari<shraddha.chaudhari@imgtec.com>");
MODULE_DESCRIPTION("Provide syfs read/write access to the scratchpad registers");
