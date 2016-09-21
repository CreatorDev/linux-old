/**
 * Imagination Technologies Pulse Density Modulator driver
 *
 * Copyright (C) 2014-2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/capability.h>
#include <linux/clk.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/img_pdm.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/string.h>
#include <linux/sysfs.h>

/* Registers */
#define PERIP_PWM_PDM_CONTROL			0x0140
#define PERIP_PWM_PDM_CONTROL_CH_MASK		0x1
#define PERIP_PWM_PDM_CONTROL_CH_SHIFT(ch)	((ch) * 4)

#define PERIP_PDM0_VAL				0x0144
#define PERIP_PDM_CH_ADDR_SHIFT(ch)		((ch) * 4)
#define PERIP_PDM_SRC_DATA_MASK			0xfff

#define IMG_NUM_PDM				4
#define PDM_CHANNEL_REQUESTED			1
#define PDM_CHANNEL_ENABLED			2

struct img_pdm_device {
	struct clk *clk;
	struct kobject **pdm_kobj;
	struct regmap *periph_regs;
	struct platform_device *pdev;
};

static struct img_pdm_channel *pdm_channels;
static DEFINE_MUTEX(pdm_lock);

int img_pdm_channel_config(struct img_pdm_channel *chan, unsigned int val)
{
	struct img_pdm_device *pdm_dev;

	mutex_lock(&pdm_lock);

	if (!chan) {
		mutex_unlock(&pdm_lock);
		return -EINVAL;
	}

	pdm_dev = chan->pdm_dev;
	if (!test_bit(PDM_CHANNEL_REQUESTED, &chan->flags)) {
		dev_err(&pdm_dev->pdev->dev, "channel not requested\n");
		mutex_unlock(&pdm_lock);
		return -EINVAL;
	}

	val &= PERIP_PDM_SRC_DATA_MASK;
	regmap_write(pdm_dev->periph_regs,
		     PERIP_PDM0_VAL + PERIP_PDM_CH_ADDR_SHIFT(chan->pdm_id),
		     val);
	mutex_unlock(&pdm_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(img_pdm_channel_config);

static int img_pdm_channel_free(struct img_pdm_channel *chan)
{
	unsigned int i;
	struct img_pdm_device *pdm_dev;

	mutex_lock(&pdm_lock);

	if (!pdm_channels || !chan) {
		mutex_unlock(&pdm_lock);
		return -EINVAL;
	}

	pdm_dev = pdm_channels[0].pdm_dev;
	if (!pdm_dev) {
		mutex_unlock(&pdm_lock);
		return -EINVAL;
	}

	for (i = 0; i < IMG_NUM_PDM; i++) {
		if (&pdm_channels[i] && (&pdm_channels[i] == chan))
			break;
	}

	if (i == IMG_NUM_PDM) {
		mutex_unlock(&pdm_lock);
		return -EINVAL;
	}

	if (test_bit(PDM_CHANNEL_ENABLED, &chan->flags)) {
		dev_err(&pdm_dev->pdev->dev,
			"can't free the channel while it is enabled\n");
		mutex_unlock(&pdm_lock);
		return -EBUSY;
	}

	if (!test_bit(PDM_CHANNEL_REQUESTED, &chan->flags)) {
		dev_err(&pdm_dev->pdev->dev,
			"trying to free channel which is not requested\n");
		mutex_unlock(&pdm_lock);
		return -EINVAL;
	}

	clear_bit(PDM_CHANNEL_REQUESTED, &chan->flags);
	mutex_unlock(&pdm_lock);

	return 0;
}

static struct img_pdm_channel *img_pdm_channel_request(unsigned int pdm_id)
{
	unsigned int i;
	struct img_pdm_device *pdm_dev;
	struct img_pdm_channel *chan = NULL;

	mutex_lock(&pdm_lock);

	if (pdm_id < 0 || pdm_id >= IMG_NUM_PDM || !pdm_channels) {
		mutex_unlock(&pdm_lock);
		return NULL;
	}

	pdm_dev = pdm_channels[0].pdm_dev;
	if (!pdm_dev)
		return NULL;

	for (i = 0; i < IMG_NUM_PDM; i++) {
		if (&pdm_channels[i] && (pdm_channels[i].pdm_id == pdm_id)) {
			chan = &pdm_channels[i];
			break;
		}
	}

	if (!chan) {
		mutex_unlock(&pdm_lock);
		return NULL;
	}

	/* Check if channel is already requested */
	if (test_bit(PDM_CHANNEL_REQUESTED, &chan->flags)) {
		dev_err(&pdm_dev->pdev->dev,
			"pdm channel %d already requested\n", chan->pdm_id);
		mutex_unlock(&pdm_lock);
		return NULL;
	}

	set_bit(PDM_CHANNEL_REQUESTED, &chan->flags);
	mutex_unlock(&pdm_lock);

	return chan;
}

static struct img_pdm_channel *of_img_pdm_channel_get(struct device_node *np)
{
	int err;
	struct of_phandle_args args;
	struct img_pdm_channel *chan;

	err = of_parse_phandle_with_args(np, "pdms", "#pdm-cells", 0, &args);
	if (err) {
		pr_debug("%s: can't parse \"pdms\" property\n", __func__);
		return ERR_PTR(err);
	}

	if (args.args_count != 2) {
		pr_debug("%s: wrong #pwm-cells\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	chan = img_pdm_channel_request(args.args[0]);
	if (chan)
		img_pdm_channel_config(chan, args.args[1]);

	return chan;
}

static void of_img_pdm_channel_put(struct device_node *np)
{
	int err;
	struct of_phandle_args args;
	struct img_pdm_channel *chan;

	err = of_parse_phandle_with_args(np, "pdms", "#pdm-cells", 0, &args);
	if (err) {
		pr_debug("%s: can't parse \"pdms\" property\n", __func__);
		return;
	}

	if (args.args_count != 2) {
		pr_debug("%s: wrong #pwm-cells\n", __func__);
		return;
	}

	if (args.args[0] < 0 || args.args[0] >= IMG_NUM_PDM || !pdm_channels)
		return;

	chan = &pdm_channels[args.args[0]];
	img_pdm_channel_free(chan);
}

struct img_pdm_channel *img_pdm_channel_get(struct device *dev)
{
	if (IS_ENABLED(CONFIG_OF) && dev && dev->of_node)
		return of_img_pdm_channel_get(dev->of_node);

	return NULL;
}
EXPORT_SYMBOL_GPL(img_pdm_channel_get);

void img_pdm_channel_put(struct device *dev)
{
	if (IS_ENABLED(CONFIG_OF) && dev && dev->of_node)
		of_img_pdm_channel_put(dev->of_node);
}
EXPORT_SYMBOL_GPL(img_pdm_channel_put);

int img_pdm_channel_enable(struct img_pdm_channel *chan, bool state)
{
	struct img_pdm_device *pdm_dev;

	mutex_lock(&pdm_lock);

	if (!chan) {
		mutex_unlock(&pdm_lock);
		return -EINVAL;
	}

	pdm_dev = chan->pdm_dev;

	if (!test_bit(PDM_CHANNEL_REQUESTED, &chan->flags)) {
		dev_err(&pdm_dev->pdev->dev, "channel not requested\n");
		mutex_unlock(&pdm_lock);
		return -EINVAL;
	}

	if (state) {
		regmap_update_bits(pdm_dev->periph_regs,
				PERIP_PWM_PDM_CONTROL,
				PERIP_PWM_PDM_CONTROL_CH_MASK <<
				PERIP_PWM_PDM_CONTROL_CH_SHIFT(chan->pdm_id),
				1 <<
				PERIP_PWM_PDM_CONTROL_CH_SHIFT(chan->pdm_id));
		set_bit(PDM_CHANNEL_ENABLED, &chan->flags);
	} else {
		regmap_write(pdm_dev->periph_regs,
			     PERIP_PDM0_VAL +
			     PERIP_PDM_CH_ADDR_SHIFT(chan->pdm_id), 0);
		regmap_update_bits(pdm_dev->periph_regs,
				PERIP_PWM_PDM_CONTROL,
				PERIP_PWM_PDM_CONTROL_CH_MASK <<
				PERIP_PWM_PDM_CONTROL_CH_SHIFT(chan->pdm_id),
				0 <<
				PERIP_PWM_PDM_CONTROL_CH_SHIFT(chan->pdm_id));
		clear_bit(PDM_CHANNEL_ENABLED, &chan->flags);
	}
	mutex_unlock(&pdm_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(img_pdm_channel_enable);

static ssize_t img_pdm_enable_read(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	int ret;
	unsigned int ch_num;
	unsigned char kobj_name[2];
	struct platform_device *pdev;
	struct img_pdm_device *pdm_dev;
	struct img_pdm_channel *chan;

	pdev = to_platform_device(kobj_to_dev(kobj->parent));
	pdm_dev = platform_get_drvdata(pdev);
	kobj_name[0] = *(kobj->name+3);
	kobj_name[1] = '\0';

	ret = kstrtou32(kobj_name, 10, &ch_num);
	if (ret) {
		dev_err(&pdev->dev, "could not parse channel number string\n");
		return ret;
	}

	chan = &pdm_channels[ch_num];
	return sprintf(buf, "%d\n",
		       test_bit(PDM_CHANNEL_ENABLED, &chan->flags) ? 1 : 0);
}

static ssize_t img_pdm_pulse_in_read(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	int ret;
	unsigned int ch_num, val;
	unsigned char kobj_name[2];
	struct platform_device *pdev;
	struct img_pdm_device *pdm_dev;
	struct img_pdm_channel *chan;

	pdev = to_platform_device(kobj_to_dev(kobj->parent));
	pdm_dev = platform_get_drvdata(pdev);
	kobj_name[0] = *(kobj->name+3);
	kobj_name[1] = '\0';
	ret = kstrtou32(kobj_name, 10, &ch_num);
	if (ret) {
		dev_err(&pdev->dev, "could not parse channel number string\n");
		return ret;
	}

	chan = &pdm_channels[ch_num];
	regmap_read(pdm_dev->periph_regs,
		    PERIP_PDM0_VAL +
		    PERIP_PDM_CH_ADDR_SHIFT(chan->pdm_id), &val);
	val &= PERIP_PDM_SRC_DATA_MASK;

	return sprintf(buf, "%d\n", val);
}

static ssize_t img_pdm_enable_write(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t size)
{
	int ret;
	unsigned int ch_num, enable;
	unsigned char kobj_name[2];
	struct platform_device *pdev;
	struct img_pdm_device *pdm_dev;

	pdev = to_platform_device(kobj_to_dev(kobj->parent));
	pdm_dev = platform_get_drvdata(pdev);

	kobj_name[0] = *(kobj->name+3);
	kobj_name[1] = '\0';
	ret = kstrtou32(kobj_name, 10, &ch_num);
	if (ret) {
		dev_err(&pdev->dev, "could not parse channel number string\n");
		return ret;
	}

	ret = kstrtou32(buf, 10, &enable);
	if (ret) {
		dev_err(&pdev->dev, "could not parse enable attr value\n");
		return ret;
	}

	ret = img_pdm_channel_enable(&pdm_channels[ch_num], !!enable);
	if (ret < 0)
		return ret;

	return size;
}

static ssize_t img_pdm_pulse_in_write(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t size)
{
	int ret;
	unsigned int pulse_in, ch_num;
	unsigned char kobj_name[2];
	struct platform_device *pdev;
	struct img_pdm_device *pdm_dev;

	pdev = to_platform_device(kobj_to_dev(kobj->parent));
	pdm_dev = platform_get_drvdata(pdev);

	kobj_name[0] = *(kobj->name+3);
	kobj_name[1] = '\0';
	ret = kstrtou32(kobj_name, 10, &ch_num);
	if (ret) {
		dev_err(&pdev->dev, "could not parse channel number string\n");
		return ret;
	}

	ret = kstrtouint(buf, 16, &pulse_in);
	if (ret) {
		dev_err(&pdev->dev,
			"could not parse pulse_in attr value\n");
		return ret;
	}

	if (pulse_in > PERIP_PDM_SRC_DATA_MASK) {
		dev_err(&pdev->dev,
			"invalid attr value for pulse_in string\n");
		return -EINVAL;
	}

	ret = img_pdm_channel_config(&pdm_channels[ch_num], pulse_in);
	if (ret < 0)
		return ret;

	return size;
}

#define PDM_ATTR(_name, _mode, _show, _store) \
struct kobj_attribute pdm_attr_##_name = { \
	.attr = {.name = __stringify(_name), .mode = _mode}, \
	.show = _show, \
	.store = _store, \
}

static PDM_ATTR(enable, S_IRUGO | S_IWUSR, img_pdm_enable_read,
					   img_pdm_enable_write);

static PDM_ATTR(pulse_in, S_IRUGO | S_IWUSR, img_pdm_pulse_in_read,
					     img_pdm_pulse_in_write);

static struct attribute *pdm_sysfs_attrs[] = {
	&pdm_attr_enable.attr,
	&pdm_attr_pulse_in.attr,
	NULL,
};

static const struct attribute_group pdm_attr_group = {
	.attrs = pdm_sysfs_attrs,
};

static ssize_t img_pdm_export(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t size)
{
	int ret;
	unsigned int ch_num;
	unsigned char kobj_name[5];
	struct platform_device *pdev;
	struct img_pdm_device *pdm_dev;
	struct img_pdm_channel *pdm_chan;

	pdev = to_platform_device(dev);
	pdm_dev = platform_get_drvdata(pdev);

	ret = kstrtou32(buf, 10, &ch_num);
	if (ret) {
		dev_err(&pdev->dev, "could not parse channel number string\n");
		return ret;
	}

	pdm_chan = img_pdm_channel_request(ch_num);
	if (!pdm_chan)
		return -EINVAL;

	memset(kobj_name, 0, sizeof(kobj_name));
	sprintf(kobj_name, "pdm%d", ch_num);
	pdm_dev->pdm_kobj[ch_num] = kobject_create_and_add(kobj_name,
							   &pdev->dev.kobj);
	if (!pdm_dev->pdm_kobj[ch_num]) {
		img_pdm_channel_free(pdm_chan);
		return -ENOMEM;
	}

	ret = sysfs_create_group(pdm_dev->pdm_kobj[ch_num], &pdm_attr_group);
	if (ret) {
		kobject_put(pdm_dev->pdm_kobj[ch_num]);
		img_pdm_channel_free(pdm_chan);
		dev_err(&pdev->dev, "unable to register device attributes\n");
		return ret;
	}

	return size;
}

static ssize_t img_pdm_unexport(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t size)
{
	int ret;
	unsigned int ch_num;
	struct img_pdm_channel *channel;
	struct platform_device *pdev;
	struct img_pdm_device *pdm_dev;

	pdev = to_platform_device(dev);
	pdm_dev = platform_get_drvdata(pdev);

	ret = kstrtou32(buf, 10, &ch_num);
	if (ret < 0)
		return ret;

	if (ch_num < 0 || ch_num >= IMG_NUM_PDM) {
		dev_err(&pdev->dev, "invalid channel number %d\n", ch_num);
		return -EINVAL;
	}

	channel = &pdm_channels[ch_num];
	if (img_pdm_channel_free(channel) < 0)
		return -EINVAL;

	if (pdm_dev->pdm_kobj[ch_num]) {
		sysfs_remove_group(pdm_dev->pdm_kobj[ch_num], &pdm_attr_group);
		kobject_put(pdm_dev->pdm_kobj[ch_num]);
	}

	return size;
}

static DEVICE_ATTR(export, S_IRUGO | S_IWUSR, NULL, img_pdm_export);
static DEVICE_ATTR(unexport, S_IRUGO | S_IWUSR, NULL, img_pdm_unexport);

static struct attribute *img_pdm_sysfs_attrs[] = {
	&dev_attr_export.attr,
	&dev_attr_unexport.attr,
	NULL,
};

static const struct attribute_group img_pdm_attr_group = {
	.attrs = img_pdm_sysfs_attrs,
};

static int img_pdm_probe(struct platform_device *pdev)
{
	int ret;
	unsigned int i;
	struct img_pdm_device *pdm_dev;

	pdm_dev = devm_kzalloc(&pdev->dev, sizeof(*pdm_dev), GFP_KERNEL);
	if (!pdm_dev)
		return -ENOMEM;

	pdm_dev->pdm_kobj = devm_kcalloc(&pdev->dev, IMG_NUM_PDM,
					 sizeof(struct kobject), GFP_KERNEL);
	if (!pdm_dev->pdm_kobj)
		return -ENOMEM;

	pdm_channels = devm_kcalloc(&pdev->dev, IMG_NUM_PDM,
				    sizeof(struct img_pdm_channel), GFP_KERNEL);
	if (!pdm_channels)
		return -ENOMEM;

	pdm_dev->periph_regs = syscon_regmap_lookup_by_phandle(
					pdev->dev.of_node, "img,cr-periph");
	if (IS_ERR(pdm_dev->periph_regs))
		return PTR_ERR(pdm_dev->periph_regs);

	pdm_dev->clk = devm_clk_get(&pdev->dev, "pdm");
	if (IS_ERR(pdm_dev->clk)) {
		dev_err(&pdev->dev, "failed to get pdm clock\n");
		return PTR_ERR(pdm_dev->clk);
	}

	ret = clk_prepare_enable(pdm_dev->clk);
	if (ret < 0) {
		dev_err(&pdev->dev, "could not prepare or enable pdm clock\n");
		return ret;
	}

	for (i = 0; i < IMG_NUM_PDM; i++) {
		pdm_channels[i].pdm_id = i;
		pdm_channels[i].pdm_dev = pdm_dev;
	}

	ret = sysfs_create_group(&pdev->dev.kobj, &img_pdm_attr_group);
	if (ret) {
		dev_err(&pdev->dev, "unable to register device attributes\n");
		clk_disable_unprepare(pdm_dev->clk);
		return ret;
	}

	pdm_dev->pdev = pdev;
	platform_set_drvdata(pdev, pdm_dev);

	return 0;
}

static int img_pdm_remove(struct platform_device *pdev)
{
	unsigned int i;
	struct img_pdm_channel *chan;
	struct img_pdm_device *pdm_dev;

	pdm_dev = platform_get_drvdata(pdev);

	for (i = 0; i < IMG_NUM_PDM; i++) {
		chan = &pdm_channels[i];
		if (test_bit(PDM_CHANNEL_REQUESTED, &chan->flags)) {
			img_pdm_channel_enable(chan, false);
			img_pdm_channel_config(chan, 0);
			if (pdm_dev->pdm_kobj[i]) {
				sysfs_remove_group(pdm_dev->pdm_kobj[i],
						   &pdm_attr_group);
				kobject_del(pdm_dev->pdm_kobj[i]);
			}
		}
	}

	clk_disable_unprepare(pdm_dev->clk);

	return 0;
}

static const struct of_device_id img_pdm_of_match[] = {
	{ .compatible = "img,pistachio-pdm", },
	{ }
};
MODULE_DEVICE_TABLE(of, img_pdm_of_match);

static struct platform_driver img_pdm_driver = {
	.driver = {
		.name = "img-pdm",
		.of_match_table = img_pdm_of_match,
	},
	.probe = img_pdm_probe,
	.remove = img_pdm_remove,
};
module_platform_driver(img_pdm_driver);

MODULE_AUTHOR("Arul Ramasamy <Arul.Ramasamy@imgtec.com>");
MODULE_DESCRIPTION("Imagination Technologies PDM driver");
MODULE_LICENSE("GPL v2");
