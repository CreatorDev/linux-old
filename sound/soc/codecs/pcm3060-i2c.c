/*
 * PCM3060 codec i2c driver
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * Author: Damien Horsley <Damien.Horsley@imgtec.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/module.h>

#include <sound/soc.h>

#include "pcm3060.h"

static int pcm3060_i2c_probe(struct i2c_client *i2c,
			     const struct i2c_device_id *id)
{
	struct regmap *regmap;

	regmap = devm_regmap_init_i2c(i2c, &pcm3060_regmap);
	if (IS_ERR(regmap))
		return PTR_ERR(regmap);

	return pcm3060_probe(&i2c->dev, regmap);
}

static int pcm3060_i2c_remove(struct i2c_client *i2c)
{
	pcm3060_remove(&i2c->dev);

	return 0;
}

static const struct i2c_device_id pcm3060_i2c_id[] = {
	{ "pcm3060", },
	{ }
};
MODULE_DEVICE_TABLE(i2c, pcm3060_i2c_id);

static const struct of_device_id pcm3060_of_match[] = {
	{ .compatible = "ti,pcm3060", },
	{ }
};
MODULE_DEVICE_TABLE(of, pcm3060_of_match);

static struct i2c_driver pcm3060_i2c_driver = {
	.probe		= pcm3060_i2c_probe,
	.remove		= pcm3060_i2c_remove,
	.id_table	= pcm3060_i2c_id,
	.driver		= {
		.name	= "pcm3060",
		.of_match_table = pcm3060_of_match,
		.pm		= &pcm3060_pm_ops,
	},
};
module_i2c_driver(pcm3060_i2c_driver);

MODULE_DESCRIPTION("PCM3060 I2C codec driver");
MODULE_AUTHOR("Damien Horsley <Damien.Horsley@imgtec.com>");
MODULE_LICENSE("GPL v2");
