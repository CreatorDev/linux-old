/*
 * Irq wake driver for Pistachio Platform.
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/platform_device.h>

#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irqchip/mips-gic.h>
#include <linux/irq.h>
#include <linux/mfd/syscon.h>
#include <linux/of_platform.h>
#include <linux/regmap.h>

#define	PISTACHIO_CLK_WAKEUP		0x010C
#define PISTACHIO_DEFAULT_WAKEIRQ_START	2
#define	PISTACHIO_DEFAULT_WAKEIRQ_END	95
/* Max number of wake registers available in Pistachio platform */
#define	PISTACHIO_WAKEREGS_NUM		3

static struct regmap *pistachio_clk_regs;
static int wakeirq_start, wakeirq_end;

bool pistachio_wakeirq_set(void)
{
	int ret = false;
	int val[PISTACHIO_WAKEREGS_NUM], i, wake_irq = 0;

	regmap_bulk_read(pistachio_clk_regs, PISTACHIO_CLK_WAKEUP, &val,
				PISTACHIO_WAKEREGS_NUM);

	for (i = 0 ; i < PISTACHIO_WAKEREGS_NUM; i++)
		wake_irq |= val[i];

	if (wake_irq)
		ret = true;

	return ret;
}

static int pistachio_irq_wake(struct irq_data *data, unsigned int on)
{
	unsigned int irq = GIC_HWIRQ_TO_SHARED(data->hwirq);
	unsigned int wake_irq_off = GIC_INTR_OFS(irq);
	unsigned int wake_irq_bit = irq - wakeirq_start;

	unsigned int offset = PISTACHIO_CLK_WAKEUP + wake_irq_off;
	unsigned int mask = BIT(wake_irq_bit);
	unsigned int val = 0;

	if (on)
		val = mask;

	regmap_update_bits(pistachio_clk_regs, offset, mask, val);

	return 0;
}

static int pistachio_irqwake_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	int ret = 0;
	int i = 0;

	pistachio_clk_regs = syscon_regmap_lookup_by_phandle(pdev->dev.of_node,
					"img,clk_core");
	if (IS_ERR(pistachio_clk_regs)) {
		dev_err(&pdev->dev, "[%s]: pistachio-clk_core lookup \
			failure irq-wake will be non-functional\n", __func__);
		return PTR_ERR(pistachio_clk_regs);
	}

	if (of_property_read_u32(np, "irq-start", &wakeirq_start))
		wakeirq_start = PISTACHIO_DEFAULT_WAKEIRQ_START;

	if (of_property_read_u32(np, "irq-end", &wakeirq_end))
		wakeirq_start = PISTACHIO_DEFAULT_WAKEIRQ_END;

	for (i = wakeirq_start; i < wakeirq_end; i++) {
		struct irq_chip *chip = irq_get_chip(i);
		chip->irq_set_wake = pistachio_irq_wake;
	}

	return ret;
}

static int pistachio_irqwake_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id pistachio_irqwake_match[] = {
	{ .compatible = "pistachio,irq-wake" },
	{}
};

static struct platform_driver pistachio_irqwake_driver = {
	.probe		= pistachio_irqwake_probe,
	.remove		= pistachio_irqwake_remove,
	.driver		= {
		.name	= "pistachio-irq-wake",
		.of_match_table	= of_match_ptr(pistachio_irqwake_match),
	}
};
module_platform_driver(pistachio_irqwake_driver);
