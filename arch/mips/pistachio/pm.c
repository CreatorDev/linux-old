/*
 * PM Suspend to memory driver for Pistachio Platform.
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <asm/tlbflush.h>
#include <linux/genalloc.h>
#include <linux/init.h>
#include <linux/of_platform.h>
#include <linux/pm.h>
#include <linux/suspend.h>

/* MIPS TOP level Gate reg */
#define CR_TOP_MIPS_CLOCK_GATE		KSEG1ADDR(0x18144104)
#define CR_TOP_MIPSCLKOUT_MIPS_BIT 	0

static void (*pistachio_suspend_in_sram_fn)(void);
extern void pistachio_sram_suspend(void);
extern bool pistachio_wakeirq_set(void);
extern unsigned int pistachio_sram_suspend_sz;

static int pistachio_pm_prepare_late(void)
{
	/*
	 * Deny system suspend if any of the wakeup sources
	 * are not enabled. If we enter suspend with no wakeup
	 * sources system is in unusable state.
	 */
	if (!pistachio_wakeirq_set()) {
		pr_warn("[%s]: No wakeup sources set cannot suspend system\n",
					__func__);
		return -EINVAL;
	}

	return 0;
}

static int pistachio_pm_enter(suspend_state_t state)
{
	local_flush_tlb_all();

	/* AUDIO Workaround: Gate audio clocks. */
	clear_bit(2, (void __iomem *)CR_TOP_MIPS_CLOCK_GATE);
	clear_bit(22, (void __iomem *)CR_TOP_MIPS_CLOCK_GATE);

	if (!pistachio_suspend_in_sram_fn) {
		/*
		 * Disable MIPS clock, this is only clock gating not power gating.
		 * so MIPS state will not be lost and we can resume from gated
		 * state.
		 */

		clear_bit(CR_TOP_MIPSCLKOUT_MIPS_BIT,
				(void __iomem *)CR_TOP_MIPS_CLOCK_GATE);

		/*
		 * Enable MIPS clock back after wakeup,
		 * PC will start resuming execution from gated state
		 * for a small time cycle, So enable MIPS clocks immediately
		 * after resume.
		 * Note: Only Wake irq mask can wakeup the system.
		 */

		set_bit(CR_TOP_MIPSCLKOUT_MIPS_BIT,
				(void __iomem *)CR_TOP_MIPS_CLOCK_GATE);

	} else {
		/*
		 * call low level suspend function in sram,
		 * as we need to put DDR to self refresh mode.
		 */
		pistachio_suspend_in_sram_fn();
	}

	/* AUDIO Workaround: Enable Audio clks. */
	set_bit(2, (void __iomem *)CR_TOP_MIPS_CLOCK_GATE);
	set_bit(22, (void __iomem *)CR_TOP_MIPS_CLOCK_GATE);

	return 0;
}

static const struct platform_suspend_ops pistachio_pm_ops = {
	.valid		= suspend_valid_only_mem,
	.prepare_late	= pistachio_pm_prepare_late,
	.enter		= pistachio_pm_enter,
};

static int __init pistachio_pm_init(void)
{
	phys_addr_t sram_pbase;
	struct device_node *node;
	struct platform_device *pdev;

	struct gen_pool *sram_pool;
	unsigned long sram_vbase;
	int ret = 0;
	void __iomem *suspend_sram_base;

	suspend_set_ops(&pistachio_pm_ops);

	node = of_find_compatible_node(NULL, NULL, "mmio-sram");
	if (!node) {
		pr_warn("%s: failed to find sram node!\n", __func__);
		return -ENODEV;
	}

	pdev = of_find_device_by_node(node);
	if (!pdev) {
		pr_warn("%s: failed to find sram device!\n", __func__);
		ret = -ENODEV;
		goto put_node;
	}

	sram_pool = gen_pool_get(&pdev->dev, NULL);
	if (!sram_pool) {
		pr_warn("%s: sram pool unavailable!\n", __func__);
		ret = -ENODEV;
		goto put_node;
	}

	sram_vbase = gen_pool_alloc(sram_pool, pistachio_sram_suspend_sz);
	if (!sram_vbase) {
		pr_warn("%s: unable to alloc sram!\n", __func__);
		ret = -ENOMEM;
		goto put_node;
	}

	sram_pbase = gen_pool_virt_to_phys(sram_pool, sram_vbase);
	suspend_sram_base = ioremap(sram_pbase, pistachio_sram_suspend_sz);
	memcpy(suspend_sram_base, (void *)pistachio_sram_suspend,
				pistachio_sram_suspend_sz);
	pistachio_suspend_in_sram_fn = (void *)suspend_sram_base;

put_node:
	of_node_put(node);

	return ret;
}
late_initcall(pistachio_pm_init);
