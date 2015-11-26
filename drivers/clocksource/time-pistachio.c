/*
 * Pistachio clocksource based on general-purpose timers
 *
 * Copyright (C) 2015 Imagination Technologies
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/clk.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/sched_clock.h>
#include <linux/time.h>

/* Top level reg */
#define CR_TIMER_CTRL_CFG		0x00
#define  TIMER_ME_GLOBAL		BIT(0)
#define CR_TIMER_REV			0x10

/* Timer specific registers */
#define TIMER_CFG			0x20
#define  TIMER_ME_LOCAL			BIT(0)
#define TIMER_RELOAD_VALUE		0x24
#define TIMER_CURRENT_VALUE		0x28
#define TIMER_CURRENT_OVERFLOW_VALUE	0x2C
#define TIMER_IRQ_STATUS		0x30
#define TIMER_IRQ_CLEAR			0x34
#define TIMER_IRQ_MASK			0x38

#define PERIP_TIMER_CONTROL		0x90

/* Timer specific configuration Values */
#define RELOAD_VALUE	0xffffffff

static void __iomem *timer_base;
static DEFINE_RAW_SPINLOCK(lock);

static inline u32 gpt_readl(u32 offset, u32 gpt_id)
{
	return readl(timer_base + 0x20 * gpt_id + offset);
}

static inline void gpt_writel(u32 value, u32 offset, u32 gpt_id)
{
	writel(value, timer_base + 0x20 * gpt_id + offset);
}

static cycle_t pistachio_clocksource_read_cycles(struct clocksource *cs)
{
	u32 counter, overflw;
	unsigned long flags;

	raw_spin_lock_irqsave(&lock, flags);
	overflw = gpt_readl(TIMER_CURRENT_OVERFLOW_VALUE, 0);
	counter = gpt_readl(TIMER_CURRENT_VALUE, 0);
	raw_spin_unlock_irqrestore(&lock, flags);

	return ~(cycle_t)counter;
}

static u64 notrace pistachio_read_sched_clock(void)
{
	return pistachio_clocksource_read_cycles(NULL);
}

static void pistachio_clksrc_enable(int timeridx)
{
	u32 val;

	/* Disable GPT local before loading reload value */
	val = gpt_readl(TIMER_CFG, timeridx);
	val &= ~TIMER_ME_LOCAL;
	gpt_writel(val, TIMER_CFG, timeridx);

	gpt_writel(RELOAD_VALUE, TIMER_RELOAD_VALUE, timeridx);

	val = gpt_readl(TIMER_CFG, timeridx);
	val |= TIMER_ME_LOCAL;
	gpt_writel(val, TIMER_CFG, timeridx);
}

static void pistachio_clksrc_disable(int timeridx)
{
	u32 val;

	/* Disable GPT local */
	val = gpt_readl(TIMER_CFG, timeridx);
	val &= ~TIMER_ME_LOCAL;
	gpt_writel(val, TIMER_CFG, timeridx);
}

static int pistachio_clocksource_enable(struct clocksource *cs)
{
	pistachio_clksrc_enable(0);
	return 0;
}

static void pistachio_clocksource_disable(struct clocksource *cs)
{
	pistachio_clksrc_disable(0);
}

/* Desirable clock source for pistachio platform */
static struct clocksource pistachio_clocksource_gpt = {
	.name		= "gptimer",
	.rating		= 300,
	.enable		= pistachio_clocksource_enable,
	.disable	= pistachio_clocksource_disable,
	.read		= pistachio_clocksource_read_cycles,
	.mask		= CLOCKSOURCE_MASK(32),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

static void __init pistachio_clksrc_of_init(struct device_node *node)
{
	struct clk *sys_clk, *fast_clk;
	struct regmap *periph_regs;
	unsigned long rate;
	int ret;

	timer_base = of_iomap(node, 0);
	if (!timer_base) {
		pr_err("cannot iomap\n");
		return;
	}

	periph_regs = syscon_regmap_lookup_by_phandle(node, "img,cr-periph");
	if (IS_ERR(periph_regs)) {
		pr_err("cannot get peripheral regmap (%lu)\n",
		       PTR_ERR(periph_regs));
		return;
	}

	/* Switch to using the fast counter clock */
	ret = regmap_update_bits(periph_regs, PERIP_TIMER_CONTROL,
				 0x1, 0x0);
	if (ret)
		return;

	sys_clk = of_clk_get_by_name(node, "sys");
	if (IS_ERR(sys_clk)) {
		pr_err("clock get failed (%lu)\n", PTR_ERR(sys_clk));
		return;
	}

	fast_clk = of_clk_get_by_name(node, "fast");
	if (IS_ERR(fast_clk)) {
		pr_err("clock get failed (%lu)\n", PTR_ERR(fast_clk));
		return;
	}

	ret = clk_prepare_enable(sys_clk);
	if (ret < 0) {
		pr_err("failed to enable clock (%d)\n", ret);
		return;
	}

	ret = clk_prepare_enable(fast_clk);
	if (ret < 0) {
		pr_err("failed to enable clock (%d)\n", ret);
		clk_disable_unprepare(sys_clk);
		return;
	}

	rate = clk_get_rate(fast_clk);

	/* Disable irq's for clocksource usage */
	gpt_writel(0, TIMER_IRQ_MASK, 0);
	gpt_writel(0, TIMER_IRQ_MASK, 1);
	gpt_writel(0, TIMER_IRQ_MASK, 2);
	gpt_writel(0, TIMER_IRQ_MASK, 3);

	/* Enable timer block */
	writel(TIMER_ME_GLOBAL, timer_base);

	sched_clock_register(pistachio_read_sched_clock, 32, rate);
	clocksource_register_hz(&pistachio_clocksource_gpt, rate);
}
CLOCKSOURCE_OF_DECLARE(pistachio_gptimer, "img,pistachio-gptimer",
		       pistachio_clksrc_of_init);
