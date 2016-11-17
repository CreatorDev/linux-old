/*
 * RTC driver for Pistachio Platform.
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <asm-generic/rtc.h>

#include <linux/bitops.h>
#include <linux/clk.h>
#include <linux/clocksource.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/timecounter.h>

/* Top level reg */
#define	CR_TIMER_CTRL_CFG		0x00
#define	TIMER_ME_GLOBAL			BIT(0)
#define	CR_TIMER_REV			0x10

/* Timer specific registers */
#define	TIMER_CFG			0x20
#define	TIMER_ME_LOCAL			BIT(0)

#define	TIMER_MAX_OVERFLOW		0xf
#define	TIMER_OVERFLOW_SHIFT		4

#define	TIMER_RELOAD_VALUE		0x24
#define	TIMER_CURRENT_VALUE		0x28
#define	TIMER_CURRENT_OVERFLOW_VALUE	0x2C
#define	TIMER_IRQ_STATUS		0x30
#define	TIMER_IRQ_CLEAR			0x34
#define	TIMER_IRQ_MASK			0x38

#define	TIMER_OVERFLOW_MAX_INT		0x2
#define	PERIP_TIMER_CONTROL		0x90

/* Timer specific configuration Values */
#define	MAX_RELOAD_VALUE		0xffffffff
#define	GP_TIMER1_MASK			CYCLECOUNTER_MASK(32)

#define	TIMER1_IDX			1
#define	TIMER1_SLOW_CLOCK_MASK		BIT(1)
#define	TIMER1_SLOW_CLOCK_EN		0x2

#define	TIMER2_IDX			2
#define	TIMER2_SLOW_CLOCK_MASK		BIT(2)
#define	TIMER2_SLOW_CLOCK_EN		0x4

struct pistachio_rtc {
	struct rtc_device *rtc;
	struct timecounter tc;
	struct cyclecounter cc;
	spinlock_t counter_lock, timer_lock;
	struct clk *sys_clk, *slow_clk;
	u64 timer_reload_ns, alarm_secs;
	void __iomem *timer_base;
	int timer_irq, alarm_irq;
	bool alarm_wakeup_en;
	u32 ct1_idx, ct2_idx;
};

static inline u32 gpt_readl(u32 offset, struct pistachio_rtc *priv, u32 idx)
{
	return readl(priv->timer_base + 0x20 * idx + offset);
}

static inline void gpt_writel(u32 value, u32 offset, struct pistachio_rtc *priv,
				u32 idx)
{
	writel(value, priv->timer_base + 0x20 * idx + offset);
}

static inline u32 counter1_readl(u32 offset, struct pistachio_rtc *priv)
{
	return gpt_readl(offset, priv, priv->ct1_idx);
}

static inline void counter1_writel(u32 value, u32 offset,
			struct pistachio_rtc *priv)
{
	gpt_writel(value, offset, priv, priv->ct1_idx);
}

static inline u32 counter2_readl(u32 offset, struct pistachio_rtc *priv)
{
	return gpt_readl(offset, priv, priv->ct2_idx);
}

static inline void counter2_writel(u32 value, u32 offset,
			struct pistachio_rtc *priv)
{
	gpt_writel(value, offset, priv, priv->ct2_idx);
}

static void pistachio_counter_enable(struct pistachio_rtc *priv, int idx,
				bool enable)
{
	u32 val;
	unsigned long flags;

	spin_lock_irqsave(&priv->timer_lock, flags);
	val = gpt_readl(TIMER_CFG, priv, idx);
	if (enable)
		val |= TIMER_ME_LOCAL;
	else
		val &= ~TIMER_ME_LOCAL;

	gpt_writel(val, TIMER_CFG, priv, idx);
	spin_unlock_irqrestore(&priv->timer_lock, flags);
}

static void pistachio_counter_setup(struct pistachio_rtc *priv, u32 reload_val,
				u32 ovrflw_val, u32 idx)
{
	unsigned long flags;

	/* Disable GPT local before loading a new reload value */
	pistachio_counter_enable(priv, idx, false);

	spin_lock_irqsave(&priv->timer_lock, flags);
	gpt_writel(reload_val, TIMER_RELOAD_VALUE, priv, idx);
	gpt_writel(ovrflw_val << TIMER_OVERFLOW_SHIFT, TIMER_CFG, priv, idx);
	spin_unlock_irqrestore(&priv->timer_lock, flags);

	pistachio_counter_enable(priv, idx, true);
}

static int pistachio_get_time(struct device *dev, struct rtc_time *tm)
{
	struct pistachio_rtc *priv = dev_get_drvdata(dev);
	unsigned long flags;
	u64 time_in_nsecs;

	spin_lock_irqsave(&priv->counter_lock, flags);
	time_in_nsecs = timecounter_read(&priv->tc);
	rtc_time64_to_tm(div64_u64(time_in_nsecs, NSEC_PER_SEC), tm);
	spin_unlock_irqrestore(&priv->counter_lock, flags);

	return rtc_valid_tm(tm);
}

static cycle_t pistachio_timer1_cc_read(const struct cyclecounter *cc)
{
	struct pistachio_rtc *priv = container_of(cc, struct pistachio_rtc, cc);
	unsigned long flags;
	u32 counter, overflw;
	cycle_t ovrflw_cyc;
	u64 ovrflw_tm, tot_cyc;

	spin_lock_irqsave(&priv->timer_lock, flags);
	overflw = counter1_readl(TIMER_CURRENT_OVERFLOW_VALUE, priv);
	counter = counter1_readl(TIMER_CURRENT_VALUE, priv);
	tot_cyc = ~counter;
	if (overflw) {
		/* In case of any overflows adjust time. */
		if (overflw - 1)
			timecounter_adjtime(&priv->tc,
				priv->timer_reload_ns * (overflw - 1));

		if (priv->tc.cycle_last) {
			ovrflw_cyc = MAX_RELOAD_VALUE - priv->tc.cycle_last;
			priv->tc.cycle_last = 0;
			ovrflw_tm = cyclecounter_cyc2ns(priv->tc.cc, ovrflw_cyc,
						priv->tc.mask, &priv->tc.frac);
			timecounter_adjtime(&priv->tc, ovrflw_tm);
		}
	}

	spin_unlock_irqrestore(&priv->timer_lock, flags);
	return tot_cyc;
}


static int pistachio_set_time(struct device *dev, struct rtc_time *tm)
{
	struct pistachio_rtc *priv = dev_get_drvdata(dev);
	unsigned long flags;
	unsigned int ret = 0;

	ret = rtc_valid_tm(tm);
	if (ret)
		return ret;

	spin_lock_irqsave(&priv->counter_lock, flags);
	/*
	 * Restart the timer block and initialize timecounter
	 * since we are setting a new time.
	 * Now we can use count from h/w timer and
	 * add to s/w timecounter to get correct timestamp.
	 */
	pistachio_counter_setup(priv, MAX_RELOAD_VALUE, TIMER_MAX_OVERFLOW,
			priv->ct1_idx);
	timecounter_init(&priv->tc, &priv->cc,
			ktime_to_ns(rtc_tm_to_ktime(*tm)));

	spin_unlock_irqrestore(&priv->counter_lock, flags);

	return 0;
}

static int pistachio_read_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct pistachio_rtc *priv = dev_get_drvdata(dev);

	if (priv->alarm_secs) {
		alarm->enabled = 1;
		rtc_time64_to_tm(priv->alarm_secs, &alarm->time);
	} else {
		alarm->enabled = 0;
		alarm->pending = 0;
		alarm->time.tm_mon = -1;
		alarm->time.tm_mday = -1;
		alarm->time.tm_year = -1;
		alarm->time.tm_hour = -1;
		alarm->time.tm_min = -1;
		alarm->time.tm_sec = -1;
	}

	return 0;
}

static int pistachio_set_alarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct pistachio_rtc *priv = dev_get_drvdata(dev);
	u64 reload_val = 0, ovrflw = 0, cyc = 0, cur_tm_sec, time_in_nsecs;

	if (alarm->enabled) {
		/*
		 * find the alarm time in seconds using
		 * current time stamp and setup it up based on
		 * slow clock rate.
		 */
		time_in_nsecs = timecounter_read(&priv->tc);
		cur_tm_sec = div64_u64(time_in_nsecs, NSEC_PER_SEC);
		priv->alarm_secs = rtc_tm_to_time64(&alarm->time);
		cyc = (priv->alarm_secs - cur_tm_sec) *
				clk_get_rate(priv->slow_clk);

		ovrflw = TIMER_MAX_OVERFLOW;
		reload_val = DIV_ROUND_UP_ULL(cyc, ovrflw - 1);
		if (reload_val > MAX_RELOAD_VALUE)
			return -EINVAL;
	}

	if (reload_val || ovrflw)
		pistachio_counter_setup(priv, reload_val,
			ovrflw, priv->ct2_idx);

	return 0;
}

static const struct rtc_class_ops pistachio_rtc_ops = {
	.read_time	= pistachio_get_time,
	.set_time	= pistachio_set_time,
	.read_alarm	= pistachio_read_alarm,
	.set_alarm	= pistachio_set_alarm,
};

static irqreturn_t pistachio_counter_irq(int irq, void *dev)
{
	struct pistachio_rtc *priv = dev_get_drvdata(dev);
	int irq_status;
	u64 time_in_nsecs;

	counter1_writel(TIMER_OVERFLOW_MAX_INT, TIMER_IRQ_CLEAR, priv);
	/*
	 * we have overflowed counter max so update time_counter
	 * with the current time stamp.
	 */
	time_in_nsecs = timecounter_read(&priv->tc);

	irq_status = counter1_readl(TIMER_IRQ_STATUS, priv);
	counter1_writel(irq_status, TIMER_IRQ_CLEAR, priv);
	counter1_writel(0x0, TIMER_IRQ_CLEAR, priv);

	return IRQ_HANDLED;
}

static irqreturn_t pistachio_alarm_handler(int irq, void *dev)
{
	struct pistachio_rtc *priv = dev_get_drvdata(dev);
	int irq_status, val;

	counter2_writel(TIMER_OVERFLOW_MAX_INT, TIMER_IRQ_CLEAR, priv);
	/*
	 * Need a to read the current overflow value
	 * and reload value to clear the current irq.
	 */
	val = counter2_readl(TIMER_CURRENT_OVERFLOW_VALUE, priv);
	val = counter2_readl(TIMER_CURRENT_VALUE, priv);

	irq_status = counter2_readl(TIMER_IRQ_STATUS, priv);
	counter2_writel(irq_status, TIMER_IRQ_CLEAR, priv);
	priv->alarm_secs = 0;
	counter2_writel(0x0, TIMER_IRQ_CLEAR, priv);
	counter2_writel(0x0, TIMER_RELOAD_VALUE, priv);

	/* Disable alarm counter2 */
	counter2_writel(0x0, TIMER_CFG, priv);

	rtc_update_irq(priv->rtc, 1, RTC_IRQF | RTC_AF);
	return IRQ_HANDLED;
}

static int pistachio_rtc_probe(struct platform_device *pdev)
{
	struct pistachio_rtc *priv;
	struct regmap *periph_regs;
	struct resource *res_regs;
	unsigned long rate;
	int ret = 0;
	u32 mult, shift;
	u64 mask;
	ktime_t sys_time;

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	res_regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	priv->timer_base = devm_ioremap_resource(&pdev->dev, res_regs);
	if (IS_ERR(priv->timer_base))
		return PTR_ERR(priv->timer_base);

	spin_lock_init(&priv->counter_lock);
	spin_lock_init(&priv->timer_lock);
	priv->ct1_idx = TIMER1_IDX;
	priv->ct2_idx = TIMER2_IDX;

	priv->timer_irq = platform_get_irq(pdev, 0);
	if (priv->timer_irq < 0) {
		dev_err(&pdev->dev, "Error getting counter1 platform irq\n");
		return priv->timer_irq;
	}

	ret = devm_request_irq(&pdev->dev, priv->timer_irq,
			pistachio_counter_irq, IRQ_TYPE_LEVEL_HIGH,
			dev_name(&pdev->dev), &pdev->dev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Error requesting irq\n");
		return ret;
	}

	priv->alarm_irq = platform_get_irq(pdev, 1);
	if (priv->alarm_irq < 0) {
		dev_err(&pdev->dev, "Error getting counter2 platform irq\n");
		return priv->alarm_irq;
	}

	ret = devm_request_irq(&pdev->dev, priv->alarm_irq,
			pistachio_alarm_handler, IRQ_TYPE_LEVEL_HIGH,
			dev_name(&pdev->dev), &pdev->dev);

	if (ret < 0) {
		dev_err(&pdev->dev, "Error requesting irq\n");
		return ret;
	}

	periph_regs = syscon_regmap_lookup_by_phandle(pdev->dev.of_node,
					"img,cr-periph");
	if (IS_ERR(periph_regs)) {
		dev_err(&pdev->dev, "cannot get peripheral regmap (%lu)\n",
		       PTR_ERR(periph_regs));
		return PTR_ERR(periph_regs);
	}

	platform_set_drvdata(pdev, priv);
	/* Switch to using the slow counter clock of gptimer1 for RTC */
	ret = regmap_update_bits(periph_regs, PERIP_TIMER_CONTROL,
			TIMER1_SLOW_CLOCK_MASK, TIMER1_SLOW_CLOCK_EN);
	if (ret)
		return ret;

	/* Switch to using the slow counter clock of gptimer2 for alarm */
	ret = regmap_update_bits(periph_regs, PERIP_TIMER_CONTROL,
			TIMER2_SLOW_CLOCK_MASK, TIMER2_SLOW_CLOCK_EN);
	if (ret)
		return ret;

	priv->sys_clk = devm_clk_get(&pdev->dev, "sys");
	if (IS_ERR(priv->sys_clk)) {
		dev_err(&pdev->dev, "clock get failed (%lu)\n",
					PTR_ERR(priv->sys_clk));
		return PTR_ERR(priv->sys_clk);
	}

	priv->slow_clk = devm_clk_get(&pdev->dev, "slow");
	if (IS_ERR(priv->slow_clk)) {
		dev_err(&pdev->dev, "clock get failed (%lu)\n",
					PTR_ERR(priv->slow_clk));
		return PTR_ERR(priv->slow_clk);
	}

	ret = clk_prepare_enable(priv->sys_clk);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to enable clock (%d)\n", ret);
		return ret;
	}

	ret = clk_prepare_enable(priv->slow_clk);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to enable clock (%d)\n", ret);
		goto sys_clk_err;
	}

	rate = clk_get_rate(priv->slow_clk);
	mask = GP_TIMER1_MASK;
	clocks_calc_mult_shift(&mult, &shift, rate,
		NSEC_PER_SEC, DIV_ROUND_UP_ULL(mask, rate));

	priv->cc.mult = mult;
	priv->cc.shift = shift;
	priv->cc.read = pistachio_timer1_cc_read;
	priv->cc.mask = mask;

	counter1_writel(TIMER_OVERFLOW_MAX_INT, TIMER_IRQ_MASK, priv);
	counter2_writel(TIMER_OVERFLOW_MAX_INT, TIMER_IRQ_MASK, priv);
	sys_time = ktime_get();
	pistachio_counter_setup(priv, MAX_RELOAD_VALUE, TIMER_MAX_OVERFLOW,
		priv->ct1_idx);
	/* Initialize timecounter with system time */
	timecounter_init(&priv->tc, &priv->cc, ktime_to_ns(sys_time));

	/*
	 * max time value on a single overflow, used to adjust time
	 * on overflow scenarios.
	 */
	priv->timer_reload_ns = cyclecounter_cyc2ns(priv->tc.cc,
			MAX_RELOAD_VALUE, priv->tc.mask, &priv->tc.frac);

	/*
	 * Enable Irq wake in case of system suspend, we need to wakeup
	 * and update our time stamp.
	 * rtc based on counter1 runs on slow clock at 31.25Khz this will
	 * max_overflow after 25.45 days.
	 * (1÷31,250)×(2^32)×(2^4)÷(60×60×24) = 25.45days
	 * 32 bits counter and 4 overflow bits.
	 */
	device_init_wakeup(&pdev->dev, true);

	priv->rtc = devm_rtc_device_register(&pdev->dev, "rtc-pistachio",
					&pistachio_rtc_ops, THIS_MODULE);
	if (IS_ERR(priv->rtc)) {
		ret = PTR_ERR(priv->rtc);
		dev_err(&pdev->dev, "failed to rtc (%d)\n", ret);
		goto slow_clk_err;
	}


	return ret;

slow_clk_err:
	clk_disable_unprepare(priv->slow_clk);
sys_clk_err:
	clk_disable_unprepare(priv->sys_clk);

	return ret;
}

static int pistachio_rtc_remove(struct platform_device *pdev)
{
	struct pistachio_rtc *priv = platform_get_drvdata(pdev);

	clk_disable_unprepare(priv->slow_clk);
	clk_disable_unprepare(priv->sys_clk);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
int pistachio_rtc_suspend(struct device *dev)
{
	struct pistachio_rtc *priv = dev_get_drvdata(dev);

	if (device_may_wakeup(dev)) {
		enable_irq_wake(priv->timer_irq);

		/*
		 * if counter2 is enabled then enable irq wake for alarm
		 */
		if (counter2_readl(TIMER_CFG, priv) & TIMER_ME_LOCAL) {
			enable_irq_wake(priv->alarm_irq);
			priv->alarm_wakeup_en = true;

		}
	}

	return 0;
}

int pistachio_rtc_resume(struct device *dev)
{
	struct pistachio_rtc *priv = dev_get_drvdata(dev);

	if (device_may_wakeup(dev)) {
		disable_irq_wake(priv->timer_irq);

		if (priv->alarm_wakeup_en) {
			priv->alarm_wakeup_en = false;
			disable_irq_wake(priv->alarm_irq);
		}
	}

	return 0;
}
#endif	/* CONFIG_PM_SLEEP */

static SIMPLE_DEV_PM_OPS(pistachio_rtc_pmops, pistachio_rtc_suspend,
				pistachio_rtc_resume);

static const struct of_device_id pistachio_rtc_of_match[] = {
	{ .compatible = "img,rtc-pistachio" },
};
MODULE_DEVICE_TABLE(of, pistachio_rtc_of_match);

static struct platform_driver pistachio_rtc_driver = {
	.driver = {
		.name = "rtc-pistachio",
		.of_match_table = pistachio_rtc_of_match,
		.pm = &pistachio_rtc_pmops,
	},
	.probe = pistachio_rtc_probe,
	.remove = pistachio_rtc_remove,
};
module_platform_driver(pistachio_rtc_driver);

MODULE_AUTHOR("Imagination Technologies Ltd.");
MODULE_DESCRIPTION("Pistachio RTC");
MODULE_LICENSE("GPL");
