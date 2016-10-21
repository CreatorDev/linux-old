/*
 * Pistachio event timer driver
 *
 * Copyright (C) 2014 Imagination Technologies Ltd.
 *
 * Author: Damien Horsley <Damien.Horsley@imgtec.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/of_irq.h>
#include <linux/clk-provider.h>
#include <linux/of_address.h>
#include <linux/delay.h>
#include <linux/clocksource.h>
#include <linux/timecounter.h>

#ifdef CONFIG_ATU
#include <linux/atu_clk.h>
#endif /* CONFIG_ATU */

#include "pistachio-event-timer.h"

#define PISTACHIO_EVT_COUNTER			0x0
#define PISTACHIO_EVT_COUNTER_MASK		0x3fffffff
#define PISTACHIO_EVT_COUNTER_ENABLE_MASK	0x80000000

#define PISTACHIO_EVT_TIMESTAMP_STS		0x4

#define PISTACHIO_EVT_TIMESTAMP_CLR		0x8

#define PISTACHIO_EVT_CLKSRC_SELECT		0xc
#define PISTACHIO_EVT_CLKSRC_SELECT_SHIFT	0
#define PISTACHIO_EVT_CLKSRC_SELECT_WIDTH	1

#define PISTACHIO_EVT_SOURCE_INTERNAL_START	0x10
#define PISTACHIO_EVT_SOURCE_INTERNAL_MASK	0xf

#define PISTACHIO_EVT_TIMESTAMP_START		0x40
#define PISTACHIO_EVT_TIMESTAMP_MASK		PISTACHIO_EVT_COUNTER_MASK

#define PISTACHIO_EVT_TIMER_ENABLE		0x100
#define PISTACHIO_EVT_TIMER_ENABLE_MASK		0x1

#define PISTACHIO_EVT_EVENT_CTL			0x120
#define PISTACHIO_EVT_EVENT_CTL_MASK		0x3
#define PISTACHIO_EVT_EVENT_CTL_WIDTH		2

#define PISTACHIO_EVT_TB			0x130
#define PISTACHIO_EVT_TIME_REG(en)		(PISTACHIO_EVT_TB + (0x4 * en))

#define PISTACHIO_EVT_TIMESTAMP_SRC_START	0x190
#define PISTACHIO_EVT_TIMESTAMP_SRC_MASK	0xff
#define PISTACHIO_EVT_TIMESTAMP_SRC_WIDTH	8

#define	PISTACHIO_EVT_MIN_EVENT_DELTA_NS	100000

struct pistachio_evt_callback {
	u64 trigger_time;
	u32 cyc;
	void (*callback)(void *context);
	void *context;
};

struct pistachio_evt_data {
	spinlock_t lock;
	struct device *dev;
	void __iomem *base;
	struct clk *clk_sys;
	struct clk *clk_ref_internal;
	struct clk *clk_ref_a;
	struct clk *clk_ref_b;
	const char *ref_names[2];
	struct cyclecounter cc;
	struct timecounter tc;
	struct notifier_block evt_clk_notifier;
	struct hrtimer poll_timer;
	ktime_t quarter_rollover;
	unsigned long rate;
	struct pistachio_evt_callback trigger_cbs[PISTACHIO_EVT_NUM_ENABLES];
};
unsigned long evt_timer_rate;

static inline u32 pistachio_evt_readl(struct pistachio_evt_data *evt, u32 reg)
{
	return readl(evt->base + reg);
}

static inline void pistachio_evt_writel(struct pistachio_evt_data *evt,
					u32 val, u32 reg)
{
	writel(val, evt->base + reg);
}

static inline void pistachio_evt_stop_count(struct pistachio_evt_data *evt)
{
	u32 reg = pistachio_evt_readl(evt, PISTACHIO_EVT_COUNTER);
	reg &= ~PISTACHIO_EVT_COUNTER_ENABLE_MASK;
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_COUNTER);
}

static inline void pistachio_evt_start_count(struct pistachio_evt_data *evt)
{
	u32 reg = pistachio_evt_readl(evt, PISTACHIO_EVT_COUNTER);
	reg |= PISTACHIO_EVT_COUNTER_ENABLE_MASK;
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_COUNTER);
}

static inline int pistachio_evt_get_count(struct pistachio_evt_data *evt)
{
	u32 reg = pistachio_evt_readl(evt, PISTACHIO_EVT_COUNTER);
	return reg & PISTACHIO_EVT_COUNTER_MASK;
}

static inline void pistachio_evt_set_count(struct pistachio_evt_data *evt,
					int count)
{
	u32 reg = pistachio_evt_readl(evt, PISTACHIO_EVT_COUNTER);
	reg = (reg & ~PISTACHIO_EVT_COUNTER_MASK) |
		(count & PISTACHIO_EVT_COUNTER_MASK);
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_COUNTER);
}

static cycle_t pistachio_evt_cc_read(const struct cyclecounter *cc)
{
	struct pistachio_evt_data *evt;

	evt = container_of(cc, struct pistachio_evt_data, cc);

	return (cycle_t)pistachio_evt_get_count(evt);
}

static u64 _pistachio_evt_read_ns(struct pistachio_evt_data *evt, u32 *cyc)
{
	u64 ret;

	ret = timecounter_read(&evt->tc);
	if (cyc)
		*cyc = evt->tc.cycle_last;

	return ret;
}

static u64 pistachio_evt_read_ns(struct pistachio_evt_data *evt, u32 *cyc)
{
	unsigned long flags;
	u64 ret;

	spin_lock_irqsave(&evt->lock, flags);
	ret = _pistachio_evt_read_ns(evt, cyc);
	spin_unlock_irqrestore(&evt->lock, flags);

	return ret;
}

void pistachio_evt_read(struct platform_device *pdev,
				struct timespec *ts)
{
	u64 tmp;
#ifndef	CONFIG_ATU
	struct pistachio_evt_data *evt = platform_get_drvdata(pdev);
#endif

#ifdef	CONFIG_ATU
	tmp = atu_get_current_time();
#else
	tmp = pistachio_evt_read_ns(evt, NULL);
#endif

	ts->tv_nsec = do_div(tmp, NSEC_PER_SEC);
	ts->tv_sec = tmp;
}
EXPORT_SYMBOL_GPL(pistachio_evt_read);

static inline bool pistachio_evt_bad_event(enum pistachio_evt_enable event)
{
	switch (event) {
	case PISTACHIO_EVT_ENABLE_PARALLEL_OUT:
	case PISTACHIO_EVT_ENABLE_I2S_OUT:
	case PISTACHIO_EVT_ENABLE_SPDIF_OUT:
	case PISTACHIO_EVT_ENABLE_EXTERNAL:
		return false;
	default:
		return true;
	}
}

static struct pistachio_evt_callback *pistachio_evt_get_next_trigger(
		struct pistachio_evt_data *evt, u64 *p_next_trigger)
{
	u64 next_trigger, tmp;
	int i;
	struct pistachio_evt_callback *cbr = NULL, *cb;

	cb = &evt->trigger_cbs[0];
	next_trigger = ULLONG_MAX;

	for (i = 0; i < PISTACHIO_EVT_NUM_ENABLES; i++) {
		if (!pistachio_evt_bad_event(i)) {
			tmp = cb->trigger_time;
			if (tmp && (tmp < next_trigger)) {
				next_trigger = tmp;
				cbr = cb;
			}
		}
		cb++;
	}

	*p_next_trigger = next_trigger;

	return cbr;
}

void _pistachio_evt_disable_event(struct platform_device *pdev,
		enum pistachio_evt_enable event)
{
	u32 reg;
	struct pistachio_evt_data *evt = platform_get_drvdata(pdev);

	dev_dbg(evt->dev, "Disable event %u\n", (unsigned int)event);

	if (pistachio_evt_bad_event(event)) {
		dev_err(evt->dev, "Disable event %u failed (bad event %u)\n", (unsigned int)event, (unsigned int)event);
		return;
	}

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_EVENT_CTL);

	reg &= ~(PISTACHIO_EVT_EVENT_CTL_MASK <<
		(PISTACHIO_EVT_EVENT_CTL_WIDTH * event));

	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_EVENT_CTL);

	evt->trigger_cbs[event].trigger_time = 0;
}
EXPORT_SYMBOL_GPL(_pistachio_evt_disable_event);

void pistachio_evt_disable_event(struct platform_device *pdev,
		enum pistachio_evt_enable event)
{
	unsigned long flags;
	struct pistachio_evt_data *evt = platform_get_drvdata(pdev);

	spin_lock_irqsave(&evt->lock, flags);
	_pistachio_evt_disable_event(pdev, event);
	spin_unlock_irqrestore(&evt->lock, flags);
}
EXPORT_SYMBOL_GPL(pistachio_evt_disable_event);

int pistachio_evt_set_event(struct platform_device *pdev,
		enum pistachio_evt_enable event, enum pistachio_evt_type type,
		struct timespec *ts,
		void (*event_trigger_callback)(void *context), void *context)
{
	u32 reg, cyc, event_reg_addr, irq_reg_addr;
	u64 trigger_time, next_trigger;
	unsigned long flags;
	struct pistachio_evt_data *evt = platform_get_drvdata(pdev);
	struct pistachio_evt_callback *cb;
#ifdef	CONFIG_ATU
	int ret;
#else
	u64 tmp;
#endif

	dev_dbg(evt->dev, "Set event %u type %u time %u,%u\n", (unsigned int)event, (unsigned int)type, (unsigned int)ts->tv_sec, (unsigned int)ts->tv_nsec);

	if (pistachio_evt_bad_event(event)) {
		dev_err(evt->dev, "Set event %u failed (bad event %u)\n", (unsigned int)event, (unsigned int)event);
		return -EINVAL;
	}

	switch(type) {
	case PISTACHIO_EVT_TYPE_LEVEL:
	case PISTACHIO_EVT_TYPE_PULSE:
		break;
	default:
		dev_err(evt->dev, "Set event %u failed (bad event type %u)\n", (unsigned int)event, (unsigned int)type);
		return -EINVAL;
	}

	if (!ts) {
		dev_err(evt->dev, "Set event %u failed (ts == NULL)\n", (unsigned int)event);
		return -EINVAL;
	}

	event_reg_addr = PISTACHIO_EVT_TIME_REG(event);
	irq_reg_addr = PISTACHIO_EVT_TIME_REG(PISTACHIO_EVT_ENABLE_IRQ_0);

	trigger_time = (u64)ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;

	spin_lock_irqsave(&evt->lock, flags);

	/* Trigger already pending for this event? */
	if (evt->trigger_cbs[event].trigger_time) {
		dev_err(evt->dev, "Set event %u failed (trigger already pending at %lldns)\n", (unsigned int)event, evt->trigger_cbs[event].trigger_time);
		spin_unlock_irqrestore(&evt->lock, flags);
		return -EINVAL;
	}

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_EVENT_CTL);

	/* Disable event first */
	reg &= ~(PISTACHIO_EVT_EVENT_CTL_MASK <<
		(PISTACHIO_EVT_EVENT_CTL_WIDTH * event));

	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_EVENT_CTL);

	reg |= (type << (PISTACHIO_EVT_EVENT_CTL_WIDTH * event));

#ifdef	CONFIG_ATU
	ret = atu_to_frc(trigger_time, &cyc, PISTACHIO_EVT_MIN_EVENT_DELTA_NS);
	if(ret) {
		spin_unlock_irqrestore(&evt->lock, flags);
		return ret;
	}
#else
	tmp = _pistachio_evt_read_ns(evt, &cyc);

	/* Trigger in the past or too close to current time? */
	if (trigger_time < (tmp + PISTACHIO_EVT_MIN_EVENT_DELTA_NS)) {
		if (trigger_time < tmp)
			dev_dbg(evt->dev, "Set event %u failed (1) (trigger in the past: -%lluns)\n", (unsigned int)event, (tmp - trigger_time));
		else
			dev_dbg(evt->dev, "Set event %u failed (1) (trigger too close to expiry: +%lluns)\n", (unsigned int)event, (trigger_time - tmp));
		spin_unlock_irqrestore(&evt->lock, flags);
		return -ETIME;
	}

	/*
	 * Convert ns difference between current time and trigger time
	 * to event timer cycles
	 */
	tmp = (trigger_time - tmp) << evt->cc.shift;
	do_div(tmp, evt->cc.mult);

	/* Trigger too far into the future (cyc value would be ambiguous)? */
	if (tmp > PISTACHIO_EVT_COUNTER_MASK) {
		dev_dbg(evt->dev, "Set event %u failed (trigger too far into the future: %lluns)\n", (unsigned int)event, trigger_time);
		spin_unlock_irqrestore(&evt->lock, flags);
		return -ETIME;
	}

	/* Calculate cycle value for trigger */
	cyc = (cyc + tmp) & PISTACHIO_EVT_COUNTER_MASK;

	cb = pistachio_evt_get_next_trigger(evt, &next_trigger);

	/* Final time check before fast write operations */
	tmp = _pistachio_evt_read_ns(evt, NULL);

	if (trigger_time < (tmp + PISTACHIO_EVT_MIN_EVENT_DELTA_NS)) {
		if (trigger_time < tmp)
			dev_dbg(evt->dev, "Set event %u failed (2) (trigger in the past: -%lluns)\n", (unsigned int)event, (tmp - trigger_time));
		else
			dev_dbg(evt->dev, "Set event %u failed (2) (trigger too close to expiry: +%lluns)\n", (unsigned int)event, (trigger_time - tmp));
		spin_unlock_irqrestore(&evt->lock, flags);
		return -ETIME;
	}
#endif

	pistachio_evt_writel(evt, cyc, event_reg_addr);

	/*
	 * No irq trigger currently set or the new trigger time is
	 * earlier than the current trigger time?
	 */
	if (!cb || (next_trigger > trigger_time)) {
		pistachio_evt_writel(evt, cyc, irq_reg_addr);
		reg |= PISTACHIO_EVT_TYPE_LEVEL <<
			(PISTACHIO_EVT_EVENT_CTL_WIDTH *
			PISTACHIO_EVT_ENABLE_IRQ_0);
	}

	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_EVENT_CTL);

	evt->trigger_cbs[event].callback = event_trigger_callback;
	evt->trigger_cbs[event].trigger_time = trigger_time;
	evt->trigger_cbs[event].cyc = cyc;
	evt->trigger_cbs[event].context = context;

	spin_unlock_irqrestore(&evt->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(pistachio_evt_set_event);

static bool pistachio_evt_retrigger(struct pistachio_evt_data *evt,
				struct pistachio_evt_callback * cb)
{
	u32 reg, trig_reg_addr;
	u64 cur_time;

	trig_reg_addr = PISTACHIO_EVT_TIME_REG(PISTACHIO_EVT_ENABLE_IRQ_0);

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_EVENT_CTL);

	reg |= (PISTACHIO_EVT_TYPE_LEVEL <<
		(PISTACHIO_EVT_EVENT_CTL_WIDTH * PISTACHIO_EVT_ENABLE_IRQ_0));

	pistachio_evt_writel(evt, cb->cyc, trig_reg_addr);
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_EVENT_CTL);

#ifdef	CONFIG_ATU
	cur_time = atu_get_current_time();
#else
	cur_time = _pistachio_evt_read_ns(evt, NULL);
#endif

	/* Trigger passed while writing? */
	if (cb->trigger_time < cur_time)
		return false;

	return true;
}

static irqreturn_t pistachio_evt_trigger_0_irq(int irq, void *dev_id)
{
	struct pistachio_evt_data *evt = (struct pistachio_evt_data *)dev_id;
	u64 next_trigger, cur_time;
	struct pistachio_evt_callback *cb;
	unsigned long flags;
	u32 reg;

	dev_dbg(evt->dev, "Trigger IRQ\n");

	spin_lock_irqsave(&evt->lock, flags);

	while (1) {
		cb = pistachio_evt_get_next_trigger(evt, &next_trigger);

		/* Disable the irq trigger */
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_EVENT_CTL);
		reg &= ~(PISTACHIO_EVT_EVENT_CTL_MASK <<
			(PISTACHIO_EVT_EVENT_CTL_WIDTH *
			PISTACHIO_EVT_ENABLE_IRQ_0));
		pistachio_evt_writel(evt, reg, PISTACHIO_EVT_EVENT_CTL);

		if (!cb)
			break;

#ifdef	CONFIG_ATU
		cur_time = atu_get_current_time();
#else
		cur_time = _pistachio_evt_read_ns(evt, NULL);
#endif

		if (cur_time >= next_trigger) {
			if (cb->callback)
				cb->callback(cb->context);
			cb->trigger_time = 0;
		} else if (pistachio_evt_retrigger(evt, cb)) {
			break;
		} else {
			if (cb->callback)
				cb->callback(cb->context);
			cb->trigger_time = 0;
		}
	}

	spin_unlock_irqrestore(&evt->lock, flags);

	return IRQ_HANDLED;
}

int pistachio_evt_set_timestamp_source(struct platform_device *pdev,
		unsigned int ts_module_index, unsigned int interrupt_source)
{
	u32 timestamps_per_reg, reg_addr, reg, shift;
	struct pistachio_evt_data *evt = platform_get_drvdata(pdev);
	unsigned long flags;

	dev_dbg(evt->dev, "Set timestamp source module index %u source %u\n", (unsigned int)ts_module_index, (unsigned int)interrupt_source);

	if (ts_module_index >= PISTACHIO_EVT_NUM_TIMESTAMP_MODULES) {
		dev_err(evt->dev, "Set timestamp source module index %u failed (bad timestamp module index %u)\n", (unsigned int)ts_module_index, ts_module_index);
		return -EINVAL;
	}

	timestamps_per_reg = (32 / PISTACHIO_EVT_TIMESTAMP_SRC_WIDTH);
	reg_addr = PISTACHIO_EVT_TIMESTAMP_SRC_START +
		((ts_module_index / timestamps_per_reg) * 4);

	shift = ts_module_index % timestamps_per_reg;
	shift *= PISTACHIO_EVT_TIMESTAMP_SRC_WIDTH;

	spin_lock_irqsave(&evt->lock, flags);

	reg = pistachio_evt_readl(evt, reg_addr);

	reg &= ~(PISTACHIO_EVT_TIMESTAMP_SRC_MASK << shift);

	reg |= (interrupt_source & PISTACHIO_EVT_TIMESTAMP_SRC_MASK) << shift;

	pistachio_evt_writel(evt, reg, reg_addr);

	pistachio_evt_writel(evt, 1 << ts_module_index,
			PISTACHIO_EVT_TIMESTAMP_CLR);

	spin_unlock_irqrestore(&evt->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(pistachio_evt_set_timestamp_source);

int pistachio_evt_get_timestamp(struct platform_device *pdev,
		unsigned int ts_module_index, struct timespec *timestamp)
{
	u32 reg, cyc, ts;
	u64 tmp;
	struct pistachio_evt_data *evt = platform_get_drvdata(pdev);
	unsigned long flags;

	dev_dbg(evt->dev, "Get timestamp module index %u\n", (unsigned int)ts_module_index);

	if (ts_module_index >= PISTACHIO_EVT_NUM_TIMESTAMP_MODULES) {
		dev_err(evt->dev, "Set timestamp source module index %u failed (bad timestamp module index %u)\n", (unsigned int)ts_module_index, ts_module_index);
		return -EINVAL;
	}

	spin_lock_irqsave(&evt->lock, flags);

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_TIMESTAMP_STS);

	/* No new timestamp available? */
	if (!(reg & (1 << ts_module_index))) {
		dev_dbg(evt->dev, "Get timestamp module index %u failed (no new timestamp)\n", (unsigned int)ts_module_index);
		spin_unlock_irqrestore(&evt->lock, flags);
		return -EBUSY;
	}

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_TIMESTAMP_START +
		(ts_module_index * 0x4));

	pistachio_evt_writel(evt, 1 << ts_module_index,
			PISTACHIO_EVT_TIMESTAMP_CLR);

	tmp = _pistachio_evt_read_ns(evt, &cyc);

	ts = reg & PISTACHIO_EVT_COUNTER_MASK;

	/*
	 * This currently assumes that the period of time between the
	 * timestamped event and the current time is less than the period
	 * of the counter. Maybe timestamps should be checked in the poll
	 * function that ensures the tc doesnt overflow...
	 */

	/* Get the cycle difference */
	cyc = (cyc - ts) & PISTACHIO_EVT_COUNTER_MASK;

	/* Calculate the ns difference and the ns timestamp value */
	tmp -= ((u64)cyc * evt->cc.mult) >> evt->cc.shift;

	spin_unlock_irqrestore(&evt->lock, flags);

	timestamp->tv_nsec = do_div(tmp, NSEC_PER_SEC);
	timestamp->tv_sec = tmp;

	return 0;
}
EXPORT_SYMBOL_GPL(pistachio_evt_get_timestamp);

enum hrtimer_restart pistachio_evt_poll(struct hrtimer *tmr)
{
	struct pistachio_evt_data *evt;
	u64 tmp, nsec;

	evt = container_of(tmr, struct pistachio_evt_data, poll_timer);

	tmp = pistachio_evt_read_ns(evt, NULL);
	nsec = do_div(tmp, NSEC_PER_SEC);

	//dev_dbg(evt->dev, "poll time = %u,%u\n", (unsigned int)tmp, (unsigned int)nsec);

	hrtimer_forward(&evt->poll_timer,
			hrtimer_get_expires(&evt->poll_timer),
			evt->quarter_rollover);

	return HRTIMER_RESTART;
}

static void pistachio_evt_clk_rate_change(struct pistachio_evt_data *evt)
{
	u64 tmp;
	unsigned long flags;
	unsigned long rate;
	ktime_t quarter_rollover;
	u32 mult, shift, mask;

	dev_dbg(evt->dev, "pistachio_evt_clk_rate_change()\n");

	mask = PISTACHIO_EVT_COUNTER_MASK;

	rate = clk_get_rate(evt->clk_ref_internal);

	tmp = ((u64)mask + 1) * NSEC_PER_SEC;
	do_div(tmp, rate);
	tmp >>= 2;
	quarter_rollover.tv64 = tmp;

	clocks_calc_mult_shift(&mult, &shift, rate,
			NSEC_PER_SEC, DIV_ROUND_UP(mask, rate));

	spin_lock_irqsave(&evt->lock, flags);
	evt->rate = rate;
	evt->quarter_rollover = quarter_rollover;
	evt->cc.mult = mult;
	evt->cc.shift = shift;
	spin_unlock_irqrestore(&evt->lock, flags);

	evt_timer_rate = rate;

	dev_dbg(evt->dev, "rate %ld cc mult %u shift %u\n", rate, evt->cc.mult,
			evt->cc.shift);
}

#ifndef	CONFIG_ATU
static void pistachio_evt_start_poll_timer(struct pistachio_evt_data *evt)
{
	ktime_t ks;

	dev_dbg(evt->dev, "pistachio_evt_start_poll_timer()\n");

	ks = ktime_get();
	ks = ktime_add(ks, evt->quarter_rollover);

	hrtimer_start(&evt->poll_timer, ks, HRTIMER_MODE_ABS);
}

static int pistachio_evt_clk_notifier_cb(struct notifier_block *nb,
		unsigned long event, void *data)
{
	struct pistachio_evt_data *evt;

	evt = container_of(nb, struct pistachio_evt_data, evt_clk_notifier);

	dev_dbg(evt->dev, "pistachio_evt_clk_notifier_cb()\n");

	switch (event) {
	case PRE_RATE_CHANGE:
		pistachio_evt_read_ns(evt, NULL);
		return NOTIFY_OK;
	case POST_RATE_CHANGE:
		hrtimer_cancel(&evt->poll_timer);
		pistachio_evt_clk_rate_change(evt);
		pistachio_evt_read_ns(evt, NULL);
		pistachio_evt_start_poll_timer(evt);
		return NOTIFY_OK;
	case ABORT_RATE_CHANGE:
		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}
}
#endif

static int pistachio_evt_driver_probe(struct platform_device *pdev)
{
	struct pistachio_evt_data *evt;
	int ret, i, irq;
	struct device_node *np = pdev->dev.of_node;
	u32 clk_select, rate;
	struct resource iomem;
	struct device *dev = &pdev->dev;

	evt = devm_kzalloc(&pdev->dev, sizeof(*evt), GFP_KERNEL);
	if (!evt)
		return -ENOMEM;
	platform_set_drvdata(pdev, evt);

	evt->dev = dev;

	spin_lock_init(&evt->lock);

	ret = of_address_to_resource(np, 0, &iomem);
	if (ret) {
		dev_err(dev, "Could not get IO memory\n");
		return ret;
	}

	evt->base = devm_ioremap_resource(dev, &iomem);
	if (IS_ERR(evt->base))
		return PTR_ERR(evt->base);

	irq = platform_get_irq(pdev, 3);
	if (irq < 0) {
		dev_err(&pdev->dev, "can't get trigger 0 irq\n");
		return irq;
	}

	ret = devm_request_irq(&pdev->dev, irq, pistachio_evt_trigger_0_irq,
				0, pdev->name, evt);
	if (ret) {
		dev_err(&pdev->dev, "can't request irq %d\n", irq);
		return ret;
	}

	if (of_property_read_u32(np, "img,clk-select", &clk_select)) {
		dev_err(&pdev->dev, "No img,clk-select property\n");
		return -EINVAL;
	}

	if (clk_select > 1)
		return -EINVAL;

	if (of_property_read_u32(np, "img,clk-rate", &rate))
		rate = 0;

	evt->clk_ref_a = devm_clk_get(&pdev->dev, "ref0");
	if (IS_ERR(evt->clk_ref_a))
		return PTR_ERR(evt->clk_ref_a);

	ret = clk_prepare_enable(evt->clk_ref_a);
	if (ret)
		return ret;

	evt->clk_ref_b = devm_clk_get(&pdev->dev, "ref1");
	if (IS_ERR(evt->clk_ref_b)) {
		ret = PTR_ERR(evt->clk_ref_b);
		goto err_ref_a;
	}

	ret = clk_prepare_enable(evt->clk_ref_b);
	if (ret)
		goto err_ref_a;

	evt->clk_sys = devm_clk_get(&pdev->dev, "sys");
	if (IS_ERR(evt->clk_sys)) {
		ret = PTR_ERR(evt->clk_sys);
		goto err_ref_b;
	}

	ret = clk_prepare_enable(evt->clk_sys);
	if (ret)
		goto err_ref_b;

	evt->ref_names[0] = __clk_get_name(evt->clk_ref_a);
	evt->ref_names[1] = __clk_get_name(evt->clk_ref_b);

	evt->clk_ref_internal = clk_register_mux(NULL, "event_timer_internal",
		evt->ref_names, 2, CLK_SET_RATE_PARENT |
		CLK_SET_RATE_NO_REPARENT,
		evt->base + PISTACHIO_EVT_CLKSRC_SELECT,
		PISTACHIO_EVT_CLKSRC_SELECT_SHIFT,
		PISTACHIO_EVT_CLKSRC_SELECT_WIDTH,
		0, NULL);

	if (IS_ERR(evt->clk_ref_internal)) {
		ret = PTR_ERR(evt->clk_ref_internal);
		goto err_sys;
	}

	ret = of_clk_add_provider(np, of_clk_src_simple_get,
			evt->clk_ref_internal);
	if (ret)
		goto err_mux;

	if (clk_select == 0)
		ret = clk_set_parent(evt->clk_ref_internal, evt->clk_ref_a);
	else
		ret = clk_set_parent(evt->clk_ref_internal, evt->clk_ref_b);

	if (ret)
		goto err_clkp;

	if (rate) {
		ret = clk_set_rate(evt->clk_ref_internal, rate);
		if (ret)
			goto err_clkp;
	}

	hrtimer_init(&evt->poll_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	evt->poll_timer.function = pistachio_evt_poll;

	evt->cc.mask = PISTACHIO_EVT_COUNTER_MASK;
	evt->cc.read = pistachio_evt_cc_read;

	pistachio_evt_writel(evt, PISTACHIO_EVT_TIMER_ENABLE_MASK,
			PISTACHIO_EVT_TIMER_ENABLE);

	pistachio_evt_start_count(evt);

	pistachio_evt_clk_rate_change(evt);

	timecounter_init(&evt->tc, (const struct cyclecounter *)&evt->cc, 0);

#ifdef CONFIG_ATU
	ret = atu_cyclecounter_register(&evt->cc, NULL);
	if(ret)
		goto err_count;
#else
	pistachio_evt_start_poll_timer(evt);

	evt->evt_clk_notifier.notifier_call = pistachio_evt_clk_notifier_cb;
	ret = clk_notifier_register(evt->clk_ref_internal,
			&evt->evt_clk_notifier);
	if (ret)
		goto err_count;
#endif

	/*
	 * 2nd layer of muxing for event timer sources.
	 * Not useful, use identity mapping
	 */
	for (i = 0; i < 12; i++) {
		pistachio_evt_writel(evt, i,
			PISTACHIO_EVT_SOURCE_INTERNAL_START + (i * 0x4));
	}

	return 0;

err_count:
#ifndef	CONFIG_ATU
	hrtimer_cancel(&evt->poll_timer);
#endif
	pistachio_evt_stop_count(evt);
	pistachio_evt_writel(evt, 0, PISTACHIO_EVT_TIMER_ENABLE);
err_clkp:
	of_clk_del_provider(np);
err_mux:
	clk_unregister(evt->clk_ref_internal);
err_sys:
	clk_disable_unprepare(evt->clk_sys);
err_ref_b:
	clk_disable_unprepare(evt->clk_ref_b);
err_ref_a:
	clk_disable_unprepare(evt->clk_ref_a);

	return ret;
}

static const struct of_device_id pistachio_evt_of_match[] = {
	{ .compatible = "img,pistachio-event-timer" },
	{ },
};
MODULE_DEVICE_TABLE(of, pistachio_evt_of_match);

static int pistachio_evt_driver_remove(struct platform_device *pdev)
{
	struct pistachio_evt_data *evt = platform_get_drvdata(pdev);

#ifdef CONFIG_ATU
	atu_cyclecounter_unregister(&evt->cc);
#else
	clk_notifier_unregister(evt->clk_ref_internal, &evt->evt_clk_notifier);
	hrtimer_cancel(&evt->poll_timer);
#endif
	of_clk_del_provider(evt->dev->of_node);
	pistachio_evt_stop_count(evt);
	pistachio_evt_writel(evt, 0, PISTACHIO_EVT_TIMER_ENABLE);
	clk_unregister(evt->clk_ref_internal);
	clk_disable_unprepare(evt->clk_sys);
	clk_disable_unprepare(evt->clk_ref_b);
	clk_disable_unprepare(evt->clk_ref_a);

	return 0;
}

static struct platform_driver pistachio_evt_driver = {
	.driver = {
		.name = "pistachio-event-timer",
		.of_match_table = pistachio_evt_of_match,
	},
	.probe = pistachio_evt_driver_probe,
	.remove = pistachio_evt_driver_remove,
};
module_platform_driver(pistachio_evt_driver);

MODULE_DESCRIPTION("Event Timer driver");
MODULE_AUTHOR("Damien Horsley");
MODULE_LICENSE("GPL v2");
