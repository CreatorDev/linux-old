/*
 * Pistachio event timer driver
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * Author: Damien Horsley <Damien.Horsley@imgtec.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/clocksource.h>
#include <linux/delay.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timecounter.h>

#include <linux/mfd/syscon.h>

#include "pistachio-event-timer.h"
#include "pistachio-event-timer-internal.h"

#define	PISTACHIO_EVT_FIFO_DEPTH		16

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

#define PISTACHIO_EVT_SOURCES			0x108
#define PISTACHIO_EVT_SOURCES_SHIFT		16
#define	PISTACHIO_EVT_SOURCES_MASK_LSB		0xffffUL

#define PISTACHIO_EVT_PHASE_FIFO		0x110

#define	PISTACHIO_EVT_SAMPLE_FIFO(id)		(0x114 + ((id) * 0x4))

#define PISTACHIO_EVT_EVENT_CTL			0x120
#define PISTACHIO_EVT_EVENT_CTL_MASK		0x3
#define PISTACHIO_EVT_EVENT_CTL_WIDTH		2

#define PISTACHIO_EVT_TIME_REG(en)		(0x130 + ((en) * 0x4))

#define PISTACHIO_EVT_INT_STATUS		0x170

#define PISTACHIO_EVT_INT_ENABLE		0x174

#define PISTACHIO_EVT_INT_CLEAR			0x178

#define	PISTACHIO_EVT_INT_SAMPLE_0_FNE_MASK	BIT(5)
#define	PISTACHIO_EVT_INT_SAMPLE_1_FNE_MASK	BIT(9)
#define	PISTACHIO_EVT_INT_PHASE_FNE_MASK	BIT(1)

#define	PISTACHIO_EVT_EXT_SRC_REG		0x158
#define	PISTACHIO_EVT_EXT_SRC_MASK		0xf
#define	PISTACHIO_EVT_EXT_SRC_NUM_BANKS		7

#define	PISTACHIO_EVT_MIN_EVENT_DELTA_NS	10000

static LIST_HEAD(pistachio_evt_list);
static DEFINE_SPINLOCK(pistachio_evt_list_spinlock);

static inline u32 pistachio_evt_readl(struct pistachio_evt *evt, u32 reg)
{
	return readl(evt->base + reg);
}

static inline void pistachio_evt_writel(struct pistachio_evt *evt,
					u32 val, u32 reg)
{
	writel(val, evt->base + reg);
}

static inline void pistachio_evt_stop_count(struct pistachio_evt *evt)
{
	u32 reg = pistachio_evt_readl(evt, PISTACHIO_EVT_COUNTER);

	reg &= ~PISTACHIO_EVT_COUNTER_ENABLE_MASK;
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_COUNTER);
}

static inline void pistachio_evt_start_count(struct pistachio_evt *evt)
{
	u32 reg = pistachio_evt_readl(evt, PISTACHIO_EVT_COUNTER);

	reg |= PISTACHIO_EVT_COUNTER_ENABLE_MASK;
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_COUNTER);
}

static inline u32 pistachio_evt_get_count(struct pistachio_evt *evt)
{
	u32 reg = pistachio_evt_readl(evt, PISTACHIO_EVT_COUNTER);

	return reg & PISTACHIO_EVT_COUNTER_MASK;
}

static cycle_t pistachio_evt_cc_read(const struct cyclecounter *cc)
{
	struct pistachio_evt *evt;

	evt = container_of(cc, struct pistachio_evt, cc);

	return (cycle_t)pistachio_evt_get_count(evt);
}

void pistachio_evt_get_time_ts(struct pistachio_evt *evt,
				struct timespec *ts)
{
	u64 tmp;

	tmp = pistachio_evt_get_time(evt);
	ts->tv_nsec = do_div(tmp, NSEC_PER_SEC);
	ts->tv_sec = tmp;
}
EXPORT_SYMBOL_GPL(pistachio_evt_get_time_ts);

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
		struct pistachio_evt *evt, u64 *p_next_trigger)
{
	u64 next_trigger, tmp;
	int i;
	struct pistachio_evt_callback *cbr = NULL, *cb;

	cb = &evt->trigger_cbs[0];
	next_trigger = ULLONG_MAX;

	for (i = 0; i < PISTACHIO_EVT_NUM_ENABLES; i++, cb++) {
		if (!pistachio_evt_bad_event(i)) {
			tmp = cb->trigger_time;
			if (tmp && (tmp < next_trigger)) {
				next_trigger = tmp;
				cbr = cb;
			}
		}
	}

	*p_next_trigger = next_trigger;

	return cbr;
}

struct pistachio_evt *pistachio_evt_get(struct device_node *np)
{
	struct pistachio_evt *evt, *ret = ERR_PTR(-EPROBE_DEFER);

	spin_lock(&pistachio_evt_list_spinlock);
	list_for_each_entry(evt, &pistachio_evt_list, list) {
		if (evt->np == np) {
			ret = evt;
			break;
		}
	}
	spin_unlock(&pistachio_evt_list_spinlock);

	return ret;
}
EXPORT_SYMBOL_GPL(pistachio_evt_get);

void _pistachio_evt_disable_event(struct pistachio_evt *evt,
		enum pistachio_evt_enable event)
{
	u32 reg;

	dev_dbg(evt->dev, "Disable event %u\n", (unsigned int)event);

	if (pistachio_evt_bad_event(event)) {
		dev_err(evt->dev, "Disable event %u failed (bad event %u)\n",
			(unsigned int)event, (unsigned int)event);
		return;
	}

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_EVENT_CTL);

	reg &= ~(PISTACHIO_EVT_EVENT_CTL_MASK <<
		(PISTACHIO_EVT_EVENT_CTL_WIDTH * event));

	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_EVENT_CTL);

	evt->trigger_cbs[event].trigger_time = 0;
}
EXPORT_SYMBOL_GPL(_pistachio_evt_disable_event);

void pistachio_evt_disable_event(struct pistachio_evt *evt,
		enum pistachio_evt_enable event)
{
	unsigned long flags;

	spin_lock_irqsave(&evt->lock, flags);
	_pistachio_evt_disable_event(evt, event);
	spin_unlock_irqrestore(&evt->lock, flags);
}
EXPORT_SYMBOL_GPL(pistachio_evt_disable_event);

int pistachio_evt_set_event(struct pistachio_evt *evt,
		enum pistachio_evt_enable event, enum pistachio_evt_type type,
		struct timespec *ts,
		void (*event_trigger_callback)(struct pistachio_evt *, void *),
		void *context)
{
	u32 reg, cyc, event_reg_addr, irq_reg_addr;
	u64 trigger_time, next_trigger;
	unsigned long flags;
	struct pistachio_evt_callback *cb;
	int ret;

	dev_dbg(evt->dev, "Set event %u type %u time %u,%ld\n",
		(unsigned int)event, (unsigned int)type,
		(unsigned int)ts->tv_sec, ts->tv_nsec);

	if (pistachio_evt_bad_event(event)) {
		dev_err(evt->dev, "Set event %u failed (bad event %u)\n",
			(unsigned int)event, (unsigned int)event);
		return -EINVAL;
	}

	switch (type) {
	case PISTACHIO_EVT_TYPE_LEVEL:
	case PISTACHIO_EVT_TYPE_PULSE:
		break;
	default:
		dev_err(evt->dev, "Set event %u failed (bad event type %u)\n",
			(unsigned int)event, (unsigned int)type);
		return -EINVAL;
	}

	if (!ts) {
		dev_err(evt->dev, "Set event %u failed (ts == NULL)\n",
			(unsigned int)event);
		return -EINVAL;
	}

	event_reg_addr = PISTACHIO_EVT_TIME_REG(event);
	irq_reg_addr = PISTACHIO_EVT_TIME_REG(PISTACHIO_EVT_ENABLE_IRQ_0);

	trigger_time = (u64)ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;

	spin_lock_irqsave(&evt->lock, flags);

	/* Trigger already pending for this event? */
	if (evt->trigger_cbs[event].trigger_time) {
		spin_unlock_irqrestore(&evt->lock, flags);
		dev_err(evt->dev, "Set event %u failed (trigger already pending at %lluns)\n",
			(unsigned int)event,
			evt->trigger_cbs[event].trigger_time);
		return -EINVAL;
	}

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_EVENT_CTL);

	/*
	 * This event may have triggered previously. The control bits need to
	 * be cleared before programming a new trigger
	 */
	reg &= ~(PISTACHIO_EVT_EVENT_CTL_MASK <<
		(PISTACHIO_EVT_EVENT_CTL_WIDTH * event));

	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_EVENT_CTL);

	reg |= (type << (PISTACHIO_EVT_EVENT_CTL_WIDTH * event));

	ret = pistachio_evt_time_to_reg(evt, trigger_time, &cyc,
					PISTACHIO_EVT_MIN_EVENT_DELTA_NS);
	if (ret) {
		spin_unlock_irqrestore(&evt->lock, flags);
		dev_err(evt->dev, "Set event %u failed (%d)\n",
			(unsigned int)event, ret);
		return ret;
	}

	pistachio_evt_writel(evt, cyc, event_reg_addr);

	cb = pistachio_evt_get_next_trigger(evt, &next_trigger);

	/*
	 * No irq trigger currently set or the new trigger time is
	 * earlier than the next trigger time?
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

static bool pistachio_evt_retrigger(struct pistachio_evt *evt,
				struct pistachio_evt_callback *cb)
{
	u32 reg, trig_reg_addr;
	u64 cur_time;

	trig_reg_addr = PISTACHIO_EVT_TIME_REG(PISTACHIO_EVT_ENABLE_IRQ_0);

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_EVENT_CTL);

	reg |= (PISTACHIO_EVT_TYPE_LEVEL <<
		(PISTACHIO_EVT_EVENT_CTL_WIDTH * PISTACHIO_EVT_ENABLE_IRQ_0));

	pistachio_evt_writel(evt, cb->cyc, trig_reg_addr);
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_EVENT_CTL);

	cur_time = _pistachio_evt_get_time(evt);

	/* Trigger passed while writing? */
	if (cb->trigger_time < cur_time)
		return false;

	return true;
}

static irqreturn_t pistachio_evt_trigger_0_irq(int irq, void *dev_id)
{
	struct pistachio_evt *evt = (struct pistachio_evt *)dev_id;
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

		cur_time = _pistachio_evt_get_time(evt);

		if (cur_time >= next_trigger) {
			if (cb->callback)
				cb->callback(evt, cb->context);
			cb->trigger_time = 0;
		} else if (pistachio_evt_retrigger(evt, cb)) {
			break;
		} else {
			if (cb->callback)
				cb->callback(evt, cb->context);
			cb->trigger_time = 0;
		}
	}

	spin_unlock_irqrestore(&evt->lock, flags);

	return IRQ_HANDLED;
}

int pistachio_evt_set_source(struct pistachio_evt *evt,
			int id, enum pistachio_evt_source source)
{
	unsigned long flags;
	u32 reg;

	if ((id >= PISTACHIO_EVT_MAX_SOURCES) ||
			(source >= PISTACHIO_EVT_NUM_SOURCES))
		return -EINVAL;

	spin_lock_irqsave(&evt->lock, flags);

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_SOURCES);
	reg &= ~(PISTACHIO_EVT_SOURCES_MASK_LSB <<
		(id * PISTACHIO_EVT_SOURCES_SHIFT));
	reg |= source << (id * PISTACHIO_EVT_SOURCES_SHIFT);
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_SOURCES);

	/*
	 * Changing one of the sources invalidates the active sample rate
	 * measurement for the source in question, and the active phase
	 * difference measurement, so reset these states and mask the
	 * interrupts
	 */
	evt->sample_rates[id].state = PISTACHIO_EVT_STATE_IDLE;
	evt->phase_difference.state = PISTACHIO_EVT_STATE_IDLE;

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_ENABLE);
	if (id == 0)
		reg &= ~PISTACHIO_EVT_INT_SAMPLE_0_FNE_MASK;
	else
		reg &= ~PISTACHIO_EVT_INT_SAMPLE_1_FNE_MASK;
	reg &= ~PISTACHIO_EVT_INT_PHASE_FNE_MASK;
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_INT_ENABLE);

	spin_unlock_irqrestore(&evt->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(pistachio_evt_set_source);

int pistachio_evt_get_source(struct pistachio_evt *evt,
		int id, enum pistachio_evt_source *source)
{
	u32 reg;

	if (id >= PISTACHIO_EVT_MAX_SOURCES)
		return -EINVAL;

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_SOURCES);

	*source = (reg >> (id * PISTACHIO_EVT_SOURCES_SHIFT)) &
		PISTACHIO_EVT_SOURCES_MASK_LSB;

	return 0;
}
EXPORT_SYMBOL_GPL(pistachio_evt_get_source);

static void pistachio_evt_clear_fifo(struct pistachio_evt *evt,
			u32 fifo_offset, u32 mask, bool enable_int)
{
	u32 reg;

	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_ENABLE);
	if (enable_int)
		reg |= mask;
	else
		reg &= ~mask;
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_INT_ENABLE);

	while (1) {
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_STATUS);
		if (!(reg & mask))
			break;
		reg = pistachio_evt_readl(evt, fifo_offset);
		pistachio_evt_writel(evt, mask, PISTACHIO_EVT_INT_CLEAR);
		pistachio_evt_writel(evt, 0, PISTACHIO_EVT_INT_CLEAR);
	}
}

static void pistachio_evt_new_sr(struct pistachio_evt *evt, int id, u32 mask)
{
	u32 reg;
	enum pistachio_evt_state new_state;
	struct pistachio_evt_measurement *sr = &evt->sample_rates[id];

	switch (sr->state) {
	case PISTACHIO_EVT_STATE_ACTIVE_FIRST:
		/* First sample rate measurement is always invalid */
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_SAMPLE_FIFO(id));
		pistachio_evt_writel(evt, mask, PISTACHIO_EVT_INT_CLEAR);
		pistachio_evt_writel(evt, 0, PISTACHIO_EVT_INT_CLEAR);
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_STATUS);
		if (reg & mask)
			new_state = PISTACHIO_EVT_STATE_COMPLETE;
		else
			new_state = PISTACHIO_EVT_STATE_ACTIVE_SECOND;
		break;

	case PISTACHIO_EVT_STATE_ACTIVE_SECOND:
		new_state = PISTACHIO_EVT_STATE_COMPLETE;
		break;

	default:
		dev_err(evt->dev, "pistachio_evt_new_sr bad state (%d)\n",
			(int)sr->state);
		return;
	}

	if (new_state == PISTACHIO_EVT_STATE_COMPLETE) {
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_ENABLE);
		reg &= ~mask;
		pistachio_evt_writel(evt, reg, PISTACHIO_EVT_INT_ENABLE);
		pistachio_evt_writel(evt, mask, PISTACHIO_EVT_INT_CLEAR);
		pistachio_evt_writel(evt, 0, PISTACHIO_EVT_INT_CLEAR);
		if (sr->callback)
			sr->callback(sr->context);
	}

	sr->state = new_state;
}

static void pistachio_evt_new_pd(struct pistachio_evt *evt)
{
	u32 reg;
	enum pistachio_evt_state new_state;
	u32 mask = PISTACHIO_EVT_INT_PHASE_FNE_MASK;
	struct pistachio_evt_measurement *pd = &evt->phase_difference;

	switch (pd->state) {
	case PISTACHIO_EVT_STATE_ACTIVE_FIRST:
		/* First two phase measurements are always invalid */
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_PHASE_FIFO);
		pistachio_evt_writel(evt, mask, PISTACHIO_EVT_INT_CLEAR);
		pistachio_evt_writel(evt, 0, PISTACHIO_EVT_INT_CLEAR);
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_STATUS);
		if (!(reg & mask)) {
			new_state = PISTACHIO_EVT_STATE_ACTIVE_SECOND;
			break;
		}
		/* Fall through */
	case PISTACHIO_EVT_STATE_ACTIVE_SECOND:
		/* First two phase measurements are always invalid */
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_PHASE_FIFO);
		pistachio_evt_writel(evt, mask, PISTACHIO_EVT_INT_CLEAR);
		pistachio_evt_writel(evt, 0, PISTACHIO_EVT_INT_CLEAR);
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_STATUS);
		if (reg & mask)
			new_state = PISTACHIO_EVT_STATE_COMPLETE;
		else
			new_state = PISTACHIO_EVT_STATE_ACTIVE_THIRD;
		break;

	case PISTACHIO_EVT_STATE_ACTIVE_THIRD:
		new_state = PISTACHIO_EVT_STATE_COMPLETE;
		break;

	default:
		dev_err(evt->dev, "pistachio_evt_new_pd bad state (%d)\n",
			(int)pd->state);
		return;
	}

	if (new_state == PISTACHIO_EVT_STATE_COMPLETE) {
		reg = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_ENABLE);
		reg &= ~mask;
		pistachio_evt_writel(evt, reg, PISTACHIO_EVT_INT_ENABLE);
		pistachio_evt_writel(evt, mask, PISTACHIO_EVT_INT_CLEAR);
		pistachio_evt_writel(evt, 0, PISTACHIO_EVT_INT_CLEAR);
		if (pd->callback)
			pd->callback(pd->context);
	}

	pd->state = new_state;
}

static irqreturn_t pistachio_evt_general_irq(int irq, void *dev_id)
{
	struct pistachio_evt *evt = (struct pistachio_evt *)dev_id;
	unsigned long flags;
	u32 mask, i, isr, ier;

	spin_lock_irqsave(&evt->lock, flags);

	while (1) {
		isr = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_STATUS);
		ier = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_ENABLE);
		isr &= ier;

		if (!isr)
			break;

		for (i = 0; i < PISTACHIO_EVT_MAX_SOURCES; i++) {
			if (i == 0)
				mask = PISTACHIO_EVT_INT_SAMPLE_0_FNE_MASK;
			else
				mask = PISTACHIO_EVT_INT_SAMPLE_1_FNE_MASK;

			if (isr & mask)
				pistachio_evt_new_sr(evt, i, mask);
		}

		if (isr & PISTACHIO_EVT_INT_PHASE_FNE_MASK)
			pistachio_evt_new_pd(evt);
	}

	spin_unlock_irqrestore(&evt->lock, flags);

	return IRQ_HANDLED;
}

int pistachio_evt_get_sample_rate(struct pistachio_evt *evt, int id,
			u32 *val, u32 *sys_freq,
			void (*callback)(void *context), void *context)
{
	unsigned long flags;
	u32 mask;
	int ret;

	if (id >= PISTACHIO_EVT_MAX_SOURCES)
		return -EINVAL;

	spin_lock_irqsave(&evt->lock, flags);

	switch (evt->sample_rates[id].state) {
	case PISTACHIO_EVT_STATE_IDLE:
		if (id == 0)
			mask = PISTACHIO_EVT_INT_SAMPLE_0_FNE_MASK;
		else
			mask = PISTACHIO_EVT_INT_SAMPLE_1_FNE_MASK;

		pistachio_evt_clear_fifo(evt, PISTACHIO_EVT_SAMPLE_FIFO(id),
					mask, true);

		ret = -EBUSY;
		evt->sample_rates[id].state = PISTACHIO_EVT_STATE_ACTIVE_FIRST;
		evt->sample_rates[id].callback = callback;
		evt->sample_rates[id].context = context;
		break;

	case PISTACHIO_EVT_STATE_COMPLETE:
		*val = pistachio_evt_readl(evt, PISTACHIO_EVT_SAMPLE_FIFO(id));
		*sys_freq = evt->sys_rate;
		evt->sample_rates[id].state = PISTACHIO_EVT_STATE_IDLE;
		ret = 0;
		break;

	default:
		ret = -EBUSY;
		break;
	}

	spin_unlock_irqrestore(&evt->lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(pistachio_evt_get_sample_rate);

extern int pistachio_evt_get_phase_difference(struct pistachio_evt *evt,
			u32 *val, u32 *sys_freq,
			void (*callback)(void *context), void *context)
{
	unsigned long flags;
	u32 mask;
	int ret = 0;

	spin_lock_irqsave(&evt->lock, flags);

	switch (evt->phase_difference.state) {
	case PISTACHIO_EVT_STATE_IDLE:
		mask = PISTACHIO_EVT_INT_PHASE_FNE_MASK;

		pistachio_evt_clear_fifo(evt, PISTACHIO_EVT_PHASE_FIFO,
						mask, true);

		ret = -EBUSY;
		evt->phase_difference.state = PISTACHIO_EVT_STATE_ACTIVE_FIRST;
		evt->phase_difference.callback = callback;
		evt->phase_difference.context = context;
		break;

	case PISTACHIO_EVT_STATE_COMPLETE:
		*val = pistachio_evt_readl(evt, PISTACHIO_EVT_PHASE_FIFO);
		*sys_freq = evt->sys_rate;
		evt->phase_difference.state = PISTACHIO_EVT_STATE_IDLE;
		break;

	default:
		ret = -EBUSY;
		break;
	}

	spin_unlock_irqrestore(&evt->lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(pistachio_evt_get_phase_difference);

void pistachio_evt_abort_measurements(struct pistachio_evt *evt)
{
	unsigned long flags;
	u32 reg;

	spin_lock_irqsave(&evt->lock, flags);
	evt->sample_rates[0].state = PISTACHIO_EVT_STATE_IDLE;
	evt->sample_rates[1].state = PISTACHIO_EVT_STATE_IDLE;
	evt->phase_difference.state = PISTACHIO_EVT_STATE_IDLE;
	reg = pistachio_evt_readl(evt, PISTACHIO_EVT_INT_ENABLE);
	reg &= ~PISTACHIO_EVT_INT_SAMPLE_0_FNE_MASK;
	reg &= ~PISTACHIO_EVT_INT_SAMPLE_1_FNE_MASK;
	reg &= ~PISTACHIO_EVT_INT_PHASE_FNE_MASK;
	pistachio_evt_writel(evt, reg, PISTACHIO_EVT_INT_ENABLE);
	spin_unlock_irqrestore(&evt->lock, flags);
}
EXPORT_SYMBOL_GPL(pistachio_evt_abort_measurements);

void pistachio_evt_clk_rate_change(struct pistachio_evt *evt)
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
	evt->quarter_rollover = quarter_rollover;
	evt->cc.mult = mult;
	evt->cc.shift = shift;
	spin_unlock_irqrestore(&evt->lock, flags);

	dev_dbg(evt->dev, "rate %ld cc mult %u shift %u\n", rate, evt->cc.mult,
			evt->cc.shift);
}

static int pistachio_evt_driver_probe(struct platform_device *pdev)
{
	struct pistachio_evt *evt;
	int ret, irq;
	struct device_node *np = pdev->dev.of_node;
	u32 clk_select, rate, ext_src_bank;
	struct resource iomem;
	struct device *dev = &pdev->dev;
	struct regmap *periph_regs;

	evt = devm_kzalloc(&pdev->dev, sizeof(*evt), GFP_KERNEL);
	if (!evt)
		return -ENOMEM;
	platform_set_drvdata(pdev, evt);

	evt->dev = dev;
	evt->np = np;

	spin_lock_init(&evt->lock);

	ret = of_address_to_resource(np, 0, &iomem);
	if (ret) {
		dev_err(dev, "Could not get IO memory\n");
		return ret;
	}

	evt->base = devm_ioremap_resource(dev, &iomem);
	if (IS_ERR(evt->base))
		return PTR_ERR(evt->base);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "can't get general irq\n");
		return irq;
	}

	ret = devm_request_irq(&pdev->dev, irq, pistachio_evt_general_irq,
				0, pdev->name, evt);
	if (ret) {
		dev_err(&pdev->dev, "can't request irq %d\n", irq);
		return ret;
	}

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

	periph_regs = syscon_regmap_lookup_by_phandle(np, "img,cr-periph");
	if (IS_ERR(periph_regs))
		return PTR_ERR(periph_regs);

	if (of_property_read_u32(np, "img,ext-src-bank", &ext_src_bank)) {
		dev_err(&pdev->dev, "No img,ext-src-bank property\n");
		return -EINVAL;
	}

	if (ext_src_bank >= PISTACHIO_EVT_EXT_SRC_NUM_BANKS)
		return -EINVAL;

	regmap_update_bits(periph_regs, PISTACHIO_EVT_EXT_SRC_REG,
			PISTACHIO_EVT_EXT_SRC_MASK, ext_src_bank);

	if (of_property_read_u32(np, "img,clk-select", &clk_select)) {
		dev_err(&pdev->dev, "No img,clk-select property\n");
		return -EINVAL;
	}

	if (clk_select > 1)
		return -EINVAL;

	if (of_property_read_u32(np, "img,clk-rate", &rate))
		rate = 0;

	evt->audio_pll = devm_clk_get(&pdev->dev, "pll");
	if (IS_ERR(evt->audio_pll))
		return PTR_ERR(evt->audio_pll);

	ret = clk_prepare_enable(evt->audio_pll);
	if (ret)
		return ret;

	evt->clk_ref_a = devm_clk_get(&pdev->dev, "ref0");
	if (IS_ERR(evt->clk_ref_a)) {
		ret = PTR_ERR(evt->audio_pll);
		goto err_pll;
	}

	ret = clk_prepare_enable(evt->clk_ref_a);
	if (ret)
		goto err_pll;

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

	evt->sys_rate = clk_get_rate(evt->clk_sys);

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

	evt->cc.mask = PISTACHIO_EVT_COUNTER_MASK;
	evt->cc.read = pistachio_evt_cc_read;

	pistachio_evt_writel(evt, PISTACHIO_EVT_TIMER_ENABLE_MASK,
			PISTACHIO_EVT_TIMER_ENABLE);

	pistachio_evt_start_count(evt);

	pistachio_evt_clk_rate_change(evt);

	ret = pistachio_evt_init(evt);
	if (ret)
		goto err_count;

	spin_lock(&pistachio_evt_list_spinlock);
	list_add(&evt->list, &pistachio_evt_list);
	spin_unlock(&pistachio_evt_list_spinlock);

	return 0;

err_count:
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
err_pll:
	clk_disable_unprepare(evt->audio_pll);

	return ret;
}

static const struct of_device_id pistachio_evt_of_match[] = {
	{ .compatible = "img,pistachio-event-timer" },
	{ },
};
MODULE_DEVICE_TABLE(of, pistachio_evt_of_match);

static int pistachio_evt_driver_remove(struct platform_device *pdev)
{
	struct pistachio_evt *evt = platform_get_drvdata(pdev);

	spin_lock(&pistachio_evt_list_spinlock);
	list_del(&evt->list);
	spin_unlock(&pistachio_evt_list_spinlock);
	pistachio_evt_deinit(evt);
	pistachio_evt_stop_count(evt);
	pistachio_evt_writel(evt, 0, PISTACHIO_EVT_TIMER_ENABLE);
	of_clk_del_provider(evt->dev->of_node);
	clk_unregister(evt->clk_ref_internal);
	clk_disable_unprepare(evt->clk_sys);
	clk_disable_unprepare(evt->clk_ref_b);
	clk_disable_unprepare(evt->clk_ref_a);
	clk_disable_unprepare(evt->audio_pll);

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
