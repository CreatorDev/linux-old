/*
 * Pistachio event timer local time units
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
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timecounter.h>

#include <linux/atu_clk.h>

#include "pistachio-event-timer.h"
#include "pistachio-event-timer-internal.h"

static u64 _pistachio_evt_get_time_cyc(struct pistachio_evt *evt, u32 *cyc)
{
	u64 ret;

	ret = timecounter_read(&evt->tc);
	if (cyc)
		*cyc = evt->tc.cycle_last;

	return ret;
}

static u64 pistachio_evt_get_time_cyc(struct pistachio_evt *evt, u32 *cyc)
{
	unsigned long flags;
	u64 ret;

	spin_lock_irqsave(&evt->lock, flags);
	ret = _pistachio_evt_get_time_cyc(evt, cyc);
	spin_unlock_irqrestore(&evt->lock, flags);

	return ret;
}

u64 _pistachio_evt_get_time(struct pistachio_evt *evt)
{
	return _pistachio_evt_get_time_cyc(evt, NULL);
}
EXPORT_SYMBOL_GPL(_pistachio_evt_get_time);

u64 pistachio_evt_get_time(struct pistachio_evt *evt)
{
	return pistachio_evt_get_time_cyc(evt, NULL);
}
EXPORT_SYMBOL_GPL(pistachio_evt_get_time);

int pistachio_evt_time_to_reg(struct pistachio_evt *evt, u64 time, u32 *reg,
				u64 min_time_delta)
{
	u64 tmp;
	u32 cyc;

	tmp = _pistachio_evt_get_time_cyc(evt, &cyc);

	/* Trigger in the past or too close to current time? */
	if (time < (tmp + min_time_delta))
		return -ETIME;

	/*
	 * Convert ns difference between current time and trigger time
	 * to event timer cycles
	 */
	tmp = (time - tmp) << evt->cc.shift;
	do_div(tmp, evt->cc.mult);

	/* Trigger too far into the future (cyc value would be ambiguous)? */
	if (tmp > evt->cc.mask)
		return -ETIME;

	/* Calculate cycle value for trigger */
	cyc = (cyc + tmp) & evt->cc.mask;

	/* Final time check before fast write operations */
	tmp = _pistachio_evt_get_time_cyc(evt, &cyc);
	if (time < (tmp + min_time_delta))
		return -ETIME;

	return 0;
}
EXPORT_SYMBOL_GPL(pistachio_evt_time_to_reg);

static enum hrtimer_restart pistachio_evt_poll(struct hrtimer *tmr)
{
	struct pistachio_evt *evt;
	u64 tmp;

	evt = container_of(tmr, struct pistachio_evt, poll_timer);

	tmp = pistachio_evt_get_time(evt);

	hrtimer_forward(&evt->poll_timer,
			hrtimer_get_expires(&evt->poll_timer),
			evt->quarter_rollover);

	return HRTIMER_RESTART;
}

static void pistachio_evt_start_poll_timer(struct pistachio_evt *evt)
{
	ktime_t ks;

	ks = ktime_get();
	ks = ktime_add(ks, evt->quarter_rollover);

	hrtimer_start(&evt->poll_timer, ks, HRTIMER_MODE_ABS);
}

static int pistachio_evt_clk_notifier_cb(struct notifier_block *nb,
		unsigned long event, void *data)
{
	struct pistachio_evt *evt;

	evt = container_of(nb, struct pistachio_evt, evt_clk_notifier);

	switch (event) {
	case PRE_RATE_CHANGE:
		pistachio_evt_get_time_cyc(evt, NULL);
		return NOTIFY_OK;
	case POST_RATE_CHANGE:
		hrtimer_cancel(&evt->poll_timer);
		pistachio_evt_clk_rate_change(evt);
		pistachio_evt_get_time_cyc(evt, NULL);
		pistachio_evt_start_poll_timer(evt);
		return NOTIFY_OK;
	case ABORT_RATE_CHANGE:
		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}
}

int pistachio_evt_init(struct pistachio_evt *evt)
{
	int ret;

	timecounter_init(&evt->tc, (const struct cyclecounter *)&evt->cc, 0);

	hrtimer_init(&evt->poll_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	evt->poll_timer.function = pistachio_evt_poll;

	pistachio_evt_start_poll_timer(evt);

	evt->evt_clk_notifier.notifier_call = pistachio_evt_clk_notifier_cb;

	ret = clk_notifier_register(evt->clk_ref_internal,
					&evt->evt_clk_notifier);

	if (ret)
		hrtimer_cancel(&evt->poll_timer);

	return ret;
}
EXPORT_SYMBOL_GPL(pistachio_evt_init);

void pistachio_evt_deinit(struct pistachio_evt *evt)
{
	clk_notifier_unregister(evt->clk_ref_internal, &evt->evt_clk_notifier);
	hrtimer_cancel(&evt->poll_timer);
}
EXPORT_SYMBOL_GPL(pistachio_evt_deinit);
