/*
 * Imagination Technologies Pistachio Event Timer Internal Header
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * Author: Damien Horsley <Damien.Horsley@imgtec.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#ifndef __IMG_PISTACHIO_EVT_INTERNAL_H__
#define __IMG_PISTACHIO_EVT_INTERNAL_H__

enum pistachio_evt_state {
	PISTACHIO_EVT_STATE_IDLE = 0,
	PISTACHIO_EVT_STATE_ACTIVE_FIRST,
	PISTACHIO_EVT_STATE_ACTIVE_SECOND,
	PISTACHIO_EVT_STATE_ACTIVE_THIRD,
	PISTACHIO_EVT_STATE_COMPLETE
};

struct pistachio_evt_callback {
	u64 trigger_time;
	u32 cyc;
	void (*callback)(struct pistachio_evt *, void *);
	void *context;
};

struct pistachio_evt_measurement {
	enum pistachio_evt_state state;
	void (*callback)(void *);
	void *context;
};

struct pistachio_evt {
	struct list_head list;
	spinlock_t lock;
	struct device *dev;
	struct device_node *np;
	void __iomem *base;
	struct clk *audio_pll;
	struct clk *clk_sys;
	struct clk *clk_ref_a;
	struct clk *clk_ref_b;
	const char *ref_names[2];
	struct clk *clk_ref_internal;
	struct cyclecounter cc;
	struct timecounter tc;
	struct notifier_block evt_clk_notifier;
	struct hrtimer poll_timer;
	ktime_t quarter_rollover;
	unsigned long sys_rate;
	struct pistachio_evt_callback trigger_cbs[PISTACHIO_EVT_NUM_ENABLES];
	struct pistachio_evt_measurement sample_rates[PISTACHIO_EVT_MAX_SOURCES];
	struct pistachio_evt_measurement phase_difference;
};

/* Call with lock held */
u64 _pistachio_evt_get_time(struct pistachio_evt *evt);
/* Call without lock held */
u64 pistachio_evt_get_time(struct pistachio_evt *evt);
int pistachio_evt_time_to_reg(struct pistachio_evt *evt, u64 time,
				u32 *reg, u64 min_time_delta);
int pistachio_evt_init(struct pistachio_evt *evt);
void pistachio_evt_deinit(struct pistachio_evt *evt);

void pistachio_evt_clk_rate_change(struct pistachio_evt *evt);
#endif
