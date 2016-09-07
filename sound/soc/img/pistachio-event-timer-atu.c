/*
 * Pistachio event timer ATU time units
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


u64 _pistachio_evt_get_time(struct pistachio_evt *evt)
{
	return atu_get_current_time();
}
EXPORT_SYMBOL_GPL(_pistachio_evt_get_time);

u64 pistachio_evt_get_time(struct pistachio_evt *evt)
{
	return atu_get_current_time();
}
EXPORT_SYMBOL_GPL(pistachio_evt_get_time);

int pistachio_evt_time_to_reg(struct pistachio_evt *evt, u64 time, u32 *reg,
				u64 min_time_delta)
{
	return atu_to_frc(time, reg, min_time_delta);
}
EXPORT_SYMBOL_GPL(pistachio_evt_time_to_reg);

int pistachio_evt_init(struct pistachio_evt *evt)
{
	return atu_cyclecounter_register(&evt->cc, evt->audio_pll);
}
EXPORT_SYMBOL_GPL(pistachio_evt_init);

void pistachio_evt_deinit(struct pistachio_evt *evt)
{
	atu_cyclecounter_unregister(&evt->cc);
}
EXPORT_SYMBOL_GPL(pistachio_evt_deinit);
