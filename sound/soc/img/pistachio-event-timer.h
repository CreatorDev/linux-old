/*
 * Imagination Technologies Pistachio Event Timer Header
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * Author: Damien Horsley <Damien.Horsley@imgtec.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#ifndef __IMG_PISTACHIO_EVT_H__
#define __IMG_PISTACHIO_EVT_H__

struct pistachio_evt;

enum pistachio_evt_enable {
	PISTACHIO_EVT_ENABLE_PARALLEL_OUT = 0,
	PISTACHIO_EVT_ENABLE_I2S_OUT,
	PISTACHIO_EVT_ENABLE_SPDIF_OUT,
	PISTACHIO_EVT_ENABLE_IRQ_0,
	PISTACHIO_EVT_ENABLE_IRQ_1,
	PISTACHIO_EVT_ENABLE_EXTERNAL,
	PISTACHIO_EVT_NUM_ENABLES
};

enum pistachio_evt_type {
	PISTACHIO_EVT_TYPE_PULSE = 1,
	PISTACHIO_EVT_TYPE_LEVEL
};

enum pistachio_evt_source {
	PISTACHIO_EVT_SOURCE_EXTERNAL = 0,
	PISTACHIO_EVT_SOURCE_SPDIF_IN,
	PISTACHIO_EVT_SOURCE_SPDIF_OUT,
	PISTACHIO_EVT_SOURCE_I2S_IN,
	PISTACHIO_EVT_SOURCE_I2S_OUT,
	PISTACHIO_EVT_SOURCE_PARALLEL_OUT,
	PISTACHIO_EVT_NUM_SOURCES
};

#define	PISTACHIO_EVT_NUM_TIMESTAMP_MODULES	12

#define	PISTACHIO_EVT_MAX_SOURCES		2

extern struct pistachio_evt *pistachio_evt_get(struct device_node *np);

extern void pistachio_evt_get_time_ts(struct pistachio_evt *evt,
				struct timespec *ts);

/* Call this outside of an event callback */
extern void pistachio_evt_disable_event(struct pistachio_evt *evt,
					enum pistachio_evt_enable event);

/* Call this inside of an event callback */
extern void _pistachio_evt_disable_event(struct pistachio_evt *evt,
					enum pistachio_evt_enable event);

extern int pistachio_evt_set_event(struct pistachio_evt *evt,
	enum pistachio_evt_enable event, enum pistachio_evt_type type,
	struct timespec *ts,
	void (*event_trigger_callback)(struct pistachio_evt *, void *),
	void *context);

extern int pistachio_evt_set_source(struct pistachio_evt *evt, int id,
				enum pistachio_evt_source source);

extern int pistachio_evt_get_source(struct pistachio_evt *evt,
			int id, enum pistachio_evt_source *source);

extern int pistachio_evt_get_sample_rate(struct pistachio_evt *evt, int id,
			u32 *val, u32 *sys_freq,
			void (*callback)(void *), void *context);

extern int pistachio_evt_get_phase_difference(struct pistachio_evt *evt,
			u32 *val, u32 *sys_freq,
			void (*callback)(void *), void *context);

extern void pistachio_evt_abort_measurements(struct pistachio_evt *evt);

#endif
