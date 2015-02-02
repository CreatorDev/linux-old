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
	PISTACHIO_EVT_TYPE_NONE = 0,
	PISTACHIO_EVT_TYPE_PULSE,
	PISTACHIO_EVT_TYPE_LEVEL
};

#define	PISTACHIO_EVT_NUM_TIMESTAMP_MODULES	12

extern void pistachio_evt_read(struct platform_device *pdev,
				struct timespec *ts);

extern void pistachio_evt_disable_event(struct platform_device *pdev,
		enum pistachio_evt_enable event);

extern void _pistachio_evt_disable_event(struct platform_device *pdev,
		enum pistachio_evt_enable event);

extern int pistachio_evt_set_event(struct platform_device *pdev,
		enum pistachio_evt_enable event, enum pistachio_evt_type type,
		struct timespec *ts,
		void (*event_trigger_callback)(void *context), void *context);

extern int pistachio_evt_set_timestamp_source(struct platform_device *pdev,
		unsigned int ts_module_index, unsigned int interrupt_source);

extern int pistachio_evt_get_timestamp(struct platform_device *pdev,
		unsigned int ts_module_index, struct timespec *timestamp);

#endif
