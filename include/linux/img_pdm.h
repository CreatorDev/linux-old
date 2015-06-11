/**
 * Imagination Technologies Pulse Density Modulator driver
 *
 * Copyright (C) 2014-2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __IMG_PDM_H
#define __IMG_PDM_H

struct img_pdm_device;

struct img_pdm_channel {
	unsigned int pdm_id;
	unsigned long flags;
	struct img_pdm_device *pdm_dev;
};

void img_pdm_channel_put(struct device *dev);
struct img_pdm_channel *img_pdm_channel_get(struct device *dev);
int img_pdm_channel_enable(struct img_pdm_channel *chan, bool state);
int img_pdm_channel_config(struct img_pdm_channel *chan, unsigned int val);

#endif /* ifndef _IMG_PDM_H */
