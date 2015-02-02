/*
 * PCM3060 codec driver header
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * Author: Damien Horsley <Damien.Horsley@imgtec.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#ifndef __PCM3060_H__
#define __PCM3060_H__

extern const struct dev_pm_ops pcm3060_pm_ops;
extern const struct regmap_config pcm3060_regmap;

extern int pcm3060_probe(struct device *dev, struct regmap *regmap);
extern void pcm3060_remove(struct device *dev);

#define PCM3060_RST_PWR_SE			0x40
#define PCM3060_MRST_MASK			0x80
#define PCM3060_SRST_MASK			0x40
#define PCM3060_ADPSV_SHIFT			5
#define PCM3060_ADPSV_MASK			0x20
#define PCM3060_DAPSV_SHIFT			4
#define PCM3060_DAPSV_MASK			0x10
#define PCM3060_SE_SHIFT			0
#define PCM3060_SE_MASK				0x01

#define PCM3060_DAC_VOL_L			0x41

#define PCM3060_DAC_VOL_R			0x42

#define PCM3060_DAC_FMT				0x43
#define PCM3060_DAC_CSEL_MASK			0x80
#define PCM3060_DAC_MS_SHIFT			4
#define PCM3060_DAC_MS_MASK			0x70
#define PCM3060_DAC_FMT_SHIFT			0
#define PCM3060_DAC_FMT_MASK			0x3

#define PCM3060_DAC_OV_PH_MUTE			0x44
#define PCM3060_DAC_OVER_SHIFT			6
#define PCM3060_DAC_OVER_MASK			0x40
#define PCM3060_DAC_DREV_SHIFT			2
#define PCM3060_DAC_DREV_MASK			0x4
#define PCM3060_DAC_MUTE_R_MASK			0x2
#define PCM3060_DAC_MUTE_L_MASK			0x1

#define PCM3060_DAC_FLT_DEMP_Z			0x45
#define PCM3060_DAC_FLT_SHIFT			7
#define PCM3060_DAC_FLT_MASK			0x80
#define PCM3060_DAC_DMF_SHIFT			5
#define PCM3060_DAC_DMF_MASK			0x60
#define PCM3060_DAC_DMC_SHIFT			4
#define PCM3060_DAC_DMC_MASK			0x10
#define PCM3060_DAC_ZREV_SHIFT			1
#define PCM3060_DAC_ZREV_MASK			0x2
#define PCM3060_DAC_AZRO_SHIFT			0
#define PCM3060_DAC_AZRO_MASK			0x1

#define PCM3060_ADC_VOL_L			0x46

#define PCM3060_ADC_VOL_R			0x47

#define PCM3060_ADC_FMT				0x48
#define PCM3060_ADC_CSEL_MASK			0x80
#define PCM3060_ADC_MS_SHIFT			4
#define PCM3060_ADC_MS_MASK			0x70
#define PCM3060_ADC_FMT_SHIFT			0
#define PCM3060_ADC_FMT_MASK			0x3

#define PCM3060_ADC_OPT				0x49
#define PCM3060_ADC_ZCDD_SHIFT			4
#define PCM3060_ADC_ZCDD_MASK			0x10
#define PCM3060_ADC_BYP_SHIFT			3
#define PCM3060_ADC_BYP_MASK			0x8
#define PCM3060_ADC_DREV_SHIFT			2
#define PCM3060_ADC_DREV_MASK			0x4
#define PCM3060_ADC_MUTE_R_SHIFT		1
#define PCM3060_ADC_MUTE_R_MASK			0x2
#define PCM3060_ADC_MUTE_L_SHIFT		0
#define PCM3060_ADC_MUTE_L_MASK			0x1

#endif
