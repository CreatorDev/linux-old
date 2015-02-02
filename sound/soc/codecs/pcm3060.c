/*
 * PCM3060 codec driver
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
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>

#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/tlv.h>

#include "pcm3060.h"

#define PCM3060_FORMATS (SNDRV_PCM_FMTBIT_S24_3LE | \
			 SNDRV_PCM_FMTBIT_S24_LE |  \
			 SNDRV_PCM_FMTBIT_S32_LE)

#define PCM3060_FMT_I2S		0x0
#define PCM3060_FMT_LEFT_J	0x1
#define PCM3060_FMT_RIGHT_J	0x2

#define PCM3060_NUM_SUPPLIES 2
static const char *const pcm3060_supply_names[PCM3060_NUM_SUPPLIES] = {
	"VCC",
	"VDD"
};

struct pcm3060_priv {
	struct regulator_bulk_data supplies[PCM3060_NUM_SUPPLIES];
	struct regmap *regmap;
	struct clk *scki_dac;
	struct clk *scki_adc;
	bool adc_slave_mode;
	bool dac_slave_mode;
	unsigned long sysclk_dac;
	unsigned long sysclk_adc;
	unsigned int adc_fmt;
	unsigned int dac_fmt;
};

static const char *const pcm3060_over_mult[] = { "1", "2" };

static SOC_ENUM_SINGLE_DECL(pcm3060_dac_over_mult, PCM3060_DAC_OV_PH_MUTE,
		PCM3060_DAC_OVER_SHIFT, pcm3060_over_mult);

static const char *const pcm3060_roll_off[] = { "Sharp", "Slow" };

static SOC_ENUM_SINGLE_DECL(pcm3060_dac_roll_off, PCM3060_DAC_FLT_DEMP_Z,
		PCM3060_DAC_FLT_SHIFT, pcm3060_roll_off);

static const char *const pcm3060_demp[] = { "44.1khz", "48khz", "32khz" };

static SOC_ENUM_SINGLE_DECL(pcm3060_dac_demp, PCM3060_DAC_FLT_DEMP_Z,
		PCM3060_DAC_DMF_SHIFT, pcm3060_demp);

static const char *const pcm3060_zf_func[] = { "Individual", "Joined" };

static SOC_ENUM_SINGLE_DECL(pcm3060_dac_zf_func, PCM3060_DAC_FLT_DEMP_Z,
		PCM3060_DAC_AZRO_SHIFT, pcm3060_zf_func);

static const char *const pcm3060_pol[] = { "Active High", "Active Low" };

static SOC_ENUM_SINGLE_DECL(pcm3060_dac_zf_pol, PCM3060_DAC_FLT_DEMP_Z,
		PCM3060_DAC_ZREV_SHIFT, pcm3060_pol);

static const char *const pcm3060_con[] = { "Differential", "Single-Ended" };

static SOC_ENUM_SINGLE_DECL(pcm3060_dac_con, PCM3060_RST_PWR_SE,
		PCM3060_SE_SHIFT, pcm3060_con);

/* -100db to 0db, register values 0-54 cause mute */
static const DECLARE_TLV_DB_SCALE(pcm3060_dac_tlv, -10050, 50, 1);

/* -100db to 20db, register values 0-14 cause mute */
static const DECLARE_TLV_DB_SCALE(pcm3060_adc_tlv, -10050, 50, 1);

static const struct snd_kcontrol_new pcm3060_snd_controls[] = {
	SOC_ENUM("DAC Connection Type", pcm3060_dac_con),
	SOC_DOUBLE_R_RANGE_TLV("DAC Playback Volume",
			PCM3060_DAC_VOL_L, PCM3060_DAC_VOL_R,
			0, 54, 255, 0, pcm3060_dac_tlv),
	SOC_ENUM("DAC Oversampling Rate Multiplier", pcm3060_dac_over_mult),
	SOC_SINGLE("DAC Invert Switch", PCM3060_DAC_OV_PH_MUTE,
			PCM3060_DAC_DREV_SHIFT, 1, 0),
	SOC_ENUM("DAC Digital Filter roll-off", pcm3060_dac_roll_off),
	SOC_SINGLE("DAC De-Emphasis Switch", PCM3060_DAC_FLT_DEMP_Z,
			PCM3060_DAC_DMC_SHIFT, 1, 0),
	SOC_ENUM("DAC De-Emphasis Type", pcm3060_dac_demp),
	SOC_ENUM("DAC Zero Flag Polarity", pcm3060_dac_zf_pol),
	SOC_ENUM("DAC Zero Flag Function", pcm3060_dac_zf_func),
	SOC_DOUBLE_R_RANGE_TLV("ADC Capture Volume",
			PCM3060_ADC_VOL_L, PCM3060_ADC_VOL_R,
			0, 14, 255, 0, pcm3060_adc_tlv),
	SOC_SINGLE("ADC Zero-Cross Detection Switch", PCM3060_ADC_OPT,
			PCM3060_ADC_ZCDD_SHIFT, 1, 1),
	SOC_SINGLE("ADC High-Pass Filter Switch", PCM3060_ADC_OPT,
			PCM3060_ADC_BYP_SHIFT, 1, 1),
	SOC_SINGLE("ADC Invert Switch", PCM3060_ADC_OPT,
			PCM3060_ADC_DREV_SHIFT, 1, 0),
	SOC_DOUBLE("ADC Mute Switch", PCM3060_ADC_OPT,
			PCM3060_ADC_MUTE_L_SHIFT, PCM3060_ADC_MUTE_R_SHIFT,
			1, 0),
};

static const struct snd_soc_dapm_widget pcm3060_dapm_widgets[] = {
	SND_SOC_DAPM_DAC("DAC", "Playback", PCM3060_RST_PWR_SE,
			PCM3060_DAPSV_SHIFT, 1),

	SND_SOC_DAPM_OUTPUT("AOUTL"),
	SND_SOC_DAPM_OUTPUT("AOUTR"),

	SND_SOC_DAPM_ADC("ADC", "Capture", PCM3060_RST_PWR_SE,
			PCM3060_ADPSV_SHIFT, 1),

	SND_SOC_DAPM_INPUT("AINL"),
	SND_SOC_DAPM_INPUT("AINR"),
};

static const struct snd_soc_dapm_route pcm3060_dapm_routes[] = {
	/* Playback */
	{ "AOUTL", NULL, "DAC" },
	{ "AOUTR", NULL, "DAC" },

	/* Capture */
	{ "ADC", NULL, "AINL" },
	{ "ADC", NULL, "AINR" },
};

static unsigned int pcm3060_scki_ratios[] = {
	768,
	512,
	384,
	256,
	192,
	128
};

#define PCM3060_NUM_SCKI_RATIOS_DAC	ARRAY_SIZE(pcm3060_scki_ratios)
#define PCM3060_NUM_SCKI_RATIOS_ADC	(ARRAY_SIZE(pcm3060_scki_ratios) - 2)

#define PCM1368A_MAX_SYSCLK	36864000

static int pcm3060_reset(struct pcm3060_priv *pcm3060)
{
	int ret;
	u32 mask = PCM3060_MRST_MASK | PCM3060_SRST_MASK;
	unsigned long sysclk = min(pcm3060->sysclk_dac, pcm3060->sysclk_adc);

	ret = regmap_update_bits(pcm3060->regmap, PCM3060_RST_PWR_SE, mask, 0);
	if (ret)
		return ret;

	/* Internal reset is de-asserted after 1024 cycles of both SCKIs */
	msleep(DIV_ROUND_UP(1024 * 1000, sysclk));

	return regmap_update_bits(pcm3060->regmap, PCM3060_RST_PWR_SE,
				mask, mask);
}

static int pcm3060_digital_mute(struct snd_soc_dai *dai, int mute)
{
	struct pcm3060_priv *pcm3060 = snd_soc_codec_get_drvdata(dai->codec);
	u32 mask = PCM3060_DAC_MUTE_R_MASK | PCM3060_DAC_MUTE_L_MASK;

	regmap_update_bits(pcm3060->regmap, PCM3060_DAC_OV_PH_MUTE,
			mask, mute ? mask : 0);

	return 0;
}

static int pcm3060_set_dai_sysclk_dac(struct snd_soc_dai *dai,
				  int clk_id, unsigned int freq, int dir)
{
	struct pcm3060_priv *pcm3060 = snd_soc_codec_get_drvdata(dai->codec);

	if (freq > PCM1368A_MAX_SYSCLK)
		return -EINVAL;

	pcm3060->sysclk_dac = freq;

	return 0;
}

static int pcm3060_set_dai_sysclk_adc(struct snd_soc_dai *dai,
				  int clk_id, unsigned int freq, int dir)
{
	struct pcm3060_priv *pcm3060 = snd_soc_codec_get_drvdata(dai->codec);

	if (freq > PCM1368A_MAX_SYSCLK)
		return -EINVAL;

	pcm3060->sysclk_adc = freq;

	return 0;
}

static int pcm3060_set_dai_fmt(struct snd_soc_dai *dai,
			       unsigned int format, bool dac)
{
	struct snd_soc_codec *codec = dai->codec;
	struct pcm3060_priv *pcm3060 = snd_soc_codec_get_drvdata(codec);
	u32 fmt, reg, mask, shift;
	bool slave_mode;

	switch (format & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_LEFT_J:
		fmt = PCM3060_FMT_LEFT_J;
		break;
	case SND_SOC_DAIFMT_I2S:
		fmt = PCM3060_FMT_I2S;
		break;
	case SND_SOC_DAIFMT_RIGHT_J:
		fmt = PCM3060_FMT_RIGHT_J;
		break;
	default:
		dev_err(codec->dev, "unsupported dai format\n");
		return -EINVAL;
	}

	switch (format & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBS_CFS:
		slave_mode = true;
		break;
	case SND_SOC_DAIFMT_CBM_CFM:
		slave_mode = false;
		break;
	default:
		dev_err(codec->dev, "unsupported master/slave mode\n");
		return -EINVAL;
	}

	switch (format & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:
		break;
	default:
		dev_err(codec->dev, "LRCLK/BCLK inversion not supported\n");
		return -EINVAL;
	}

	if (dac) {
		reg = PCM3060_DAC_FMT;
		mask = PCM3060_DAC_FMT_MASK;
		shift = PCM3060_DAC_FMT_SHIFT;
		pcm3060->dac_slave_mode = slave_mode;
		pcm3060->dac_fmt = fmt;
	} else {
		reg = PCM3060_ADC_FMT;
		mask = PCM3060_ADC_FMT_MASK;
		shift = PCM3060_ADC_FMT_SHIFT;
		pcm3060->adc_slave_mode = slave_mode;
		pcm3060->adc_fmt = fmt;
	}

	regmap_update_bits(pcm3060->regmap, reg, mask, fmt << shift);

	return 0;
}

static int pcm3060_set_dai_fmt_dac(struct snd_soc_dai *dai,
			       unsigned int format)
{
	return pcm3060_set_dai_fmt(dai, format, true);
}

static int pcm3060_set_dai_fmt_adc(struct snd_soc_dai *dai,
			       unsigned int format)
{
	return pcm3060_set_dai_fmt(dai, format, false);
}

static int pcm3060_hw_params(struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *params,
			     struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct pcm3060_priv *pcm3060 = snd_soc_codec_get_drvdata(codec);
	u32 val, mask, shift, reg;
	bool slave_mode, tx;
	unsigned int fmt, rate, channels, max_ratio, ratio;
	int i;
	snd_pcm_format_t format;

	rate = params_rate(params);
	format = params_format(params);
	channels = params_channels(params);

	tx = substream->stream == SNDRV_PCM_STREAM_PLAYBACK;
	if (tx) {
		max_ratio = PCM3060_NUM_SCKI_RATIOS_DAC;
		reg = PCM3060_DAC_FMT;
		mask = PCM3060_DAC_MS_MASK;
		shift = PCM3060_DAC_MS_SHIFT;
		ratio = pcm3060->sysclk_dac / rate;
		slave_mode = pcm3060->dac_slave_mode;
		fmt = pcm3060->dac_fmt;
	} else {
		max_ratio = PCM3060_NUM_SCKI_RATIOS_ADC;
		reg = PCM3060_ADC_FMT;
		mask = PCM3060_ADC_MS_MASK;
		shift = PCM3060_ADC_MS_SHIFT;
		ratio = pcm3060->sysclk_adc / rate;
		slave_mode = pcm3060->adc_slave_mode;
		fmt = pcm3060->adc_fmt;
	}

	for (i = 0; i < max_ratio; i++) {
		if (pcm3060_scki_ratios[i] == ratio)
			break;
	}

	if (i == max_ratio) {
		dev_err(codec->dev, "unsupported sysclk ratio\n");
		return -EINVAL;
	}

	if (!slave_mode && (format == SNDRV_PCM_FORMAT_S24_3LE)) {
		dev_err(codec->dev,
			"48-bit frames not supported in master mode\n");
		return -EINVAL;
	}

	val = slave_mode ? 0 : ((i + 1) << shift);

	regmap_update_bits(pcm3060->regmap, reg, mask, val);

	if (tx) {
		mask = PCM3060_DAC_FMT_MASK;
		shift = PCM3060_DAC_FMT_SHIFT;
	} else {
		mask = PCM3060_ADC_FMT_MASK;
		shift = PCM3060_ADC_FMT_SHIFT;
	}

	if ((fmt == PCM3060_FMT_RIGHT_J) && (format == SNDRV_PCM_FORMAT_S32)) {
		/*
		 * Justification has no effect here as the whole frame
		 * is filled with the samples, but the register field
		 * must be set to left justified for correct operation
		 */
		fmt = PCM3060_FMT_LEFT_J;
	}

	regmap_update_bits(pcm3060->regmap, reg, mask, fmt << shift);

	return 0;
}

static const struct snd_soc_dai_ops pcm3060_dac_dai_ops = {
	.set_fmt	= pcm3060_set_dai_fmt_dac,
	.set_sysclk	= pcm3060_set_dai_sysclk_dac,
	.hw_params	= pcm3060_hw_params,
	.digital_mute	= pcm3060_digital_mute,
};

static const struct snd_soc_dai_ops pcm3060_adc_dai_ops = {
	.set_fmt	= pcm3060_set_dai_fmt_adc,
	.set_sysclk	= pcm3060_set_dai_sysclk_adc,
	.hw_params	= pcm3060_hw_params,
};

static struct snd_soc_dai_driver pcm3060_dais[] = {
	{
		.name = "pcm3060-dac",
		.playback = {
			.stream_name = "Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = PCM3060_FORMATS,
		},
		.ops = &pcm3060_dac_dai_ops,
	},
	{
		.name = "pcm3060-adc",
		.capture = {
			.stream_name = "Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_96000,
			.formats = PCM3060_FORMATS,
		},
		.ops = &pcm3060_adc_dai_ops,
	},
};

static const struct reg_default pcm3060_reg_default[] = {
	{ PCM3060_RST_PWR_SE, PCM3060_MRST_MASK | PCM3060_SRST_MASK |
			PCM3060_ADPSV_MASK | PCM3060_DAPSV_MASK },
	{ PCM3060_DAC_VOL_L, 0xff },
	{ PCM3060_DAC_VOL_R, 0xff },
	{ PCM3060_DAC_FMT, 0x00 },
	{ PCM3060_DAC_OV_PH_MUTE, 0x00 },
	{ PCM3060_DAC_FLT_DEMP_Z, 0x00 },
	{ PCM3060_ADC_VOL_L, 0xd7 },
	{ PCM3060_ADC_VOL_R, 0xd7 },
	{ PCM3060_ADC_FMT, 0x00 },
	{ PCM3060_ADC_OPT, 0x00 },
};

static bool pcm3060_volatile_register(struct device *dev, unsigned int reg)
{
	return false;
}

static bool pcm3060_readable_register(struct device *dev, unsigned int reg)
{
	if (reg >= PCM3060_RST_PWR_SE)
		return true;
	else
		return false;
}

static bool pcm3060_writeable_register(struct device *dev, unsigned int reg)
{
	if (reg >= PCM3060_RST_PWR_SE)
		return true;
	else
		return false;
}

const struct regmap_config pcm3060_regmap = {
	.reg_bits = 8,
	.val_bits = 8,

	.max_register = PCM3060_ADC_OPT,
	.reg_defaults = pcm3060_reg_default,
	.num_reg_defaults = ARRAY_SIZE(pcm3060_reg_default),
	.readable_reg = pcm3060_readable_register,
	.volatile_reg = pcm3060_volatile_register,
	.writeable_reg = pcm3060_writeable_register,
	.cache_type = REGCACHE_FLAT,
};
EXPORT_SYMBOL_GPL(pcm3060_regmap);

static const struct snd_soc_codec_driver pcm3060_driver = {
	.controls = pcm3060_snd_controls,
	.num_controls = ARRAY_SIZE(pcm3060_snd_controls),
	.dapm_widgets = pcm3060_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(pcm3060_dapm_widgets),
	.dapm_routes = pcm3060_dapm_routes,
	.num_dapm_routes = ARRAY_SIZE(pcm3060_dapm_routes),
};

int pcm3060_probe(struct device *dev, struct regmap *regmap)
{
	struct pcm3060_priv *pcm3060;
	int ret, i;

	pcm3060 = devm_kzalloc(dev, sizeof(*pcm3060), GFP_KERNEL);
	if (pcm3060 == NULL)
		return -ENOMEM;

	dev_set_drvdata(dev, pcm3060);

	pcm3060->scki_dac = devm_clk_get(dev, "sckid");
	if (IS_ERR(pcm3060->scki_dac)) {
		dev_err(dev, "failed to get the clock (dac): %ld\n",
				PTR_ERR(pcm3060->scki_dac));
		return PTR_ERR(pcm3060->scki_dac);
	}

	ret = clk_prepare_enable(pcm3060->scki_dac);
	if (ret) {
		dev_err(dev, "failed to enable mclk (dac): %d\n", ret);
		return ret;
	}

	pcm3060->sysclk_dac = clk_get_rate(pcm3060->scki_dac);

	pcm3060->scki_adc = devm_clk_get(dev, "sckia");
	if (IS_ERR(pcm3060->scki_adc)) {
		dev_err(dev, "failed to get the clock (adc): %ld\n",
				PTR_ERR(pcm3060->scki_adc));
		ret = PTR_ERR(pcm3060->scki_adc);
		goto err_clk;
	}

	ret = clk_prepare_enable(pcm3060->scki_adc);
	if (ret) {
		dev_err(dev, "failed to enable mclk (adc): %d\n", ret);
		goto err_clk;
	}

	pcm3060->sysclk_adc = clk_get_rate(pcm3060->scki_adc);

	for (i = 0; i < ARRAY_SIZE(pcm3060->supplies); i++)
		pcm3060->supplies[i].supply = pcm3060_supply_names[i];

	ret = devm_regulator_bulk_get(dev,
			ARRAY_SIZE(pcm3060->supplies), pcm3060->supplies);
	if (ret) {
		dev_err(dev, "failed to request supplies: %d\n", ret);
		goto err_clks;
	}

	ret = regulator_bulk_enable(ARRAY_SIZE(pcm3060->supplies),
				    pcm3060->supplies);
	if (ret) {
		dev_err(dev, "failed to enable supplies: %d\n", ret);
		goto err_clks;
	}

	pcm3060->regmap = regmap;
	if (IS_ERR(pcm3060->regmap)) {
		ret = PTR_ERR(pcm3060->regmap);
		dev_err(dev, "failed to allocate regmap: %d\n", ret);
		goto err_regulator;
	}

	ret = pcm3060_reset(pcm3060);
	if (ret) {
		dev_err(dev, "Failed to reset device: %d\n", ret);
		goto err_regulator;
	}

	ret = snd_soc_register_codec(dev, &pcm3060_driver, pcm3060_dais,
			ARRAY_SIZE(pcm3060_dais));
	if (ret) {
		dev_err(dev, "failed to register codec:%d\n", ret);
		goto err_regulator;
	}

	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);
	pm_runtime_idle(dev);

	return 0;

err_regulator:
	regulator_bulk_disable(ARRAY_SIZE(pcm3060->supplies),
			pcm3060->supplies);
err_clks:
	clk_disable_unprepare(pcm3060->scki_adc);
err_clk:
	clk_disable_unprepare(pcm3060->scki_dac);

	return ret;
}
EXPORT_SYMBOL_GPL(pcm3060_probe);

void pcm3060_remove(struct device *dev)
{
	snd_soc_unregister_codec(dev);
	pm_runtime_disable(dev);
}
EXPORT_SYMBOL_GPL(pcm3060_remove);

#ifdef CONFIG_PM
static int pcm3060_rt_resume(struct device *dev)
{
	struct pcm3060_priv *pcm3060 = dev_get_drvdata(dev);
	int ret;

	ret = clk_prepare_enable(pcm3060->scki_dac);
	if (ret) {
		dev_err(dev, "failed to enable mclk (dac): %d\n", ret);
		return ret;
	}

	ret = clk_prepare_enable(pcm3060->scki_adc);
	if (ret) {
		dev_err(dev, "failed to enable mclk (adc): %d\n", ret);
		goto err_clk;
	}

	ret = regulator_bulk_enable(ARRAY_SIZE(pcm3060->supplies),
				    pcm3060->supplies);
	if (ret) {
		dev_err(dev, "failed to enable supplies: %d\n", ret);
		goto err_clks;
	}

	ret = pcm3060_reset(pcm3060);
	if (ret) {
		dev_err(dev, "Failed to reset device: %d\n", ret);
		goto err_regulator;
	}

	regcache_cache_only(pcm3060->regmap, false);

	regcache_mark_dirty(pcm3060->regmap);

	ret = regcache_sync(pcm3060->regmap);
	if (ret) {
		dev_err(dev, "failed to sync regmap: %d\n", ret);
		goto err_regulator;
	}

	return 0;

err_regulator:
	regulator_bulk_disable(ARRAY_SIZE(pcm3060->supplies),
			       pcm3060->supplies);
err_clks:
	clk_disable_unprepare(pcm3060->scki_adc);
err_clk:
	clk_disable_unprepare(pcm3060->scki_dac);

	return ret;
}

static int pcm3060_rt_suspend(struct device *dev)
{
	struct pcm3060_priv *pcm3060 = dev_get_drvdata(dev);

	regcache_cache_only(pcm3060->regmap, true);

	regulator_bulk_disable(ARRAY_SIZE(pcm3060->supplies),
			       pcm3060->supplies);

	clk_disable_unprepare(pcm3060->scki_adc);
	clk_disable_unprepare(pcm3060->scki_dac);

	return 0;
}
#endif

const struct dev_pm_ops pcm3060_pm_ops = {
	SET_RUNTIME_PM_OPS(pcm3060_rt_suspend, pcm3060_rt_resume, NULL)
};
EXPORT_SYMBOL_GPL(pcm3060_pm_ops);

MODULE_DESCRIPTION("PCM3060 codec driver");
MODULE_AUTHOR("Damien Horsley <Damien.Horsley@imgtec.com>");
MODULE_LICENSE("GPL v2");
