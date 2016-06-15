/*
 * Pistachio Bring-Up Board audio card driver
 *
 * Copyright (C) 2014 Imagination Technologies Ltd.
 *
 * Author: Damien Horsley <Damien.Horsley@imgtec.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

//#define	DEBUG
//#define	VERBOSE_DEBUG

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>

#include <linux/mfd/syscon.h>
#include <linux/regmap.h>

#include <sound/jack.h>
#include <sound/soc.h>

#include "../codecs/tpa6130a2.h"

#include <dt-bindings/sound/pistachio-bub-audio.h>

#include "pistachio-event-timer.h"

extern void snd_pcm_startat_register(struct snd_pcm_substream *substream,
	int clock_class, int clock_type, const struct timespec *start_time,
	void *data);
void snd_pcm_startat_unregister(struct snd_pcm_substream *substream);

#define PISTACHIO_LINK_SPDIF_OUT	0
#define PISTACHIO_LINK_SPDIF_IN		1
#define PISTACHIO_LINK_PRL_OUT		2
#define PISTACHIO_LINK_I2S_OUT		3
#define PISTACHIO_LINK_I2S_IN		4

#define PISTACHIO_CODEC_TPA6130A2	0
#define PISTACHIO_CODEC_PCM3060_DAC	1
#define PISTACHIO_CODEC_PCM3060_ADC	2
#define PISTACHIO_CODEC_PCM3168A_1_DAC	3
#define PISTACHIO_CODEC_PCM3168A_1_ADC	4
#define PISTACHIO_CODEC_PCM3168A_2_DAC	5
#define PISTACHIO_CODEC_PCM3168A_2_ADC	6
#define PISTACHIO_CPU_I2S_OUT		7
#define PISTACHIO_FRAME_EXTERNAL	8

#define PISTACHIO_MAX_LINKS		5

#define PISTACHIO_MAX_CODECS		7
#define PISTACHIO_MAX_CODEC_DT_NODES	4

static const unsigned int pistachio_clk_ratios[] = {
	768,
	512,
	384,
	256,
	192,
	128
};

#define PCM1368A_PCM3060_MAX_MCLK			36864000
#define PCM3168A_PCM3060_NUM_MCLK_RATIOS_DAC		6
#define PCM3168A_PCM3060_NUM_MCLK_RATIOS_ADC		4
#define PISTACHIO_I2S_MCLK_RATIO_START			2
#define PISTACHIO_I2S_MCLK_NUM_RATIOS			2

struct pistachio_codec {
	unsigned int fmt;
	struct snd_soc_dai *dai;
	struct device_node *np;
};

struct pistachio_card_data {
	struct snd_soc_card card;
	struct snd_soc_dai_link dai_links_st[PISTACHIO_MAX_LINKS];
	struct snd_soc_dai_link *dai_links[PISTACHIO_MAX_LINKS];
	struct snd_soc_dai_link_component codec_st[PISTACHIO_MAX_CODECS];
	struct snd_soc_codec_conf codec_conf[PISTACHIO_MAX_CODEC_DT_NODES];
	struct pistachio_codec codecs[PISTACHIO_MAX_CODECS];
	unsigned int i2s_out_cpu_fmt;
	unsigned int i2s_in_cpu_fmt;
	struct snd_soc_jack hp_jack;
	struct snd_soc_jack_pin hp_jack_pin;
	struct snd_soc_jack_gpio hp_jack_gpio;
	unsigned int i2s_out_master;
	unsigned int i2s_in_master;
	spinlock_t spdif_out_lock;
	unsigned int spdif_out_active_rate;
	struct snd_pcm_substream *spdif_out_start_at_substream;
	spinlock_t parallel_out_lock;
	unsigned int parallel_out_active_rate;
	struct snd_pcm_substream *parallel_out_start_at_substream;
	spinlock_t i2s_out_lock;
	unsigned int i2s_out_active_rate;
	struct snd_pcm_substream *i2s_out_start_at_substream;
	unsigned int i2s_in_active_rate;
	struct clk *audio_pll;
	unsigned long audio_pll_rate;
	struct clk *i2s_mclk;
	unsigned long i2s_mclk_rate;
	u32 db;
	u32 mclk_source;
	struct clk *dac_clk;
	unsigned long dac_clk_rate;
	struct clk *evt_clk;
	unsigned long evt_clk_rate;
	u32 mclk_max;
	struct regmap *periph_regs;
	struct regmap *top_regs;
	struct notifier_block i2s_clk_notifier;
	struct platform_device *event_timer;

};

int pistachio_card_get_best_clk_rate(struct pistachio_card_data *pbc,
		long rate, bool is_mclk, unsigned int ratios_start,
		unsigned int num_ratios, long cur_rate,
		unsigned long *new_clk_rate)
{
	int i;
	long pre_div_rate, temp, diff, best_diff = LONG_MAX;
	unsigned long best_pre_div_rate, clk_max;
	bool change = false;
	struct device *dev = pbc->card.dev;

	clk_max = (is_mclk) ? pbc->mclk_max : ULONG_MAX;

	dev_dbg(dev, "pistachio_card_get_best_clk_rate()\n");
	dev_dbg(dev, "clk_ratios_start %u num_clk_ratios %u\n",
		ratios_start, num_ratios);

	for (i = ratios_start; i < (ratios_start + num_ratios); i++) {
		temp = cur_rate / pistachio_clk_ratios[i];
		diff = abs(temp - rate);
		if (!diff)
			break;
		if (diff < best_diff)
			best_diff = diff;
	}

	if (i != (ratios_start + num_ratios)) {
		dev_dbg(dev, "current clk rate is optimal (zero diff)\n");
		return 0;
	}

	dev_dbg(dev, "current clk rate may not be optimal, checking...\n");

	for (i = ratios_start; i < (ratios_start + num_ratios); i++) {
		pre_div_rate = rate * pistachio_clk_ratios[i];
		temp = (pbc->audio_pll_rate + (pre_div_rate / 2)) / pre_div_rate;
		if(temp > 256)
			temp = 256;
		pre_div_rate = (pbc->audio_pll_rate + (temp / 2)) / temp;

		diff = abs((pre_div_rate / pistachio_clk_ratios[i]) - rate);
		if ((diff < best_diff) && (pre_div_rate <= clk_max)) {
			best_diff = diff;
			best_pre_div_rate = pre_div_rate;
			change = true;
		}
	}

	if (!change) {
		dev_dbg(dev, "current clk rate is optimal (diff %ld)\n",
			best_diff);
		return 0;
	}

	dev_dbg(dev, "New clk rate %lu (diff %ld)\n",
		best_pre_div_rate, best_diff);

	*new_clk_rate = best_pre_div_rate;

	return 1;
}

int pistachio_card_update_codec_sysclks(struct pistachio_card_data *pbc,
				unsigned long new_rate)
{
	struct pistachio_codec *codec;
	int ret;

	codec = &pbc->codecs[PISTACHIO_CODEC_PCM3060_DAC];
	if (codec->dai) {
		ret = snd_soc_dai_set_sysclk(codec->dai, 0, new_rate, 0);
		if (ret)
			return ret;
	}

	codec = &pbc->codecs[PISTACHIO_CODEC_PCM3060_ADC];
	if (codec->dai) {
		ret = snd_soc_dai_set_sysclk(codec->dai, 0, new_rate, 0);
		if (ret)
			return ret;
	}

	codec = &pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_DAC];
	if (!codec->dai)
		codec = &pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_ADC];
	if (codec->dai) {
		ret = snd_soc_dai_set_sysclk(codec->dai, 0, new_rate, 0);
		if (ret)
			return ret;
	}

	codec = &pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_DAC];
	if (!codec->dai)
		codec = &pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_ADC];
	if (codec->dai) {
		ret = snd_soc_dai_set_sysclk(codec->dai, 0, new_rate, 0);
		if (ret)
			return ret;
	}

	return 0;
}

int pistachio_card_set_dac_clk(struct pistachio_card_data *pbc,
				long rate, bool dac)
{
	int num_ratios, ret;
	unsigned long new_rate;

	num_ratios = (dac) ? (PCM3168A_PCM3060_NUM_MCLK_RATIOS_DAC) :
			(PCM3168A_PCM3060_NUM_MCLK_RATIOS_ADC);

	ret = pistachio_card_get_best_clk_rate(pbc, rate, true, 0, num_ratios,
			pbc->dac_clk_rate, &new_rate);
	if (ret <= 0)
		return ret;

	if (dac && pbc->i2s_in_active_rate) {
		dev_dbg(pbc->card.dev,
			"Cannot change dclk rate, i2s in active\n");
		return -EINVAL;
	} else if (!dac && pbc->i2s_out_active_rate) {
		dev_dbg(pbc->card.dev,
			"Cannot change dclk rate, i2s out active\n");
		return -EINVAL;
	}

	ret = clk_set_rate(pbc->dac_clk, new_rate);
	if (ret)
		return ret;

	pbc->dac_clk_rate = new_rate;

	return pistachio_card_update_codec_sysclks(pbc, new_rate);
}

#define CR_AUDIO_DAC_CTRL		0x40
#define CR_AUDIO_DAC_CTRL_MUTE_MASK	0x4
#define CR_AUDIO_DAC_CTRL_PWR_SEL_MASK	0x2
#define CR_AUDIO_DAC_CTRL_PWR_MASK	0x1

#define CR_AUDIO_DAC_RESET		0x44
#define CR_AUDIO_DAC_RESET_SR_MASK	0x1

#define CR_AUDIO_DAC_GTI_CTRL			0x48
#define CR_AUDIO_DAC_GTI_CTRL_ADDR_SHIFT	0
#define CR_AUDIO_DAC_GTI_CTRL_ADDR_MASK		0xFFF
#define CR_AUDIO_DAC_GTI_CTRL_WE_MASK		0x1000
#define CR_AUDIO_DAC_GTI_CTRL_WDATA_SHIFT	13
#define CR_AUDIO_DAC_GTI_CTRL_WDATA_MASK	0x1FE000

#define CR_AUDIO_DAC_GTI_OUT			0x4C
#define CR_AUDIO_DAC_GTI_OUT_RDATA_SHIFT	0
#define CR_AUDIO_DAC_GTI_OUT_RDATA_MASK		0xFF

static int pistachio_card_prl_out_link_init(struct snd_soc_pcm_runtime *rtd)
{
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	int ret;
	struct pistachio_codec *pc;

	pc = &pbc->codecs[PISTACHIO_CODEC_TPA6130A2];

	if (pc->np && (pc->np == rtd->codec_dais[0]->dev->of_node)) {
		pc->dai = rtd->codec_dais[0];

		ret = tpa6130a2_stereo_enable(pc->dai->codec, 1);
	}

	regmap_update_bits(pbc->top_regs, CR_AUDIO_DAC_CTRL,
			CR_AUDIO_DAC_CTRL_PWR_MASK, 1);

	msleep(10);

	regmap_update_bits(pbc->top_regs, CR_AUDIO_DAC_GTI_CTRL,
			CR_AUDIO_DAC_GTI_CTRL_ADDR_MASK,
			1 << CR_AUDIO_DAC_GTI_CTRL_ADDR_SHIFT);

	regmap_update_bits(pbc->top_regs, CR_AUDIO_DAC_GTI_CTRL,
			CR_AUDIO_DAC_GTI_CTRL_WDATA_MASK,
			1 << CR_AUDIO_DAC_GTI_CTRL_WDATA_SHIFT);

	regmap_update_bits(pbc->top_regs, CR_AUDIO_DAC_GTI_CTRL,
			CR_AUDIO_DAC_GTI_CTRL_WE_MASK,
			CR_AUDIO_DAC_GTI_CTRL_WE_MASK);

	regmap_update_bits(pbc->top_regs, CR_AUDIO_DAC_GTI_CTRL,
			CR_AUDIO_DAC_GTI_CTRL_WE_MASK, 0);

	regmap_update_bits(pbc->top_regs, CR_AUDIO_DAC_CTRL,
			CR_AUDIO_DAC_CTRL_PWR_MASK, 0);

	return ret;
}

static int pistachio_card_parallel_out_startup(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned long flags;

	spin_lock_irqsave(&pbc->parallel_out_lock, flags);
	pbc->parallel_out_active_rate = 0;
	spin_unlock_irqrestore(&pbc->parallel_out_lock, flags);

	return 0;
}

static void pistachio_card_parallel_out_shutdown(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned long flags;

	spin_lock_irqsave(&pbc->parallel_out_lock, flags);
	pbc->parallel_out_active_rate = 0;
	spin_unlock_irqrestore(&pbc->parallel_out_lock, flags);
}

static int pistachio_card_parallel_out_hw_params(struct snd_pcm_substream *st,
				struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);

	pbc->parallel_out_active_rate = params_rate(params);

	return 0;
}

static void pistachio_card_parallel_out_start_cb(void *context)
{
	struct pistachio_card_data *pbc;
	unsigned long flags;
	struct snd_pcm_substream *st;
	//int ret;

	pbc = (struct pistachio_card_data *)context;

	spin_lock_irqsave(&pbc->parallel_out_lock, flags);

	st = pbc->parallel_out_start_at_substream;

	if (!st) {
		spin_unlock_irqrestore(&pbc->parallel_out_lock, flags);
		return;
	}

	snd_pcm_stream_lock(st);

	snd_pcm_startat_unregister(st);

	if(!snd_pcm_do_start(st, SNDRV_PCM_STATE_RUNNING))
		snd_pcm_post_start(st, SNDRV_PCM_STATE_RUNNING);

	snd_pcm_stream_unlock(st);

	_pistachio_evt_disable_event(pbc->event_timer,
			PISTACHIO_EVT_ENABLE_PARALLEL_OUT);

	pbc->parallel_out_start_at_substream = NULL;

	spin_unlock_irqrestore(&pbc->parallel_out_lock, flags);
}

static int pistachio_card_parallel_out_start_at(struct snd_pcm_substream *st,
		int clock_type, const struct timespec *ts)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	int ret;
	unsigned long flags;

	ret = snd_pcm_pre_start(st, SNDRV_PCM_STATE_PREPARED);
	if (ret)
		return ret;

	spin_lock_irqsave(&pbc->parallel_out_lock, flags);

	ret = pistachio_evt_set_event(pbc->event_timer,
		PISTACHIO_EVT_ENABLE_PARALLEL_OUT,
		PISTACHIO_EVT_TYPE_LEVEL, (struct timespec *)ts,
		pistachio_card_parallel_out_start_cb, pbc);
	if (ret) {
		spin_unlock_irqrestore(&pbc->parallel_out_lock, flags);
		return ret;
	}

	snd_pcm_startat_register(st, SNDRV_PCM_CLOCK_CLASS_AUDIO,
		clock_type, ts, NULL);

	pbc->parallel_out_start_at_substream = st;

	spin_unlock_irqrestore(&pbc->parallel_out_lock, flags);

	return 0;
}

static int pistachio_card_parallel_out_start_at_abort(
		struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned long flags;

	spin_lock_irqsave(&pbc->parallel_out_lock, flags);

	if (!pbc->parallel_out_start_at_substream) {
		/* Already started */
		spin_unlock_irqrestore(&pbc->parallel_out_lock, flags);
		return -EINVAL;
	}

	snd_pcm_startat_unregister(st);

	pbc->parallel_out_start_at_substream = NULL;

	spin_unlock_irqrestore(&pbc->parallel_out_lock, flags);

	pistachio_evt_disable_event(pbc->event_timer,
		PISTACHIO_EVT_ENABLE_PARALLEL_OUT);

	return 0;
}

static struct snd_soc_ops pistachio_card_parallel_out_ops = {
	.startup = pistachio_card_parallel_out_startup,
	.shutdown = pistachio_card_parallel_out_shutdown,
	.hw_params = pistachio_card_parallel_out_hw_params,
	.start_at = pistachio_card_parallel_out_start_at,
	.start_at_abort = pistachio_card_parallel_out_start_at_abort
};

static int pistachio_card_parse_of_parallel_out(struct device_node *node,
		struct pistachio_card_data *pbc, struct snd_soc_dai_link *link,
		struct snd_soc_dai_link_component *components)
{
	struct device_node *np;

	link->name = link->stream_name = "pistachio-parallel-out";
	np = of_parse_phandle(node, "cpu-dai", 0);
	if (!np)
		return -EINVAL;
	link->cpu_of_node = np;
	link->platform_of_node = np;
	np = of_parse_phandle(node, "tpa6130a2", 0);
	if (np) {
		link->codecs = components;
		link->codecs[0].of_node = np;
		link->codecs[0].dai_name = "tpa6130a2";
		pbc->codecs[PISTACHIO_CODEC_TPA6130A2].np = np;
		link->num_codecs = 1;

	} else {
		link->codec_dai_name = "snd-soc-dummy-dai";
		link->codec_name = "snd-soc-dummy";
	}
	link->init = pistachio_card_prl_out_link_init;
	link->ops = &pistachio_card_parallel_out_ops;

	return link->num_codecs;
}

static int pistachio_card_spdif_out_startup(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned long flags;

	spin_lock_irqsave(&pbc->spdif_out_lock, flags);
	pbc->spdif_out_active_rate = 0;
	spin_unlock_irqrestore(&pbc->spdif_out_lock, flags);

	return 0;
}

static void pistachio_card_spdif_out_shutdown(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned long flags;

	spin_lock_irqsave(&pbc->spdif_out_lock, flags);
	pbc->spdif_out_active_rate = 0;
	spin_unlock_irqrestore(&pbc->spdif_out_lock, flags);
}

static int pistachio_card_spdif_out_hw_params(struct snd_pcm_substream *st,
				struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);

	pbc->spdif_out_active_rate = params_rate(params);

	return 0;
}

static void pistachio_card_spdif_out_start_cb(void *context)
{
	struct pistachio_card_data *pbc;
	unsigned long flags;
	struct snd_pcm_substream *st;
	//int ret;

	pbc = (struct pistachio_card_data *)context;

	spin_lock_irqsave(&pbc->spdif_out_lock, flags);

	st = pbc->spdif_out_start_at_substream;

	if (!st) {
		spin_unlock_irqrestore(&pbc->spdif_out_lock, flags);
		return;
	}

	snd_pcm_stream_lock(st);

	snd_pcm_startat_unregister(st);

	if(!snd_pcm_do_start(st, SNDRV_PCM_STATE_RUNNING))
		snd_pcm_post_start(st, SNDRV_PCM_STATE_RUNNING);

	snd_pcm_stream_unlock(st);

	_pistachio_evt_disable_event(pbc->event_timer,
			PISTACHIO_EVT_ENABLE_SPDIF_OUT);

	pbc->spdif_out_start_at_substream = NULL;

	spin_unlock_irqrestore(&pbc->spdif_out_lock, flags);
}

static int pistachio_card_spdif_out_start_at(struct snd_pcm_substream *st,
		int clock_type, const struct timespec *ts)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	int ret;
	unsigned long flags;

	ret = snd_pcm_pre_start(st, SNDRV_PCM_STATE_PREPARED);
	if (ret)
		return ret;

	spin_lock_irqsave(&pbc->spdif_out_lock, flags);

	ret = pistachio_evt_set_event(pbc->event_timer,
		PISTACHIO_EVT_ENABLE_SPDIF_OUT,
		PISTACHIO_EVT_TYPE_LEVEL, (struct timespec *)ts,
		pistachio_card_spdif_out_start_cb, pbc);
	if (ret) {
		spin_unlock_irqrestore(&pbc->spdif_out_lock, flags);
		return ret;
	}

	snd_pcm_startat_register(st, SNDRV_PCM_CLOCK_CLASS_AUDIO,
		clock_type, ts, NULL);

	pbc->spdif_out_start_at_substream = st;

	spin_unlock_irqrestore(&pbc->spdif_out_lock, flags);

	return 0;
}

static int pistachio_card_spdif_out_start_at_abort(
		struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned long flags;

	spin_lock_irqsave(&pbc->spdif_out_lock, flags);

	if (!pbc->spdif_out_start_at_substream) {
		/* Already started */
		spin_unlock_irqrestore(&pbc->spdif_out_lock, flags);
		return -EINVAL;
	}

	snd_pcm_startat_unregister(st);

	pbc->spdif_out_start_at_substream = NULL;

	spin_unlock_irqrestore(&pbc->spdif_out_lock, flags);

	pistachio_evt_disable_event(pbc->event_timer,
		PISTACHIO_EVT_ENABLE_SPDIF_OUT);

	return 0;
}

static struct snd_soc_ops pistachio_card_spdif_out_ops = {
	.startup = pistachio_card_spdif_out_startup,
	.shutdown = pistachio_card_spdif_out_shutdown,
	.hw_params = pistachio_card_spdif_out_hw_params,
	.start_at = pistachio_card_spdif_out_start_at,
	.start_at_abort = pistachio_card_spdif_out_start_at_abort
};

static int pistachio_card_parse_of_spdif_out(struct device_node *node,
		struct pistachio_card_data *pbc, struct snd_soc_dai_link *link)
{
	struct device_node *np;

	link->name = link->stream_name = "pistachio-spdif-out";
	np = of_parse_phandle(node, "cpu-dai", 0);
	if (!np)
		return -EINVAL;
	link->cpu_of_node = np;
	link->platform_of_node = np;
	link->codec_dai_name = "snd-soc-dummy-dai";
	link->codec_name = "snd-soc-dummy";
	link->ops = &pistachio_card_spdif_out_ops;

	return 0;
}

static int pistachio_card_parse_of_spdif_in(struct device_node *node,
		struct pistachio_card_data *pbc, struct snd_soc_dai_link *link)
{
	struct device_node *np;

	link->name = link->stream_name = "pistachio-spdif-in";
	np = of_parse_phandle(node, "cpu-dai", 0);
	if (!np)
		return -EINVAL;
	link->cpu_of_node = np;
	link->platform_of_node = np;
	link->codec_dai_name = "snd-soc-dummy-dai";
	link->codec_name = "snd-soc-dummy";

	return 0;
}

static int pistachio_card_find_codec_i2s(struct pistachio_card_data *pbc,
		struct snd_soc_dai *codec, bool i2s_out)
{
	int i;
	struct device_node *np;

	for (i = 0; i < PISTACHIO_MAX_CODECS; i++) {
		np = pbc->codecs[i].np;
		if (np && (np == codec->dev->of_node)) {
			switch (i) {
			case PISTACHIO_CODEC_PCM3060_DAC:
			case PISTACHIO_CODEC_PCM3060_ADC:
				if (i2s_out)
					return PISTACHIO_CODEC_PCM3060_DAC;
				else
					return PISTACHIO_CODEC_PCM3060_ADC;
			case PISTACHIO_CODEC_PCM3168A_1_DAC:
			case PISTACHIO_CODEC_PCM3168A_1_ADC:
				if (i2s_out)
					return PISTACHIO_CODEC_PCM3168A_1_DAC;
				else
					return PISTACHIO_CODEC_PCM3168A_1_ADC;
			case PISTACHIO_CODEC_PCM3168A_2_DAC:
			case PISTACHIO_CODEC_PCM3168A_2_ADC:
				if (i2s_out)
					return PISTACHIO_CODEC_PCM3168A_2_DAC;
				else
					return PISTACHIO_CODEC_PCM3168A_2_ADC;
			default:
				return -1;
			}
		}
	}

	return -1;
}

static int pistachio_card_i2s_mclk_setup(struct pistachio_card_data *pbc,
		unsigned int rate, bool i2s_out_mclk_shared, bool i2s_out)
{
	int ret;
	unsigned int ratio_start, num_ratios;
	unsigned long new_rate, temp;

	if (i2s_out) {
		ratio_start = PISTACHIO_I2S_MCLK_RATIO_START;
		num_ratios = PISTACHIO_I2S_MCLK_NUM_RATIOS;
	} else {
		ratio_start = 0;
		num_ratios = PCM3168A_PCM3060_NUM_MCLK_RATIOS_ADC;
	}

	ret = pistachio_card_get_best_clk_rate(pbc, rate, i2s_out_mclk_shared,
			ratio_start, num_ratios, pbc->i2s_mclk_rate, &new_rate);
	if (ret <= 0)
		return ret;

	if (i2s_out_mclk_shared) {
		if (i2s_out && pbc->i2s_in_active_rate) {
			dev_dbg(pbc->card.dev,
				"Cannot change mclk rate, i2s in active\n");
			return -EINVAL;
		} else if (!i2s_out && pbc->i2s_out_active_rate) {
			dev_dbg(pbc->card.dev,
				"Cannot change mclk rate, i2s out active\n");
			return -EINVAL;
		}
	}

	temp = pbc->i2s_mclk_rate;
	pbc->i2s_mclk_rate = new_rate;

	ret = clk_set_rate(pbc->i2s_mclk, new_rate);
	if (ret) {
		pbc->i2s_mclk_rate = temp;
		return ret;
	}

	if (i2s_out_mclk_shared)
		return pistachio_card_update_codec_sysclks(pbc, new_rate);

	return 0;
}

static int pistachio_card_i2s_clk_notifier_cb(struct notifier_block *nb,
		unsigned long event, void *data)
{
	struct clk_notifier_data *ndata = data;
	struct pistachio_card_data *pbc;
	int diff;
	u64 tolerance;

	pbc = container_of(nb, struct pistachio_card_data, i2s_clk_notifier);

	switch (event) {
	case PRE_RATE_CHANGE:
		diff = abs((int)ndata->new_rate - (int)pbc->i2s_mclk_rate);

		tolerance = ((u64)pbc->i2s_mclk_rate * 5) + 50;
		do_div(tolerance, 100);

		if (diff < (int)tolerance) {
			dev_dbg(pbc->card.dev,
				"rate change OK (%lu)\n", ndata->new_rate);
			return NOTIFY_OK;
		} else {
			dev_dbg(pbc->card.dev,
				"rate change DENIED (%lu)\n", ndata->new_rate);
			return NOTIFY_STOP;
		}
	case POST_RATE_CHANGE:
	case ABORT_RATE_CHANGE:
		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}
}

static int pistachio_card_i2s_hw_params(struct pistachio_card_data *pbc,
				unsigned int rate, bool out)
{
	bool i2s_out_mclk_shared, use_dac_clk;
	int ret;

	i2s_out_mclk_shared = (pbc->mclk_source == PISTACHIO_MCLK_I2S);
	use_dac_clk = (pbc->mclk_source == PISTACHIO_MCLK_DAC_CLK);

	if (out) {
		ret = pistachio_card_i2s_mclk_setup(pbc, rate,
				i2s_out_mclk_shared, true);
		if (ret)
			return ret;

		if (use_dac_clk) {
			ret = pistachio_card_set_dac_clk(pbc, rate, true);
			if (ret)
				return ret;
		}
	} else {
		if (i2s_out_mclk_shared) {
			ret = pistachio_card_i2s_mclk_setup(pbc, rate,
				i2s_out_mclk_shared, false);
			if (ret)
				return ret;
		} else if (use_dac_clk) {
			ret = pistachio_card_set_dac_clk(pbc, rate, false);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int pistachio_card_get_i2s_out_master(struct pistachio_card_data *pbc,
					struct device_node *i2s_out_master)
{
	struct pistachio_codec *codec;
	struct snd_soc_dai_link *link = pbc->dai_links[PISTACHIO_LINK_I2S_OUT];
	bool found = false;

	if (!link)
		return 0;

	if (IS_ERR(i2s_out_master))
		return PTR_ERR(i2s_out_master);

	pbc->i2s_out_cpu_fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
	if (i2s_out_master && (i2s_out_master == link->cpu_of_node)) {
		pbc->i2s_out_master = PISTACHIO_CPU_I2S_OUT;
		pbc->i2s_out_cpu_fmt |= SND_SOC_DAIFMT_CBS_CFS;
		found = true;
	} else {
		pbc->i2s_out_cpu_fmt |= SND_SOC_DAIFMT_CBM_CFM;
	}

	codec =  &pbc->codecs[PISTACHIO_CODEC_PCM3060_DAC];
	codec->fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
	if (i2s_out_master && (i2s_out_master == codec->np)) {
		pbc->i2s_out_master = PISTACHIO_CODEC_PCM3060_DAC;
		codec->fmt |= SND_SOC_DAIFMT_CBM_CFM;
		found = true;
	} else {
		codec->fmt |= SND_SOC_DAIFMT_CBS_CFS;
	}

	codec =  &pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_DAC];
	codec->fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
	if (i2s_out_master && (i2s_out_master == codec->np)) {
		pbc->i2s_out_master = PISTACHIO_CODEC_PCM3168A_1_DAC;
		codec->fmt |= SND_SOC_DAIFMT_CBM_CFM;
		found = true;
	} else {
		codec->fmt |= SND_SOC_DAIFMT_CBS_CFS;
	}

	codec =  &pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_DAC];
	codec->fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
	if (i2s_out_master && (i2s_out_master == codec->np)) {
		pbc->i2s_out_master = PISTACHIO_CODEC_PCM3168A_2_DAC;
		codec->fmt |= SND_SOC_DAIFMT_CBM_CFM;
		found = true;
	} else {
		codec->fmt |= SND_SOC_DAIFMT_CBS_CFS;
	}

	if (!found)
		pbc->i2s_out_master = PISTACHIO_FRAME_EXTERNAL;

	return 0;
}

static int pistachio_card_i2s_out_link_init(struct snd_soc_pcm_runtime *rtd)
{
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	struct snd_soc_dai *codec, *cpu = rtd->cpu_dai;
	int ret, i, j;
	unsigned long sysclk;

	ret = snd_soc_dai_set_fmt(cpu, pbc->i2s_out_cpu_fmt);
	if (ret)
		return ret;

	for (i = 0; i < rtd->num_codecs; i++) {
		codec = rtd->codec_dais[i];
		j = pistachio_card_find_codec_i2s(pbc, codec, true);
		if (j < 0)
			continue;
		pbc->codecs[j].dai = codec;
		ret = snd_soc_dai_set_fmt(codec, pbc->codecs[j].fmt);
		if (ret)
			return ret;

		if (pbc->mclk_source == PISTACHIO_MCLK_DAC_CLK)
			sysclk = pbc->dac_clk_rate;
		else
			sysclk = pbc->i2s_mclk_rate;

		ret = snd_soc_dai_set_sysclk(codec, 0, sysclk, 0);
		if (ret)
			return ret;
	}

	return 0;
}

static int pistachio_card_i2s_out_startup(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned long flags;

	spin_lock_irqsave(&pbc->i2s_out_lock, flags);
	pbc->i2s_out_active_rate = 0;
	spin_unlock_irqrestore(&pbc->i2s_out_lock, flags);

	return 0;
}

static void pistachio_card_i2s_out_shutdown(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned long flags;

	spin_lock_irqsave(&pbc->i2s_out_lock, flags);
	pbc->i2s_out_active_rate = 0;
	spin_unlock_irqrestore(&pbc->i2s_out_lock, flags);
}

static int pistachio_card_i2s_out_hw_params(struct snd_pcm_substream *st,
				struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned int rate;

	rate = params_rate(params);
	pbc->i2s_out_active_rate = rate;

	return pistachio_card_i2s_hw_params(pbc, rate, true);
}

static void pistachio_card_i2s_out_start_cb(void *context)
{
	struct pistachio_card_data *pbc;
	unsigned long flags;
	struct snd_pcm_substream *st;
	//int ret;

	pbc = (struct pistachio_card_data *)context;

	spin_lock_irqsave(&pbc->i2s_out_lock, flags);

	st = pbc->i2s_out_start_at_substream;

	if (!st) {
		spin_unlock_irqrestore(&pbc->i2s_out_lock, flags);
		return;
	}

	snd_pcm_stream_lock(st);

	snd_pcm_startat_unregister(st);

	if(!snd_pcm_do_start(st, SNDRV_PCM_STATE_RUNNING))
		snd_pcm_post_start(st, SNDRV_PCM_STATE_RUNNING);

	snd_pcm_stream_unlock(st);

	_pistachio_evt_disable_event(pbc->event_timer,
			PISTACHIO_EVT_ENABLE_I2S_OUT);

	pbc->i2s_out_start_at_substream = NULL;

	spin_unlock_irqrestore(&pbc->i2s_out_lock, flags);
}

static int pistachio_card_i2s_out_start_at(struct snd_pcm_substream *st,
		int clock_type, const struct timespec *ts)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	int ret;
	unsigned long flags;
	struct timespec ts_modified = *ts;
	struct timespec ts_sub;

	printk("### pistachio_card_i2s_out_start_at\n");

	ret = snd_pcm_pre_start(st, SNDRV_PCM_STATE_PREPARED);
	if (ret)
		return ret;

	printk("### pistachio_card_i2s_out_start_at 2\n");

	spin_lock_irqsave(&pbc->i2s_out_lock, flags);

	/*
	 * I2S outputs zero samples for the first frame. The first sample
	 * of audio data from the application is then used in the second
	 * frame. Subtract a frame from the start time to ensure start_at
	 * has the same meaning for all interfaces
	 */
	ts_sub.tv_sec = 0;
	ts_sub.tv_nsec = DIV_ROUND_CLOSEST(1000000000,
			pbc->i2s_out_active_rate);
	ts_modified = timespec_sub(ts_modified, ts_sub);

	ret = pistachio_evt_set_event(pbc->event_timer,
		PISTACHIO_EVT_ENABLE_I2S_OUT,
		PISTACHIO_EVT_TYPE_LEVEL, &ts_modified,
		pistachio_card_i2s_out_start_cb, pbc);
	if (ret) {
		spin_unlock_irqrestore(&pbc->i2s_out_lock, flags);
		return ret;
	}

	printk("### pistachio_card_i2s_out_start_at 3\n");

	snd_pcm_startat_register(st, SNDRV_PCM_CLOCK_CLASS_AUDIO,
		clock_type, ts, NULL);

	pbc->i2s_out_start_at_substream = st;

	spin_unlock_irqrestore(&pbc->i2s_out_lock, flags);

	return 0;
}

static int pistachio_card_i2s_out_start_at_abort(
		struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned long flags;

	spin_lock_irqsave(&pbc->i2s_out_lock, flags);

	if (!pbc->i2s_out_start_at_substream) {
		/* Already started */
		spin_unlock_irqrestore(&pbc->i2s_out_lock, flags);
		return -EINVAL;
	}

	snd_pcm_startat_unregister(st);

	pbc->i2s_out_start_at_substream = NULL;

	spin_unlock_irqrestore(&pbc->i2s_out_lock, flags);

	pistachio_evt_disable_event(pbc->event_timer,
		PISTACHIO_EVT_ENABLE_I2S_OUT);

	return 0;
}

static struct snd_soc_ops pistachio_card_i2s_out_ops = {
	.startup = pistachio_card_i2s_out_startup,
	.shutdown = pistachio_card_i2s_out_shutdown,
	.hw_params = pistachio_card_i2s_out_hw_params,
	.start_at = pistachio_card_i2s_out_start_at,
	.start_at_abort = pistachio_card_i2s_out_start_at_abort
};

static int pistachio_card_parse_of_i2s_out(struct device_node *node,
		struct pistachio_card_data *pbc, struct snd_soc_dai_link *link,
		struct snd_soc_dai_link_component *components,
		struct device_node **i2s_out_master)
{
	struct device_node *np;
	unsigned int fmt;
	struct device *dev = pbc->card.dev;

	link->name = link->stream_name = "pistachio-i2s-out";
	np = of_parse_phandle(node, "cpu-dai", 0);
	if (!np)
		return -EINVAL;
	link->cpu_of_node = np;
	link->platform_of_node = np;
	fmt = snd_soc_of_parse_daifmt(node, "cpu-", NULL, NULL);
	pbc->i2s_out_cpu_fmt = fmt;
	link->codecs = components;
	np = of_parse_phandle(node, "pcm3060", 0);
	if (np) {
		if (pbc->db != PISTACHIO_DAUGHTERBOARD_NONE) {
			of_node_put(np);
			dev_err(dev, "pcm3060 is available only when no daughterboard is present");
			return -EINVAL;
		}
		pbc->codecs[PISTACHIO_CODEC_PCM3060_DAC].np = np;
		link->codecs[link->num_codecs].dai_name = "pcm3060-dac";
		link->codecs[link->num_codecs++].of_node = np;
		fmt = snd_soc_of_parse_daifmt(node, "pcm3060-", NULL, NULL);
		pbc->codecs[PISTACHIO_CODEC_PCM3060_DAC].fmt = fmt;
	}
	np = of_parse_phandle(node, "pcm3168a-1", 0);
	if (np) {
		if (pbc->db != PISTACHIO_DAUGHTERBOARD_CODEC) {
			of_node_put(np);
			dev_err(dev, "pcm3168a-1 is available only when codec daughterboard is present");
			return -EINVAL;
		}
		pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_DAC].np = np;
		link->codecs[link->num_codecs].dai_name = "pcm3168a-dac";
		link->codecs[link->num_codecs++].of_node = np;
		fmt = snd_soc_of_parse_daifmt(node, "pcm3168a-1-", NULL, NULL);
		pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_DAC].fmt = fmt;
	}
	np = of_parse_phandle(node, "pcm3168a-2", 0);
	if (np) {
		if (pbc->db != PISTACHIO_DAUGHTERBOARD_CODEC) {
			of_node_put(np);
			dev_err(dev, "pcm3168a-2 is available only when codec daughterboard is present");
			return -EINVAL;
		}
		pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_DAC].np = np;
		link->codecs[link->num_codecs].dai_name = "pcm3168a-dac";
		link->codecs[link->num_codecs++].of_node = np;
		fmt = snd_soc_of_parse_daifmt(node, "pcm3168a-2-", NULL, NULL);
		pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_DAC].fmt = fmt;
	}
	if (!link->num_codecs) {
		link->codec_dai_name = "snd-soc-dummy-dai";
		link->codec_name = "snd-soc-dummy";
		link->codecs = NULL;
	}
	link->init = pistachio_card_i2s_out_link_init;
	link->ops = &pistachio_card_i2s_out_ops;

	*i2s_out_master = of_parse_phandle(node, "clock-master", 0);

	return link->num_codecs;
}

#define PISTACHIO_I2S_LOOPBACK_REG		0x88
#define PISTACHIO_I2S_LOOPBACK_DATA_MASK	0x4
#define PISTACHIO_I2S_LOOPBACK_CLK_MASK		0x3
#define PISTACHIO_I2S_LOOPBACK_CLK_SHIFT	0

#define PISTACHIO_I2S_LOOPBACK_CLK_NONE		0
#define PISTACHIO_I2S_LOOPBACK_CLK_MFIO		1
#define PISTACHIO_I2S_LOOPBACK_CLK_LOCAL	2

static int pistachio_card_get_i2s_in_master(struct pistachio_card_data *pbc,
					struct device_node *i2s_in_master)
{
	struct pistachio_codec *codec;
	struct snd_soc_dai_link *link = pbc->dai_links[PISTACHIO_LINK_I2S_IN];
	bool found = false;
	u32 loopback_val;

	if (!link)
		return 0;

	if (IS_ERR(i2s_in_master))
		return PTR_ERR(i2s_in_master);

	link = pbc->dai_links[PISTACHIO_LINK_I2S_OUT];

	pbc->i2s_in_cpu_fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
	pbc->i2s_in_cpu_fmt |= SND_SOC_DAIFMT_CBM_CFM;
	if (link && i2s_in_master && (i2s_in_master == link->cpu_of_node)) {
		if (pbc->i2s_out_master != PISTACHIO_CPU_I2S_OUT) {
			dev_err(pbc->card.dev, "Invalid i2s master config");
			return -EINVAL;
		}
		pbc->i2s_in_master = PISTACHIO_CPU_I2S_OUT;
		found = true;
	}

	codec =  &pbc->codecs[PISTACHIO_CODEC_PCM3060_ADC];
	codec->fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
	if (i2s_in_master && (i2s_in_master == codec->np)) {
		pbc->i2s_in_master = PISTACHIO_CODEC_PCM3060_ADC;
		codec->fmt |= SND_SOC_DAIFMT_CBM_CFM;
		found = true;
	} else {
		codec->fmt |= SND_SOC_DAIFMT_CBS_CFS;
	}

	codec =  &pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_ADC];
	codec->fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
	if (i2s_in_master && (i2s_in_master == codec->np)) {
		pbc->i2s_in_master = PISTACHIO_CODEC_PCM3168A_1_ADC;
		codec->fmt |= SND_SOC_DAIFMT_CBM_CFM;
		found = true;
	} else {
		codec->fmt |= SND_SOC_DAIFMT_CBS_CFS;
	}

	codec =  &pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_ADC];
	codec->fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
	if (i2s_in_master && (i2s_in_master == codec->np)) {
		pbc->i2s_in_master = PISTACHIO_CODEC_PCM3168A_2_ADC;
		codec->fmt |= SND_SOC_DAIFMT_CBM_CFM;
		found = true;
	} else {
		codec->fmt |= SND_SOC_DAIFMT_CBS_CFS;
	}

	if (!found)
		pbc->i2s_in_master = PISTACHIO_FRAME_EXTERNAL;

	if (pbc->i2s_in_master == PISTACHIO_CPU_I2S_OUT)
		loopback_val = PISTACHIO_I2S_LOOPBACK_CLK_LOCAL;
	else
		loopback_val = PISTACHIO_I2S_LOOPBACK_CLK_NONE;

	loopback_val <<= PISTACHIO_I2S_LOOPBACK_CLK_SHIFT;

	regmap_update_bits(pbc->periph_regs, PISTACHIO_I2S_LOOPBACK_REG,
		PISTACHIO_I2S_LOOPBACK_CLK_MASK, loopback_val);

	return 0;
}

static int pistachio_card_i2s_in_link_init(struct snd_soc_pcm_runtime *rtd)
{
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	struct snd_soc_dai *codec, *cpu = rtd->cpu_dai;
	int ret, i, j;
	unsigned int fmt;
	unsigned long sysclk;

	fmt = pbc->i2s_in_cpu_fmt;

	if ((fmt & SND_SOC_DAIFMT_MASTER_MASK) == SND_SOC_DAIFMT_CBS_CFS) {
		fmt = (fmt & ~SND_SOC_DAIFMT_MASTER_MASK) |
			SND_SOC_DAIFMT_CBM_CFM;
	}
	ret = snd_soc_dai_set_fmt(cpu, fmt);
	if (ret)
		return ret;

	for (i = 0; i < rtd->num_codecs; i++) {
		codec = rtd->codec_dais[i];
		j = pistachio_card_find_codec_i2s(pbc, codec, false);
		if (j == -1)
			continue;
		pbc->codecs[j].dai = codec;
		ret = snd_soc_dai_set_fmt(codec, pbc->codecs[j].fmt);
		if (ret)
			return ret;

		if (pbc->mclk_source == PISTACHIO_MCLK_DAC_CLK)
			sysclk = pbc->dac_clk_rate;
		else
			sysclk = pbc->i2s_mclk_rate;

		ret = snd_soc_dai_set_sysclk(codec, 0, sysclk, 0);
		if (ret)
			return ret;
	}

	return 0;
}

static int pistachio_card_i2s_in_startup(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);

	pbc->i2s_in_active_rate = 0;

	return 0;
}

static void pistachio_card_i2s_in_shutdown(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);

	pbc->i2s_in_active_rate = 0;
}

static int pistachio_card_i2s_in_hw_params(struct snd_pcm_substream *st,
				struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(rtd->card);
	unsigned int rate;

	rate = params_rate(params);
	pbc->i2s_in_active_rate = rate;

	return pistachio_card_i2s_hw_params(pbc, rate, false);
}

static struct snd_soc_ops pistachio_card_i2s_in_ops = {
	.startup = pistachio_card_i2s_in_startup,
	.shutdown = pistachio_card_i2s_in_shutdown,
	.hw_params = pistachio_card_i2s_in_hw_params
};

static int pistachio_card_parse_of_i2s_in(struct device_node *node,
		struct pistachio_card_data *pbc, struct snd_soc_dai_link *link,
		struct snd_soc_dai_link_component *components,
		struct device_node **i2s_in_master)
{
	struct device_node *np;
	unsigned int fmt;
	struct device *dev = pbc->card.dev;

	link->name = link->stream_name = "pistachio-i2s-in";
	np = of_parse_phandle(node, "cpu-dai", 0);
	if (!np)
		return -EINVAL;
	link->cpu_of_node = np;
	link->platform_of_node = np;
	fmt = snd_soc_of_parse_daifmt(node, "cpu-", NULL, NULL);
	pbc->i2s_in_cpu_fmt = fmt;
	link->codecs = components;
	np = of_parse_phandle(node, "pcm3060", 0);
	if (np) {
		if (pbc->db != PISTACHIO_DAUGHTERBOARD_NONE) {
			of_node_put(np);
			dev_err(dev, "pcm3060 is available only when no daughterboard is present");
			return -EINVAL;
		}
		pbc->codecs[PISTACHIO_CODEC_PCM3060_ADC].np = np;
		link->codecs[link->num_codecs].dai_name = "pcm3060-adc";
		link->codecs[link->num_codecs++].of_node = np;
		fmt = snd_soc_of_parse_daifmt(node, "pcm3060-", NULL, NULL);
		pbc->codecs[PISTACHIO_CODEC_PCM3060_ADC].fmt = fmt;
	}
	np = of_parse_phandle(node, "pcm3168a-1", 0);
	if (np) {
		if (pbc->db != PISTACHIO_DAUGHTERBOARD_CODEC) {
			of_node_put(np);
			dev_err(dev, "pcm3168a-1 is available only when codec daughterboard is present");
			return -EINVAL;
		}
		pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_ADC].np = np;
		link->codecs[link->num_codecs].dai_name = "pcm3168a-adc";
		link->codecs[link->num_codecs++].of_node = np;
		fmt = snd_soc_of_parse_daifmt(node, "pcm3168a-1-", NULL, NULL);
		pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_ADC].fmt = fmt;
	}
	np = of_parse_phandle(node, "pcm3168a-2", 0);
	if (np) {
		if (pbc->db != PISTACHIO_DAUGHTERBOARD_CODEC) {
			of_node_put(np);
			dev_err(dev, "pcm3168a-2 is available only when codec daughterboard is present");
			return -EINVAL;
		}
		pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_ADC].np = np;
		link->codecs[link->num_codecs].dai_name = "pcm3168a-adc";
		link->codecs[link->num_codecs++].of_node = np;
		fmt = snd_soc_of_parse_daifmt(node, "pcm3168a-2-", NULL, NULL);
		pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_ADC].fmt = fmt;
	}
	if (!link->num_codecs) {
		link->codec_dai_name = "snd-soc-dummy-dai";
		link->codec_name = "snd-soc-dummy";
		link->codecs = NULL;
	}
	link->init = pistachio_card_i2s_in_link_init;
	link->ops = &pistachio_card_i2s_in_ops;

	*i2s_in_master = of_parse_phandle(node, "clock-master", 0);

	return link->num_codecs;
}

static int pistachio_card_parse_of(struct device_node *node,
	struct pistachio_card_data *pbc, struct device_node **i2s_out_master,
	struct device_node **i2s_in_master)
{
	int ret;
	struct device_node *np;
	struct snd_soc_dai_link *dai_link = pbc->dai_links_st;
	struct snd_soc_dai_link_component *component = pbc->codec_st;

	if (!node)
		return -EINVAL;

	pbc->card.name = "pistachio-card";

	/* The off-codec widgets */
	if (of_property_read_bool(node, "widgets")) {
		ret = snd_soc_of_parse_audio_simple_widgets(&pbc->card,
					"widgets");
		if (ret)
			return ret;
	}

	/* DAPM routes */
	if (of_property_read_bool(node, "routing")) {
		ret = snd_soc_of_parse_audio_routing(&pbc->card,
					"routing");
		if (ret)
			return ret;
	}

	np = of_get_child_by_name(node, "spdif-out");
	if (np) {
		ret = pistachio_card_parse_of_spdif_out(np, pbc, dai_link);
		if (ret)
			return ret;
		pbc->dai_links[PISTACHIO_LINK_SPDIF_OUT] = dai_link++;
	}

	np = of_get_child_by_name(node, "spdif-in");
	if (np) {
		ret = pistachio_card_parse_of_spdif_in(np, pbc, dai_link);
		if (ret)
			return ret;
		pbc->dai_links[PISTACHIO_LINK_SPDIF_IN] = dai_link++;
	}

	np = of_get_child_by_name(node, "parallel-out");
	if (np) {
		ret = pistachio_card_parse_of_parallel_out(np, pbc,
				dai_link, component);
		if (ret < 0)
			return ret;
		pbc->dai_links[PISTACHIO_LINK_PRL_OUT] = dai_link++;
		component += ret;
	}

	np = of_get_child_by_name(node, "i2s-out");
	if (np) {
		ret = pistachio_card_parse_of_i2s_out(np, pbc,
				dai_link, component, i2s_out_master);
		if (ret < 0)
			return ret;
		pbc->dai_links[PISTACHIO_LINK_I2S_OUT] = dai_link++;
		component += ret;
	}

	np = of_get_child_by_name(node, "i2s-in");
	if (np) {
		ret = pistachio_card_parse_of_i2s_in(np, pbc,
				dai_link, component, i2s_in_master);
		if (ret < 0)
			return ret;
		pbc->dai_links[PISTACHIO_LINK_I2S_IN] = dai_link++;
	}

	pbc->hp_jack_gpio.gpio = of_get_named_gpio(node,
				"img,hp-det-gpio", 0);
	if (pbc->hp_jack_gpio.gpio == -EPROBE_DEFER)
		return -EPROBE_DEFER;

	return dai_link - pbc->dai_links_st;
}

/* Decrease the reference count of the device nodes */
static void pistachio_card_unref(struct platform_device *pdev,
	struct device_node *i2s_out_master, struct device_node *i2s_in_master)
{
	struct snd_soc_card *card = platform_get_drvdata(pdev);
	struct snd_soc_dai_link *dai_link;
	struct device_node *np;
	const struct device_node *npc;
	int i, j;

	dai_link = card->dai_link;

	for (i = 0; i < card->num_links; i++, dai_link++) {

		np = (struct device_node *) dai_link->cpu_of_node;
		if (np)
			of_node_put(np);

		if (dai_link->codecs) {
			for (j = 0; j < dai_link->num_codecs; j++) {
				npc = dai_link->codecs[j].of_node;
				np = (struct device_node *)npc;
				if (np)
					of_node_put(np);
			}
		}
	}
}

static int pistachio_card_init_clk(struct device *dev, char *name,
		struct clk **pclk, unsigned long *rate)
{
	struct clk *clk;
	int ret;

	clk = devm_clk_get(dev, name);
	if (IS_ERR(clk)) {
		ret = PTR_ERR(clk);
		return ret;
	}

	ret = clk_prepare_enable(clk);
	if (ret)
		return ret;

	*rate = clk_get_rate(clk);

	*pclk = clk;

	return 0;
}

static int pistachio_card_info_event_time(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_info *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER64;
	uinfo->count = 2;
	uinfo->value.integer64.min = 0;
	uinfo->value.integer64.max = LLONG_MAX;

	return 0;
}

static int pistachio_card_get_event_time(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *uc)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(card);
	struct timespec ts;

	pistachio_evt_read(pbc->event_timer, &ts);

	uc->value.integer64.value[0] = ts.tv_sec;
	uc->value.integer64.value[1] = ts.tv_nsec;

	return 0;
}

static struct snd_kcontrol_new pistachio_bub_controls[] = {
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READ |
			SNDRV_CTL_ELEM_ACCESS_VOLATILE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "Event Time",
		.info = pistachio_card_info_event_time,
		.get = pistachio_card_get_event_time
	},
};

static int pistachio_card_probe(struct platform_device *pdev)
{
	struct pistachio_card_data *pbc;
	struct device_node *np_event, *np = pdev->dev.of_node;
	struct device *dev = &pdev->dev;
	int ret;
	struct device_node *i2s_out_master, *i2s_in_master, *codec_np;
	struct snd_soc_codec_conf *codec_conf;

	pbc = devm_kzalloc(dev, sizeof(*pbc), GFP_KERNEL);
	if (!pbc)
		return -ENOMEM;

	pbc->card.owner = THIS_MODULE;
	pbc->card.dev = dev;

	spin_lock_init(&pbc->parallel_out_lock);
	spin_lock_init(&pbc->spdif_out_lock);
	spin_lock_init(&pbc->i2s_out_lock);

	pbc->hp_jack_gpio.gpio = -ENOENT;

	if (!np || !of_device_is_available(np))
		return -EINVAL;

	i2s_out_master = NULL;
	i2s_in_master = NULL;

	ret = of_property_read_u32(np, "img,daughterboard", &pbc->db);
	if (ret)
		return ret;
	if (pbc->db > PISTACHIO_DAUGHTERBOARD_MAX)
		return -EINVAL;

	ret = of_property_read_u32(np, "img,mclk", &pbc->mclk_source);
	if (ret)
		return ret;
	if (pbc->mclk_source > PISTACHIO_MCLK_MAX)
		return -EINVAL;

	ret = of_property_read_u32(np, "img,mclk-max", &pbc->mclk_max);
	if (ret) {
		switch (pbc->db) {
		case PISTACHIO_DAUGHTERBOARD_NONE:
		case PISTACHIO_DAUGHTERBOARD_CODEC:
			pbc->mclk_max = PCM1368A_PCM3060_MAX_MCLK;
			break;
		case PISTACHIO_DAUGHTERBOARD_BREAKOUT:
			pbc->mclk_max = ULONG_MAX;
			break;
		default:
			return -EINVAL;
		};
	}

	pbc->periph_regs = syscon_regmap_lookup_by_phandle(pdev->dev.of_node,
							    "img,cr-periph");
	if (IS_ERR(pbc->periph_regs))
		return PTR_ERR(pbc->periph_regs);

	pbc->top_regs = syscon_regmap_lookup_by_phandle(pdev->dev.of_node,
							    "img,cr-top");
	if (IS_ERR(pbc->top_regs))
		return PTR_ERR(pbc->top_regs);

	np_event = of_parse_phandle(np, "img,event-timer", 0);
	if (!np_event)
		return -EINVAL;
	pbc->event_timer = of_find_device_by_node(np_event);
	if (!pbc->event_timer)
		return -EPROBE_DEFER;

	ret = pistachio_card_parse_of(np, pbc,
			&i2s_out_master, &i2s_in_master);
	if (ret < 0) {
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "parse error %d\n", ret);
		goto err;
	}

	if (ret > 0) {
		pbc->card.dai_link = pbc->dai_links_st;
		pbc->card.num_links = ret;
	}

	ret = pistachio_card_get_i2s_out_master(pbc, i2s_out_master);
	if (!ret)
		ret = pistachio_card_get_i2s_in_master(pbc, i2s_in_master);

	if (!IS_ERR_OR_NULL(i2s_out_master))
		of_node_put(i2s_out_master);

	if (!IS_ERR_OR_NULL(i2s_in_master))
		of_node_put(i2s_in_master);

	if (ret)
		goto err;

	codec_conf = pbc->codec_conf;

	codec_np = pbc->codecs[PISTACHIO_CODEC_TPA6130A2].np;
	if (codec_np) {
		codec_conf->of_node = codec_np;
		codec_conf->name_prefix = "TPA";
		codec_conf++;
	}

	codec_np = pbc->codecs[PISTACHIO_CODEC_PCM3060_DAC].np;
	if (!codec_np)
		codec_np = pbc->codecs[PISTACHIO_CODEC_PCM3060_ADC].np;
	if (codec_np) {
		codec_conf->of_node = codec_np;
		codec_conf->name_prefix = "PCM3060";
		codec_conf++;
	}

	codec_np = pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_DAC].np;
	if (!codec_np)
		codec_np = pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_ADC].np;
	if (codec_np) {
		codec_conf->of_node = codec_np;
		codec_conf->name_prefix = "PCM3168A 1";
		codec_conf++;
	}

	codec_np = pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_DAC].np;
	if (!codec_np)
		codec_np = pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_ADC].np;
	if (codec_np) {
		codec_conf->of_node = codec_np;
		codec_conf->name_prefix = "PCM3168A 2";
		codec_conf++;
	}

	pbc->card.codec_conf = pbc->codec_conf;
	pbc->card.num_configs = (codec_conf - pbc->codec_conf);

	ret = pistachio_card_init_clk(dev, "audio_pll", &pbc->audio_pll,
			&pbc->audio_pll_rate);
	if (ret)
		goto err;

	ret = pistachio_card_init_clk(dev, "i2s_mclk", &pbc->i2s_mclk,
			&pbc->i2s_mclk_rate);
	if (ret)
		goto err_clk_audio_pll;

	pbc->i2s_clk_notifier.notifier_call =
			pistachio_card_i2s_clk_notifier_cb;
	ret = clk_notifier_register(pbc->i2s_mclk,
			&pbc->i2s_clk_notifier);
	if (ret)
		goto err_clk_mclk;

	if (pbc->mclk_source == PISTACHIO_MCLK_DAC_CLK) {
		ret = pistachio_card_init_clk(dev, "dac_clk", &pbc->dac_clk,
				&pbc->dac_clk_rate);
		if (ret)
			goto err_clk_mclk;
	}

	ret = pistachio_card_init_clk(dev, "evt_clk", &pbc->evt_clk,
				&pbc->evt_clk_rate);
	if (ret)
		goto err_clk_dac;

	snd_soc_card_set_drvdata(&pbc->card, pbc);

	ret = devm_snd_soc_register_card(dev, &pbc->card);
	if (ret < 0)
		goto err_clk_evt;

	ret = snd_soc_add_card_controls(&pbc->card, pistachio_bub_controls,
			ARRAY_SIZE(pistachio_bub_controls));
	if(ret < 0)
		goto err_clk_evt;

	if (gpio_is_valid(pbc->hp_jack_gpio.gpio)) {
		pbc->hp_jack_pin.pin = "Headphones";
		pbc->hp_jack_pin.mask = SND_JACK_HEADPHONE;
		pbc->hp_jack_gpio.name = "Headphone detection";
		pbc->hp_jack_gpio.report = SND_JACK_HEADPHONE;
		pbc->hp_jack_gpio.debounce_time = 150;
		snd_soc_card_jack_new(&pbc->card, "Headphones",
				SND_JACK_HEADPHONE, &pbc->hp_jack, &pbc->hp_jack_pin, 1);
		snd_soc_jack_add_gpios(&pbc->hp_jack, 1, &pbc->hp_jack_gpio);
	}

	dev_info(dev, "\n");
	dev_info(dev, "#####################################\n");
	dev_info(dev, "\n");
	dev_info(dev, "Pistachio BuB Audio Card\n");
	dev_info(dev, "\n");

	if (!pbc->card.num_links) {
		dev_info(dev, "No dai links present\n");
	} else {
		if (pbc->dai_links[PISTACHIO_LINK_SPDIF_OUT]) {
			dev_info(dev, "SPDIF OUT\n");
			dev_info(dev, "\n");
		}
		if (pbc->dai_links[PISTACHIO_LINK_SPDIF_IN]) {
			dev_info(dev, "SPDIF IN\n");
			dev_info(dev, "\n");
		}
		if (pbc->dai_links[PISTACHIO_LINK_PRL_OUT]) {
			dev_info(dev, "PARALLEL OUT\n");
			if (pbc->codecs[PISTACHIO_CODEC_TPA6130A2].np)
				dev_info(dev, "    TPA6130A2\n");
			dev_info(dev, "\n");
		}
		if (pbc->dai_links[PISTACHIO_LINK_I2S_OUT]) {
			dev_info(dev, "I2S OUT%s\n",
				((pbc->i2s_out_master == PISTACHIO_CPU_I2S_OUT) ?
				((pbc->i2s_in_master == PISTACHIO_CPU_I2S_OUT) ?
				(" (Dual Frame + Bit Clock Master)") : (" (Frame + Bit Clock Master)")) :
				("")));
			if (pbc->codecs[PISTACHIO_CODEC_PCM3060_DAC].np)
				dev_info(dev, "    PCM3060%s\n",
					(pbc->i2s_out_master == PISTACHIO_CODEC_PCM3060_DAC) ?
					(" (Frame + Bit Clock Master)") : (""));
			if (pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_DAC].np)
				dev_info(dev, "    PCM3168A 1%s\n",
					(pbc->i2s_out_master == PISTACHIO_CODEC_PCM3168A_1_DAC) ?
					(" (Frame + Bit Clock Master)") : (""));
			if (pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_DAC].np)
				dev_info(dev, "    PCM3168A 2%s\n",
					(pbc->i2s_out_master == PISTACHIO_CODEC_PCM3168A_2_DAC) ?
					(" (Frame + Bit Clock Master)") : (""));
			dev_info(dev, "\n");
		}
		if (pbc->dai_links[PISTACHIO_LINK_I2S_IN]) {
			dev_info(dev, "I2S IN\n");
			if (pbc->codecs[PISTACHIO_CODEC_PCM3060_ADC].np)
				dev_info(dev, "    PCM3060%s\n",
					(pbc->i2s_in_master == PISTACHIO_CODEC_PCM3060_ADC) ?
					(" (Frame + Bit Clock Master)") : (""));
			if (pbc->codecs[PISTACHIO_CODEC_PCM3168A_1_ADC].np)
				dev_info(dev, "    PCM3168A 1%s\n",
					(pbc->i2s_in_master == PISTACHIO_CODEC_PCM3168A_1_ADC) ?
					(" (Frame + Bit Clock Master)") : (""));
			if (pbc->codecs[PISTACHIO_CODEC_PCM3168A_2_ADC].np)
				dev_info(dev, "    PCM3168A 2%s\n",
					(pbc->i2s_in_master == PISTACHIO_CODEC_PCM3168A_2_ADC) ?
					(" (Frame + Bit Clock Master)") : (""));
			if (pbc->i2s_in_master == PISTACHIO_FRAME_EXTERNAL)
				dev_info(dev, "    EXTERNAL (Frame + Bit Clock Master)\n");
			dev_info(dev, "\n");
		}
	}
	dev_info(dev, "#####################################\n");
	dev_info(dev, "\n");

	return 0;

err_clk_evt:
	clk_disable_unprepare(pbc->evt_clk);
err_clk_dac:
	if (pbc->mclk_source == PISTACHIO_MCLK_DAC_CLK)
		clk_disable_unprepare(pbc->dac_clk);
err_clk_mclk:
	clk_disable_unprepare(pbc->i2s_mclk);
err_clk_audio_pll:
	clk_disable_unprepare(pbc->audio_pll);
err:
	pistachio_card_unref(pdev, i2s_out_master, i2s_in_master);

	return ret;
}

static int pistachio_card_remove(struct platform_device *pdev)
{
	struct snd_soc_card *card = platform_get_drvdata(pdev);
	struct pistachio_card_data *pbc = snd_soc_card_get_drvdata(card);

	if (gpio_is_valid(pbc->hp_jack_gpio.gpio))
		snd_soc_jack_free_gpios(&pbc->hp_jack, 1,
					&pbc->hp_jack_gpio);

	pistachio_card_unref(pdev, NULL, NULL);

	return 0;
}

static const struct of_device_id pistachio_card_of_match[] = {
	{ .compatible = "img,pistachio-bub-audio" },
	{},
};
MODULE_DEVICE_TABLE(of, pistachio_card_of_match);

static struct platform_driver pistachio_card = {
	.driver = {
		.name = "pistachio-bub-card",
		.of_match_table = pistachio_card_of_match,
	},
	.probe = pistachio_card_probe,
	.remove = pistachio_card_remove,
};
module_platform_driver(pistachio_card);

MODULE_DESCRIPTION("Pistachio BuB audio card driver");
MODULE_AUTHOR("Damien Horsley <Damien.Horsley@imgtec.com>");
MODULE_LICENSE("GPL v2");
