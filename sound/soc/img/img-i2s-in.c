/*
 * IMG I2S input controller driver
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
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/reset.h>

#include <linux/mfd/syscon.h>

#include <sound/core.h>
#include <sound/dmaengine_pcm.h>
#include <sound/initval.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>

#define IMG_I2S_IN_RX_FIFO			0x0

#define IMG_I2S_IN_CTL				0x4
#define IMG_I2S_IN_CTL_ACTIVE_CHAN_MASK		0xfffffffc
#define IMG_I2S_IN_CTL_ACTIVE_CH_SHIFT		2
#define IMG_I2S_IN_CTL_16PACK_MASK		BIT(1)
#define IMG_I2S_IN_CTL_ME_MASK			BIT(0)

#define IMG_I2S_IN_CH_RX_FIFO(chan)		((chan) * 0x20)

#define IMG_I2S_IN_CH_CTL			0x4
#define IMG_I2S_IN_CH_CTL_CCDEL_MASK		0x38000
#define IMG_I2S_IN_CH_CTL_CCDEL_SHIFT		15
#define IMG_I2S_IN_CH_CTL_FEN_MASK		BIT(14)
#define IMG_I2S_IN_CH_CTL_FMODE_MASK		BIT(13)
#define IMG_I2S_IN_CH_CTL_16PACK_MASK		BIT(12)
#define IMG_I2S_IN_CH_CTL_JUST_MASK		BIT(10)
#define IMG_I2S_IN_CH_CTL_PACKH_MASK		BIT(9)
#define IMG_I2S_IN_CH_CTL_CLK_TRANS_MASK	BIT(8)
#define IMG_I2S_IN_CH_CTL_BLKP_MASK		BIT(7)
#define IMG_I2S_IN_CH_CTL_FIFO_FLUSH_MASK	BIT(6)
#define IMG_I2S_IN_CH_CTL_LRD_MASK		BIT(3)
#define IMG_I2S_IN_CH_CTL_FW_MASK		BIT(2)
#define IMG_I2S_IN_CH_CTL_SW_MASK		BIT(1)
#define IMG_I2S_IN_CH_CTL_ME_MASK		BIT(0)

#define IMG_I2S_IN_CH_STRIDE			0x20

#define	IMG_I2S_IN_CH_SCNT			0x10

#define	PERIPH_I2S_IN_CLOCK_MASTER		0x280

#define	PERIPH_SAMPLE_CAPTURE			0x80
#define	PERIPH_SAMPLE_CAPTURE_I2S_IN_MASK	0x3f

#define	IMG_I2S_IN_CH_BIT(i2s, ch)  (1UL << (((i2s)->max_i2s_chan - 1) - (ch)))
#define	IMG_I2S_IN_CS_MASK(i2s, cs) (((1UL << (cs)->active_channels) - 1) << \
				    (((i2s)->max_i2s_chan -	\
				    (cs)->active_channels) - (cs)->first_channel))

struct img_i2s_in_channel;

struct img_i2s_in_channel_group {
	u32 mask;
	u32 channel_sets;
	u32 active_channel_sets;
	u32 master;
	bool stopping;
};

struct img_i2s_in_channel_set {
	struct img_i2s_in_channel_group *group;
	char dma_name[5];
	char cpu_dai_name[18];
	char platform_name[23];
	struct snd_dmaengine_dai_dma_data dma_data;
	u32 first_channel;
	u32 last_channel;
	u32 active_channels;
	bool active;
	bool shared_dma;
};

struct img_i2s_in_channel {
	struct img_i2s_in_channel_set *set;
};

struct img_i2s_in {
	spinlock_t lock;
	void __iomem *base;
	struct clk *clk_sys;
	struct device *dev;
	unsigned int max_i2s_chan;
	void __iomem *channel_base;
	u32 active_channel_sets;
	bool core_me;
	struct regmap *periph_regs;
	u32 clock_masters;
	u32 shared_dma_channels;
	struct img_i2s_in_channel_set *channel_sets;
	struct img_i2s_in_channel *channels;
	struct img_i2s_in_channel_group *groups;
	struct snd_soc_dai_driver *cpu_dais;
	struct snd_soc_component_driver img_i2s_in_component;
};

static inline void img_i2s_in_writel(struct img_i2s_in *i2s, u32 val, u32 reg)
{
	writel(val, i2s->base + reg);
}

static inline u32 img_i2s_in_readl(struct img_i2s_in *i2s, u32 reg)
{
	return readl(i2s->base + reg);
}

static inline void img_i2s_in_ch_writel(struct img_i2s_in *i2s, u32 chan,
					u32 val, u32 reg)
{
	writel(val, i2s->channel_base + (chan * IMG_I2S_IN_CH_STRIDE) + reg);
}

static inline u32 img_i2s_in_ch_readl(struct img_i2s_in *i2s, u32 chan,
					u32 reg)
{
	return readl(i2s->channel_base + (chan * IMG_I2S_IN_CH_STRIDE) + reg);
}

static inline u32 img_i2s_in_ch_disable(struct img_i2s_in *i2s, u32 chan)
{
	u32 reg;

	reg = img_i2s_in_ch_readl(i2s, chan, IMG_I2S_IN_CH_CTL);
	reg &= ~IMG_I2S_IN_CH_CTL_ME_MASK;
	img_i2s_in_ch_writel(i2s, chan, reg, IMG_I2S_IN_CH_CTL);

	return reg;
}

static inline void img_i2s_in_ch_enable(struct img_i2s_in *i2s, u32 chan,
					u32 reg)
{
	reg |= IMG_I2S_IN_CH_CTL_ME_MASK;
	img_i2s_in_ch_writel(i2s, chan, reg, IMG_I2S_IN_CH_CTL);
}

static inline void img_i2s_in_flush(struct img_i2s_in *i2s,
		struct img_i2s_in_channel_set *cs)
{
	int i;
	u32 reg;

	for (i = cs->first_channel; i <= cs->last_channel; i++) {
		reg = img_i2s_in_ch_readl(i2s, i, IMG_I2S_IN_CH_CTL);
		reg |= IMG_I2S_IN_CH_CTL_FIFO_FLUSH_MASK;
		img_i2s_in_ch_writel(i2s, i, reg, IMG_I2S_IN_CH_CTL);
		reg &= ~IMG_I2S_IN_CH_CTL_FIFO_FLUSH_MASK;
		img_i2s_in_ch_writel(i2s, i, reg, IMG_I2S_IN_CH_CTL);
	}
}

static void img_i2s_in_do_multistart(struct img_i2s_in *i2s, u32 mask)
{
	int i;
	u32 reg;

	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if (mask & IMG_I2S_IN_CH_BIT(i2s, i)) {
			reg = img_i2s_in_ch_readl(i2s, i, IMG_I2S_IN_CH_CTL);
			reg |= IMG_I2S_IN_CH_CTL_ME_MASK;
			img_i2s_in_ch_writel(i2s, i, reg, IMG_I2S_IN_CH_CTL);
		}
	}
}

static void img_i2s_in_do_multistop(struct img_i2s_in *i2s, u32 mask)
{
	int i;
	u32 reg;

	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if (mask & IMG_I2S_IN_CH_BIT(i2s, i)) {
			reg = img_i2s_in_ch_readl(i2s, i, IMG_I2S_IN_CH_CTL);
			reg &= ~IMG_I2S_IN_CH_CTL_ME_MASK;
			img_i2s_in_ch_writel(i2s, i, reg, IMG_I2S_IN_CH_CTL);
		}
	}
}

static void img_i2s_in_multistart(struct img_i2s_in *i2s, u32 mask)
{
	int n = 0, i, first = -1, last;
	u32 reg, regb, regc, regd;

	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if (mask & IMG_I2S_IN_CH_BIT(i2s, i)) {
			n++;
			if (first == -1)
				first = i;
			last = i;
		}
	}

	if (n == 0) {
		return;
	} else if ((n == 1) || (!i2s->core_me)) {
		img_i2s_in_do_multistart(i2s, mask);
	} else {
		while (1) {
			regmap_update_bits(i2s->periph_regs,
					PERIPH_SAMPLE_CAPTURE,
					PERIPH_SAMPLE_CAPTURE_I2S_IN_MASK,
					PERIPH_SAMPLE_CAPTURE_I2S_IN_MASK);
			regmap_update_bits(i2s->periph_regs,
					PERIPH_SAMPLE_CAPTURE,
					PERIPH_SAMPLE_CAPTURE_I2S_IN_MASK,
					0);
			reg = img_i2s_in_ch_readl(i2s, first,
						IMG_I2S_IN_CH_SCNT);
			regb = img_i2s_in_ch_readl(i2s, last,
						IMG_I2S_IN_CH_SCNT);
			img_i2s_in_do_multistart(i2s, mask);
			regmap_update_bits(i2s->periph_regs,
					PERIPH_SAMPLE_CAPTURE,
					PERIPH_SAMPLE_CAPTURE_I2S_IN_MASK,
					PERIPH_SAMPLE_CAPTURE_I2S_IN_MASK);
			regmap_update_bits(i2s->periph_regs,
					PERIPH_SAMPLE_CAPTURE,
					PERIPH_SAMPLE_CAPTURE_I2S_IN_MASK,
					0);
			regc = img_i2s_in_ch_readl(i2s, first,
						IMG_I2S_IN_CH_SCNT);
			regd = img_i2s_in_ch_readl(i2s, last,
						IMG_I2S_IN_CH_SCNT);
			if ((regc - reg) == (regd - regb))
				break;
			img_i2s_in_do_multistop(i2s, mask);
		}
	}
}

static u32 img_i2s_in_get_mask_shared_dma_first_only(struct img_i2s_in *i2s,
							u32 mask)
{
	if (i2s->shared_dma_channels &&
			(mask & (1UL << (i2s->max_i2s_chan - 1)))) {
		mask &= ~(((1UL << i2s->shared_dma_channels) - 1) <<
			(i2s->max_i2s_chan - i2s->shared_dma_channels));
		mask |= 1UL << (i2s->max_i2s_chan - 1);
	}

	return mask;
}

static u32 img_i2s_in_get_mask_shared_dma_all(struct img_i2s_in *i2s,
							u32 mask)
{
	if (i2s->shared_dma_channels &&
			(mask & (1UL << (i2s->max_i2s_chan - 1)))) {
		mask |= ((1UL << i2s->shared_dma_channels) - 1) <<
			(i2s->max_i2s_chan - i2s->shared_dma_channels);
	}

	return mask;
}

static u32 img_i2s_in_get_mask_shared_dma_active_only(struct img_i2s_in *i2s,
							u32 mask)
{
	u32 active_channels = i2s->channel_sets[0].active_channels;

	if (i2s->shared_dma_channels &&
			(mask & (1UL << (i2s->max_i2s_chan - 1)))) {
		mask &= ~(((1UL << i2s->shared_dma_channels) - 1) <<
			(i2s->max_i2s_chan - i2s->shared_dma_channels));
		mask |= ((1UL << active_channels) - 1) <<
			(i2s->max_i2s_chan - active_channels);
	}

	return mask;
}

static int img_i2s_in_trigger(struct snd_pcm_substream *substream, int cmd,
	struct snd_soc_dai *dai)
{
	struct img_i2s_in *i2s = snd_soc_dai_get_drvdata(dai);
	u32 reg, mask;
	unsigned long flags;
	int ret = 0;
	struct img_i2s_in_channel_set *cs;
	struct img_i2s_in_channel_group *group;
	struct img_i2s_in_channel *ch;
	bool nostart = false;

	cs = &i2s->channel_sets[dai->id];
	ch = &i2s->channels[cs->first_channel];

	spin_lock_irqsave(&i2s->lock, flags);

	group = cs->group;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:

		if (cs->active)
			break;

		if (!group || group->stopping) {
			ret = -EINVAL;
			break;
		}

		group->active_channel_sets++;

		if (group->active_channel_sets == group->channel_sets) {
			mask = group->mask;
			mask = img_i2s_in_get_mask_shared_dma_active_only(i2s,
									mask);
			img_i2s_in_multistart(i2s, mask);
			group->stopping = true;
		} else {
			nostart = true;
		}

		if (!i2s->core_me && !nostart) {
			reg = img_i2s_in_readl(i2s, IMG_I2S_IN_CTL);
			reg |= IMG_I2S_IN_CTL_ME_MASK;
			img_i2s_in_writel(i2s, reg, IMG_I2S_IN_CTL);
			i2s->core_me = true;
		}

		i2s->active_channel_sets++;
		cs->active = true;

		break;

	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:

		if (!cs->active)
			break;

		if (!group) {
			ret = -EINVAL;
			break;
		}

		mask = IMG_I2S_IN_CS_MASK(i2s, cs);
		img_i2s_in_do_multistop(i2s, mask);

		i2s->active_channel_sets--;
		cs->active = false;
		group->active_channel_sets--;
		if (!group->active_channel_sets)
			group->stopping = false;

		if (!i2s->active_channel_sets) {
			reg = img_i2s_in_readl(i2s, IMG_I2S_IN_CTL);
			reg &= ~IMG_I2S_IN_CTL_ME_MASK;
			img_i2s_in_writel(i2s, reg, IMG_I2S_IN_CTL);
			i2s->core_me = false;
		}

		img_i2s_in_flush(i2s, cs);

		break;
	default:
		ret = -EINVAL;
	}

	spin_unlock_irqrestore(&i2s->lock, flags);

	return ret;
}

static int img_i2s_in_check_rate(struct img_i2s_in *i2s,
		unsigned int sample_rate, unsigned int frame_size,
		unsigned int *bclk_filter_enable,
		unsigned int *bclk_filter_value)
{
	unsigned int bclk_freq, cur_freq;

	bclk_freq = sample_rate * frame_size;

	cur_freq = clk_get_rate(i2s->clk_sys);

	if (cur_freq >= bclk_freq * 8) {
		*bclk_filter_enable = 1;
		*bclk_filter_value = 0;
	} else if (cur_freq >= bclk_freq * 7) {
		*bclk_filter_enable = 1;
		*bclk_filter_value = 1;
	} else if (cur_freq >= bclk_freq * 6) {
		*bclk_filter_enable = 0;
		*bclk_filter_value = 0;
	} else {
		dev_err(i2s->dev,
			"Sys clock rate %u insufficient for sample rate %u\n",
			cur_freq, sample_rate);
		return -EINVAL;
	}

	return 0;
}

static int img_i2s_in_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params, struct snd_soc_dai *dai)
{
	struct img_i2s_in *i2s = snd_soc_dai_get_drvdata(dai);
	unsigned int rate, channels, i2s_channels, frame_size;
	unsigned int bclk_filter_enable, bclk_filter_value;
	int i, ret = 0;
	u32 reg, control_reg, control_mask, chan_control_mask;
	u32 control_set = 0, chan_control_set = 0, max_chan;
	u32 channel_mask, mask, new_control_reg, new_reg;
	unsigned long flags;
	struct img_i2s_in_channel_set *cs;
	bool includes_shared = false;
	bool control_reg_diff = false;
	snd_pcm_format_t format;

	cs = &i2s->channel_sets[dai->id];

	rate = params_rate(params);
	format = params_format(params);
	channels = params_channels(params);
	i2s_channels = channels / 2;

	switch (format) {
	case SNDRV_PCM_FORMAT_S32_LE:
		frame_size = 64;
		chan_control_set |= IMG_I2S_IN_CH_CTL_SW_MASK;
		chan_control_set |= IMG_I2S_IN_CH_CTL_FW_MASK;
		chan_control_set |= IMG_I2S_IN_CH_CTL_PACKH_MASK;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
		frame_size = 64;
		chan_control_set |= IMG_I2S_IN_CH_CTL_SW_MASK;
		chan_control_set |= IMG_I2S_IN_CH_CTL_FW_MASK;
		break;
	case SNDRV_PCM_FORMAT_S16_LE:
		frame_size = 32;
		control_set |= IMG_I2S_IN_CTL_16PACK_MASK;
		chan_control_set |= IMG_I2S_IN_CH_CTL_16PACK_MASK;
		break;
	default:
		return -EINVAL;
	}

	max_chan = ((cs->last_channel - cs->first_channel) + 1) * 2;
	if ((channels < 2) || (channels > max_chan) || (channels % 2))
		return -EINVAL;

	ret = img_i2s_in_check_rate(i2s, rate, frame_size,
			&bclk_filter_enable, &bclk_filter_value);
	if (ret < 0)
		return ret;

	if (bclk_filter_enable)
		chan_control_set |= IMG_I2S_IN_CH_CTL_FEN_MASK;

	if (bclk_filter_value)
		chan_control_set |= IMG_I2S_IN_CH_CTL_FMODE_MASK;

	chan_control_mask = (u32)(~IMG_I2S_IN_CH_CTL_16PACK_MASK &
			~IMG_I2S_IN_CH_CTL_FEN_MASK &
			~IMG_I2S_IN_CH_CTL_FMODE_MASK &
			~IMG_I2S_IN_CH_CTL_SW_MASK &
			~IMG_I2S_IN_CH_CTL_FW_MASK &
			~IMG_I2S_IN_CH_CTL_PACKH_MASK);

	control_mask = ~IMG_I2S_IN_CTL_16PACK_MASK;

	channel_mask = i2s->clock_masters;
	if (!(IMG_I2S_IN_CH_BIT(i2s, cs->first_channel) & channel_mask))
		channel_mask = ~channel_mask;

	mask = 1UL << (i2s->max_i2s_chan - 1);

	includes_shared = (i2s->shared_dma_channels && (channel_mask & mask));

	spin_lock_irqsave(&i2s->lock, flags);

	/* See if the wrapper register needs to change */
	if (includes_shared) {
		if (cs->shared_dma) {
			control_set |= ((i2s_channels - 1) <<
				IMG_I2S_IN_CTL_ACTIVE_CH_SHIFT);
			control_mask &= ~IMG_I2S_IN_CTL_ACTIVE_CHAN_MASK;
		}

		control_reg = img_i2s_in_readl(i2s, IMG_I2S_IN_CTL);

		new_control_reg = (control_reg & control_mask) | control_set;

		/* If it does, and there are any active channels, fail */
		if (new_control_reg != control_reg) {
			if (i2s->active_channel_sets) {
				spin_unlock_irqrestore(&i2s->lock, flags);
				return -EBUSY;
			}
			control_reg_diff = true;
		}
	}

	/*
	 * Check that no individual registers need to change where the
	 * corresponding channel is active
	 */
	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if ((channel_mask & mask) && i2s->channels[i].set->active) {
			reg = img_i2s_in_ch_readl(i2s, i, IMG_I2S_IN_CH_CTL);
			new_reg = (reg & chan_control_mask) | chan_control_set;
			if (new_reg != reg) {
				spin_unlock_irqrestore(&i2s->lock, flags);
				return -EBUSY;
			}
		}
		mask >>= 1;
	}

	mask = 1UL << (i2s->max_i2s_chan - 1);

	if (control_reg_diff)
		img_i2s_in_writel(i2s, new_control_reg, IMG_I2S_IN_CTL);

	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if (channel_mask & mask) {
			reg = img_i2s_in_ch_readl(i2s, i, IMG_I2S_IN_CH_CTL);
			new_reg = (reg & chan_control_mask) | chan_control_set;
			if (new_reg != reg)
				img_i2s_in_ch_writel(i2s, i, new_reg,
						IMG_I2S_IN_CH_CTL);
		}
		mask >>= 1;
	}

	cs->active_channels = i2s_channels;

	spin_unlock_irqrestore(&i2s->lock, flags);

	return 0;
}

static int img_i2s_in_set_fmt(struct snd_soc_dai *dai, unsigned int fmt)
{
	struct img_i2s_in *i2s = snd_soc_dai_get_drvdata(dai);
	int i;
	u32 chan_control_mask, lrd_set = 0, blkp_set = 0, chan_control_set = 0;
	u32 reg, channel_mask, mask;
	struct img_i2s_in_channel_set *cs;
	unsigned long flags;

	cs = &i2s->channel_sets[dai->id];

	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:
		lrd_set |= IMG_I2S_IN_CH_CTL_LRD_MASK;
		break;
	case SND_SOC_DAIFMT_NB_IF:
		break;
	case SND_SOC_DAIFMT_IB_NF:
		lrd_set |= IMG_I2S_IN_CH_CTL_LRD_MASK;
		blkp_set |= IMG_I2S_IN_CH_CTL_BLKP_MASK;
		break;
	case SND_SOC_DAIFMT_IB_IF:
		blkp_set |= IMG_I2S_IN_CH_CTL_BLKP_MASK;
		break;
	default:
		return -EINVAL;
	}

	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:
		chan_control_set |= IMG_I2S_IN_CH_CTL_CLK_TRANS_MASK;
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		break;
	default:
		return -EINVAL;
	}

	switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBM_CFM:
		break;
	default:
		return -EINVAL;
	}

	chan_control_mask = (u32)~IMG_I2S_IN_CH_CTL_CLK_TRANS_MASK;

	channel_mask = i2s->clock_masters;
	if (!(IMG_I2S_IN_CH_BIT(i2s, cs->first_channel) & channel_mask))
		channel_mask = ~channel_mask;

	mask = 1UL << (i2s->max_i2s_chan - 1);

	spin_lock_irqsave(&i2s->lock, flags);

	if (i2s->active_channel_sets) {
		spin_unlock_irqrestore(&i2s->lock, flags);
		return -EBUSY;
	}

	/*
	 * BLKP and LRD must be set during separate register writes
	 */
	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if (mask & channel_mask) {
			reg = img_i2s_in_ch_readl(i2s, i, IMG_I2S_IN_CH_CTL);
			reg = (reg & chan_control_mask) | chan_control_set;
			img_i2s_in_ch_writel(i2s, i, reg, IMG_I2S_IN_CH_CTL);
			reg = (reg & ~IMG_I2S_IN_CH_CTL_BLKP_MASK) | blkp_set;
			img_i2s_in_ch_writel(i2s, i, reg, IMG_I2S_IN_CH_CTL);
			reg = (reg & ~IMG_I2S_IN_CH_CTL_LRD_MASK) | lrd_set;
			img_i2s_in_ch_writel(i2s, i, reg, IMG_I2S_IN_CH_CTL);
		}
		mask >>= 1;
	}

	spin_unlock_irqrestore(&i2s->lock, flags);

	return 0;
}

static const struct snd_soc_dai_ops img_i2s_in_dai_ops = {
	.trigger = img_i2s_in_trigger,
	.hw_params = img_i2s_in_hw_params,
	.set_fmt = img_i2s_in_set_fmt
};

static int img_i2s_in_group_info(struct snd_kcontrol *kcontrol,
					struct snd_ctl_elem_info *uinfo)
{
	struct snd_soc_dai *cpu_dai = snd_kcontrol_chip(kcontrol);
	struct img_i2s_in *i2s = snd_soc_dai_get_drvdata(cpu_dai);

	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = i2s->max_i2s_chan;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 1;

	return 0;
}

static int img_i2s_in_group_get(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_value *ucontrol, int group)
{
	struct snd_soc_dai *cpu_dai = snd_kcontrol_chip(kcontrol);
	struct img_i2s_in *i2s = snd_soc_dai_get_drvdata(cpu_dai);
	int i;
	u32 mask;
	unsigned long flags;

	spin_lock_irqsave(&i2s->lock, flags);

	mask = i2s->groups[group].mask;

	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if (mask & IMG_I2S_IN_CH_BIT(i2s, i))
			ucontrol->value.integer.value[i] = 1;
		else
			ucontrol->value.integer.value[i] = 0;
	}

	spin_unlock_irqrestore(&i2s->lock, flags);

	return 0;
}

static int img_i2s_in_group_get_a(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_value *ucontrol)
{
	return img_i2s_in_group_get(kcontrol, ucontrol, 0);
}

static int img_i2s_in_group_get_b(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_value *ucontrol)
{
	return img_i2s_in_group_get(kcontrol, ucontrol, 1);
}

static int img_i2s_in_group_set(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_value *ucontrol, int group)
{
	struct snd_soc_dai *cpu_dai = snd_kcontrol_chip(kcontrol);
	struct img_i2s_in *i2s = snd_soc_dai_get_drvdata(cpu_dai);
	int i;
	u32 mask, new_mask;
	unsigned long flags;

	new_mask = 0;
	for (i = 0; i < i2s->max_i2s_chan; i++)
		if (ucontrol->value.integer.value[i])
			new_mask |= IMG_I2S_IN_CH_BIT(i2s, i);

	/* Master must be present in group */
	if (!(new_mask & IMG_I2S_IN_CH_BIT(i2s, i2s->groups[group].master)))
		return -EINVAL;

	spin_lock_irqsave(&i2s->lock, flags);

	/* Members of the group must have the specified bclk/lrclk master */
	if (group) {
		if ((new_mask & i2s->clock_masters) != new_mask) {
			spin_unlock_irqrestore(&i2s->lock, flags);
			return -EINVAL;
		}
	} else {
		if ((new_mask & ~i2s->clock_masters) != new_mask) {
			spin_unlock_irqrestore(&i2s->lock, flags);
			return -EINVAL;
		}
	}

	mask = i2s->groups[group].mask;

	/* Check none of the channels currently in the group are active */
	if (i2s->groups[group].active_channel_sets) {
		spin_unlock_irqrestore(&i2s->lock, flags);
		return -EINVAL;
	}

	/*
	 * If one of the channels using the shared dma is present in the new
	 * group, all of the channels that use the shared dma must be present
	 */
	mask = img_i2s_in_get_mask_shared_dma_all(i2s, new_mask);
	if ((mask & new_mask) != mask) {
		spin_unlock_irqrestore(&i2s->lock, flags);
		return -EINVAL;
	}

	mask = i2s->groups[group].mask;

	for (i = 0; i < i2s->max_i2s_chan; i++)
		if (new_mask & IMG_I2S_IN_CH_BIT(i2s, i))
			i2s->channels[i].set->group = &i2s->groups[group];
		else if (mask & IMG_I2S_IN_CH_BIT(i2s, i))
			i2s->channels[i].set->group = NULL;

	i2s->groups[group].mask = new_mask;

	i2s->groups[group].channel_sets = 0;
	new_mask = img_i2s_in_get_mask_shared_dma_first_only(i2s, new_mask);
	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if (new_mask & IMG_I2S_IN_CH_BIT(i2s, i))
			i2s->groups[group].channel_sets++;
	}

	spin_unlock_irqrestore(&i2s->lock, flags);

	return 0;
}

static int img_i2s_in_group_set_a(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_value *ucontrol)
{
	return img_i2s_in_group_set(kcontrol, ucontrol, 0);
}

static int img_i2s_in_group_set_b(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_value *ucontrol)
{
	return img_i2s_in_group_set(kcontrol, ucontrol, 1);
}

static struct snd_kcontrol_new img_i2s_in_controls[] = {
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READWRITE,
		.iface = SNDRV_CTL_ELEM_IFACE_PCM,
		.name = "I2S In Group 1",
		.info = img_i2s_in_group_info,
		.get = img_i2s_in_group_get_a,
		.put = img_i2s_in_group_set_a
	},
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READWRITE,
		.iface = SNDRV_CTL_ELEM_IFACE_PCM,
		.name = "I2S In Group 2",
		.info = img_i2s_in_group_info,
		.get = img_i2s_in_group_get_b,
		.put = img_i2s_in_group_set_b
	},
};

static int img_i2s_in_dai_probe(struct snd_soc_dai *dai)
{
	struct img_i2s_in *i2s = snd_soc_dai_get_drvdata(dai);
	struct img_i2s_in_channel_set *cs;

	cs = &i2s->channel_sets[dai->id];

	snd_soc_dai_init_dma_data(dai, NULL, &cs->dma_data);

	if (!dai->id)
		snd_soc_add_dai_controls(dai, img_i2s_in_controls, 2);

	return 0;
}

static int img_i2s_in_dma_prepare_slave_config(struct snd_pcm_substream *st,
	struct snd_pcm_hw_params *params, struct dma_slave_config *sc)
{
	unsigned int i2s_channels = params_channels(params) / 2;
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct snd_dmaengine_dai_dma_data *dma_data;
	int ret;

	dma_data = snd_soc_dai_get_dma_data(rtd->cpu_dai, st);

	ret = snd_hwparams_to_dma_slave_config(st, params, sc);
	if (ret)
		return ret;

	sc->src_addr = dma_data->addr;
	sc->src_addr_width = dma_data->addr_width;
	sc->src_maxburst = 4 * i2s_channels;

	return 0;
}

static const struct snd_dmaengine_pcm_config img_i2s_in_dma_config = {
	.prepare_slave_config = img_i2s_in_dma_prepare_slave_config
};

static int img_i2s_in_probe(struct platform_device *pdev)
{
	struct img_i2s_in *i2s;
	struct img_i2s_in_channel_set *cs;
	struct snd_soc_dai_driver *cd;
	struct resource *res;
	void __iomem *base;
	int ret, i;
	struct reset_control *rst;
	u32 reg, temp, mask, num_channel_sets;
	unsigned int max_i2s_chan_pow_2;
	struct device *dev = &pdev->dev;

	i2s = devm_kzalloc(dev, sizeof(*i2s), GFP_KERNEL);
	if (!i2s)
		return -ENOMEM;

	platform_set_drvdata(pdev, i2s);

	i2s->dev = dev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	base = devm_ioremap_resource(dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	i2s->base = base;

	if (of_property_read_u32(pdev->dev.of_node, "img,i2s-channels",
			&i2s->max_i2s_chan)) {
		dev_err(dev, "No img,i2s-channels property\n");
		return -EINVAL;
	}

	if (!i2s->max_i2s_chan)
		return -EINVAL;

	max_i2s_chan_pow_2 = 1 << get_count_order(i2s->max_i2s_chan);

	i2s->channel_base = base + (max_i2s_chan_pow_2 * 0x20);

	i2s->periph_regs = syscon_regmap_lookup_by_phandle(pdev->dev.of_node,
							    "img,cr-periph");
	if (IS_ERR(i2s->periph_regs))
		return PTR_ERR(i2s->periph_regs);

	of_property_read_u32(pdev->dev.of_node, "img,clock-master",
			&i2s->clock_masters);

	i2s->clock_masters <<= 2;

	if (of_property_read_u32(pdev->dev.of_node, "img,shared-dma",
			&i2s->shared_dma_channels)) {
		i2s->shared_dma_channels = i2s->max_i2s_chan;
	}

	if (i2s->shared_dma_channels > i2s->max_i2s_chan) {
		dev_err(dev, "img,shared-dma must be <= img,i2s-channels\n");
		return -EINVAL;
	}

	mask = (1UL << i2s->shared_dma_channels) - 1;
	temp = (i2s->clock_masters >>
		(i2s->max_i2s_chan - i2s->shared_dma_channels)) & mask;

	if (temp && (temp != mask)) {
		dev_err(dev, "img,shared-dma channels must have the same clock-master\n");
		return -EINVAL;
	}

	if (i2s->clock_masters & ~0x3CUL) {
		dev_err(dev, "channels 4/5 cannot use MFIO11/MFIO12 for BCLK/LRCLK\n");
		return -EINVAL;
	}

	mask = 0x3F;
	if (i2s->clock_masters) {
		reg = 0x30;
		reg |= (i2s->clock_masters & 0x20) ? 0x1 : 0x0;
		reg |= (i2s->clock_masters & 0x10) ? 0x2 : 0x0;
		reg |= (i2s->clock_masters & 0x8) ? 0x4 : 0x0;
		reg |= (i2s->clock_masters & 0x4) ? 0x8 : 0x0;

	} else {
		reg = 0;
	}
	regmap_update_bits(i2s->periph_regs, PERIPH_I2S_IN_CLOCK_MASTER,
				mask, reg);

	i2s->clk_sys = devm_clk_get(dev, "sys");
	if (IS_ERR(i2s->clk_sys))
		return PTR_ERR(i2s->clk_sys);

	ret = clk_prepare_enable(i2s->clk_sys);
	if (ret)
		return ret;

	rst = devm_reset_control_get(dev, "rst");
	if (IS_ERR(rst)) {
		dev_dbg(dev, "No top level reset found\n");

		reg = img_i2s_in_readl(i2s, IMG_I2S_IN_CTL);
		reg &= ~IMG_I2S_IN_CTL_ME_MASK;
		img_i2s_in_writel(i2s, reg, IMG_I2S_IN_CTL);

		for (i = 0; i < i2s->max_i2s_chan; i++) {
			reg = img_i2s_in_ch_disable(i2s, i);
			reg |= IMG_I2S_IN_CH_CTL_FIFO_FLUSH_MASK;
			img_i2s_in_ch_writel(i2s, i, reg, IMG_I2S_IN_CH_CTL);
			reg &= ~IMG_I2S_IN_CH_CTL_FIFO_FLUSH_MASK;
			img_i2s_in_ch_writel(i2s, i, reg, IMG_I2S_IN_CH_CTL);
		}
	} else {
		reset_control_assert(rst);
		reset_control_deassert(rst);
	}

	img_i2s_in_writel(i2s, 0, IMG_I2S_IN_CTL);

	for (i = 0; i < i2s->max_i2s_chan; i++)
		img_i2s_in_ch_writel(i2s, i,
			(4 << IMG_I2S_IN_CH_CTL_CCDEL_SHIFT) |
			IMG_I2S_IN_CH_CTL_JUST_MASK |
			IMG_I2S_IN_CH_CTL_FW_MASK, IMG_I2S_IN_CH_CTL);

	spin_lock_init(&i2s->lock);

	num_channel_sets = i2s->max_i2s_chan - i2s->shared_dma_channels;
	if (i2s->shared_dma_channels)
		num_channel_sets++;

	i2s->channel_sets = devm_kzalloc(dev,
		sizeof(*i2s->channel_sets) * num_channel_sets, GFP_KERNEL);
	if (!i2s->channel_sets) {
		ret = -ENOMEM;
		goto err_clk_disable;
	}

	i2s->cpu_dais = devm_kzalloc(dev,
		sizeof(*i2s->cpu_dais) * num_channel_sets, GFP_KERNEL);
	if (!i2s->cpu_dais) {
		ret = -ENOMEM;
		goto err_clk_disable;
	}

	i2s->channels = devm_kzalloc(dev,
		sizeof(*i2s->channels) * i2s->max_i2s_chan, GFP_KERNEL);
	if (!i2s->channels) {
		ret = -ENOMEM;
		goto err_clk_disable;
	}

	i2s->groups = devm_kzalloc(dev, sizeof(*i2s->groups) * 2, GFP_KERNEL);
	if (!i2s->groups) {
		ret = -ENOMEM;
		goto err_clk_disable;
	}

	i2s->img_i2s_in_component.name = "img-i2s-in-component";

	cs = &i2s->channel_sets[0];
	cd = &i2s->cpu_dais[0];

	if (i2s->shared_dma_channels) {
		cd->probe = img_i2s_in_dai_probe;
		cd->capture.channels_min = 2;
		cd->capture.channels_max = 2 * i2s->shared_dma_channels;
		cd->capture.rates = SNDRV_PCM_RATE_8000_192000;
		cd->capture.formats = SNDRV_PCM_FMTBIT_S32_LE |
					SNDRV_PCM_FMTBIT_S24_LE |
					SNDRV_PCM_FMTBIT_S16_LE;
		cd->ops = &img_i2s_in_dai_ops;
		strcpy(cs->cpu_dai_name, "img-i2s-in-shared");
		cd->name = cs->cpu_dai_name;
		strcpy(cs->platform_name, "img-i2s-in-plat-shared");

		cs->first_channel = 0;
		cs->last_channel = i2s->shared_dma_channels - 1;

		cs->dma_data.addr = res->start + IMG_I2S_IN_RX_FIFO;
		cs->dma_data.addr_width = 4;

		cs->shared_dma = true;

		ret = devm_snd_dmaengine_pcm_register_id_name(dev,
				&img_i2s_in_dma_config, 0, 0,
				cs->platform_name);
		if (ret)
			goto err_clk_disable;

		for (i = 0; i < i2s->shared_dma_channels; i++)
			i2s->channels[i].set = cs;

		cs++;
		cd++;
	}

	for (i = i2s->shared_dma_channels; i < i2s->max_i2s_chan; i++) {
		cd->probe = img_i2s_in_dai_probe;
		cd->capture.channels_min = 2;
		cd->capture.channels_max = 2;
		cd->capture.rates = SNDRV_PCM_RATE_8000_192000;
		cd->capture.formats = SNDRV_PCM_FMTBIT_S32_LE |
				SNDRV_PCM_FMTBIT_S24_LE |
				SNDRV_PCM_FMTBIT_S16_LE;
		cd->ops = &img_i2s_in_dai_ops;
		sprintf(cs->cpu_dai_name, "img-i2s-in-%d", i);
		cd->name = cs->cpu_dai_name;
		sprintf(cs->platform_name, "img-i2s-in-plat-%d", i);

		cs->first_channel = i;
		cs->last_channel = i;

		sprintf(cs->dma_name, "rx%d", i);
		cs->dma_data.chan_name = cs->dma_name;
		cs->dma_data.addr = res->start + (max_i2s_chan_pow_2 * 0x20) +
					IMG_I2S_IN_CH_RX_FIFO(i);
		cs->dma_data.addr_width = 4;
		cs->dma_data.maxburst = 4;

		ret = devm_snd_dmaengine_pcm_register_id_name(dev, NULL,
				SND_DMAENGINE_PCM_FLAG_CUSTOM_CHANNEL_NAME,
				(i - i2s->shared_dma_channels) + 1,
				cs->platform_name);
		if (ret)
			goto err_clk_disable;

		i2s->channels[i].set = cs;

		cs++;
		cd++;
	}

	ret = devm_snd_soc_register_component(dev, &i2s->img_i2s_in_component,
					i2s->cpu_dais, num_channel_sets);
	if (ret)
		goto err_clk_disable;

	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if (~i2s->clock_masters & IMG_I2S_IN_CH_BIT(i2s, i))
			break;
	}

	if (i != i2s->max_i2s_chan) {
		i2s->groups[0].master = i;
		mask = IMG_I2S_IN_CH_BIT(i2s, i);
		mask = img_i2s_in_get_mask_shared_dma_all(i2s, mask);
		i2s->groups[0].mask = mask;
		i2s->groups[0].channel_sets = 1;
		i2s->channels[i].set->group = &i2s->groups[0];
	}

	for (i = 0; i < i2s->max_i2s_chan; i++) {
		if (i2s->clock_masters & IMG_I2S_IN_CH_BIT(i2s, i))
			break;
	}

	if (i != i2s->max_i2s_chan) {
		i2s->groups[1].master = i;
		mask = IMG_I2S_IN_CH_BIT(i2s, i);
		mask = img_i2s_in_get_mask_shared_dma_all(i2s, mask);
		i2s->groups[1].mask = mask;
		i2s->groups[1].channel_sets = 1;
		i2s->channels[i].set->group = &i2s->groups[1];
	}


	return 0;

err_clk_disable:
	clk_disable_unprepare(i2s->clk_sys);

	return ret;
}

static int img_i2s_in_dev_remove(struct platform_device *pdev)
{
	struct img_i2s_in *i2s = platform_get_drvdata(pdev);

	clk_disable_unprepare(i2s->clk_sys);

	return 0;
}

static const struct of_device_id img_i2s_in_of_match[] = {
	{ .compatible = "img,i2s-in" },
	{}
};
MODULE_DEVICE_TABLE(of, img_i2s_in_of_match);

static struct platform_driver img_i2s_in_driver = {
	.driver = {
		.name = "img-i2s-in",
		.of_match_table = img_i2s_in_of_match
	},
	.probe = img_i2s_in_probe,
	.remove = img_i2s_in_dev_remove
};
module_platform_driver(img_i2s_in_driver);

MODULE_AUTHOR("Damien Horsley <Damien.Horsley@imgtec.com>");
MODULE_DESCRIPTION("IMG I2S Input Driver");
MODULE_LICENSE("GPL v2");
