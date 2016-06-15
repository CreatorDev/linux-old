/*
 * Pistachio audio card driver
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
#include <linux/device.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/of_gpio.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#include <linux/mfd/syscon.h>

#include <sound/jack.h>
#include <sound/soc.h>

#include <dt-bindings/sound/pistachio-bub-audio.h>

#include "pistachio-event-timer.h"

#define	PLL_RATE_8000_16000_32000_48000_96000_192000	147456000
#define	PLL_RATE_11025_22050_44100_64000_88200_176400	135475200
#define	PISTACHIO_MAX_DIV				256
#define	PISTACHIO_MIN_MCLK_FREQ				(135475200 / 256)

#define	PISTACHIO_CLOCK_MASTER_EXT	-1
#define	PISTACHIO_CLOCK_MASTER_LOOPBACK	-2

#define	PISTACHIO_MAX_I2S_CODECS	12

#define	PISTACHIO_MAX_FS_RATES	20

#define	PISTACHIO_I2S_MCLK_MAX_FREQ	200000000
#define	PISTACHIO_DAC_MCLK_MAX_FREQ	200000000

#define	PISTACHIO_INTERNAL_DAC_PREFIX	"internal-dac"

#define PISTACHIO_I2S_LOOPBACK_REG		0x88
#define PISTACHIO_I2S_LOOPBACK_CLK_MASK		0x3
#define PISTACHIO_I2S_LOOPBACK_CLK_SHIFT	0

#define PISTACHIO_I2S_LOOPBACK_CLK_NONE		0
#define PISTACHIO_I2S_LOOPBACK_CLK_MFIO		1
#define PISTACHIO_I2S_LOOPBACK_CLK_LOCAL	2

struct pistachio_start_at {
	enum pistachio_evt_enable enable;
	spinlock_t lock;
	struct snd_pcm_substream *substream;
	unsigned int dummy_frames;
};

struct pistachio_output {
	struct pistachio_start_at start_at;
	unsigned int active_rate;
};

struct pistachio_parallel_out {
	struct pistachio_output output;
	struct snd_soc_dai_link_component internal_dac;
};

struct pistachio_mclk {
	struct clk *mclk;
	unsigned int cur_rate;
	unsigned int min_rate;
	unsigned int max_rate;
};

struct pistachio_i2s_mclk {
	struct pistachio_mclk *mclk;
	unsigned int *fs_rates;
	unsigned int num_fs_rates;
};

struct pistachio_codec_i2s {
	struct pistachio_mclk *mclk;
	struct snd_soc_dai *dai;
	unsigned int mclk_index;
};

struct pistachio_i2s {
	struct pistachio_i2s_mclk mclk_a;
	struct pistachio_i2s_mclk mclk_b;
	struct pistachio_codec_i2s *codecs;
	struct snd_soc_dai_link_component *components;
	unsigned int num_codecs;
};

struct pistachio_i2s_out {
	struct pistachio_i2s i2s;
	struct pistachio_output output;
	struct device *cpu_dev;
};

struct pistachio_i2s_in {
	struct pistachio_i2s i2s;
	unsigned int active_rate;
	unsigned int fmt;
	int frame_master;
	int bitclock_master;
	struct device *cpu_dev;
};

struct pistachio_i2s_codec_info_s {
	const char *prefix;
	const char *dai_name;
	struct device_node *np;
	struct pistachio_mclk *mclk;
	unsigned int mclk_index;
};

struct pistachio_i2s_codec_info {
	unsigned int total_codecs;
	unsigned int unique_codecs;
	int bitclock_master_idx;
	int frame_master_idx;
	struct pistachio_i2s_codec_info_s codecs[PISTACHIO_MAX_I2S_CODECS];
};

struct pistachio_i2s_mclk_fs_info {
	unsigned int fs_rates[PISTACHIO_MAX_FS_RATES];
	unsigned int num_fs_rates;
};

struct pistachio_card {
	struct pistachio_output *spdif_out;
	struct pistachio_parallel_out *parallel_out;
	struct pistachio_i2s_out *i2s_out;
	struct pistachio_i2s_in *i2s_in;
	bool spdif_in;
	struct device_node *event_timer_np;
	struct pistachio_evt *event_timer;
	struct snd_soc_card card;
	struct snd_soc_jack hp_jack;
	struct snd_soc_jack_pin hp_jack_pin;
	struct snd_soc_jack_gpio hp_jack_gpio;
	unsigned int mute_gpio;
	bool mute_gpio_inverted;
	struct mutex rate_mutex;
	struct clk *audio_pll;
	unsigned int audio_pll_rate;
	struct pistachio_mclk i2s_mclk;
	struct pistachio_mclk dac_mclk;
	struct regmap *periph_regs;
	struct notifier_block i2s_clk_notifier;
	struct snd_ctl_elem_id *sample_rate_ids[PISTACHIO_EVT_MAX_SOURCES];
	struct snd_ctl_elem_id *phase_difference_id;
};

static void pistachio_card_set_mclk_codecs(struct pistachio_i2s *i2s,
			struct pistachio_mclk *mclk, unsigned int rate)
{
	int i;
	struct pistachio_codec_i2s *codec;

	for (i = 0; i < i2s->num_codecs; i++) {
		codec = &i2s->codecs[i];
		if (codec->mclk == mclk) {
			snd_soc_dai_set_sysclk(codec->dai, codec->mclk_index,
						rate, SND_SOC_CLOCK_IN);
		}
	}
}

static int pistachio_card_set_mclk(struct pistachio_card *pbc,
		struct pistachio_mclk *mclk, unsigned int rate)
{
	int ret;
	unsigned int old_rate = mclk->cur_rate;

	if (mclk->cur_rate != rate) {
		/*
		 * Set cur_rate before the clk_set_rate call to stop the i2s
		 * mclk rate change callback rejecting the change
		 */
		mclk->cur_rate = rate;
		ret = clk_set_rate(mclk->mclk, rate);
		if (ret) {
			mclk->cur_rate = old_rate;
			return ret;
		}
	}

	if (pbc->i2s_out)
		pistachio_card_set_mclk_codecs(&pbc->i2s_out->i2s, mclk, rate);

	if (pbc->i2s_in)
		pistachio_card_set_mclk_codecs(&pbc->i2s_in->i2s, mclk, rate);

	return 0;
}

static int pistachio_card_set_pll_rate(struct pistachio_card *pbc,
					unsigned int rate)
{
	int ret;
	unsigned int old_i2s_rate;

	/*
	 * If any active streams are currently using a clock derived
	 * from the audio pll, a pll rate change cannot take place
	 */
	if ((pbc->spdif_out && pbc->spdif_out->active_rate) ||
	(pbc->parallel_out && pbc->parallel_out->output.active_rate) ||
	(pbc->i2s_out && pbc->i2s_out->output.active_rate) ||
	(pbc->i2s_in && pbc->i2s_in->active_rate &&
	pbc->i2s_in->i2s.mclk_a.mclk))
		return -EBUSY;

	/*
	 * Set cur_rate before the clk_set_rate call to stop the i2s
	 * mclk rate change callback rejecting the change
	 */
	old_i2s_rate = pbc->i2s_mclk.cur_rate;
	pbc->i2s_mclk.cur_rate = rate / (pbc->audio_pll_rate / old_i2s_rate);

	ret = clk_set_rate(pbc->audio_pll, rate);

	if (ret) {
		pbc->i2s_mclk.cur_rate = old_i2s_rate;
	} else {
		pbc->audio_pll_rate = rate;
		pbc->dac_mclk.cur_rate = rate / (pbc->audio_pll_rate /
						 pbc->dac_mclk.cur_rate);
		pistachio_card_set_mclk(pbc, &pbc->i2s_mclk,
				pbc->i2s_mclk.cur_rate);
		pistachio_card_set_mclk(pbc, &pbc->dac_mclk,
				pbc->dac_mclk.cur_rate);
	}

	return ret;
}

static void pistachio_card_rate_err(struct pistachio_card *pbc,
	struct pistachio_i2s_mclk *mclk_a, struct pistachio_i2s_mclk *mclk_b,
	unsigned int rate_a, unsigned int rate_b)
{
	char *mclk_name, *dir_a, *dir_b;

	if (mclk_a->mclk == &pbc->i2s_mclk)
		mclk_name = "i2s";
	else
		mclk_name = "dac";

	if (pbc->i2s_out && ((mclk_a == &pbc->i2s_out->i2s.mclk_a) ||
			(mclk_a == &pbc->i2s_out->i2s.mclk_b))) {
		dir_a = "I2S out";
		dir_b = "I2S in";
	} else {
		dir_a = "I2S in";
		dir_b = "I2S out";
	}

	if (!mclk_b) {
		dev_err(pbc->card.dev,
			"No valid rate for mclk %s (%s sample rate %u)\n",
			mclk_name, dir_a, rate_a);
	} else {
		dev_err(pbc->card.dev,
			"No valid rate for mclk %s (%s sample rate %u, %s sample rate %u)\n",
			mclk_name, dir_a, rate_a, dir_b, rate_b);
	}
}

static int pistachio_card_get_optimal_mclk_rate(struct pistachio_card *pbc,
	struct pistachio_i2s_mclk *mclk_a, struct pistachio_i2s_mclk *mclk_b,
	unsigned int rate_a, unsigned int rate_b, unsigned int *p_mclk_rate)
{
	int i, j;
	unsigned int div, total_div, mclk_rate;

	/*
	 * If the current system clock rate has zero difference, do not
	 * change the rate. This ensures a rate set using the "I2S Rates"
	 * control will not be erroneously overridden by a hw_params call
	 */
	for (i = 0; i < mclk_a->num_fs_rates; i++)
		if ((mclk_a->mclk->cur_rate / mclk_a->fs_rates[i]) == rate_a)
			break;
	if (i != mclk_a->num_fs_rates) {
		if (mclk_b) {
			for (i = 0; i < mclk_b->num_fs_rates; i++)
				if ((mclk_b->mclk->cur_rate /
						mclk_b->fs_rates[i]) == rate_b)
					break;
			if (i != mclk_b->num_fs_rates) {
				*p_mclk_rate = mclk_a->mclk->cur_rate;
				return 0;
			}
		} else {
			*p_mclk_rate = mclk_a->mclk->cur_rate;
			return 0;
		}
	}

	total_div = pbc->audio_pll_rate / rate_a;

	for (i = 0; i < mclk_a->num_fs_rates; i++) {
		div = total_div / mclk_a->fs_rates[i];
		if (div > PISTACHIO_MAX_DIV)
			continue;
		mclk_rate = pbc->audio_pll_rate / div;
		if ((mclk_rate < mclk_a->mclk->min_rate) ||
				(mclk_rate > mclk_a->mclk->max_rate))
			continue;
		if ((rate_a * mclk_a->fs_rates[i] * div) != pbc->audio_pll_rate)
			continue;

		if (!mclk_b)
			break;

		for (j = 0; j < mclk_b->num_fs_rates; j++) {
			if ((rate_b * mclk_b->fs_rates[j] * div) ==
					pbc->audio_pll_rate)
				break;
		}
		if (j != mclk_b->num_fs_rates)
			break;
	}

	if (i == mclk_a->num_fs_rates) {
		pistachio_card_rate_err(pbc, mclk_a, mclk_b, rate_a, rate_b);
		return -EINVAL;
	}

	*p_mclk_rate = mclk_rate;

	return 0;
}

static bool pistachio_card_mclk_active(struct pistachio_card *pbc,
					struct pistachio_mclk *mclk)
{
	if (pbc->i2s_out && pbc->i2s_out->output.active_rate) {
		if (pbc->i2s_out->i2s.mclk_a.mclk == mclk)
			return true;
		if (pbc->i2s_out->i2s.mclk_b.mclk == mclk)
			return true;
	}

	if (pbc->i2s_in && pbc->i2s_in->active_rate) {
		if (pbc->i2s_in->i2s.mclk_a.mclk == mclk)
			return true;
		if (pbc->i2s_in->i2s.mclk_b.mclk == mclk)
			return true;
	}

	return false;
}

static int pistachio_card_update_mclk(struct pistachio_card *pbc,
	struct pistachio_i2s_mclk *mclk_a, struct pistachio_i2s_mclk *mclk_b,
	unsigned int rate_a, unsigned int rate_b)
{
	unsigned int mclk_rate;
	int ret;

	ret = pistachio_card_get_optimal_mclk_rate(pbc, mclk_a, mclk_b, rate_a,
							rate_b, &mclk_rate);
	if (ret)
		return ret;

	if (mclk_a->mclk->cur_rate != mclk_rate) {
		if (pistachio_card_mclk_active(pbc, mclk_a->mclk))
			return -EBUSY;
		return pistachio_card_set_mclk(pbc, mclk_a->mclk, mclk_rate);
	}

	return 0;
}

static int pistachio_card_update_mclk_single(struct pistachio_card *pbc,
		struct pistachio_i2s_mclk *mclk, unsigned int rate)
{
	return pistachio_card_update_mclk(pbc, mclk, NULL, rate, 0);
}

static inline int pistachio_card_get_pll_rate(unsigned int rate)
{
	switch (rate) {
	case 8000:
	case 16000:
	case 32000:
	case 48000:
	case 96000:
	case 192000:
		return PLL_RATE_8000_16000_32000_48000_96000_192000;
	case 11025:
	case 22050:
	case 44100:
	case 64000:
	case 88200:
	case 176400:
		return PLL_RATE_11025_22050_44100_64000_88200_176400;
	default:
		return -EINVAL;
	}
}

static int _pistachio_card_change_rate(struct pistachio_card *pbc,
			unsigned int rate, struct pistachio_i2s *i2s)
{
	int ret = 0;
	unsigned int pll_rate;

	ret = pistachio_card_get_pll_rate(rate);
	if (ret < 0)
		return ret;

	pll_rate = ret;

	if (pbc->audio_pll_rate != pll_rate) {
		ret = pistachio_card_set_pll_rate(pbc, pll_rate);
		if (ret)
			return ret;
	}

	/*
	 * Nothing more to do if an mclk is not used. The individual
	 * cpu-dai drivers will make the required clock changes
	 */
	if (!i2s)
		return 0;

	ret = pistachio_card_update_mclk_single(pbc, &i2s->mclk_a, rate);
	if (ret)
		return ret;

	if (!i2s->mclk_b.mclk)
		return 0;

	return pistachio_card_update_mclk_single(pbc, &i2s->mclk_b, rate);
}

static int pistachio_card_change_rate(struct pistachio_card *pbc,
			unsigned int rate, struct pistachio_i2s *i2s,
			unsigned int *active_rate)
{
	int ret;

	mutex_lock(&pbc->rate_mutex);
	ret = _pistachio_card_change_rate(pbc, rate, i2s);
	if (!ret)
		*active_rate = rate;
	mutex_unlock(&pbc->rate_mutex);

	return ret;
}

static void pistachio_card_start_at_cb(struct pistachio_evt *evt,
					void *context)
{
	struct pistachio_start_at *sa = context;
	unsigned long flags;

	spin_lock_irqsave(&sa->lock, flags);

	if (!sa->substream) {
		spin_unlock_irqrestore(&sa->lock, flags);
		return;
	}

	snd_pcm_start_at_trigger(sa->substream);

	_pistachio_evt_disable_event(evt, sa->enable);

	sa->substream = NULL;

	spin_unlock_irqrestore(&sa->lock, flags);
}

static int pistachio_card_start_at(struct pistachio_output *output,
		struct pistachio_evt *evt, struct snd_pcm_substream *st,
		const struct timespec *ts)
{
	int ret;
	unsigned long flags;
	struct timespec ts_sub, ts_new;
	struct pistachio_start_at *sa = &output->start_at;
	u64 temp;

	/* Adjust start time to account for dummy frames output at start */
	temp = (u64)NSEC_PER_SEC * sa->dummy_frames;
	ts_sub.tv_sec = 0;
	ts_sub.tv_nsec = DIV_ROUND_CLOSEST_ULL(temp, output->active_rate);
	ts_new = timespec_sub(*ts, ts_sub);

	spin_lock_irqsave(&sa->lock, flags);

	ret = pistachio_evt_set_event(evt, sa->enable,
		PISTACHIO_EVT_TYPE_LEVEL, &ts_new,
		pistachio_card_start_at_cb, sa);
	if (!ret)
		sa->substream = st;

	spin_unlock_irqrestore(&sa->lock, flags);

	return ret;
}

static int pistachio_card_start_at_abort(struct pistachio_start_at *sa,
		struct pistachio_evt *evt, struct snd_pcm_substream *st)
{
	unsigned long flags;

	if (spin_trylock_irqsave(&sa->lock, flags)) {
		if (!sa->substream) {
			/* Already started */
			spin_unlock_irqrestore(&sa->lock, flags);
			return -EINVAL;
		}

		snd_pcm_start_at_cleanup(st);

		sa->substream = NULL;

		spin_unlock_irqrestore(&sa->lock, flags);

		pistachio_evt_disable_event(evt, sa->enable);
	} else {
		/* In the process of being started */
		spin_unlock_irqrestore(&sa->lock, flags);
		return -EINVAL;
	}

	return 0;
}

static int pistachio_card_i2s_link_init(struct pistachio_i2s *i2s,
					struct snd_soc_pcm_runtime *rtd)
{
	int ret, i, id;
	unsigned long rate;
	struct pistachio_codec_i2s *codec;

	for (i = 0; i < i2s->num_codecs; i++) {
		codec = &i2s->codecs[i];
		codec->dai = rtd->codec_dais[i];
		if (codec->mclk) {
			rate = codec->mclk->cur_rate;
			id = codec->mclk_index;
			ret = snd_soc_dai_set_sysclk(codec->dai, id, rate, 0);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static void pistachio_card_parallel_out_shutdown(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	pbc->parallel_out->output.active_rate = 0;
}

static int pistachio_card_parallel_out_hw_params(struct snd_pcm_substream *st,
				struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_change_rate(pbc, params_rate(params), NULL,
				&pbc->parallel_out->output.active_rate);
}

static int pistachio_card_parallel_out_start_at(struct snd_pcm_substream *st,
		int clock_type, const struct timespec *ts)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_start_at(&pbc->parallel_out->output,
					pbc->event_timer, st, ts);
}

static int pistachio_card_parallel_out_start_at_abort(
			struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_start_at_abort(
					&pbc->parallel_out->output.start_at,
					pbc->event_timer, st);
}

static struct snd_soc_ops pistachio_card_parallel_out_ops = {
	.shutdown = pistachio_card_parallel_out_shutdown,
	.hw_params = pistachio_card_parallel_out_hw_params,
	.start_at = pistachio_card_parallel_out_start_at,
	.start_at_abort = pistachio_card_parallel_out_start_at_abort
};

static void pistachio_card_spdif_out_shutdown(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	pbc->spdif_out->active_rate = 0;
}

static int pistachio_card_spdif_out_hw_params(struct snd_pcm_substream *st,
					struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_change_rate(pbc, params_rate(params), NULL,
					&pbc->spdif_out->active_rate);
}

static int pistachio_card_spdif_out_start_at(struct snd_pcm_substream *st,
		int clock_type, const struct timespec *ts)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_start_at(pbc->spdif_out, pbc->event_timer,
					st, ts);
}

static int pistachio_card_spdif_out_start_at_abort(
		struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_start_at_abort(&pbc->spdif_out->start_at,
						pbc->event_timer, st);
}

static struct snd_soc_ops pistachio_card_spdif_out_ops = {
	.shutdown = pistachio_card_spdif_out_shutdown,
	.hw_params = pistachio_card_spdif_out_hw_params,
	.start_at = pistachio_card_spdif_out_start_at,
	.start_at_abort = pistachio_card_spdif_out_start_at_abort
};

static int pistachio_card_i2s_clk_cb(struct notifier_block *nb,
					unsigned long event, void *data)
{
	struct clk_notifier_data *ndata = data;
	struct pistachio_card *pbc;
	unsigned int diff;
	u64 cur_rate;
	u64 tolerance;

	pbc = container_of(nb, struct pistachio_card, i2s_clk_notifier);

	cur_rate = pbc->i2s_mclk.cur_rate;

	switch (event) {
	case PRE_RATE_CHANGE:
		diff = abs(ndata->new_rate - cur_rate);
		tolerance = DIV_ROUND_CLOSEST_ULL(cur_rate * 5, 100);
		if (diff < tolerance) {
			/*
			 * Fractional adjustment made by atu, or new rate set
			 * by card driver if diff is zero
			 */
			return NOTIFY_OK;
		} else {
			/* Significant change made by i2s cpu dai driver */
			return NOTIFY_STOP;
		}
	case POST_RATE_CHANGE:
	case ABORT_RATE_CHANGE:
		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}
}

static int pistachio_card_i2s_out_link_init(struct snd_soc_pcm_runtime *rtd)
{
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	pbc->i2s_out->cpu_dev = rtd->cpu_dai->dev;

	return pistachio_card_i2s_link_init(&pbc->i2s_out->i2s, rtd);
}

static void pistachio_card_i2s_out_shutdown(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	pbc->i2s_out->output.active_rate = 0;
}

static int pistachio_card_i2s_out_hw_params(struct snd_pcm_substream *st,
				struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_change_rate(pbc, params_rate(params),
		&pbc->i2s_out->i2s, &pbc->i2s_out->output.active_rate);
}

static int pistachio_card_i2s_out_start_at(struct snd_pcm_substream *st,
		int clock_type, const struct timespec *ts)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_start_at(&pbc->i2s_out->output,
					pbc->event_timer, st, ts);
}

static int pistachio_card_i2s_out_start_at_abort(
		struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_start_at_abort(&pbc->i2s_out->output.start_at,
						pbc->event_timer, st);
}

static struct snd_soc_ops pistachio_card_i2s_out_ops = {
	.shutdown = pistachio_card_i2s_out_shutdown,
	.hw_params = pistachio_card_i2s_out_hw_params,
	.start_at = pistachio_card_i2s_out_start_at,
	.start_at_abort = pistachio_card_i2s_out_start_at_abort
};

static int pistachio_card_i2s_in_link_init(struct snd_soc_pcm_runtime *rtd)
{
	int ret, i;
	unsigned int fmt;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);
	u32 val;

	pbc->i2s_in->cpu_dev = rtd->cpu_dai->dev;

	ret = pistachio_card_i2s_link_init(&pbc->i2s_in->i2s, rtd);
	if (ret)
		return ret;

	fmt = pbc->i2s_in->fmt | SND_SOC_DAIFMT_CBM_CFM;
	ret = snd_soc_dai_set_fmt(rtd->cpu_dai, fmt);
	if (ret)
		return ret;

	for (i = 0; i < pbc->i2s_in->i2s.num_codecs; i++) {
		fmt = pbc->i2s_in->fmt;

		if (i == pbc->i2s_in->frame_master)
			if (i == pbc->i2s_in->bitclock_master)
				fmt |= SND_SOC_DAIFMT_CBM_CFM;
			else
				fmt |= SND_SOC_DAIFMT_CBS_CFM;
		else
			if (i == pbc->i2s_in->bitclock_master)
				fmt |= SND_SOC_DAIFMT_CBM_CFS;
			else
				fmt |= SND_SOC_DAIFMT_CBS_CFS;

		ret = snd_soc_dai_set_fmt(rtd->codec_dais[i], fmt);
		if (ret)
			return ret;
	}

	if (pbc->i2s_in->frame_master == PISTACHIO_CLOCK_MASTER_LOOPBACK)
		val = PISTACHIO_I2S_LOOPBACK_CLK_LOCAL;
	else
		val = PISTACHIO_I2S_LOOPBACK_CLK_NONE;

	regmap_update_bits(pbc->periph_regs, PISTACHIO_I2S_LOOPBACK_REG,
				PISTACHIO_I2S_LOOPBACK_CLK_MASK, val);

	return 0;
}

static void pistachio_card_i2s_in_shutdown(struct snd_pcm_substream *st)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	pbc->i2s_in->active_rate = 0;
}

static int pistachio_card_i2s_in_hw_params(struct snd_pcm_substream *st,
				struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = st->private_data;
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(rtd->card);

	return pistachio_card_change_rate(pbc, params_rate(params),
		&pbc->i2s_in->i2s, &pbc->i2s_in->active_rate);
}

static struct snd_soc_ops pistachio_card_i2s_in_ops = {
	.shutdown = pistachio_card_i2s_in_shutdown,
	.hw_params = pistachio_card_i2s_in_hw_params
};

static int pistachio_card_parse_of_spdif_out(struct device_node *node,
		struct pistachio_card *pbc, struct snd_soc_dai_link *link)
{
	struct device_node *np;

	pbc->spdif_out = devm_kzalloc(pbc->card.dev, sizeof(*pbc->spdif_out),
					GFP_KERNEL);
	if (!pbc->spdif_out)
		return -ENOMEM;

	pbc->spdif_out->start_at.enable = PISTACHIO_EVT_ENABLE_SPDIF_OUT;
	pbc->spdif_out->start_at.dummy_frames = 1;
	spin_lock_init(&pbc->spdif_out->start_at.lock);

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
		struct pistachio_card *pbc, struct snd_soc_dai_link *link)
{
	struct device_node *np;

	pbc->spdif_in = true;

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

static int pistachio_card_parse_of_parallel_out(struct device_node *node,
		struct pistachio_card *pbc, struct snd_soc_dai_link *link)
{
	struct device_node *np;
	int ret;

	pbc->parallel_out = devm_kzalloc(pbc->card.dev,
			sizeof(*pbc->parallel_out), GFP_KERNEL);
	if (!pbc->parallel_out)
		return -ENOMEM;

	pbc->parallel_out->output.start_at.enable =
			PISTACHIO_EVT_ENABLE_PARALLEL_OUT;
	pbc->parallel_out->output.start_at.dummy_frames = 2;
	spin_lock_init(&pbc->parallel_out->output.start_at.lock);

	link->name = link->stream_name = "pistachio-parallel-out";

	np = of_parse_phandle(node, "cpu-dai", 0);
	if (!np)
		return -EINVAL;

	link->cpu_of_node = np;
	link->platform_of_node = np;
	link->codecs = &pbc->parallel_out->internal_dac;
	np = of_parse_phandle(node, "sound-dai", 0);
	if (!np)
		return -EINVAL;
	link->codecs[0].of_node = np;
	link->num_codecs = 1;
	ret = snd_soc_of_get_dai_name(node, &link->codecs[0].dai_name);
	if (ret)
		return ret;

	link->ops = &pistachio_card_parallel_out_ops;

	return 0;
}

static int pistachio_card_parse_of_i2s_mclk(struct device_node *np,
	struct pistachio_mclk *mclk, struct pistachio_i2s_mclk_fs_info *fs)
{
	int ret, i, j, k, num_fs_rates;
	u32 min_freq, max_freq, fs_rates[PISTACHIO_MAX_FS_RATES];

	ret = of_property_read_u32(np, "mclk-min-freq", &min_freq);
	if (ret)
		return ret;
	ret = of_property_read_u32(np, "mclk-max-freq", &max_freq);
	if (ret)
		return ret;

	if (max_freq < PISTACHIO_MIN_MCLK_FREQ)
		return -EINVAL;
	if (min_freq > mclk->min_rate)
		mclk->min_rate = min_freq;
	if (max_freq < mclk->max_rate)
		mclk->max_rate = max_freq;
	if (mclk->min_rate > mclk->max_rate)
		return -EINVAL;

	num_fs_rates = of_property_count_u32_elems(np, "mclk-fs");
	if (num_fs_rates < 0)
		return num_fs_rates;
	if (!num_fs_rates || (num_fs_rates > PISTACHIO_MAX_FS_RATES))
		return -EINVAL;

	ret = of_property_read_u32_array(np, "mclk-fs", fs_rates,
						num_fs_rates);
	if (ret)
		return ret;

	/*
	 * If this is the first fs-rates list for this combination
	 * of {i2s direction, mclk}, this list defines the
	 * current fs-rate list for this combination. Else, this list
	 * subtracts any fs-rates that are not present in both lists from the
	 * current list for this combination
	 */
	if (!fs->num_fs_rates) {
		for (i = 0; i < num_fs_rates; i++)
			fs->fs_rates[i] = fs_rates[i];
		fs->num_fs_rates = num_fs_rates;
	} else {
		for (j = 0; j < fs->num_fs_rates; j++) {
			for (i = 0; i < num_fs_rates; i++)
				if (fs->fs_rates[j] == fs_rates[i])
					break;
			if (i == num_fs_rates) {
				for (k = j; k < (fs->num_fs_rates - 1); k++)
					fs->fs_rates[k] = fs->fs_rates[k + 1];
				fs->num_fs_rates--;
				if (!fs->num_fs_rates)
					return -EINVAL;
				j--;
			}
		}
	}

	return 0;
}

static int pistachio_card_parse_of_i2s_codecs(struct device_node *np,
			struct pistachio_card *pbc,
			struct pistachio_i2s_codec_info *codec_info,
			struct pistachio_i2s_mclk_fs_info *i2s_fs_info,
			struct pistachio_i2s_mclk_fs_info *dac_fs_info)
{
	int i, j, ret;
	struct device_node *subnode, *codec;
	struct pistachio_i2s_codec_info_s *info;
	u32 mclk_id;
	struct pistachio_mclk *mclk;
	struct pistachio_i2s_mclk_fs_info *fs_info;

	j = 0;
	for_each_child_of_node(np, subnode) {
		ret = of_property_read_u32(subnode, "mclk", &mclk_id);
		if (ret)
			return ret;

		switch (mclk_id) {
		case PISTACHIO_MCLK_I2S:
			mclk = &pbc->i2s_mclk;
			fs_info = i2s_fs_info;
			break;
		case PISTACHIO_MCLK_DAC:
			mclk = &pbc->dac_mclk;
			fs_info = dac_fs_info;
			break;
		case PISTACHIO_MCLK_NONE:
			mclk = NULL;
			break;
		default:
			ret = -EINVAL;
			goto err_subnode;
		}
		if (mclk) {
			ret = pistachio_card_parse_of_i2s_mclk(subnode, mclk,
								fs_info);
			if (ret)
				goto err_subnode;
		}

		codec = of_parse_phandle(subnode, "sound-dai", 0);
		if (!codec)
			continue;
		if (codec_info->total_codecs == PISTACHIO_MAX_I2S_CODECS) {
			ret = -EINVAL;
			of_node_put(codec);
			goto err_subnode;
		}
		for (i = 0; i < codec_info->total_codecs; i++)
			if (codec_info->codecs[i].np == codec)
				break;
		if (i == codec_info->total_codecs)
			codec_info->unique_codecs++;
		info = &codec_info->codecs[codec_info->total_codecs++];
		info->np = codec;
		info->prefix = subnode->name;
		ret = snd_soc_of_get_dai_name(subnode, &info->dai_name);
		if (ret)
			goto err_subnode;
		info->mclk = mclk;
		ret = of_property_read_u32(subnode, "mclk-index",
						&info->mclk_index);
		if (ret)
			info->mclk_index = 0;
		if (of_property_read_bool(subnode, "frame-master")) {
			if (codec_info->frame_master_idx != -1) {
				ret = -EINVAL;
				goto err_subnode;
			}
			codec_info->frame_master_idx = j;
		}
		if (of_property_read_bool(subnode, "bitclock-master")) {
			if (codec_info->bitclock_master_idx != -1) {
				ret = -EINVAL;
				goto err_subnode;
			}
			codec_info->bitclock_master_idx = j;
		}
		j++;
	}

	return 0;

err_subnode:
	of_node_put(subnode);
	return ret;
}

static int pistachio_card_parse_of_i2s_common(struct device_node *node,
	struct pistachio_card *pbc, struct pistachio_i2s *i2s,
	struct snd_soc_dai_link *link,
	struct pistachio_i2s_codec_info *codec_info,
	struct pistachio_i2s_mclk_fs_info *i2s_mclk_info,
	struct pistachio_i2s_mclk_fs_info *dac_mclk_info)
{
	int ret, i;
	unsigned int initial_codecs = codec_info->total_codecs, size;
	struct pistachio_i2s_codec_info_s *codecs;
	struct pistachio_i2s_mclk *mclk;

	codecs = &codec_info->codecs[initial_codecs];

	ret = pistachio_card_parse_of_i2s_codecs(node, pbc, codec_info,
					i2s_mclk_info, dac_mclk_info);
	i2s->num_codecs = codec_info->total_codecs - initial_codecs;
	if (ret)
		goto err_codec_info;

	mclk = &i2s->mclk_a;

	if (i2s_mclk_info->num_fs_rates) {
		mclk->mclk = &pbc->i2s_mclk;
		mclk->num_fs_rates = i2s_mclk_info->num_fs_rates;
		size = sizeof(*mclk->fs_rates) * mclk->num_fs_rates;
		mclk->fs_rates = devm_kzalloc(pbc->card.dev, size,
							GFP_KERNEL);
		if (!mclk->fs_rates) {
			ret = -ENOMEM;
			goto err_codec_info;
		}
		memcpy(mclk->fs_rates, i2s_mclk_info->fs_rates, size);
		mclk = &i2s->mclk_b;
	}

	if (dac_mclk_info->num_fs_rates) {
		mclk->mclk = &pbc->dac_mclk;
		mclk->num_fs_rates = dac_mclk_info->num_fs_rates;
		size = sizeof(*mclk->fs_rates) * mclk->num_fs_rates;
		mclk->fs_rates = devm_kzalloc(pbc->card.dev, size,
							GFP_KERNEL);
		if (!mclk->fs_rates) {
			ret = -ENOMEM;
			goto err_codec_info;
		}
		memcpy(mclk->fs_rates, dac_mclk_info->fs_rates, size);
	}

	if (!i2s->num_codecs) {
		link->codec_dai_name = "snd-soc-dummy-dai";
		link->codec_name = "snd-soc-dummy";
		return 0;
	}

	i2s->codecs = devm_kzalloc(pbc->card.dev,
		sizeof(*i2s->codecs) * i2s->num_codecs, GFP_KERNEL);
	if (!i2s->codecs) {
		ret = -ENOMEM;
		goto err_codec_info;
	}

	for (i = 0; i < i2s->num_codecs; i++) {
		i2s->codecs[i].mclk = codecs[i].mclk;
		i2s->codecs[i].mclk_index = codecs[i].mclk_index;
	}

	i2s->components = devm_kzalloc(pbc->card.dev,
		sizeof(*i2s->components) * i2s->num_codecs, GFP_KERNEL);
	if (!i2s->components) {
		ret = -ENOMEM;
		goto err_codec_info;
	}

	for (i = 0; i < i2s->num_codecs; i++) {
		i2s->components[i].dai_name = codecs[i].dai_name;
		i2s->components[i].of_node = codecs[i].np;
	}

	link->codecs = i2s->components;
	link->num_codecs = i2s->num_codecs;

	return 0;

err_codec_info:
	for (i = 0; i < i2s->num_codecs; i++)
		of_node_put(codecs[i].np);

	return ret;
}

static int pistachio_card_parse_of_i2s(struct device_node *i2s_out_np,
	struct device_node *i2s_in_np, struct pistachio_card *pbc,
	struct snd_soc_dai_link *links,
	struct pistachio_i2s_codec_info *codec_info,
	bool i2s_loopback)
{
	int ret;
	struct device *dev = pbc->card.dev;
	unsigned int fmt;
	struct device_node *np;
	struct pistachio_i2s_mclk_fs_info i2s_mclk_info, dac_mclk_info;

	pbc->i2s_mclk.max_rate = PISTACHIO_I2S_MCLK_MAX_FREQ;
	pbc->dac_mclk.max_rate = PISTACHIO_DAC_MCLK_MAX_FREQ;

	codec_info->bitclock_master_idx = -1;
	codec_info->frame_master_idx = -1;

	if (i2s_out_np) {
		pbc->i2s_out = devm_kzalloc(dev, sizeof(*pbc->i2s_out),
						GFP_KERNEL);
		if (!pbc->i2s_out)
			return -ENOMEM;

		pbc->i2s_out->output.start_at.enable =
				PISTACHIO_EVT_ENABLE_I2S_OUT;
		pbc->i2s_out->output.start_at.dummy_frames = 1;
		spin_lock_init(&pbc->i2s_out->output.start_at.lock);

		links->name = links->stream_name = "pistachio-i2s-out";

		np = of_parse_phandle(i2s_out_np, "cpu-dai", 0);
		if (!np)
			return -EINVAL;

		links->cpu_of_node = np;
		links->platform_of_node = np;

		fmt = snd_soc_of_parse_daifmt(i2s_out_np, NULL, NULL, NULL);
		fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
		fmt |= SND_SOC_DAIFMT_CBS_CFS;
		links->dai_fmt = fmt;

		/*
		 * Internal i2s out controller uses i2s_mclk and
		 * accepts 256fs,384fs
		 */
		i2s_mclk_info.fs_rates[0] = 256;
		i2s_mclk_info.fs_rates[1] = 384;
		i2s_mclk_info.num_fs_rates = 2;
		dac_mclk_info.num_fs_rates = 0;

		ret = pistachio_card_parse_of_i2s_common(i2s_out_np, pbc,
				&pbc->i2s_out->i2s, links, codec_info,
				&i2s_mclk_info, &dac_mclk_info);
		if (ret)
			return ret;

		links->init = pistachio_card_i2s_out_link_init;
		links->ops = &pistachio_card_i2s_out_ops;

		links++;
	}

	if (i2s_in_np) {
		pbc->i2s_in = devm_kzalloc(dev, sizeof(*pbc->i2s_in),
						GFP_KERNEL);
		if (!pbc->i2s_in)
			return -ENOMEM;

		links->name = links->stream_name = "pistachio-i2s-in";

		np = of_parse_phandle(i2s_in_np, "cpu-dai", 0);
		if (!np)
			return -EINVAL;

		links->cpu_of_node = np;
		links->platform_of_node = np;

		fmt = snd_soc_of_parse_daifmt(i2s_in_np, NULL, NULL, NULL);
		fmt &= ~SND_SOC_DAIFMT_MASTER_MASK;
		pbc->i2s_in->fmt = fmt;

		i2s_mclk_info.num_fs_rates = 0;
		dac_mclk_info.num_fs_rates = 0;

		ret = pistachio_card_parse_of_i2s_common(i2s_in_np, pbc,
				&pbc->i2s_in->i2s, links, codec_info,
				&i2s_mclk_info, &dac_mclk_info);
		if (ret)
			return ret;

		if (i2s_loopback) {
			pbc->i2s_in->frame_master =
					PISTACHIO_CLOCK_MASTER_LOOPBACK;
			pbc->i2s_in->bitclock_master =
					PISTACHIO_CLOCK_MASTER_LOOPBACK;
		} else if ((codec_info->bitclock_master_idx == -1) ||
				(codec_info->frame_master_idx == -1)) {
			pbc->i2s_in->frame_master =
					PISTACHIO_CLOCK_MASTER_EXT;
			pbc->i2s_in->bitclock_master =
					PISTACHIO_CLOCK_MASTER_EXT;
		} else {
			pbc->i2s_in->frame_master =
					codec_info->frame_master_idx;
			pbc->i2s_in->bitclock_master =
					codec_info->bitclock_master_idx;
		}

		links->init = pistachio_card_i2s_in_link_init;

		/*
		 * If no mclks are used by i2s in, there is nothing for
		 * the ops callbacks to do, so leave this as NULL
		 */
		if (pbc->i2s_in->i2s.mclk_a.mclk)
			links->ops = &pistachio_card_i2s_in_ops;
	}

	return 0;
}

static int pistachio_card_parse_of_confs(struct pistachio_card *pbc,
			struct pistachio_i2s_codec_info *codec_info,
			struct snd_soc_dai_link *parallel_out)
{
	int i, j, n;
	unsigned int size;
	struct pistachio_i2s_codec_info_s *codecs;
	struct snd_soc_codec_conf *conf, *c;

	n = codec_info->unique_codecs;
	if (parallel_out)
		n++;
	codecs = codec_info->codecs;

	size = sizeof(*pbc->card.codec_conf) * n;
	pbc->card.codec_conf = devm_kzalloc(pbc->card.dev, size, GFP_KERNEL);
	if (!pbc->card.codec_conf)
		return -ENOMEM;

	conf = pbc->card.codec_conf;

	for (i = 0; i < codec_info->total_codecs; i++) {
		for (j = 0; j < i; j++)
			if (codecs[j].np == codecs[i].np)
				break;
		if (j == i) {
			conf->of_node = codecs[i].np;
			conf->name_prefix = codecs[i].prefix;
			conf++;
		}
	}

	if (parallel_out) {
		conf->of_node = parallel_out->codecs[0].of_node;
		conf->name_prefix = PISTACHIO_INTERNAL_DAC_PREFIX;
	}

	pbc->card.num_configs = n;

	for (i = 0; i < n; i++) {
		conf = &pbc->card.codec_conf[i];
		for (j = i + 1; j < n; j++) {
			c = &pbc->card.codec_conf[j];
			if (!strcasecmp(conf->name_prefix, c->name_prefix)) {
				dev_err(pbc->card.dev, "Prefix clash: %s\n",
						conf->name_prefix);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static int pistachio_card_parse_of(struct device_node *node,
				struct pistachio_card *pbc)
{
	int ret = 0;
	struct device_node *spdif_out_np, *spdif_in_np, *parallel_out_np;
	struct device_node *i2s_out_np, *i2s_in_np, *event_np;
	struct snd_soc_dai_link *link, *prl_out = NULL;
	enum of_gpio_flags flags;
	struct pistachio_i2s_codec_info i2s_codec_info;
	bool i2s_loopback;

	pbc->periph_regs = syscon_regmap_lookup_by_phandle(node,
						"img,cr-periph");
	if (IS_ERR(pbc->periph_regs))
		return PTR_ERR(pbc->periph_regs);

	event_np = of_parse_phandle(node, "img,event-timer", 0);
	if (!event_np)
		return -EINVAL;
	pbc->event_timer_np = event_np;
	pbc->event_timer = pistachio_evt_get(event_np);
	if (IS_ERR(pbc->event_timer))
		return PTR_ERR(pbc->event_timer);

	if (of_property_read_bool(node, "img,widgets")) {
		ret = snd_soc_of_parse_audio_simple_widgets(&pbc->card,
					"img,widgets");
		if (ret)
			return ret;
	}

	if (of_property_read_bool(node, "img,routing")) {
		ret = snd_soc_of_parse_audio_routing(&pbc->card,
					"img,routing");
		if (ret)
			return ret;
	}

	spdif_out_np = of_get_child_by_name(node, "spdif-out");
	if (spdif_out_np)
		pbc->card.num_links++;

	spdif_in_np = of_get_child_by_name(node, "spdif-in");
	if (spdif_in_np)
		pbc->card.num_links++;

	parallel_out_np = of_get_child_by_name(node, "parallel-out");
	if (parallel_out_np)
		pbc->card.num_links++;

	i2s_out_np = of_get_child_by_name(node, "i2s-out");
	if (i2s_out_np)
		pbc->card.num_links++;

	i2s_in_np = of_get_child_by_name(node, "i2s-in");
	if (i2s_in_np)
		pbc->card.num_links++;

	i2s_loopback = of_property_read_bool(node, "img,i2s-clk-loopback");
	if (i2s_loopback && (!i2s_out_np || !i2s_in_np)) {
		ret = -EINVAL;
		goto end;
	}

	if (!pbc->card.num_links) {
		ret = -EINVAL;
		goto end;
	}

	pbc->card.dai_link = devm_kzalloc(pbc->card.dev,
		sizeof(*pbc->card.dai_link) * pbc->card.num_links, GFP_KERNEL);
	if (!pbc->card.dai_link) {
		ret = -ENOMEM;
		goto end;
	}

	i2s_codec_info.total_codecs = 0;
	i2s_codec_info.unique_codecs = 0;

	link = pbc->card.dai_link;

	if (spdif_out_np) {
		ret = pistachio_card_parse_of_spdif_out(spdif_out_np, pbc,
							link);
		if (ret)
			goto end;
		link++;
	}

	if (spdif_in_np) {
		ret = pistachio_card_parse_of_spdif_in(spdif_in_np, pbc,
							link);
		if (ret)
			goto end;
		link++;
	}

	if (parallel_out_np) {
		ret = pistachio_card_parse_of_parallel_out(parallel_out_np,
								pbc, link);
		if (ret)
			goto end;
		prl_out = link;
		link++;
	}

	if (i2s_out_np || i2s_in_np) {
		ret = pistachio_card_parse_of_i2s(i2s_out_np, i2s_in_np, pbc,
					link, &i2s_codec_info, i2s_loopback);
		if (ret)
			goto end;
	}

	ret = pistachio_card_parse_of_confs(pbc, &i2s_codec_info, prl_out);
	if (ret)
		goto end;

	pbc->hp_jack_gpio.gpio = of_get_named_gpio_flags(node,
					"img,hp-det-gpio", 0, &flags);
	pbc->hp_jack_gpio.invert = !!(flags & OF_GPIO_ACTIVE_LOW);
	if (pbc->hp_jack_gpio.gpio == -EPROBE_DEFER) {
		ret = -EPROBE_DEFER;
		goto end;
	}

	pbc->mute_gpio = of_get_named_gpio_flags(node, "img,mute-gpio", 0,
						&flags);
	pbc->mute_gpio_inverted = !!(flags & OF_GPIO_ACTIVE_LOW);
	if (pbc->mute_gpio_inverted == -EPROBE_DEFER) {
		ret = -EPROBE_DEFER;
		goto end;
	}

end:
	if (spdif_out_np)
		of_node_put(spdif_out_np);
	if (spdif_in_np)
		of_node_put(spdif_in_np);
	if (parallel_out_np)
		of_node_put(parallel_out_np);
	if (i2s_out_np)
		of_node_put(i2s_out_np);
	if (i2s_in_np)
		of_node_put(i2s_in_np);

	return ret;
}

static void pistachio_card_unref(struct pistachio_card *pbc)
{
	int i, j;
	struct snd_soc_dai_link *link;

	if (pbc->event_timer_np)
		of_node_put(pbc->event_timer_np);

	link = pbc->card.dai_link;
	if (!link)
		return;

	for (i = 0; i < pbc->card.num_links; i++, link++) {
		if (link->cpu_of_node)
			of_node_put(link->cpu_of_node);
		for (j = 0; j < link->num_codecs; j++)
			of_node_put(link->codecs[j].of_node);
	}
}

static int pistachio_card_init_clk(struct device *dev, char *name,
					struct clk **pclk)
{
	struct clk *clk;
	int ret;

	clk = devm_clk_get(dev, name);
	if (IS_ERR(clk))
		return PTR_ERR(clk);

	ret = clk_prepare_enable(clk);
	if (ret)
		return ret;

	*pclk = clk;

	return 0;
}

static int pistachio_card_init_rates(struct pistachio_card *pbc)
{
	unsigned int rate;
	int ret;

	rate = PLL_RATE_11025_22050_44100_64000_88200_176400;
	ret = clk_set_rate(pbc->audio_pll, rate);
	if (ret)
		return ret;
	pbc->audio_pll_rate = rate;

	rate = PISTACHIO_MIN_MCLK_FREQ;
	ret = clk_set_rate(pbc->i2s_mclk.mclk, rate);
	if (ret)
		return ret;
	pbc->i2s_mclk.cur_rate = rate;
	ret = clk_set_rate(pbc->dac_mclk.mclk, rate);
	if (ret)
		return ret;
	pbc->dac_mclk.cur_rate = rate;

	return 0;
}

static int pistachio_card_info_timespec(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_info *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 2;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = LONG_MAX;

	return 0;
}

static int pistachio_card_get_event_time(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *uc)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);
	struct timespec ts;

	pistachio_evt_get_time_ts(pbc->event_timer, &ts);

	uc->value.integer.value[0] = ts.tv_sec;
	uc->value.integer.value[1] = ts.tv_nsec;

	return 0;
}

static int pistachio_card_info_source(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_info *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 1;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = PISTACHIO_EVT_NUM_SOURCES - 1;

	return 0;
}

static int pistachio_card_set_source(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol,
				  int id)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);

	return pistachio_evt_set_source(pbc->event_timer, id,
		ucontrol->value.integer.value[0]);
}

static int pistachio_card_set_source_a(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	return pistachio_card_set_source(kcontrol, ucontrol, 0);
}

static int pistachio_card_set_source_b(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	return pistachio_card_set_source(kcontrol, ucontrol, 1);
}

static int pistachio_card_get_source(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol,
				  int id)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);
	enum pistachio_evt_source source;
	int ret;

	ret = pistachio_evt_get_source(pbc->event_timer, id, &source);

	if (!ret)
		ucontrol->value.integer.value[0] = source;

	return ret;
}

static int pistachio_card_get_source_a(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	return pistachio_card_get_source(kcontrol, ucontrol, 0);
}

static int pistachio_card_get_source_b(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	return pistachio_card_get_source(kcontrol, ucontrol, 1);
}

void pistachio_card_sample_rate_notify(int id, void *context)
{
	struct pistachio_card *pbc = context;

	if (pbc->sample_rate_ids[id])
		snd_ctl_notify(pbc->card.snd_card, SNDRV_CTL_EVENT_MASK_VALUE,
				pbc->sample_rate_ids[id]);
}

void pistachio_card_sample_rate_notify_a(void *context)
{
	pistachio_card_sample_rate_notify(0, context);
}

void pistachio_card_sample_rate_notify_b(void *context)
{
	pistachio_card_sample_rate_notify(1, context);
}

void pistachio_card_phase_difference_notify(void *context)
{
	struct pistachio_card *pbc = context;

	if (pbc->phase_difference_id)
		snd_ctl_notify(pbc->card.snd_card, SNDRV_CTL_EVENT_MASK_VALUE,
				pbc->phase_difference_id);
}

static int pistachio_card_get_sample_period(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol,
				  int id)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);
	int ret;
	u32 val, freq, nsec;
	u64 temp;

	pbc->sample_rate_ids[id] = &kcontrol->id;

	ret = pistachio_evt_get_sample_rate(pbc->event_timer, id, &val, &freq,
				pistachio_card_sample_rate_notify_a, pbc);

	if (!ret) {
		temp = ((u64)val * NSEC_PER_SEC) + (freq / 2);
		do_div(temp, freq);
		nsec = do_div(temp, NSEC_PER_SEC);
		ucontrol->value.integer.value[0] = temp;
		ucontrol->value.integer.value[1] = nsec;
	}

	return ret;
}

static int pistachio_card_get_sample_period_a(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	return pistachio_card_get_sample_period(kcontrol, ucontrol, 0);
}

static int pistachio_card_get_sample_period_b(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	return pistachio_card_get_sample_period(kcontrol, ucontrol, 1);
}

static int pistachio_card_info_sample_rate(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_info *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 1;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = LONG_MAX;

	return 0;
}

static int pistachio_card_get_sample_rate(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol,
				  int id)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);
	int ret;
	u32 val, freq, rate;

	pbc->sample_rate_ids[id] = &kcontrol->id;

	ret = pistachio_evt_get_sample_rate(pbc->event_timer, id, &val, &freq,
				pistachio_card_sample_rate_notify_b, pbc);

	if (!ret) {
		if (!val)
			return -EINVAL;
		rate = DIV_ROUND_CLOSEST(freq, val);
		ucontrol->value.integer.value[0] = rate;
	}

	return ret;
}

static int pistachio_card_get_sample_rate_a(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	return pistachio_card_get_sample_rate(kcontrol, ucontrol, 0);
}

static int pistachio_card_get_sample_rate_b(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	return pistachio_card_get_sample_rate(kcontrol, ucontrol, 1);
}

static int pistachio_card_get_phase_difference(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);
	int ret;
	u32 val, freq, nsec;
	u64 temp;

	pbc->phase_difference_id = &kcontrol->id;

	ret = pistachio_evt_get_phase_difference(pbc->event_timer, &val,
			&freq, pistachio_card_phase_difference_notify, pbc);

	if (!ret) {
		temp = ((u64)val * NSEC_PER_SEC) + (freq / 2);
		do_div(temp, freq);
		nsec = do_div(temp, NSEC_PER_SEC);
		ucontrol->value.integer.value[0] = temp;
		ucontrol->value.integer.value[1] = nsec;
	}

	return ret;
}

static int pistachio_card_get_mute(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);
	int ret;

	ret = gpio_get_value_cansleep(pbc->mute_gpio);
	if (ret < 0)
		return ret;
	else if (pbc->mute_gpio_inverted)
		ucontrol->value.integer.value[0] = !ret;
	else
		ucontrol->value.integer.value[0] = !!ret;

	return 0;
}

static int pistachio_card_set_mute(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);
	int val;

	if (pbc->mute_gpio_inverted)
		val = !ucontrol->value.integer.value[0];
	else
		val = ucontrol->value.integer.value[0];

	gpio_set_value_cansleep(pbc->mute_gpio, val);

	return 0;
}

static int pistachio_card_info_sample_rates(struct snd_kcontrol *kcontrol,
		struct snd_ctl_elem_info *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 2;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 192000;

	return 0;
}

static int pistachio_card_set_sample_rates_mclk(struct pistachio_card *pbc,
		struct pistachio_mclk *mclk, unsigned int i2s_out_rate,
		unsigned int i2s_in_rate)
{
	struct pistachio_i2s_mclk *mclk_a, *mclk_b;
	unsigned int rate_a, rate_b;
	int ret = 0;

	mclk_a = NULL;
	mclk_b = NULL;
	rate_a = i2s_out_rate;
	rate_b = i2s_in_rate;

	if (i2s_out_rate) {
		if (pbc->i2s_out->i2s.mclk_a.mclk == mclk)
			mclk_a = &pbc->i2s_out->i2s.mclk_a;
		else if (pbc->i2s_out->i2s.mclk_b.mclk == mclk)
			mclk_a = &pbc->i2s_out->i2s.mclk_b;
	}
	if (i2s_in_rate) {
		if (pbc->i2s_in->i2s.mclk_a.mclk == mclk)
			mclk_b = &pbc->i2s_in->i2s.mclk_a;
		else if (pbc->i2s_in->i2s.mclk_b.mclk == mclk)
			mclk_b = &pbc->i2s_in->i2s.mclk_b;
	}
	if (!mclk_a) {
		mclk_a = mclk_b;
		rate_a = rate_b;
		mclk_b = NULL;
	}

	if (mclk_a) {
		ret = pistachio_card_update_mclk(pbc, mclk_a, mclk_b, rate_a,
						rate_b);
	}

	return ret;
}

static int pistachio_card_set_sample_rates(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_card *card = snd_kcontrol_chip(kcontrol);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);
	int ret;
	unsigned int pll_rate, i2s_out_rate = 0, i2s_in_rate = 0;

	if (pbc->i2s_out)
		i2s_out_rate = ucontrol->value.integer.value[0];
	if (pbc->i2s_in && pbc->i2s_in->i2s.mclk_a.mclk)
		i2s_in_rate = ucontrol->value.integer.value[1];

	if (!i2s_out_rate && !i2s_in_rate)
		return 0;

	pll_rate = 0;

	if (i2s_out_rate) {
		ret = pistachio_card_get_pll_rate(i2s_out_rate);
		if (ret < 0)
			return ret;
		pll_rate = ret;
	}

	if (i2s_in_rate) {
		ret = pistachio_card_get_pll_rate(i2s_in_rate);
		if (ret < 0)
			return ret;
		if (pll_rate && (ret != pll_rate))
			return -EINVAL;
		pll_rate = ret;
	}

	mutex_lock(&pbc->rate_mutex);

	if (pbc->audio_pll_rate != pll_rate) {
		ret = pistachio_card_set_pll_rate(pbc, pll_rate);
		if (ret) {
			mutex_unlock(&pbc->rate_mutex);
			return ret;
		}
	}

	ret = pistachio_card_set_sample_rates_mclk(pbc, &pbc->i2s_mclk,
						i2s_out_rate, i2s_in_rate);
	if (ret) {
		mutex_unlock(&pbc->rate_mutex);
		return ret;
	}

	ret = pistachio_card_set_sample_rates_mclk(pbc, &pbc->dac_mclk,
						i2s_out_rate, i2s_in_rate);

	mutex_unlock(&pbc->rate_mutex);

	return ret;
}

static struct snd_kcontrol_new pistachio_controls[] = {
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READ |
			SNDRV_CTL_ELEM_ACCESS_VOLATILE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "Event Time",
		.info = pistachio_card_info_timespec,
		.get = pistachio_card_get_event_time
	},
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READWRITE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "Measurement Source A",
		.info = pistachio_card_info_source,
		.get = pistachio_card_get_source_a,
		.put = pistachio_card_set_source_a
	},
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READWRITE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "Measurement Source B",
		.info = pistachio_card_info_source,
		.get = pistachio_card_get_source_b,
		.put = pistachio_card_set_source_b
	},
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READ |
			SNDRV_CTL_ELEM_ACCESS_VOLATILE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "Sample Rate A",
		.info = pistachio_card_info_sample_rate,
		.get = pistachio_card_get_sample_rate_a,
	},
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READ |
			SNDRV_CTL_ELEM_ACCESS_VOLATILE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "Sample Rate B",
		.info = pistachio_card_info_sample_rate,
		.get = pistachio_card_get_sample_rate_b,
	},
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READ |
			SNDRV_CTL_ELEM_ACCESS_VOLATILE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "Sample Period A",
		.info = pistachio_card_info_timespec,
		.get = pistachio_card_get_sample_period_a,
	},
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READ |
			SNDRV_CTL_ELEM_ACCESS_VOLATILE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "Sample Period B",
		.info = pistachio_card_info_timespec,
		.get = pistachio_card_get_sample_period_b,
	},
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READ |
			SNDRV_CTL_ELEM_ACCESS_VOLATILE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "Phase Difference",
		.info = pistachio_card_info_timespec,
		.get = pistachio_card_get_phase_difference,
	},
	{
		.access = SNDRV_CTL_ELEM_ACCESS_WRITE,
		.iface = SNDRV_CTL_ELEM_IFACE_CARD,
		.name = "I2S Rates",
		.info = pistachio_card_info_sample_rates,
		.put = pistachio_card_set_sample_rates
	},
};

#ifdef DEBUG

static void pistachio_card_info_mclk(struct pistachio_card *pbc,
					struct pistachio_i2s_mclk *mclk)
{
	struct device *dev = pbc->card.dev;
	int i;

	dev_dbg(dev, "        Min Freq: %u\n", mclk->mclk->min_rate);
	dev_dbg(dev, "        Max Freq: %u\n", mclk->mclk->max_rate);
	dev_dbg(dev, "        FS Rates:\n");

	for (i = 0; i < mclk->num_fs_rates; i++)
		dev_dbg(dev, "            %u\n", mclk->fs_rates[i]);
}

static void pistachio_card_info_mclks(struct pistachio_card *pbc,
					struct pistachio_i2s *i2s)
{
	struct pistachio_i2s_mclk *i2s_mclk;
	struct pistachio_i2s_mclk *dac_mclk;
	struct device *dev = pbc->card.dev;

	if (i2s->mclk_a.mclk == &pbc->i2s_mclk)
		i2s_mclk = &i2s->mclk_a;
	else if (pbc->i2s_in->i2s.mclk_b.mclk == &pbc->i2s_mclk)
		i2s_mclk = &i2s->mclk_b;
	else
		i2s_mclk = NULL;

	if (i2s_mclk) {
		dev_dbg(dev, "    I2S MCLK\n");
		pistachio_card_info_mclk(pbc, i2s_mclk);
	} else {
		dev_dbg(dev, "    I2S MCLK NOT USED\n");
	}

	dev_dbg(dev, "\n");

	if (i2s->mclk_a.mclk == &pbc->dac_mclk)
		dac_mclk = &i2s->mclk_a;
	else if (i2s->mclk_b.mclk == &pbc->dac_mclk)
		dac_mclk = &i2s->mclk_b;
	else
		dac_mclk = NULL;

	if (dac_mclk) {
		dev_dbg(dev, "    DAC MCLK\n");
		pistachio_card_info_mclk(pbc, dac_mclk);
	} else {
		dev_dbg(dev, "    DAC MCLK NOT USED\n");
	}
}

static void pistachio_card_info_i2s_out(struct pistachio_card *pbc,
					struct snd_soc_dai_link *link)
{
	int i, j;
	struct snd_soc_dai_link_component *components;
	struct snd_soc_codec_conf *confs;
	struct device *dev = pbc->card.dev;
	char *text;

	components = pbc->i2s_out->i2s.components;
	confs = pbc->card.codec_conf;

	dev_dbg(dev, "I2S OUT\n");
	dev_dbg(dev, "\n");
	if (pbc->i2s_in && (pbc->i2s_in->frame_master ==
			PISTACHIO_CLOCK_MASTER_LOOPBACK))
		text = "(Dual Frame + Bit Clock Master)";
	else
		text = "(Frame + Bit Clock Master)";
	dev_dbg(dev, "    CPU DAI\n");
	dev_dbg(dev, "        i2s-out (%s) %s\n",
		link->cpu_of_node->name, text);
	dev_dbg(dev, "\n");
	dev_dbg(dev, "    CODECS\n");

	for (i = 0; i < pbc->i2s_out->i2s.num_codecs; i++) {
		for (j = 0; j < pbc->card.num_configs; j++)
			if (confs[j].of_node == components[i].of_node)
				break;

		dev_dbg(dev, "        %s (%s) (%s)\n", confs[j].name_prefix,
			confs[j].of_node->name,
			components[i].dai_name);
	}
	dev_dbg(dev, "\n");

	pistachio_card_info_mclks(pbc, &pbc->i2s_out->i2s);

	dev_dbg(dev, "\n");

	if ((link->dai_fmt & SND_SOC_DAIFMT_FORMAT_MASK) == SND_SOC_DAIFMT_I2S)
		text = "I2S";
	else
		text = "Left Justified";
	dev_dbg(dev, "    Format: %s\n", text);

	if ((link->dai_fmt & SND_SOC_DAIFMT_CLOCK_MASK) == SND_SOC_DAIFMT_CONT)
		text = "Yes";
	else
		text = "No";
	dev_dbg(dev, "    Continuous Clock: %s\n", text);

	dev_dbg(dev, "\n");
}

static void pistachio_card_info_i2s_in(struct pistachio_card *pbc,
					struct snd_soc_dai_link *link)
{
	int i, j;
	struct snd_soc_dai_link_component *components;
	struct snd_soc_codec_conf *confs;
	char *text;
	struct device *dev = pbc->card.dev;

	components = pbc->i2s_in->i2s.components;
	confs = pbc->card.codec_conf;

	dev_dbg(dev, "I2S IN\n");
	dev_dbg(dev, "\n");
	dev_dbg(dev, "    CPU DAI\n");
	dev_dbg(dev, "        i2s-in (%s)\n",
		link->cpu_of_node->name);
	dev_dbg(dev, "\n");
	dev_dbg(dev, "    CODECS\n");

	for (i = 0; i < pbc->i2s_out->i2s.num_codecs; i++) {
		for (j = 0; j < pbc->card.num_configs; j++)
			if (confs[j].of_node == components[i].of_node)
				break;

		if (i == pbc->i2s_in->frame_master)
			if (i == pbc->i2s_in->bitclock_master)
				text = "(Frame + Bit Clock Master)";
			else
				text = "(Frame Master)";
		else
			if (i == pbc->i2s_in->bitclock_master)
				text = "(Bitclock Master)";
			else
				text = "";

		dev_dbg(dev, "        %s (%s) (%s) %s\n", confs[j].name_prefix,
			confs[j].of_node->name,
			components[i].dai_name, text);
	}
	dev_dbg(dev, "\n");

	pistachio_card_info_mclks(pbc, &pbc->i2s_in->i2s);

	dev_dbg(dev, "\n");

	if ((pbc->i2s_in->fmt & SND_SOC_DAIFMT_FORMAT_MASK) ==
			SND_SOC_DAIFMT_I2S)
		text = "I2S";
	else
		text = "Left Justified";
	dev_dbg(dev, "    Format: %s\n", text);

	if ((pbc->i2s_in->fmt & SND_SOC_DAIFMT_CLOCK_MASK) ==
			SND_SOC_DAIFMT_CONT)
		text = "Yes";
	else
		text = "No";
	dev_dbg(dev, "    Continuous Clock: %s\n", text);

	dev_dbg(dev, "\n");
}

static void pistachio_card_info(struct pistachio_card *pbc)
{
	struct device *dev = pbc->card.dev;
	struct snd_soc_codec_conf *conf;
	struct snd_soc_dai_link *link;
	char *text;

	link = pbc->card.dai_link;

	dev_dbg(dev, "\n");
	dev_dbg(dev, "####################################################\n");
	dev_dbg(dev, "\n");
	dev_dbg(dev, "Pistachio Audio Card\n");
	dev_dbg(dev, "\n");

	if (pbc->spdif_out) {
		dev_dbg(dev, "SPDIF OUT\n");
		dev_dbg(dev, "\n");
		dev_dbg(dev, "    CPU DAI\n");
		dev_dbg(dev, "        spdif-out (%s)\n",
			link->cpu_of_node->name);
		dev_dbg(dev, "\n");
		link++;
	}
	if (pbc->spdif_in) {
		dev_dbg(dev, "SPDIF IN\n");
		dev_dbg(dev, "\n");
		dev_dbg(dev, "    CPU DAI\n");
		dev_dbg(dev, "        spdif-in (%s)\n",
			link->cpu_of_node->name);
		dev_dbg(dev, "\n");
		link++;
	}
	if (pbc->parallel_out) {
		dev_dbg(dev, "PARALLEL OUT\n");
		dev_dbg(dev, "\n");
		dev_dbg(dev, "    CPU DAI\n");
		dev_dbg(dev, "        parallel-out (%s)\n",
			link->cpu_of_node->name);
		dev_dbg(dev, "\n");
		dev_dbg(dev, "    CODECS\n");
		conf = &pbc->card.codec_conf[pbc->card.num_configs - 1];
		dev_dbg(dev, "        %s (%s) (%s)\n", conf->name_prefix,
			conf->of_node->name,
			pbc->parallel_out->internal_dac.dai_name);
		dev_dbg(dev, "\n");
		link++;
	}
	if (pbc->i2s_out) {
		pistachio_card_info_i2s_out(pbc, link);
		link++;
	}

	if (pbc->i2s_in)
		pistachio_card_info_i2s_in(pbc, link);

	if (gpio_is_valid(pbc->mute_gpio)) {
		if (pbc->mute_gpio_inverted)
			text = "(Active Low)";
		else
			text = "(Active High)";
		dev_dbg(dev, "Mute: GPIO %u %s\n", pbc->mute_gpio, text);
	}
	if (gpio_is_valid(pbc->hp_jack_gpio.gpio)) {
		if (pbc->hp_jack_gpio.invert)
			text = "(Active Low)";
		else
			text = "(Active High)";
		dev_dbg(dev, "Headphone-Detect: GPIO %u %s\n",
				pbc->hp_jack_gpio.gpio, text);
	}
	dev_dbg(dev, "\n");
	dev_dbg(dev, "####################################################\n");
	dev_dbg(dev, "\n");
}

#endif

static int pistachio_card_probe(struct platform_device *pdev)
{
	struct pistachio_card *pbc;
	struct device_node *np = pdev->dev.of_node;
	struct device *dev = &pdev->dev;
	int ret;
	unsigned long gpio_flags;
	struct snd_kcontrol_new *control;

	if (!np || !of_device_is_available(np))
		return -EINVAL;

	pbc = devm_kzalloc(dev, sizeof(*pbc), GFP_KERNEL);
	if (!pbc)
		return -ENOMEM;

	pbc->card.owner = THIS_MODULE;
	pbc->card.dev = dev;
	pbc->card.name = "pistachio-card";

	snd_soc_card_set_drvdata(&pbc->card, pbc);

	mutex_init(&pbc->rate_mutex);

	pbc->hp_jack_gpio.gpio = -ENOENT;
	pbc->mute_gpio = -ENOENT;

	ret = pistachio_card_parse_of(np, pbc);
	if (ret)
		goto err;

	ret = pistachio_card_init_clk(dev, "audio_pll", &pbc->audio_pll);
	if (ret)
		goto err;

	ret = pistachio_card_init_clk(dev, "i2s_mclk", &pbc->i2s_mclk.mclk);
	if (ret)
		goto err_clk_audio_pll;

	ret = pistachio_card_init_clk(dev, "dac_clk", &pbc->dac_mclk.mclk);
	if (ret)
		goto err_clk_i2s;

	ret = pistachio_card_init_rates(pbc);
	if (ret)
		goto err_clk_dac;

	pbc->i2s_clk_notifier.notifier_call = pistachio_card_i2s_clk_cb;
	ret = clk_notifier_register(pbc->i2s_mclk.mclk,
					&pbc->i2s_clk_notifier);
	if (ret)
		goto err_clk_dac;

	ret = devm_snd_soc_register_card(dev, &pbc->card);
	if (ret)
		goto err_notifier;

	ret = snd_soc_add_card_controls(&pbc->card, pistachio_controls,
					ARRAY_SIZE(pistachio_controls));
	if (ret)
		goto err_notifier;

	if (gpio_is_valid(pbc->hp_jack_gpio.gpio)) {
		pbc->hp_jack_pin.pin = "Headphones";
		pbc->hp_jack_pin.mask = SND_JACK_HEADPHONE;
		pbc->hp_jack_gpio.name = "Headphone detection";
		pbc->hp_jack_gpio.report = SND_JACK_HEADPHONE;
		pbc->hp_jack_gpio.debounce_time = 150;
		ret = snd_soc_card_jack_new(&pbc->card, "Headphones",
			SND_JACK_HEADPHONE, &pbc->hp_jack, &pbc->hp_jack_pin,
			1);
		if (ret)
			goto err_notifier;
		ret = snd_soc_jack_add_gpios(&pbc->hp_jack, 1,
				&pbc->hp_jack_gpio);
		if (ret)
			goto err_notifier;
	}

	if (gpio_is_valid(pbc->mute_gpio)) {
		if (pbc->mute_gpio_inverted)
			gpio_flags = GPIOF_OUT_INIT_HIGH;
		else
			gpio_flags = GPIOF_OUT_INIT_LOW;
		ret = gpio_request_one(pbc->mute_gpio, gpio_flags, "Mute");
		if (ret)
			goto err_jack;
		control = devm_kzalloc(dev, sizeof(*control), GFP_KERNEL);
		if (!control) {
			ret = -ENOMEM;
			goto err_mute;
		}
		control->access = SNDRV_CTL_ELEM_ACCESS_READWRITE;
		control->iface = SNDRV_CTL_ELEM_IFACE_CARD;
		control->name = "Mute Switch";
		control->info = snd_ctl_boolean_mono_info;
		control->get = pistachio_card_get_mute;
		control->put = pistachio_card_set_mute;
		ret = snd_soc_add_card_controls(&pbc->card, control, 1);
		if (ret)
			goto err_mute;
	}

#ifdef	DEBUG
	pistachio_card_info(pbc);
#endif

	return 0;

err_mute:
	if (gpio_is_valid(pbc->mute_gpio))
		gpio_free(pbc->mute_gpio);
err_jack:
	if (gpio_is_valid(pbc->hp_jack_gpio.gpio))
		snd_soc_jack_free_gpios(&pbc->hp_jack, 1, &pbc->hp_jack_gpio);
err_notifier:
	clk_notifier_unregister(pbc->i2s_mclk.mclk, &pbc->i2s_clk_notifier);
err_clk_dac:
	clk_disable_unprepare(pbc->dac_mclk.mclk);
err_clk_i2s:
	clk_disable_unprepare(pbc->i2s_mclk.mclk);
err_clk_audio_pll:
	clk_disable_unprepare(pbc->audio_pll);
err:
	pistachio_card_unref(pbc);

	return ret;
}

static int pistachio_card_remove(struct platform_device *pdev)
{
	struct snd_soc_card *card = platform_get_drvdata(pdev);
	struct pistachio_card *pbc = snd_soc_card_get_drvdata(card);

	pistachio_evt_abort_measurements(pbc->event_timer);
	if (gpio_is_valid(pbc->mute_gpio))
		gpio_free(pbc->mute_gpio);
	if (gpio_is_valid(pbc->hp_jack_gpio.gpio))
		snd_soc_jack_free_gpios(&pbc->hp_jack, 1, &pbc->hp_jack_gpio);
	clk_notifier_unregister(pbc->i2s_mclk.mclk, &pbc->i2s_clk_notifier);
	clk_disable_unprepare(pbc->dac_mclk.mclk);
	clk_disable_unprepare(pbc->i2s_mclk.mclk);
	clk_disable_unprepare(pbc->audio_pll);
	pistachio_card_unref(pbc);

	return 0;
}

static const struct of_device_id pistachio_card_of_match[] = {
	{ .compatible = "img,pistachio-audio" },
	{},
};
MODULE_DEVICE_TABLE(of, pistachio_card_of_match);

static struct platform_driver pistachio_card = {
	.driver = {
		.name = "pistachio-card",
		.of_match_table = pistachio_card_of_match,
	},
	.probe = pistachio_card_probe,
	.remove = pistachio_card_remove,
};
module_platform_driver(pistachio_card);

MODULE_DESCRIPTION("Pistachio audio card driver");
MODULE_AUTHOR("Damien Horsley <Damien.Horsley@imgtec.com>");
MODULE_LICENSE("GPL v2");
