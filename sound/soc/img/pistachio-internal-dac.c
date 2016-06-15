/*
 * Pistachio internal dac driver
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
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <linux/mfd/syscon.h>

#include <sound/pcm_params.h>
#include <sound/soc.h>

#define CR_AUDIO_DAC_CTRL		0x40
#define CR_AUDIO_DAC_CTRL_MUTE_MASK	0x4
#define CR_AUDIO_DAC_CTRL_PWR_SEL_MASK	0x2
#define CR_AUDIO_DAC_CTRL_PWRDN_MASK	0x1

#define CR_AUDIO_DAC_GTI_CTRL			0x48
#define CR_AUDIO_DAC_GTI_CTRL_ADDR_SHIFT	0
#define CR_AUDIO_DAC_GTI_CTRL_ADDR_MASK		0xFFF
#define CR_AUDIO_DAC_GTI_CTRL_WE_MASK		0x1000
#define CR_AUDIO_DAC_GTI_CTRL_WDATA_SHIFT	13
#define CR_AUDIO_DAC_GTI_CTRL_WDATA_MASK	0x1FE000

#define	AUDIO_DAC_INTERNAL_REG_PWR		0x1

#define PISTACHIO_INTERNAL_DAC_FORMATS (SNDRV_PCM_FMTBIT_S24_LE |  \
					SNDRV_PCM_FMTBIT_S32_LE)

/* codec private data */
struct pistachio_internal_dac {
	spinlock_t lock;
	struct regmap *regmap;

	/* The mute state as set by alsa using the digital_mute callback */
	bool alsa_mute_state;
	/* The mute state as set by the userspace mute control */
	bool control_mute_state;
	/* The actual mute state is equal to an OR of the above */
};

static int pistachio_internal_dac_get_mute(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct pistachio_internal_dac *dac = snd_soc_codec_get_drvdata(codec);

	ucontrol->value.integer.value[0] = dac->control_mute_state;

	return 0;
}

static void pistachio_internal_dac_mute(struct pistachio_internal_dac *dac)
{
	u32 reg;

	if (dac->control_mute_state || dac->alsa_mute_state)
		reg = CR_AUDIO_DAC_CTRL_MUTE_MASK;
	else
		reg = 0;

	regmap_update_bits(dac->regmap, CR_AUDIO_DAC_CTRL,
			CR_AUDIO_DAC_CTRL_MUTE_MASK, reg);
}

static int pistachio_internal_dac_set_mute(struct snd_kcontrol *kcontrol,
				  struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct pistachio_internal_dac *dac = snd_soc_codec_get_drvdata(codec);
	unsigned long flags;

	spin_lock_irqsave(&dac->lock, flags);
	dac->control_mute_state = ucontrol->value.integer.value[0];
	pistachio_internal_dac_mute(dac);
	spin_unlock_irqrestore(&dac->lock, flags);

	return 0;
}

static const struct snd_kcontrol_new pistachio_internal_dac_snd_controls[] = {
	{
		.access = SNDRV_CTL_ELEM_ACCESS_READWRITE,
		.iface = SNDRV_CTL_ELEM_IFACE_PCM,
		.name = "Mute Switch",
		.info = snd_ctl_boolean_mono_info,
		.get = pistachio_internal_dac_get_mute,
		.put = pistachio_internal_dac_set_mute,
	}
};

static int pistachio_internal_dac_digital_mute(struct snd_soc_dai *dai,
						int mute)
{
	struct snd_soc_codec *codec = dai->codec;
	struct pistachio_internal_dac *dac = snd_soc_codec_get_drvdata(codec);
	unsigned long flags;

	spin_lock_irqsave(&dac->lock, flags);
	dac->alsa_mute_state = mute;
	pistachio_internal_dac_mute(dac);
	spin_unlock_irqrestore(&dac->lock, flags);

	return 0;
}

static const struct snd_soc_dapm_widget pistachio_internal_dac_widgets[] = {
	SND_SOC_DAPM_DAC("DAC", "Playback", SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_OUTPUT("AOUTL"),
	SND_SOC_DAPM_OUTPUT("AOUTR"),
};

static const struct snd_soc_dapm_route pistachio_internal_dac_routes[] = {
	{ "AOUTL", NULL, "DAC" },
	{ "AOUTR", NULL, "DAC" },
};

static void pistachio_internal_dac_reg_writel(struct regmap *top_regs,
						u32 val, u32 reg)
{
	regmap_update_bits(top_regs, CR_AUDIO_DAC_GTI_CTRL,
			CR_AUDIO_DAC_GTI_CTRL_ADDR_MASK,
			reg << CR_AUDIO_DAC_GTI_CTRL_ADDR_SHIFT);

	regmap_update_bits(top_regs, CR_AUDIO_DAC_GTI_CTRL,
			CR_AUDIO_DAC_GTI_CTRL_WDATA_MASK,
			val << CR_AUDIO_DAC_GTI_CTRL_WDATA_SHIFT);

	regmap_update_bits(top_regs, CR_AUDIO_DAC_GTI_CTRL,
			CR_AUDIO_DAC_GTI_CTRL_WE_MASK,
			CR_AUDIO_DAC_GTI_CTRL_WE_MASK);

	regmap_update_bits(top_regs, CR_AUDIO_DAC_GTI_CTRL,
			CR_AUDIO_DAC_GTI_CTRL_WE_MASK, 0);
}

static void pistachio_internal_dac_pwr_off(struct pistachio_internal_dac *dac)
{
	regmap_update_bits(dac->regmap, CR_AUDIO_DAC_CTRL,
		CR_AUDIO_DAC_CTRL_PWRDN_MASK,
		CR_AUDIO_DAC_CTRL_PWRDN_MASK);

	pistachio_internal_dac_reg_writel(dac->regmap, 0,
					AUDIO_DAC_INTERNAL_REG_PWR);

	msleep(10);
}

static void pistachio_internal_dac_pwr_on(struct pistachio_internal_dac *dac)
{
	pistachio_internal_dac_reg_writel(dac->regmap, 1,
					AUDIO_DAC_INTERNAL_REG_PWR);

	regmap_update_bits(dac->regmap, CR_AUDIO_DAC_CTRL,
			CR_AUDIO_DAC_CTRL_PWRDN_MASK, 0);
}

static const struct snd_soc_dai_ops pistachio_internal_dac_dac_dai_ops = {
	.digital_mute	= pistachio_internal_dac_digital_mute,
};

static struct snd_soc_dai_driver pistachio_internal_dac_dais[] = {
	{
		.name = "pistachio_internal_dac",
		.playback = {
			.stream_name = "Playback",
			.channels_min = 2,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = PISTACHIO_INTERNAL_DAC_FORMATS,
		},
		.ops = &pistachio_internal_dac_dac_dai_ops,
	},
};

static const struct snd_soc_codec_driver pistachio_internal_dac_driver = {
	.controls = pistachio_internal_dac_snd_controls,
	.num_controls = ARRAY_SIZE(pistachio_internal_dac_snd_controls),
	.dapm_widgets = pistachio_internal_dac_widgets,
	.num_dapm_widgets = ARRAY_SIZE(pistachio_internal_dac_widgets),
	.dapm_routes = pistachio_internal_dac_routes,
	.num_dapm_routes = ARRAY_SIZE(pistachio_internal_dac_routes),
};

static int pistachio_internal_dac_probe(struct platform_device *pdev)
{
	struct pistachio_internal_dac *dac;
	int ret;
	struct device *dev = &pdev->dev;

	dac = devm_kzalloc(dev,
		sizeof(*dac), GFP_KERNEL);

	if (dac == NULL)
		return -ENOMEM;

	spin_lock_init(&dac->lock);

	platform_set_drvdata(pdev, dac);

	dac->regmap = syscon_regmap_lookup_by_phandle(pdev->dev.of_node,
							    "img,cr-top");
	if (IS_ERR(dac->regmap))
		return PTR_ERR(dac->regmap);

	pistachio_internal_dac_pwr_off(dac);
	pistachio_internal_dac_pwr_on(dac);

	ret = snd_soc_register_codec(dev, &pistachio_internal_dac_driver,
			pistachio_internal_dac_dais,
			ARRAY_SIZE(pistachio_internal_dac_dais));
	if (ret) {
		dev_err(dev, "failed to register codec:%d\n", ret);
		return ret;
	}

	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);
	pm_runtime_idle(dev);

	return 0;
}

static int pistachio_internal_dac_remove(struct platform_device *pdev)
{
	snd_soc_unregister_codec(&pdev->dev);
	pm_runtime_disable(&pdev->dev);

	return 0;
}

#ifdef CONFIG_PM
static int pistachio_internal_dac_rt_resume(struct device *dev)
{
	struct pistachio_internal_dac *dac = dev_get_drvdata(dev);

	pistachio_internal_dac_pwr_on(dac);

	return 0;
}

static int pistachio_internal_dac_rt_suspend(struct device *dev)
{
	struct pistachio_internal_dac *dac = dev_get_drvdata(dev);

	pistachio_internal_dac_pwr_off(dac);

	return 0;
}
#endif

static const struct dev_pm_ops pistachio_internal_dac_pm_ops = {
	SET_RUNTIME_PM_OPS(pistachio_internal_dac_rt_suspend,
			pistachio_internal_dac_rt_resume, NULL)
};

static const struct of_device_id pistachio_internal_dac_of_match[] = {
	{ .compatible = "img,pistachio-internal-dac" },
	{}
};
MODULE_DEVICE_TABLE(of, pistachio_internal_dac_of_match);

static struct platform_driver pistachio_internal_dac_plat_driver = {
	.driver = {
		.name = "img-pistachio-internal-dac",
		.of_match_table = pistachio_internal_dac_of_match,
		.pm = &pistachio_internal_dac_pm_ops
	},
	.probe = pistachio_internal_dac_probe,
	.remove = pistachio_internal_dac_remove
};
module_platform_driver(pistachio_internal_dac_plat_driver);

MODULE_DESCRIPTION("Pistachio Internal DAC driver");
MODULE_AUTHOR("Damien Horsley <Damien.Horsley@imgtec.com>");
MODULE_LICENSE("GPL v2");
