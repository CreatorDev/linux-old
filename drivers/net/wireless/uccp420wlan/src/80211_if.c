/*
 * File Name  : 80211_if.c
 *
 * This file is the glue layer between net/mac80211 and UMAC
 *
 * Copyright (c) 2011, 2012, 2013, 2014 Imagination Technologies Ltd.
 * All rights reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/device.h>

#include <net/mac80211.h>
#include <net/cfg80211.h>
#include <net/ieee80211_radiotap.h>

#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/etherdevice.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>

#include "version.h"
#include "core.h"
#include "utils.h"

#include <linux/firmware.h>

#include <fwldr.h>

/* Its value will be the default mac address and it can only be updated with the
 * command line arguments
 */
unsigned int vht_support = 1;
module_param(vht_support, int, 0);
MODULE_PARM_DESC(vht_support, "Configure the 11ac support for this device");

static unsigned int ftm;
module_param(ftm, int, 0);
MODULE_PARM_DESC(ftm, "Factory Test Mode, should be used only for calibrations.");

unsigned int system_rev = 0x494D47; /*ASCII: IMG*/

static void uccp420_roc_complete_work(struct work_struct *work);
static void uccp420wlan_exit(void);
static int load_fw(struct ieee80211_hw *hw);

#define CHAN2G(_freq, _idx)  {		\
	.band = IEEE80211_BAND_2GHZ,	\
	.center_freq = (_freq),		\
	.hw_value = (_idx),		\
	.max_power = 20,		\
}

#define CHAN5G(_freq, _idx, _flags) {	\
	.band = IEEE80211_BAND_5GHZ,	\
	.center_freq = (_freq),		\
	.hw_value = (_idx),		\
	.max_power = 20,		\
	.flags = (_flags),		\
}

struct wifi_dev {
	struct proc_dir_entry *umac_proc_dir_entry;
	struct wifi_params params;
	struct wifi_stats stats;
	struct ieee80211_hw *hw;
};

static struct wifi_dev *wifi;

static struct ieee80211_channel dsss_chantable[] = {
	CHAN2G(2412, 0),  /* Channel 1 */
	CHAN2G(2417, 1),  /* Channel 2 */
	CHAN2G(2422, 2),  /* Channel 3 */
	CHAN2G(2427, 3),  /* Channel 4 */
	CHAN2G(2432, 4),  /* Channel 5 */
	CHAN2G(2437, 5),  /* Channel 6 */
	CHAN2G(2442, 6),  /* Channel 7 */
	CHAN2G(2447, 7),  /* Channel 8 */
	CHAN2G(2452, 8),  /* Channel 9 */
	CHAN2G(2457, 9),  /* Channel 10 */
	CHAN2G(2462, 10), /* Channel 11 */
	CHAN2G(2467, 11), /* Channel 12 */
	CHAN2G(2472, 12), /* Channel 13 */
	CHAN2G(2484, 13), /* Channel 14 */
};

static struct ieee80211_channel ofdm_chantable[] = {
	CHAN5G(5180, 14, 0), /* Channel 36 */
	CHAN5G(5200, 15, 0), /* Channel 40 */
	CHAN5G(5220, 16, 0), /* Channel 44 */
	CHAN5G(5240, 17, 0), /* Channel 48 */
	CHAN5G(5260, 18, IEEE80211_CHAN_RADAR), /* Channel 52 */
	CHAN5G(5280, 19, IEEE80211_CHAN_RADAR), /* Channel 56 */
	CHAN5G(5300, 20, IEEE80211_CHAN_RADAR), /* Channel 60 */
	CHAN5G(5320, 21, IEEE80211_CHAN_RADAR), /* Channel 64 */
	CHAN5G(5500, 22, IEEE80211_CHAN_RADAR), /* Channel 100 */
	CHAN5G(5520, 23, IEEE80211_CHAN_RADAR), /* Channel 104 */
	CHAN5G(5540, 24, IEEE80211_CHAN_RADAR), /* Channel 108 */
	CHAN5G(5560, 25, IEEE80211_CHAN_RADAR), /* Channel 112 */
	CHAN5G(5580, 26, IEEE80211_CHAN_RADAR), /* Channel 116 */
	CHAN5G(5600, 27, IEEE80211_CHAN_RADAR), /* Channel 120 */
	CHAN5G(5620, 28, IEEE80211_CHAN_RADAR), /* Channel 124 */
	CHAN5G(5640, 29, IEEE80211_CHAN_RADAR), /* Channel 128 */
	CHAN5G(5660, 30, IEEE80211_CHAN_RADAR), /* Channel 132 */
	CHAN5G(5680, 31, IEEE80211_CHAN_RADAR), /* Channel 136 */
	CHAN5G(5700, 32, IEEE80211_CHAN_RADAR), /* Channel 140 */
	CHAN5G(5720, 33, IEEE80211_CHAN_RADAR), /* Channel 144 */
	CHAN5G(5745, 34, 0), /* Channel 149 */
	CHAN5G(5765, 35, 0), /* Channel 153 */
	CHAN5G(5785, 36, 0), /* Channel 157 */
	CHAN5G(5805, 37, 0), /* Channel 161 */
	CHAN5G(5825, 38, 0), /* Channel 165 */
};

static struct ieee80211_rate dsss_rates[] = {
	{ .bitrate = 10, .hw_value = 2},
	{ .bitrate = 20, .hw_value = 4,
	.flags = IEEE80211_RATE_SHORT_PREAMBLE},
	{ .bitrate = 55, .hw_value = 11,
	.flags = IEEE80211_RATE_SHORT_PREAMBLE},
	{ .bitrate = 110, .hw_value = 22,
	.flags = IEEE80211_RATE_SHORT_PREAMBLE},
	{ .bitrate = 60, .hw_value = 12},
	{ .bitrate = 90, .hw_value = 18},
	{ .bitrate = 120, .hw_value = 24},
	{ .bitrate = 180, .hw_value = 36},
	{ .bitrate = 240, .hw_value = 48},
	{ .bitrate = 360, .hw_value = 72},
	{ .bitrate = 480, .hw_value = 96},
	{ .bitrate = 540, .hw_value = 108}
};

static struct ieee80211_rate ofdm_rates[] = {
	{ .bitrate = 60, .hw_value = 12},
	{ .bitrate = 90, .hw_value = 18},
	{ .bitrate = 120, .hw_value = 24},
	{ .bitrate = 180, .hw_value = 36},
	{ .bitrate = 240, .hw_value = 48},
	{ .bitrate = 360, .hw_value = 72},
	{ .bitrate = 480, .hw_value = 96},
	{ .bitrate = 540, .hw_value = 108}
};

static struct ieee80211_supported_band band_2ghz = {
	.channels = dsss_chantable,
	.n_channels = ARRAY_SIZE(dsss_chantable),
	.band = IEEE80211_BAND_2GHZ,
	.bitrates = dsss_rates,
	.n_bitrates = ARRAY_SIZE(dsss_rates),
};

static struct ieee80211_supported_band band_5ghz = {
	.channels = ofdm_chantable,
	.n_channels = ARRAY_SIZE(ofdm_chantable),
	.band = IEEE80211_BAND_5GHZ,
	.bitrates = ofdm_rates,
	.n_bitrates = ARRAY_SIZE(ofdm_rates),
};


/* Interface combinations for Virtual interfaces*/
static const struct ieee80211_iface_limit if_limit1[] = {
		{ .max = 2, .types = BIT(NL80211_IFTYPE_STATION)}
};

static const struct ieee80211_iface_limit if_limit2[] = {
		{ .max = 1, .types = BIT(NL80211_IFTYPE_STATION)},
		{ .max = 1, .types = BIT(NL80211_IFTYPE_AP) |
				     BIT(NL80211_IFTYPE_P2P_CLIENT) |
				     BIT(NL80211_IFTYPE_ADHOC) |
				     BIT(NL80211_IFTYPE_P2P_GO)}
};

static const struct ieee80211_iface_limit if_limit3[] = {
		{ .max = 2, .types = BIT(NL80211_IFTYPE_P2P_CLIENT)}
};

static const struct ieee80211_iface_limit if_limit4[] = {
		{ .max = 1, .types = BIT(NL80211_IFTYPE_ADHOC)},
		{ .max = 1, .types = BIT(NL80211_IFTYPE_P2P_CLIENT)}
};


static const struct ieee80211_iface_combination if_comb[] = {
	{ .limits = if_limit1,
	  .n_limits = ARRAY_SIZE(if_limit1),
	  .max_interfaces = 2,
	  .num_different_channels = 1},
	{ .limits = if_limit2,
	  .n_limits = ARRAY_SIZE(if_limit2),
	  .max_interfaces = 2,
	  .num_different_channels = 1},
	{ .limits = if_limit3,
	  .n_limits = ARRAY_SIZE(if_limit3),
	  .max_interfaces = 2,
	  .num_different_channels = 1},
	{ .limits = if_limit4,
	  .n_limits = ARRAY_SIZE(if_limit4),
	  .max_interfaces = 2,
	  .num_different_channels = 1}
};


/* For getting the dev pointer */
static struct class *hwsim_class;

static const struct wiphy_wowlan_support uccp_wowlan_support = {
	.flags = WIPHY_WOWLAN_ANY,
};

static int conv_str_to_byte(unsigned char *byte,
		     unsigned char *str,
		     int len)
{
	int  i, j = 0;
	unsigned char ch, val = 0;

	for (i = 0; i < (len * 2); i++) {
		/*convert to lower*/
		ch = ((str[i] >= 'A' && str[i] <= 'Z') ? str[i] + 32 : str[i]);

		if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f'))
			return -1;

		if (ch >= '0' && ch <= '9')  /*check is digit*/
			ch = ch - '0';
		else
			ch = ch - 'a' + 10;

		val += ch;

		if (!(i%2))
			val <<= 4;
		else {
			byte[j] = val;
			j++;
			val = 0;
		}
	}

	return 0;
}


static void tx(struct ieee80211_hw *hw,
	       struct ieee80211_tx_control *txctl,
	       struct sk_buff *skb)
{
	struct mac80211_dev *dev = hw->priv;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
	struct umac_vif *uvif;
	unsigned char null_bssid[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	struct iphdr *iphdr;
	unsigned char *pktgen_magic;
	unsigned int orig_pktgen_magic = 0x55e99bbe; /*Endianness 0xbe9be955*/
	struct umac_event_noa noa_event;

	if (tx_info->control.vif == NULL) {
		pr_debug("%s: Dropping injected TX frame\n",
			 dev->name);
		dev_kfree_skb_any(skb);
		return;
	}

	uvif = (struct umac_vif *)(tx_info->control.vif->drv_priv);

	if (wifi->params.production_test) {
		if (((hdr->frame_control &
		      IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_DATA) ||
		    (tx_info->control.vif == NULL))
			goto tx_status;

		iphdr = (struct iphdr *) skb_network_header(skb);
		if (iphdr->protocol == IPPROTO_UDP) {
			pktgen_magic = skb_transport_header(skb);
			pktgen_magic += sizeof(struct udphdr);
			/*If not PKTGEN, then drop it*/
			if (memcmp(pktgen_magic, &orig_pktgen_magic, 4) != 0) {
				pr_debug("%s:%d prod_mode: The pkt is NOT PKTGEN so dropping it\n",
					 __func__, __LINE__);
				goto tx_status;
			}
		} else {
			pr_debug("%s:%d prod_mode: The pkt is NOT PKTGEN so dropping it.\n",
				 __func__, __LINE__);
			goto tx_status;
		}
	}
	if (!memcmp(hdr->addr3, null_bssid, ETH_ALEN))
		goto tx_status;

	if ((dev->power_save == PWRSAVE_STATE_DOZE) &&
	    (((hdr->frame_control &
	      IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA) ||
		 is_bufferable_mgmt_frame(hdr)))
		hdr->frame_control |= IEEE80211_FCTL_PM;

	if (uvif->noa_active) {
		memset(&noa_event, 0, sizeof(noa_event));
		noa_event.if_index = uvif->vif_index;
		uccp420wlan_noa_event(FROM_TX, &noa_event, dev, skb);
		return;
	}

	uccp420wlan_tx_frame(skb, txctl->sta, dev, false);
	return;

tx_status:
	tx_info->flags |= IEEE80211_TX_STAT_ACK;
	tx_info->status.rates[0].count = 1;
	ieee80211_tx_status(hw, skb);
	return;
}

static int start(struct ieee80211_hw *hw)
{
	struct mac80211_dev *dev = (struct mac80211_dev *)hw->priv;

	if ((wifi->params.fw_loading == 1) && load_fw(hw)) {
		DEBUG_LOG("%s-80211IF: FW load failed\n", dev->name);
		return -ENODEV;
	}

	DEBUG_LOG("%s-80211IF: In start\n", dev->name);

	mutex_lock(&dev->mutex);
	if ((uccp420wlan_core_init(dev, ftm)) < 0) {
		DEBUG_LOG("%s-80211IF: umac init failed\n", dev->name);
		mutex_unlock(&dev->mutex);
		return -ENODEV;
	}
	INIT_DELAYED_WORK(&dev->roc_complete_work, uccp420_roc_complete_work);
	dev->state = STARTED;
	memset(dev->params->pdout_voltage, 0 ,
	       sizeof(char) * MAX_AUX_ADC_SAMPLES);
	mutex_unlock(&dev->mutex);

	return 0;
}

static void stop(struct ieee80211_hw *hw)
{
	struct mac80211_dev    *dev = (struct mac80211_dev *)hw->priv;

	DEBUG_LOG("%s-80211IF:In stop\n", dev->name);
	mutex_lock(&dev->mutex);
	uccp420wlan_core_deinit(dev, ftm);
	dev->state = STOPPED;
	mutex_unlock(&dev->mutex);

	hal_ops.reset_hal_params();

}

static int add_interface(struct ieee80211_hw *hw,
		struct ieee80211_vif *vif)
{
	struct mac80211_dev    *dev = hw->priv;
	struct ieee80211_vif *v;
	struct umac_vif   *uvif;
	int vif_index, iftype;

	iftype = vif->type;
	v = vif;
	vif->driver_flags |= IEEE80211_VIF_BEACON_FILTER;
	vif->driver_flags |= IEEE80211_VIF_SUPPORTS_UAPSD;

	if (!(iftype == NL80211_IFTYPE_STATION ||
				iftype == NL80211_IFTYPE_ADHOC ||
				iftype == NL80211_IFTYPE_AP)) {
		pr_err("Invalid Interface type\n");
		return -ENOTSUPP;
	}

	mutex_lock(&dev->mutex);

	if (wifi->params.production_test) {
		if (dev->active_vifs || iftype != NL80211_IFTYPE_ADHOC) {
			mutex_unlock(&dev->mutex);
			return -EBUSY;
		}
	}
	for (vif_index = 0; vif_index < wifi->params.num_vifs; vif_index++)
		if (dev->if_mac_addresses[vif_index].addr[5] == vif->addr[5])
			break;
	uvif = (struct umac_vif *)&v->drv_priv;
	uvif->vif_index = vif_index;
	uvif->vif = v;
	uvif->dev = dev;
	uvif->seq_no = 0;
	uccp420wlan_vif_add(uvif);
	dev->active_vifs |= (1 << vif_index);

	if (iftype == NL80211_IFTYPE_ADHOC)
		dev->tx_last_beacon = 0;

	rcu_assign_pointer(dev->vifs[vif_index], v);
	synchronize_rcu();

	mutex_unlock(&dev->mutex);

	return 0;
}

static void remove_interface(struct ieee80211_hw *hw,
		struct ieee80211_vif *vif)
{
	struct mac80211_dev    *dev = hw->priv;
	struct ieee80211_vif *v;
	int vif_index;
	v = vif;
	vif_index = ((struct umac_vif *)&v->drv_priv)->vif_index;

	mutex_lock(&dev->mutex);

	uccp420wlan_vif_remove((struct umac_vif *)&v->drv_priv);
	dev->active_vifs &= ~(1 << vif_index);
	rcu_assign_pointer(dev->vifs[vif_index], NULL);
	synchronize_rcu();

	mutex_unlock(&dev->mutex);

}


static int config(struct ieee80211_hw *hw,
		unsigned int changed)
{
	struct mac80211_dev *dev = hw->priv;
	struct ieee80211_conf *conf = &hw->conf;
	unsigned int pri_chnl_num;
	unsigned int chnl_num1;
	unsigned int chnl_num2;
	unsigned int freq_band;
	unsigned int ch_width;
	int center_freq = 0;
	int center_freq1 = 0;
	int i;
	int cf_offset;
	int is_vht_bw80;
	int is_vht_bw80_sec_40minus;
	int is_vht_bw80_sec_40plus;

	DEBUG_LOG("%s-80211IF:In config\n", dev->name);

	mutex_lock(&dev->mutex);

	if (changed & IEEE80211_CONF_CHANGE_POWER) {
		dev->txpower = conf->power_level;
		uccp420wlan_prog_txpower(dev->txpower);
	}

	/* Check for change in channel */
	if (changed & IEEE80211_CONF_CHANGE_CHANNEL) {
		center_freq = conf->chandef.chan->center_freq;
		center_freq1 = conf->chandef.center_freq1;
		cf_offset = center_freq1;

		pri_chnl_num = ieee80211_frequency_to_channel(center_freq);
		freq_band = conf->chandef.chan->band;

		ch_width = conf->chandef.width;

		DEBUG_LOG("%s-80211IF:Primary Channel is %d\n",
			       dev->name,
			       pri_chnl_num);

		if (wifi->params.production_test == 1) {

			if ((wifi->params.prod_mode_chnl_bw_40_mhz == 1) &&
			    (wifi->params.sec_ch_offset_40_minus == 1)) {
				/*  NL80211_CHAN_HT40MINUS */
				ch_width = 2;
				cf_offset = center_freq - 10;
			} else if (wifi->params.prod_mode_chnl_bw_40_mhz == 1) {
				/* NL80211_CHAN_HT40PLUS */
				ch_width = 2;
				cf_offset = center_freq + 10;
			}

			is_vht_bw80 = vht_support &&
				(wifi->params.prod_mode_chnl_bw_80_mhz == 1);

			is_vht_bw80_sec_40minus = is_vht_bw80 &&
				(wifi->params.sec_ch_offset_40_minus == 1);

			is_vht_bw80_sec_40plus = is_vht_bw80 &&
				(wifi->params.sec_ch_offset_40_plus == 1);

			if (is_vht_bw80)
				ch_width = 3;

			if (is_vht_bw80_sec_40minus &&
			    (wifi->params.sec_40_ch_offset_80_minus == 1))
				cf_offset = center_freq - 30;
			else if (is_vht_bw80_sec_40minus &&
				 (wifi->params.sec_40_ch_offset_80_plus == 1))
				cf_offset = center_freq + 10;
			else if (is_vht_bw80_sec_40minus)/* default */
				cf_offset = center_freq - 30;

			if (is_vht_bw80_sec_40plus &&
			    (wifi->params.sec_40_ch_offset_80_minus == 1))
				cf_offset = center_freq - 10;
			else if (is_vht_bw80_sec_40plus &&
				 (wifi->params.sec_40_ch_offset_80_plus == 1))
				cf_offset = center_freq + 30;
			else if (is_vht_bw80_sec_40plus)/* default */
				cf_offset = center_freq - 10;
		}

		chnl_num1 = ieee80211_frequency_to_channel(cf_offset);
		chnl_num2 = 0;

		/*Store the currrent Channel*/
		dev->cur_chan.pri_chnl_num = pri_chnl_num;
		dev->cur_chan.chnl_num1 = chnl_num1;
		dev->cur_chan.chnl_num2 = chnl_num2;
		dev->cur_chan.ch_width  = ch_width;
		dev->cur_chan.freq_band = freq_band;

		dev->chan_prog_done = 0;
		uccp420wlan_prog_channel(pri_chnl_num, chnl_num1, chnl_num2,
					 ch_width, freq_band);
	}

	/* Check for change in Power save state */

	for (i = 0; i < MAX_VIFS; i++) {

		if (!(changed & IEEE80211_CONF_CHANGE_PS))
			break;

		if (!(dev->active_vifs & (1 << i)))
			continue;

		/* When ROC is in progress, do not mess with
		 * PS state
		 */
		if (dev->roc_params.roc_in_progress)
			continue;

		if (wifi->params.disable_power_save)
			continue;

		if (conf->flags & IEEE80211_CONF_PS)
			dev->power_save = PWRSAVE_STATE_DOZE;
		else
			dev->power_save = PWRSAVE_STATE_AWAKE;

		DEBUG_LOG("%s-80211IF:PS state of VIF %d changed to %d\n",
			       dev->name,
			       i,
			       dev->power_save);

		uccp420wlan_prog_ps_state(i,
					  dev->if_mac_addresses[i].addr,
					  dev->power_save);
	}

	/* TODO: Make this global config as it effects all VIF's */
	for (i = 0; i < MAX_VIFS; i++) {

		if (!(changed & IEEE80211_CONF_CHANGE_SMPS))
			break;

		if (wifi->params.production_test == 1)
			break;

		if (!(dev->active_vifs & (1 << i)))
			continue;

		DEBUG_LOG("%s-80211IF:MIMO PS state of VIF %d -> %d\n",
			       dev->name,
			       i,
			       conf->smps_mode);

		uccp420wlan_prog_vif_smps(i,
					  dev->if_mac_addresses[i].addr,
					  conf->smps_mode);
	}

	/* Check for change in Retry Limits */
	if (changed & IEEE80211_CONF_CHANGE_RETRY_LIMITS) {

		DEBUG_LOG("%s-80211IF:Retry Limits changed to %d and %d\n",
			       dev->name,
			       conf->short_frame_max_tx_count,
			       conf->long_frame_max_tx_count);
	}

	for (i = 0; i < MAX_VIFS; i++) {

		if (!(changed & IEEE80211_CONF_CHANGE_RETRY_LIMITS))
			break;

		if (!(dev->active_vifs & (1 << i)))
			continue;

		uccp420wlan_prog_short_retry(i,
					     dev->if_mac_addresses[i].addr,
					     conf->short_frame_max_tx_count);
		uccp420wlan_prog_long_retry(i,
					    dev->if_mac_addresses[i].addr,
					    conf->long_frame_max_tx_count);
	}

	mutex_unlock(&dev->mutex);
	return 0;
}


static u64 prepare_multicast(struct ieee80211_hw *hw,
			     struct netdev_hw_addr_list *mc_list)
{
	struct mac80211_dev *dev = hw->priv;
	int i;
	struct netdev_hw_addr *ha;
	int mc_count = 0;

	if (dev->state != STARTED)
		return 0;

	mc_count = netdev_hw_addr_list_count(mc_list);
	{
		if (mc_count > MCST_ADDR_LIMIT) {
			mc_count = 0;
			pr_warn("%s-80211IF:Disabling MCAST filter (cnt=%d)\n",
				dev->name, mc_count);
			goto out;
		}
	}
	DEBUG_LOG("%s-80211IF:M-cast filter cnt adding:%d removing: %d\n",
			dev->name, mc_count, dev->mc_filter_count);

	if (dev->mc_filter_count > 0) {
		/* Remove all previous multicast addresses from the LMAC */
		for (i = 0; i < dev->mc_filter_count; i++)
			uccp420wlan_prog_mcast_addr_cfg(dev->mc_filters[i],
							WLAN_MCAST_ADDR_REM);
	}

	i = 0;

	netdev_hw_addr_list_for_each(ha, mc_list) {
		/* Prog the multicast address into the LMAC */
		uccp420wlan_prog_mcast_addr_cfg(ha->addr, WLAN_MCAST_ADDR_ADD);
		memcpy(dev->mc_filters[i], ha->addr, 6);
		i++;
	}

	dev->mc_filter_count = mc_count;
out:
	return mc_count;
}


static void configure_filter(struct ieee80211_hw *hw,
		unsigned int changed_flags,
		unsigned int *new_flags,
		u64 mc_count)
{
	struct mac80211_dev *dev = hw->priv;
	mutex_lock(&dev->mutex);

	changed_flags &= SUPPORTED_FILTERS;
	*new_flags &= SUPPORTED_FILTERS;

	if (dev->state != STARTED) {
		mutex_unlock(&dev->mutex);
		return;
	}

	if ((*new_flags & FIF_ALLMULTI) || (mc_count == 0)) {
		/* Disable the multicast filter in LMAC */
		DEBUG_LOG("%s-80211IF: Multicast filters disabled\n",
			       dev->name);
		uccp420wlan_prog_mcast_filter_control(MCAST_FILTER_DISABLE);
	} else if (mc_count) {
		/* Enable the multicast filter in LMAC */
		DEBUG_LOG("%s-80211IF: Multicast filters enabled\n",
			       dev->name);
		uccp420wlan_prog_mcast_filter_control(MCAST_FILTER_ENABLE);
	}

	if (changed_flags == 0)
		/* No filters which we support changed */
		goto out;

	if (wifi->params.production_test == 0) {
		if (*new_flags & FIF_BCN_PRBRESP_PROMISC) {
			/* Receive all beacons and probe responses */
			DEBUG_LOG("%s-80211IF: RCV ALL bcns\n",
				       dev->name);
			uccp420wlan_prog_rcv_bcn_mode(RCV_ALL_BCNS);
		} else {
			/* Receive only network beacons and probe responses */
			DEBUG_LOG("%s-80211IF: RCV NW bcns\n",
				       dev->name);
			uccp420wlan_prog_rcv_bcn_mode(RCV_ALL_NETWORK_ONLY);
		}
	}
out:
	if (wifi->params.production_test == 1) {
		DEBUG_LOG("%s-80211IF: RCV ALL bcns\n", dev->name);
		uccp420wlan_prog_rcv_bcn_mode(RCV_ALL_BCNS);
	}

	mutex_unlock(&dev->mutex);
	return;
}


static int conf_vif_tx(struct ieee80211_hw  *hw,
		struct ieee80211_vif *vif,
		unsigned short queue,
		const struct ieee80211_tx_queue_params *txq_params)
{
	struct mac80211_dev *dev = hw->priv;
	int vif_index, vif_active;
	struct edca_params params;

	for (vif_index = 0; vif_index < wifi->params.num_vifs; vif_index++)
		if (dev->if_mac_addresses[vif_index].addr[5] == vif->addr[5])
			break;

	vif_active = 0;

	if ((dev->active_vifs & (1 << vif_index)))
		vif_active = 1;

	memset(&params, 0, sizeof(params));
	params.aifs = txq_params->aifs;
	params.txop = txq_params->txop;
	params.cwmin = txq_params->cw_min;
	params.cwmax = txq_params->cw_max;
	params.uapsd = txq_params->uapsd;

	mutex_lock(&dev->mutex);
	uccp420wlan_vif_set_edca_params(queue,
					(struct umac_vif *)&vif->drv_priv,
					&params,
					vif_active);
	mutex_unlock(&dev->mutex);
	return 0;
}


static int set_key(struct ieee80211_hw *hw,
		   enum set_key_cmd cmd,
		   struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta,
		   struct ieee80211_key_conf *key_conf)
{

	struct umac_key sec_key;
	unsigned int result = 0;
	struct mac80211_dev *dev = hw->priv;
	unsigned int cipher_type, key_type;
	int vif_index;
	struct umac_vif *uvif;
	uvif = ((struct umac_vif *)&vif->drv_priv);

	memset(&sec_key, 0, sizeof(struct umac_key));

	switch (key_conf->cipher) {
	case WLAN_CIPHER_SUITE_WEP40:
		sec_key.key = key_conf->key;
		cipher_type = CIPHER_TYPE_WEP40;
		break;
	case WLAN_CIPHER_SUITE_WEP104:
		sec_key.key = key_conf->key;
		cipher_type = CIPHER_TYPE_WEP104;
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		key_conf->flags |= IEEE80211_KEY_FLAG_GENERATE_MMIC;
		/* We get the key in the following form:
		 * KEY (16 bytes) - TX MIC (8 bytes) - RX MIC (8 bytes)
		 */
		sec_key.key = key_conf->key;
		sec_key.tx_mic = key_conf->key + 16;
		sec_key.rx_mic = key_conf->key + 24;
		cipher_type = CIPHER_TYPE_TKIP;
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		sec_key.key = key_conf->key;
		cipher_type = CIPHER_TYPE_CCMP;
		break;
	default:
		result = -EOPNOTSUPP;
		mutex_unlock(&dev->mutex);
		goto out;
	}

	vif_index = ((struct umac_vif *)&vif->drv_priv)->vif_index;

	mutex_lock(&dev->mutex);

	if (cmd == SET_KEY) {
		key_conf->hw_key_idx = 0; /* Don't really use this */

		/* This flag indicate that it requires IV generation */
		key_conf->flags |= IEEE80211_KEY_FLAG_GENERATE_IV;


		if (cipher_type == CIPHER_TYPE_WEP40 ||
		    cipher_type == CIPHER_TYPE_WEP104) {
			DEBUG_LOG("%s-80211IF:ADD IF KEY.vif_index = %d\n",
				       dev->name,
				       vif_index);
			DEBUG_LOG("	keyidx = %d\n",
				       key_conf->keyidx);
			DEBUG_LOG("	cipher_type = %d\n",
				       cipher_type);

			uccp420wlan_prog_if_key(vif_index,
						vif->addr,
						KEY_CTRL_ADD,
						key_conf->keyidx,
						cipher_type,
						&sec_key);
		} else if (sta) {
			sec_key.peer_mac = sta->addr;

			if (key_conf->flags & IEEE80211_KEY_FLAG_PAIRWISE)
				key_type = KEY_TYPE_UCAST;
			else
				key_type = KEY_TYPE_BCAST;

			DEBUG_LOG("%s-80211IF:ADD PEER KEY.vif_index = %d",
				       dev->name, vif_index);
			DEBUG_LOG("	keyidx = %d, keytype = %d\n",
				       key_conf->keyidx, key_type);
			DEBUG_LOG("	cipher_type = %d\n",
				       cipher_type);

			uccp420wlan_prog_peer_key(vif_index,
						  vif->addr,
						  KEY_CTRL_ADD,
						  key_conf->keyidx,
						  key_type,
						  cipher_type,
						  &sec_key);
		} else {
			key_type = KEY_TYPE_BCAST;

			if (vif->type == NL80211_IFTYPE_STATION) {
				sec_key.peer_mac =
					(unsigned char *)vif->bss_conf.bssid;

				memcpy(uvif->bssid,
				       (vif->bss_conf.bssid),
				       ETH_ALEN);

				DEBUG_LOG("%s-80211IF: ADD PEER KEY\n",
					       dev->name);
				DEBUG_LOG("	vif_index = %d\n",
					       vif_index);
				DEBUG_LOG("	keyidx = %d\n",
					       key_conf->keyidx);
				DEBUG_LOG("	keytype = %d\n",
					       key_type);
				DEBUG_LOG("	cipher = %d\n",
					       cipher_type);

				uccp420wlan_prog_peer_key(vif_index,
							  vif->addr,
							  KEY_CTRL_ADD,
							  key_conf->keyidx,
							  key_type, cipher_type,
							  &sec_key);

			} else if (vif->type == NL80211_IFTYPE_AP) {
				DEBUG_LOG("%s-80211IF: ADD IF KEY.\n",
					       dev->name);
				DEBUG_LOG("	vif_index = %d\n",
					       vif_index);
				DEBUG_LOG("	keyidx = %d\n",
					       key_conf->keyidx);
				DEBUG_LOG("	cipher_type = %d\n",
					       cipher_type);

				uccp420wlan_prog_if_key(vif_index,
							vif->addr,
							KEY_CTRL_ADD,
							key_conf->keyidx,
							cipher_type,
							&sec_key);
			} else {
				/* ADHOC */
				DEBUG_LOG("%s-80211IF: ADD IF KEY.\n",
					       dev->name);
				DEBUG_LOG("	vif_index = %d\n",
					       vif_index);
				DEBUG_LOG("	keyidx = %d\n",
					       key_conf->keyidx);
				DEBUG_LOG("	cipher_type = %d\n",
					       cipher_type);

				uccp420wlan_prog_if_key(vif_index,
							vif->addr,
							KEY_CTRL_ADD,
							key_conf->keyidx,
							cipher_type,
							&sec_key);
			}
			}
	} else if (cmd == DISABLE_KEY) {
		if ((cipher_type == CIPHER_TYPE_WEP40) ||
		    (cipher_type == CIPHER_TYPE_WEP104)) {
			uccp420wlan_prog_if_key(vif_index,
						vif->addr,
						KEY_CTRL_DEL,
						key_conf->keyidx,
						cipher_type,
						&sec_key);
		} else if (sta) {
			sec_key.peer_mac = sta->addr;

			if (key_conf->flags & IEEE80211_KEY_FLAG_PAIRWISE)
				key_type = KEY_TYPE_UCAST;
			else
				key_type = KEY_TYPE_BCAST;

			uccp420wlan_prog_peer_key(vif_index,
						  vif->addr,
						  KEY_CTRL_DEL,
						  key_conf->keyidx,
						  key_type,
						  cipher_type,
						  &sec_key);
		} else {
			if (vif->type == NL80211_IFTYPE_STATION) {
				sec_key.peer_mac = uvif->bssid;

				uccp420wlan_prog_peer_key(vif_index,
							  vif->addr,
							  KEY_CTRL_DEL,
							  key_conf->keyidx,
							  KEY_TYPE_BCAST,
							  cipher_type,
							  &sec_key);

			} else if (vif->type == NL80211_IFTYPE_AP)
				uccp420wlan_prog_if_key(vif_index,
							vif->addr,
							KEY_CTRL_DEL,
							key_conf->keyidx,
							cipher_type,
							&sec_key);
			else
				uccp420wlan_prog_if_key(vif_index,
							vif->addr,
							KEY_CTRL_DEL,
							key_conf->keyidx,
							cipher_type,
							&sec_key);
		}
	}

	mutex_unlock(&dev->mutex);

out:
	return result;
}


static void bss_info_changed(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif,
			     struct ieee80211_bss_conf *bss_conf,
			     unsigned int changed)
{
	struct mac80211_dev   *dev = hw->priv;

	mutex_lock(&dev->mutex);

	if (wifi->params.production_test || wifi->params.disable_beacon_ibss) {
		/*Disable beacon generation when running pktgen
		 *for performance*/
		changed &= ~BSS_CHANGED_BEACON_INT;
		changed &= ~BSS_CHANGED_BEACON_ENABLED;
	}

	uccp420wlan_vif_bss_info_changed((struct umac_vif *)&vif->drv_priv,
					 bss_conf,
					 changed);
	mutex_unlock(&dev->mutex);

	return;
}


static void setup_ht_cap(struct ieee80211_sta_ht_cap *ht_info)
{
	int i;
	memset(ht_info, 0, sizeof(*ht_info));
	ht_info->ht_supported = true;
	pr_info("SETUP HT CALLED\n");
#if 0
	ht_info->cap |= IEEE80211_HT_CAP_DSSSCCK40;
#endif
	ht_info->cap = 0;
	ht_info->cap |= IEEE80211_HT_CAP_MAX_AMSDU;
	ht_info->cap |= IEEE80211_HT_CAP_SGI_40;
	ht_info->cap |= IEEE80211_HT_CAP_SGI_20;
	ht_info->cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
	ht_info->cap |= IEEE80211_HT_CAP_GRN_FLD;
	ht_info->cap |= IEEE80211_HT_CAP_LDPC_CODING;
	ht_info->cap |= IEEE80211_HT_CAP_TX_STBC;
	ht_info->cap |= (1 << IEEE80211_HT_CAP_RX_STBC_SHIFT);
	ht_info->cap |= IEEE80211_HT_CAP_LSIG_TXOP_PROT;
	/*We support SMPS*/

	ht_info->ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
	ht_info->ampdu_density = IEEE80211_HT_MPDU_DENSITY_4;

	memset(&ht_info->mcs, 0, sizeof(ht_info->mcs));

	if (wifi->params.max_tx_streams != wifi->params.max_rx_streams) {
		ht_info->mcs.tx_params |= IEEE80211_HT_MCS_TX_RX_DIFF;
		ht_info->mcs.tx_params |= ((wifi->params.max_tx_streams - 1)
				<< IEEE80211_HT_MCS_TX_MAX_STREAMS_SHIFT);
	}

	for (i = 0; i < wifi->params.max_rx_streams; i++)
		ht_info->mcs.rx_mask[i] = 0xff;
	ht_info->mcs.rx_mask[4] = 0x1;

	ht_info->mcs.tx_params |= IEEE80211_HT_MCS_TX_DEFINED;
}


#define IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT 13
#define IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT 16
static void setup_vht_cap(struct ieee80211_sta_vht_cap *vht_info)
{
	if (!vht_support)
		return;

	memset(vht_info, 0, sizeof(*vht_info));
	vht_info->vht_supported = true;
	pr_info("SETUP VHT CALLED\n");

	vht_info->cap = IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454 |
			/*64KB Rx buffer size*/
			(3 <<
			IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT) |
#if 0
			IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE |
			IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE |
			(1 << IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT) |
			(1 << IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT) |
#endif
			IEEE80211_VHT_CAP_SHORT_GI_80 |
			IEEE80211_VHT_CAP_RXLDPC |
			IEEE80211_VHT_CAP_TXSTBC |
			IEEE80211_VHT_CAP_RXSTBC_1 |
			IEEE80211_VHT_CAP_HTC_VHT;
	/* 1x1 */
	if ((wifi->params.max_tx_streams == 1) &&
	    (wifi->params.max_rx_streams == 1)) {
		vht_info->vht_mcs.rx_mcs_map =
			((IEEE80211_VHT_MCS_SUPPORT_0_7) << (2*0)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*1)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*2)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*3)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*4)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*5)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*6)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*7));
	}

	/*2x2 */
	if ((wifi->params.max_tx_streams == 2) &&
	    (wifi->params.max_rx_streams == 2)) {
		vht_info->vht_mcs.rx_mcs_map =
			((IEEE80211_VHT_MCS_SUPPORT_0_7) << (2*0)) |
			((IEEE80211_VHT_MCS_SUPPORT_0_7) << (2*1)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*2)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*3)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*4)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*5)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*6)) |
			((IEEE80211_VHT_MCS_NOT_SUPPORTED) << (2*7));
	}

	vht_info->vht_mcs.tx_mcs_map = vht_info->vht_mcs.rx_mcs_map;
}


static void init_hw(struct ieee80211_hw *hw)
{
	struct mac80211_dev  *dev = (struct mac80211_dev *)hw->priv;
	int num_if_comb = 0;

	/* Supported Interface Types and other Default values*/
	hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
				     BIT(NL80211_IFTYPE_ADHOC) |
				     BIT(NL80211_IFTYPE_AP) |
				     BIT(NL80211_IFTYPE_P2P_CLIENT) |
				     BIT(NL80211_IFTYPE_P2P_GO);

	hw->wiphy->iface_combinations = if_comb;

	num_if_comb = (sizeof(if_comb) /
		       sizeof(struct ieee80211_iface_combination));
	hw->wiphy->n_iface_combinations = num_if_comb;

	hw->flags = IEEE80211_HW_SIGNAL_DBM | IEEE80211_HW_SUPPORTS_PS;
	hw->flags |= IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING;
	hw->flags |= IEEE80211_HW_AMPDU_AGGREGATION;
	hw->flags |= IEEE80211_HW_MFP_CAPABLE;

	if (wifi->params.dot11a_support)
		hw->flags |= IEEE80211_HW_SPECTRUM_MGMT;

	hw->flags |= IEEE80211_HW_SUPPORTS_PER_STA_GTK;

	hw->flags |= IEEE80211_HW_CONNECTION_MONITOR;

	hw->wiphy->max_scan_ssids = MAX_NUM_SSIDS; /* 4 */
	 /* Low priority bg scan */
	hw->wiphy->features |= NL80211_FEATURE_LOW_PRIORITY_SCAN;
	hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;
	hw->max_listen_interval = 10;
	hw->wiphy->max_remain_on_channel_duration = 5000; /*ROC*/
	hw->max_rates = 4;
	hw->max_rate_tries = 5;
	hw->queues = 4;

	/* Size */
	hw->extra_tx_headroom = 0;
	hw->vif_data_size = sizeof(struct umac_vif);

	if (wifi->params.dot11g_support) {
		hw->wiphy->bands[IEEE80211_BAND_2GHZ] = &band_2ghz;
		setup_ht_cap(&hw->wiphy->bands[IEEE80211_BAND_2GHZ]->ht_cap);
	}

	if (wifi->params.dot11a_support) {
		if (vht_support)
			setup_vht_cap(&band_5ghz.vht_cap);
		hw->wiphy->bands[IEEE80211_BAND_5GHZ] = &band_5ghz;
		setup_ht_cap(&hw->wiphy->bands[IEEE80211_BAND_5GHZ]->ht_cap);
	}

	memset(hw->wiphy->addr_mask, 0, sizeof(hw->wiphy->addr_mask));

	if (wifi->params.num_vifs == 1) {
		hw->wiphy->addresses = NULL;
		SET_IEEE80211_PERM_ADDR(hw, dev->if_mac_addresses[0].addr);
	} else {
		hw->wiphy->n_addresses = wifi->params.num_vifs;
		hw->wiphy->addresses = dev->if_mac_addresses;
	}

	hw->wiphy->flags |= WIPHY_FLAG_AP_UAPSD;
	hw->wiphy->flags |= WIPHY_FLAG_IBSS_RSN;
	hw->wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;

	if (!wifi->params.disable_power_save &&
	    !wifi->params.disable_sm_power_save) {
		/* SMPS Support both Static and Dynamic */
		hw->wiphy->features |= NL80211_FEATURE_STATIC_SMPS;
		hw->wiphy->features |= NL80211_FEATURE_DYNAMIC_SMPS;
        }

#ifdef CONFIG_PM
	hw->wiphy->wowlan = &uccp_wowlan_support;
#endif
}


static int ampdu_action(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif,
				enum ieee80211_ampdu_mlme_action action,
				struct ieee80211_sta *sta,
				u16 tid, u16 *ssn, u8 buf_size)
{
	int ret = 0;
	unsigned int val = 0;
	struct mac80211_dev *dev = (struct mac80211_dev *)hw->priv;

	DEBUG_LOG("%s-80211IF: ampdu action started\n",
		       ((struct mac80211_dev *)(hw->priv))->name);

	switch (action) {
	case IEEE80211_AMPDU_RX_START:
		{
		val = tid | TID_INITIATOR_AP;
		dev->tid_info[val].tid_state = TID_STATE_AGGR_START;
		dev->tid_info[val].ssn = *ssn;
		uccp420wlan_prog_ba_session_data(1,
						 tid,
						 &dev->tid_info[val].ssn,
						 1,
						 vif->addr,
				   (unsigned char *)(vif->bss_conf.bssid));
		}
		break;
	case IEEE80211_AMPDU_RX_STOP:
		{
		val = tid | TID_INITIATOR_AP;
		dev->tid_info[val].tid_state = TID_STATE_AGGR_STOP;
		uccp420wlan_prog_ba_session_data(0,
						 tid,
						 &dev->tid_info[val].ssn,
						 1,
						 vif->addr,
				   (unsigned char *)(vif->bss_conf.bssid));
		}
		break;
	case IEEE80211_AMPDU_TX_START:
		{
		val = tid | TID_INITIATOR_STA;
		ieee80211_start_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		dev->tid_info[val].tid_state = TID_STATE_AGGR_START;
		dev->tid_info[val].ssn = *ssn;
		}
		break;
	case IEEE80211_AMPDU_TX_STOP_FLUSH:
	case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
	case IEEE80211_AMPDU_TX_STOP_CONT:
		{
		val = tid | TID_INITIATOR_STA;
		dev->tid_info[val].tid_state = TID_STATE_AGGR_STOP;
		ieee80211_stop_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		}
		break;
	case IEEE80211_AMPDU_TX_OPERATIONAL:
		{
		val = tid | TID_INITIATOR_STA;
		dev->tid_info[val].tid_state = TID_STATE_AGGR_OPERATIONAL;
		}
		break;
	default:
		pr_err("%s: Invalid command, ignoring\n",
		       __func__);
	}
	return ret;
}


static int set_antenna(struct ieee80211_hw *hw, u32 tx_ant, u32 rx_ant)
{
	struct mac80211_dev *dev = (struct mac80211_dev *)hw->priv;

	/* Maximum no of antenna supported =2 */
	if (!tx_ant || (tx_ant & ~3) || !rx_ant || (rx_ant & ~3))
		return -EINVAL;

	dev->tx_antenna = (tx_ant & 3);

	return 0;
}


static void uccp420_roc_complete_work(struct work_struct *work)
{
	struct delayed_work *dwork;
	int i;
	struct mac80211_dev *dev;

	dwork = container_of(work, struct delayed_work, work);
	dev = container_of(dwork, struct mac80211_dev, roc_complete_work);

	if (atomic_read(&dev->roc_params.roc_mgmt_tx_count) != 0) {
		DEBUG_LOG("%s:%d but %d off channel tx frames pending\n",
			  __func__,
			  __LINE__,
			  atomic_read(&dev->roc_params.roc_mgmt_tx_count));
		return;
	}

	/* ROC Completed */
	mutex_lock(&dev->mutex);

	/* Put the chip back to its original state */
	for (i = 0; i < MAX_VIFS; i++) {

		if (!dev->roc_params.roc_ps_changed)
			break;

		if (!(dev->active_vifs & (1 << i)))
			continue;

		uccp420wlan_prog_ps_state(i,
					  dev->if_mac_addresses[i].addr,
					  dev->power_save);
	}

	dev->roc_params.roc_ps_changed = 0;

	if (dev->roc_params.roc_chan_changed) {
		dev->chan_prog_done = 0;

		uccp420wlan_prog_channel(dev->cur_chan.pri_chnl_num,
					 dev->cur_chan.chnl_num1,
					 dev->cur_chan.chnl_num2,
					 dev->cur_chan.ch_width,
					 dev->cur_chan.freq_band);

		if (wait_for_channel_prog_complete(dev)) {
			pr_err("%s:%d ROC Complete: Programming the Channel %d Timed-out (500ms)\n",
			       __func__, __LINE__, dev->cur_chan.pri_chnl_num);
			dev->roc_params.roc_in_progress = 0;
			dev->roc_params.roc_chan_changed = 0;
			ieee80211_remain_on_channel_expired(dev->hw);
			mutex_unlock(&dev->mutex);

			/* Unable to go back to Home channel, what next?? */
			return;
		}

		dev->roc_params.roc_chan_changed = 0;
	}

	/* Inform FW that ROC is started */
	uccp420wlan_prog_roc(ROC_START, dev->cur_chan.pri_chnl_num, 0);

	ieee80211_remain_on_channel_expired(dev->hw);
	dev->roc_params.roc_in_progress = 0;

	DEBUG_LOG("%s:%d Coming back to Orig: %d\n",
		  __func__,
		  __LINE__,
		  dev->power_save);

	mutex_unlock(&dev->mutex);
}


static int remain_on_channel(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif,
			     struct ieee80211_channel *channel,
			     int duration,
			     enum ieee80211_roc_type type)

{
	int i;
	struct mac80211_dev *dev = (struct mac80211_dev *)hw->priv;
	unsigned int pri_chnl_num = 0;
	unsigned int chnl_num1 = 0;
	unsigned int chnl_num2 = 0;
	unsigned int freq_band = channel->band;
	unsigned int ch_width = 0; /* 20MHz */

	pri_chnl_num = ieee80211_frequency_to_channel(channel->center_freq);
	chnl_num1 = ieee80211_frequency_to_channel(channel->center_freq);

	mutex_lock(&dev->mutex);

	DEBUG_LOG("%s:%d orig_ps: %d The Params are: channel:%d\n",
		  __func__, __LINE__,
		  dev->power_save,
		  pri_chnl_num);
	DEBUG_LOG("	duration:%d type: %d c1:%d band:%d\n",
		  duration,
		  type,
		  chnl_num1,
		  freq_band);

	/* Put the chip in powersave */
	for (i = 0; i < MAX_VIFS; i++) {
		if (dev->power_save == PWRSAVE_STATE_AWAKE)
			break;

		dev->roc_params.roc_ps_changed = 1;

		if (!(dev->active_vifs & (1 << i)))
			continue;

		uccp420wlan_prog_ps_state(i,
					  dev->if_mac_addresses[i].addr,
					  PWRSAVE_STATE_AWAKE);
	}

	do {
		if (dev->cur_chan.pri_chnl_num == pri_chnl_num)
			break;

		DEBUG_LOG("%s:%d Programming the Channel\n",
			  __func__, __LINE__);

		dev->chan_prog_done = 0;

		uccp420wlan_prog_channel(pri_chnl_num,
					 chnl_num1,
					 chnl_num2,
					 ch_width, freq_band);

		if (!wait_for_channel_prog_complete(dev)) {
			dev->roc_params.roc_chan_changed = 1;
			break;
		}

		pr_err("%s:%d ROC Start: Programming the Channel %d Timed-out (500ms)\n",
			__func__, __LINE__, pri_chnl_num);

		/* Put the chip back to its orig state*/
		for (i = 0; i < MAX_VIFS; i++) {
			if (!dev->roc_params.roc_ps_changed)
				break;

			if (!(dev->active_vifs & (1 << i)))
				continue;

			uccp420wlan_prog_ps_state(i,
						  dev->if_mac_addresses[i].addr,
						  dev->power_save);
		}

		dev->roc_params.roc_ps_changed = 0;

		ieee80211_remain_on_channel_expired(dev->hw);
		mutex_unlock(&dev->mutex);

		return 0;

	} while (0);

	DEBUG_LOG("%s:%d Programming the Channel Success:%d\n",
		  __func__, __LINE__,
		  dev->chan_prog_done);

	/* Inform FW that ROC is started */
	uccp420wlan_prog_roc(ROC_START, pri_chnl_num, duration);

	ieee80211_queue_delayed_work(hw,
				     &dev->roc_complete_work,
				     msecs_to_jiffies(duration));

	dev->roc_params.roc_in_progress = 1;

	ieee80211_ready_on_channel(dev->hw);

	mutex_unlock(&dev->mutex);

	return 0;
}


static int cancel_remain_on_channel(struct ieee80211_hw *hw)
{
	int i = 0;
	struct mac80211_dev *dev = (struct mac80211_dev *)hw->priv;

	mutex_lock(&dev->mutex);

	if (dev->roc_params.roc_in_progress) {
		cancel_delayed_work_sync(&dev->roc_complete_work);

		/* Put the chip back to its original state */
		for (i = 0; i < MAX_VIFS; i++) {
			if (!(dev->active_vifs & (1 << i)))
				continue;

			uccp420wlan_prog_ps_state(i,
						  dev->if_mac_addresses[i].addr,
						  dev->power_save);
		}

		DEBUG_LOG("%s:%d Coming back to Orig:%d\n",
			  __func__, __LINE__,
			  dev->power_save);

		dev->roc_params.roc_in_progress = 0;
	}

	mutex_unlock(&dev->mutex);

	return 0;
}


/* Needed in case of IBSS to send out probe responses when we are beaconing */
static int tx_last_beacon(struct ieee80211_hw *hw)
{
	struct mac80211_dev *dev = (struct mac80211_dev *)hw->priv;

	return dev->tx_last_beacon;
}


#ifdef CONFIG_PM
static int wait_for_econ_ps_cfg(struct mac80211_dev *dev)
{
	int count = 0;
	char econ_ps_cfg_done = 0;

check_econ_ps_cfg_complete:
	mutex_lock(&dev->mutex);
	econ_ps_cfg_done = dev->econ_ps_cfg_stats.completed;
	mutex_unlock(&dev->mutex);

	if (!econ_ps_cfg_done && (count < PS_ECON_CFG_TIMEOUT_TICKS)) {
		count++;
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
		goto check_econ_ps_cfg_complete;
	}

	if (!econ_ps_cfg_done) {
		pr_warn("%s: Didn't get ECON_PS_CFG_DONE event\n",
		       __func__);
		return -1;
	}

	pr_debug("%s : Received ECON_PS_CFG_DONE event\n",
		 __func__);

	return 0;
}

static int img_resume(struct ieee80211_hw *hw)
{
	int i = 0;
	int active_vif_index = -1;
	struct mac80211_dev *dev = NULL;

	if (hw == NULL) {
		pr_err("%s: Invalid parameters\n",
		       __func__);
		return -1;
	}

	dev = (struct mac80211_dev *)hw->priv;

	mutex_lock(&dev->mutex);

	for (i = 0; i < MAX_VIFS; i++) {
		if (dev->active_vifs & (1 << i))
			active_vif_index = i;
	}

	dev->econ_ps_cfg_stats.completed = 0;
	dev->econ_ps_cfg_stats.result = 0;

	if (uccp420wlan_prog_econ_ps_state(active_vif_index,
					   PWRSAVE_STATE_AWAKE)) {
		pr_err(" %s : Error Occured\n",
		       __func__);
		mutex_unlock(&dev->mutex);
		return -1;
	}

	mutex_unlock(&dev->mutex);

	if (!wait_for_econ_ps_cfg(dev)) {
		if (!dev->econ_ps_cfg_stats.result) {
			dev->power_save = PWRSAVE_STATE_AWAKE;
			pr_debug("%s: Successful\n",
				 __func__);

			return 0;
		}
	}

	pr_err("%s: Error Occured\n",
	       __func__);

	return -1;
}


static int img_suspend(struct ieee80211_hw *hw,
		       struct cfg80211_wowlan *wowlan)
{
	int i = 0;
	int active_vif_index = -1;
	int count = 0;
	struct mac80211_dev *dev = NULL;

	if (hw == NULL) {
		pr_err("%s: Invalid parameters\n",
		       __func__);
		return -1;
	}

	if (WARN_ON((wifi->params.hw_scan_status == HW_SCAN_STATUS_PROGRESS)))
		return -1;

	dev = (struct mac80211_dev *)hw->priv;

	mutex_lock(&dev->mutex);

	for (i = 0; i < MAX_VIFS; i++) {
		if (dev->active_vifs & (1 << i)) {
			active_vif_index = i;
			count++;
		}
	}

	if (count != 1) {
		pr_err("%s: Economy mode supported only for single VIF in STA mode\n",
		       __func__);
		mutex_unlock(&dev->mutex);
		return -1;
	}

	if (dev->vifs[active_vif_index]->type != NL80211_IFTYPE_STATION) {
		pr_err("%s: VIF is not in STA Mode\n",
		       __func__);
		mutex_unlock(&dev->mutex);
		return -1;
	 }

	dev->econ_ps_cfg_stats.completed = 0;
	dev->econ_ps_cfg_stats.result = 0;
	dev->econ_ps_cfg_stats.wake_trig = -1;

	if (uccp420wlan_prog_econ_ps_state(active_vif_index,
					   PWRSAVE_STATE_DOZE)) {
		pr_err("%s : Error Occured\n",
		       __func__);
		mutex_unlock(&dev->mutex);

		return -1;
	}

	mutex_unlock(&dev->mutex);

	if (!wait_for_econ_ps_cfg(dev)) {
		if (!dev->econ_ps_cfg_stats.result) {
			dev->power_save = PWRSAVE_STATE_DOZE;
			pr_debug("%s: Successful\n",
				 __func__);
			return 0;
		}
	}

	pr_err("%s: Error Occured\n",
	       __func__);

	return -1;
}
#endif


int scan(struct ieee80211_hw *hw,
	 struct ieee80211_vif *vif,
	 struct ieee80211_scan_request *ireq)
{
	struct umac_vif *uvif = (struct umac_vif *)vif->drv_priv;
	struct scan_req scan_req = {0};
	int i = 0;

        struct cfg80211_scan_request *req;
        req = &ireq->req;

	scan_req.n_ssids = req->n_ssids;
	scan_req.n_channels = req->n_channels;
	scan_req.ie_len = req->ie_len;

	if (wifi->params.hw_scan_status != HW_SCAN_STATUS_NONE)
		return -EBUSY; /* Already in HW SCAN State */

	/* Keep track of HW Scan requests and compeltes */
	wifi->params.hw_scan_status = HW_SCAN_STATUS_PROGRESS;

	if (uvif->dev->params->production_test == 1) {
		/* Drop scan, its just intended for IBSS
		 * and some data traffic
		 */
		if (wifi->params.hw_scan_status != HW_SCAN_STATUS_NONE) {
			ieee80211_scan_completed(uvif->dev->hw, false);
			wifi->params.hw_scan_status = HW_SCAN_STATUS_NONE;
		}

		return 0;
	}

	if (req->ie_len)
		memcpy(scan_req.ie, req->ie, req->ie_len);

	for (i = 0; i < req->n_channels; i++) {
		scan_req.center_freq[i] = req->channels[i]->center_freq;
		scan_req.freq_max_power[i] = req->channels[i]->max_power;
		scan_req.chan_flags[i] = req->channels[i]->flags;
		/* The type of scan comes from mac80211 so its taken care of */
	}

	scan_req.p2p_probe = req->no_cck;

	/* For hostapd scan (40MHz) and scan_type=passive, n_ssids=0
	 * and req->ssids is NULL
	 */
	if (req->n_ssids > 0) {
		for (i = 0; i < req->n_ssids; i++) {
			scan_req.ssids[i].ssid_len = req->ssids[i].ssid_len;
			if (req->ssids[i].ssid_len > 0)
				memcpy(scan_req.ssids[i].ssid,
				       req->ssids[i].ssid,
				       req->ssids[i].ssid_len);
		}
	}

	return uccp420wlan_scan(uvif->vif_index, &scan_req);
}


void uccp420wlan_scan_complete(void *context,
			       struct host_event_scanres *scan_res,
			       unsigned char *skb,
			       unsigned int len)
{
	struct mac80211_dev *dev = (struct mac80211_dev *)context;

	/* DO NOT update the scan results through cfg80211 API's we just pass
	 * the beacons and probe responses up and mac80211 will inform cfg80211
	 */
	if (scan_res->more_results == 0) {
		DEBUG_LOG("Event Scan Complete from UCCP:\n");
		DEBUG_LOG("	More_results: 0, Scan is Completed\n");

		/* There can be a race where we receive remove_interface and
		 * abort the scan(1)
		 * But we get scan_complete from the FW(2), this check will make
		 * sure we are not calling scan_complete when we have already
		 * aborted the scan. Eg: Killing wpa_supplicant in middle of
		 * scanning
		 */
		if (wifi->params.hw_scan_status != HW_SCAN_STATUS_NONE) {
			dev->stats->umac_scan_complete++;
			ieee80211_scan_completed(dev->hw, false);

			/* Keep track of HW Scan requests and compeltes */
			wifi->params.hw_scan_status = HW_SCAN_STATUS_NONE;
		}
	} else {
		DEBUG_LOG("Event Scan Complete from UCCP:\n");
		DEBUG_LOG("More_results: %d, Still Scanning\n",
				scan_res->more_results);

	}
}


void cancel_hw_scan(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct umac_vif *uvif = (struct umac_vif *)vif->drv_priv;
	struct mac80211_dev *dev = NULL;

	dev = (struct mac80211_dev *)hw->priv;

	if (wifi->params.hw_scan_status == HW_SCAN_STATUS_PROGRESS) {
		pr_info("Aborting pending scan request...\n");

		dev->scan_abort_done = 0;

		if (uccp420wlan_scan_abort(uvif->vif_index))
			return;

		if (!wait_for_scan_abort(dev)) {
			ieee80211_scan_completed(hw, true);
			wifi->params.hw_scan_status = HW_SCAN_STATUS_NONE;
			dev->stats->umac_scan_complete++;
			return;
		}
	}
}


int set_rts_threshold(struct ieee80211_hw *hw,
		      u32 value)
{
	struct mac80211_dev *dev = NULL;

	dev = (struct mac80211_dev *)hw->priv;
	/*if thres>=2347 (default case) hostapd sends down (u32) -1*/
	if (value > 65536)
		dev->rts_threshold = 65536;
	else
		dev->rts_threshold = value;
	return 0;

}
int sta_add(struct ieee80211_hw *hw,
	    struct ieee80211_vif *vif,
	    struct ieee80211_sta *sta)
{
	struct umac_vif *uvif = (struct umac_vif *)vif->drv_priv;
	struct peer_sta_info peer_st_info = {0};
	int i;
	for (i = 0; i < STA_NUM_BANDS; i++)
		peer_st_info.supp_rates[i] = sta->supp_rates[i];
	/*HT info*/
	peer_st_info.ht_cap = sta->ht_cap.cap;
	peer_st_info.ht_supported = sta->ht_cap.ht_supported;
	peer_st_info.vht_supported = sta->vht_cap.vht_supported;
	peer_st_info.vht_cap = sta->vht_cap.cap;
	peer_st_info.ampdu_factor = sta->ht_cap.ampdu_factor;
	peer_st_info.ampdu_density = sta->ht_cap.ampdu_density;
	peer_st_info.rx_highest = sta->ht_cap.mcs.rx_highest;
	peer_st_info.tx_params = sta->ht_cap.mcs.tx_params;
	peer_st_info.uapsd_queues = sta->uapsd_queues;

	/* will be used in enforcing rules during Aggregation*/
	uvif->peer_ampdu_factor = (1 << (13 + sta->ht_cap.ampdu_factor)) - 1;

	if (sta->vht_cap.vht_supported) {
		if (sta->vht_cap.cap & IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE)
			uvif->dev->params->vht_beamform_support = 1;

	}
	for (i = 0; i < HT_MCS_MASK_LEN; i++)
		peer_st_info.rx_mask[i] = sta->ht_cap.mcs.rx_mask[i];

	for (i = 0; i < ETH_ALEN; i++)
		peer_st_info.addr[i] = sta->addr[i];

	return uccp420wlan_sta_add(uvif->vif_index, &peer_st_info);
}
int sta_remove(struct ieee80211_hw *hw,
	       struct ieee80211_vif *vif,
	       struct ieee80211_sta *sta)
{
	struct umac_vif *uvif = (struct umac_vif *)vif->drv_priv;
	struct peer_sta_info peer_st_info = {0};
	int i;
	for (i = 0; i < ETH_ALEN; i++)
		peer_st_info.addr[i] = sta->addr[i];

	return uccp420wlan_sta_remove(uvif->vif_index, &peer_st_info);
}

static int load_fw(struct ieee80211_hw *hw)
{
	int err = 0;
	int i = 0;
	struct mac80211_dev *dev = (struct mac80211_dev *)hw->priv;
	const struct firmware *fw = NULL;
	const char *bin_name[FWLDR_NUM_BINS] = {FWLDR_HW_BIN,
						FWLDR_FW_BIN};

	do {
		err = request_firmware(&fw, bin_name[i], dev->dev);

		if (err) {
			pr_err("Failed to get %s, Error = %d\n",
			       bin_name[i],
			       err);
			break;
		}

		err = fwldr_load_fw(fw->data, i);

		if (err == FWLDR_SUCCESS)
			pr_info("%s is loaded\n", bin_name[i]);
		else
			pr_err("Loading of %s failed\n", bin_name[i]);

		release_firmware(fw);

		i++;

	} while ((i < FWLDR_NUM_BINS) && (!err));

	return err;
}


static struct ieee80211_ops ops = {
	.tx                 = tx,
	.start              = start,
	.stop               = stop,
	.add_interface      = add_interface,
	.remove_interface   = remove_interface,
	.config             = config,
	.prepare_multicast  = prepare_multicast,
	.configure_filter   = configure_filter,
	.sw_scan_start      = NULL,
	.sw_scan_complete   = NULL,
	.get_stats          = NULL,
	.sta_notify         = NULL,
	.conf_tx            = conf_vif_tx,
	.bss_info_changed   = bss_info_changed,
	.set_tim            = NULL,
	.set_key            = set_key,
	.get_tkip_seq       = NULL,
	.tx_last_beacon     = tx_last_beacon,
	.ampdu_action       = ampdu_action,
	.set_antenna	    = set_antenna,
	.remain_on_channel = remain_on_channel,
	.cancel_remain_on_channel = cancel_remain_on_channel,
#ifdef CONFIG_PM
	.suspend	    = img_suspend,
	.resume		    = img_resume,
#endif
	.hw_scan	    = scan,
	.cancel_hw_scan	    = cancel_hw_scan,
	.set_rekey_data     = NULL,
	.set_rts_threshold  = set_rts_threshold,
	.sta_add	    = sta_add,
	.sta_remove	    = sta_remove,
};

static void uccp420wlan_exit(void)
{
	/* DEV Release */
	struct mac80211_dev *dev = (struct mac80211_dev *)wifi->hw->priv;

	ieee80211_unregister_hw(wifi->hw);
	device_release_driver(dev->dev);
	device_destroy(hwsim_class, 0);
	ieee80211_free_hw(wifi->hw);
	wifi->hw = NULL;

	class_destroy(hwsim_class);
}

static int uccp420wlan_init(void)
{
	struct ieee80211_hw *hw;
	int error;
	struct mac80211_dev *dev = NULL;
	int i;

	/* Allocate new hardware device */
	hw = ieee80211_alloc_hw(sizeof(struct mac80211_dev), &ops);

	if (hw == NULL) {
		pr_err("Failed to allocate memory for ieee80211_hw\n");
		error = -ENOMEM;
		goto out;
	}

	dev = (struct mac80211_dev *)hw->priv;

	hwsim_class = class_create(THIS_MODULE, "uccp420");

	if (IS_ERR(hwsim_class)) {
		pr_err("Failed to create the device class\n");
		error = PTR_ERR(hwsim_class);
		goto out;
	}

	/* Only 1 per physical intf*/
	dev->dev = device_create(hwsim_class, NULL, 0, hw, "uccwlan");

	if (IS_ERR(dev->dev)) {
		pr_err("uccwlan: device_create failed (%ld)\n",
		       PTR_ERR(dev->dev));
		error = -ENOMEM;
		goto auto_dev_class_failed;
	}

	dev->dev->driver = &img_uccp_driver.driver;

	if (device_is_registered(dev->dev)) {
		error = device_bind_driver(dev->dev);
	} else {
		pr_err("Device is not registered\n");
		error = -ENODEV;
		goto failed_hw;
	}

	if (error != 0) {
		pr_err("uccwlan: device_bind_driver failed (%d)\n", error);
		goto failed_hw;
	}

	pr_info("MAC ADDR: %pM\n", vif_macs);
	SET_IEEE80211_DEV(hw, dev->dev);

	mutex_init(&dev->mutex);
	spin_lock_init(&dev->bcast_lock);

	dev->state = STOPPED;
	dev->active_vifs = 0;
	dev->txpower = DEFAULT_TX_POWER;
	dev->tx_antenna = DEFAULT_TX_ANT_SELECT;
	dev->rts_threshold = DEFAULT_RTS_THRESHOLD;
	strncpy(dev->name, UCCP_DRIVER_NAME, 11);
	dev->name[11] = '\0';

	for (i = 0; i < wifi->params.num_vifs; i++)
		ether_addr_copy(dev->if_mac_addresses[i].addr, vif_macs[i]);

	/* Initialize HW parameters */
	init_hw(hw);
	dev->hw = hw;
	dev->params = &wifi->params;
	dev->stats = &wifi->stats;
	dev->umac_proc_dir_entry = wifi->umac_proc_dir_entry;
	dev->stats->system_rev = system_rev;

	/*Register hardware*/
	error = ieee80211_register_hw(hw);

	/* Production test hack: Set all channel flags to 0 to allow IBSS
	 * creation in all channels
	 */
	if (wifi->params.production_test && !error) {
		enum ieee80211_band band;
		struct ieee80211_supported_band *sband;
		for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
			sband = hw->wiphy->bands[band];
			if (sband)
				for (i = 0; i < sband->n_channels; i++)
					sband->channels[i].flags = 0;
		}
	}

	if (!error) {
		wifi->hw = hw;
		goto out;
	} else {
		uccp420wlan_exit();
		goto out;
	}

failed_hw:
	device_release_driver(dev->dev);
	device_destroy(hwsim_class, 0);
auto_dev_class_failed:
	class_destroy(hwsim_class);
out:
	return error;
}


static int proc_read_config(struct seq_file *m, void *v)
{
	int i = 0;
	int cnt = 0;
	int rf_params_size = sizeof(wifi->params.rf_params) /
			     sizeof(wifi->params.rf_params[0]);

	seq_puts(m, "************* Configurable Parameters ***********\n");
	seq_printf(m, "dot11g_support = %d\n", wifi->params.dot11g_support);
	seq_printf(m, "dot11a_support = %d\n", wifi->params.dot11a_support);
	seq_printf(m, "sensitivity = %d\n", wifi->params.ed_sensitivity);
	seq_printf(m, "auto_sensitivity = %d\n", wifi->params.auto_sensitivity);
	/*RF Input params*/
	seq_puts(m, "rf_params =");
	for (i = 0; i < rf_params_size; i++)
		seq_printf(m, " %02X", wifi->params.rf_params[i]);

	seq_puts(m, "\n");

	seq_puts(m, "rf_params_vpd =");
	for (i = 0; i < rf_params_size; i++)
		seq_printf(m, " %02X", wifi->params.rf_params_vpd[i]);

	seq_puts(m, "\n");

	seq_printf(m, "production_test = %d\n", wifi->params.production_test);
	seq_printf(m, "tx_fixed_mcs_indx = %d (%s)\n",
		   wifi->params.tx_fixed_mcs_indx,
		   (wifi->params.prod_mode_rate_flag &
		    ENABLE_VHT_FORMAT) ?
		   "VHT" : (wifi->params.prod_mode_rate_flag &
			    ENABLE_11N_FORMAT) ? "HT" : "Not Set");
	if (wifi->params.tx_fixed_rate > -1) {
		if (wifi->params.tx_fixed_rate == 55)
			seq_puts(m, "tx_fixed_rate = 5.5\n");
		else
			seq_printf(m, "tx_fixed_rate = %d\n",
				   wifi->params.tx_fixed_rate);
	} else
		seq_printf(m, "tx_fixed_rate = %d\n",
			   wifi->params.tx_fixed_rate);
	seq_printf(m, "num_spatial_streams (Per Frame) = %d\n",
		   wifi->params.num_spatial_streams);
	seq_printf(m, "uccp_num_spatial_streams (UCCP Init) = %d\n",
		   wifi->params.uccp_num_spatial_streams);
	seq_printf(m, "antenna_sel (UCCP Init) = %d\n",
		   wifi->params.antenna_sel);
	seq_printf(m, "max_data_size = %d (%dK)\n",
		   wifi->params.max_data_size,
		   wifi->params.max_data_size/1024);
	seq_printf(m, "max_tx_cmds = %d\n",
		   wifi->params.max_tx_cmds);
	seq_printf(m, "disable_power_save (Disables all power save's) = %d\n",
		   wifi->params.disable_power_save);
	seq_printf(m, "disable_sm_power_save (Disables MIMO PS only) = %d\n",
		   wifi->params.disable_sm_power_save);
	seq_printf(m, "mgd_mode_tx_fixed_mcs_indx = %d (%s)\n",
		   wifi->params.mgd_mode_tx_fixed_mcs_indx,
		   (wifi->params.prod_mode_rate_flag &
		    ENABLE_VHT_FORMAT) ?
		   "VHT" : (wifi->params.prod_mode_rate_flag &
			    ENABLE_11N_FORMAT) ? "HT" : "Not Set");
	if (wifi->params.mgd_mode_tx_fixed_rate > -1) {
		if (wifi->params.mgd_mode_tx_fixed_rate == 55)
			seq_puts(m, "mgd_mode_tx_fixed_rate = 5.5\n");
		else
			seq_printf(m, "mgd_mode_tx_fixed_rate = %d\n",
				   wifi->params.mgd_mode_tx_fixed_rate);
	} else
		seq_printf(m, "mgd_mode_tx_fixed_rate = %d\n",
			   wifi->params.mgd_mode_tx_fixed_rate);

	seq_printf(m, "num_vifs = %d\n",
		   wifi->params.num_vifs);

	seq_printf(m, "chnl_bw = %d\n",
		   wifi->params.chnl_bw);

	seq_printf(m, "prod_mode_chnl_bw_40_mhz = %d\n",
		   wifi->params.prod_mode_chnl_bw_40_mhz);
	if (vht_support)
		seq_printf(m, "prod_mode_chnl_bw_80_mhz = %d\n",
			   wifi->params.prod_mode_chnl_bw_80_mhz);
	seq_printf(m, "sec_ch_offset_40_plus = %d\n",
		   wifi->params.sec_ch_offset_40_plus);
	seq_printf(m, "sec_ch_offset_40_minus = %d\n",
		   wifi->params.sec_ch_offset_40_minus);

	if (vht_support) {
		seq_printf(m, "sec_40_ch_offset_80_plus = %d\n",
			   wifi->params.sec_40_ch_offset_80_plus);
		seq_printf(m, "sec_40_ch_offset_80_minus = %d\n",
			   wifi->params.sec_40_ch_offset_80_minus);
	}
	seq_printf(m, "rate_protection_type = %d (0: Disable, 1: Enable)\n",
		   wifi->params.rate_protection_type);
	seq_puts(m, "Bits:80MHz-VHT-11N-SGI-40MHz-GF\n");
	seq_printf(m, "prod_mode_rate_flag = %d\n",
		   wifi->params.prod_mode_rate_flag);
	seq_printf(m, "prod_mode_rate_preamble_type (0: Short, 1: Long) = %d\n",
		   wifi->params.prod_mode_rate_preamble_type);
	seq_printf(m, "prod_mode_stbc_enabled = %d\n",
		   wifi->params.prod_mode_stbc_enabled);
	seq_printf(m, "prod_mode_bcc_or_ldpc = %d\n",
		   wifi->params.prod_mode_bcc_or_ldpc);
	seq_printf(m, "vht_beamformer_enable = %d\n",
		   wifi->params.vht_beamform_enable);
	seq_printf(m, "vht_beamformer_period = %dms\n",
		   wifi->params.vht_beamform_period);
	seq_printf(m, "bg_scan_enable = %d\n",
		   wifi->params.bg_scan_enable);
	seq_puts(m, "bg_scan_channel_list =");

	for (i = 0; i < wifi->params.bg_scan_num_channels;  i++) {
		if (wifi->params.bg_scan_channel_list[i])
			seq_printf(m, " %d",
				   wifi->params.bg_scan_channel_list[i]);
	}

	seq_puts(m, "\n");
	seq_puts(m, "bg_scan_channel_flags =");

	for (i = 0; i < wifi->params.bg_scan_num_channels;  i++) {
		if (wifi->params.bg_scan_channel_flags[i])
			seq_printf(m, " %d",
				   wifi->params.bg_scan_channel_flags[i]);
	}

	seq_puts(m, "\n");
	seq_printf(m, "bg_scan_intval = %dms\n",
		   wifi->params.bg_scan_intval/1000);

	/*currently not used in LMAC, so don't export to user*/
#if 0
	seq_printf(m, "bg_scan_chan_dur = %d\n", wifi->params.bg_scan_chan_dur);
	seq_printf(m, "bg_scan_serv_chan_dur = %d\n",
		   wifi->params.bg_scan_serv_chan_dur);
#endif
	seq_printf(m, "bg_scan_num_channels = %d\n",
		   wifi->params.bg_scan_num_channels);
	seq_printf(m, "nw_selection = %d\n",
		   wifi->params.nw_selection);
	seq_printf(m, "scan_type = %d (PASSIVE: 0, ACTIVE: 1)\n",
		   wifi->params.scan_type);
#ifdef PERF_PROFILING
	seq_printf(m, "driver_tput = %d\n",
		   wifi->params.driver_tput);
#endif
	seq_printf(m, "fw_loading = %d\n", wifi->params.fw_loading);
	seq_printf(m, "bt_state = %d\n", wifi->params.bt_state);

	/* Beacon Time Stamp */
	for (cnt = 0; cnt < MAX_VIFS; cnt++) {
		unsigned long long ts1;
		unsigned long long bssid, atu;
		int status;
		char dev_name[10];
		unsigned int t2;

		spin_lock_bh(&tsf_lock);
		ts1 = get_unaligned_le64(wifi->params.sync[cnt].ts1);
		bssid = get_unaligned_le64(wifi->params.sync[cnt].bssid);
		status = wifi->params.sync[cnt].status;
		sprintf(dev_name, "%s%d", "wlan", cnt);
		atu = wifi->params.sync[cnt].atu;
		t2 = wifi->params.sync[cnt].ts2;
		spin_unlock_bh(&tsf_lock);
		if (status && wifi->params.sync[cnt].name)
			seq_printf(m, "sync=%s %d %llu %llu %llx t2=%u\n",
				dev_name, status, (unsigned long long)ts1,
				atu, (unsigned long long) bssid, t2);
	}

	seq_puts(m, "****** Production Test (or) FTM Parameters *******\n");
	seq_printf(m, "pkt_gen_val = %d (-1: Infinite loop)\n",
		   wifi->params.pkt_gen_val);
	seq_printf(m, "payload_length = %d bytes\n",
		   wifi->params.payload_length);
	seq_printf(m, "start_prod_mode = channel: %d\n",
		   wifi->params.start_prod_mode);

	if (ftm || wifi->params.production_test)
		seq_printf(m, "set_tx_power = %d dB\n",
			   wifi->params.set_tx_power);

	if (ftm)
		seq_printf(m, "aux_adc_chain_id = %d\n",
			   wifi->params.aux_adc_chain_id);

	seq_puts(m, "To see the updated stats\n");
	seq_puts(m, "please run: echo get_stats=1 > /proc/uccp420/params\n");
	seq_puts(m, "To see the cleared phy stats\n");
	seq_puts(m, "please run: echo clear_stats=1 > /proc/uccp420/params\n");
	seq_puts(m, "************* VERSION ***********\n");
	seq_printf(m, "UCCP_DRIVER_VERSION = %s\n", UCCP_DRIVER_VERSION);

	if (wifi->hw &&
	    (((struct mac80211_dev *)(wifi->hw->priv))->state != STARTED)) {
		seq_printf(m, "LMAC_VERSION = %s\n", "UNKNOWN");
		seq_printf(m, "Firmware version = %s\n", "UNKNOWN");
	} else {
		seq_printf(m, "LMAC_VERSION = %s\n",
			   wifi->stats.uccp420_lmac_version);
		seq_printf(m, "Firmware version= %d.%d\n",
			   (wifi->stats.uccp420_lmac_version[0] - '0'),
			   (wifi->stats.uccp420_lmac_version[2] - '0'));
	}

	return 0;
}


static int proc_read_phy_stats(struct seq_file *m, void *v)
{

	int i = 0;

	seq_puts(m, "************* BB Stats ***********\n");
	seq_printf(m, "ed_cnt=%d\n",
		   wifi->stats.ed_cnt);
	seq_printf(m, "mpdu_cnt=%d\n",
		   wifi->stats.mpdu_cnt);
	seq_printf(m, "ofdm_crc32_pass_cnt=%d\n",
		   wifi->stats.ofdm_crc32_pass_cnt);
	seq_printf(m, "ofdm_crc32_fail_cnt=%d\n",
		   wifi->stats.ofdm_crc32_fail_cnt);
	seq_printf(m, "dsss_crc32_pass_cnt=%d\n",
		   wifi->stats.dsss_crc32_pass_cnt);
	seq_printf(m, "dsss_crc32_fail_cnt=%d\n",
		   wifi->stats.dsss_crc32_fail_cnt);
	seq_printf(m, "mac_id_pass_cnt=%d\n",
		   wifi->stats.mac_id_pass_cnt);
	seq_printf(m, "mac_id_fail_cnt=%d\n",
		   wifi->stats.mac_id_fail_cnt);
	seq_printf(m, "ofdm_corr_pass_cnt=%d\n",
		   wifi->stats.ofdm_corr_pass_cnt);
	seq_printf(m, "ofdm_corr_fail_cnt=%d\n",
		   wifi->stats.ofdm_corr_fail_cnt);
	seq_printf(m, "dsss_corr_pass_cnt=%d\n",
		   wifi->stats.dsss_corr_pass_cnt);
	seq_printf(m, "dsss_corr_fail_cnt=%d\n",
		   wifi->stats.dsss_corr_fail_cnt);
	seq_printf(m, "ofdm_s2l_fail_cnt=%d\n",
		   wifi->stats.ofdm_s2l_fail_cnt);
	seq_printf(m, "lsig_fail_cnt=%d\n",
		   wifi->stats.lsig_fail_cnt);
	seq_printf(m, "htsig_fail_cnt=%d\n",
		   wifi->stats.htsig_fail_cnt);
	seq_printf(m, "vhtsiga_fail_cnt=%d\n",
		   wifi->stats.vhtsiga_fail_cnt);
	seq_printf(m, "vhtsigb_fail_cnt=%d\n",
		   wifi->stats.vhtsigb_fail_cnt);
	seq_printf(m, "nonht_ofdm_cnt=%d\n",
		   wifi->stats.nonht_ofdm_cnt);
	seq_printf(m, "nonht_dsss_cnt=%d\n",
		   wifi->stats.nonht_dsss_cnt);
	seq_printf(m, "mm_cnt=%d\n",
		   wifi->stats.mm_cnt);
	seq_printf(m, "gf_cnt=%d\n",
		   wifi->stats.gf_cnt);
	seq_printf(m, "vht_cnt=%d\n",
		   wifi->stats.vht_cnt);
	seq_printf(m, "aggregation_cnt=%d\n",
		   wifi->stats.aggregation_cnt);
	seq_printf(m, "non_aggregation_cnt=%d\n",
		   wifi->stats.non_aggregation_cnt);
	seq_printf(m, "ndp_cnt=%d\n",
		   wifi->stats.ndp_cnt);
	seq_printf(m, "ofdm_ldpc_cnt=%d\n",
		   wifi->stats.ofdm_ldpc_cnt);
	seq_printf(m, "ofdm_bcc_cnt=%d\n",
		   wifi->stats.ofdm_bcc_cnt);
	seq_printf(m, "midpacket_cnt=%d\n",
		   wifi->stats.midpacket_cnt);
	seq_printf(m, "dsss_sfd_fail_cnt=%d\n",
		   wifi->stats.dsss_sfd_fail_cnt);
	seq_printf(m, "dsss_hdr_fail_cnt=%d\n",
		   wifi->stats.dsss_hdr_fail_cnt);
	seq_printf(m, "dsss_short_preamble_cnt=%d\n",
		   wifi->stats.dsss_short_preamble_cnt);
	seq_printf(m, "dsss_long_preamble_cnt=%d\n",
		   wifi->stats.dsss_long_preamble_cnt);
	seq_printf(m, "sifs_event_cnt=%d\n",
		   wifi->stats.sifs_event_cnt);
	seq_printf(m, "cts_cnt=%d\n",
		   wifi->stats.cts_cnt);
	seq_printf(m, "ack_cnt=%d\n",
		   wifi->stats.ack_cnt);
	seq_printf(m, "sifs_no_resp_cnt=%d\n",
		   wifi->stats.sifs_no_resp_cnt);
	seq_printf(m, "unsupported_cnt=%d\n",
		   wifi->stats.unsupported_cnt);
	seq_printf(m, "l1_corr_fail_cnt=%d\n",
		   wifi->stats.l1_corr_fail_cnt);
	seq_printf(m, "phy_stats_reserved22=%d\n",
		   wifi->stats.phy_stats_reserved22);
	seq_printf(m, "phy_stats_reserved23=%d\n",
		   wifi->stats.phy_stats_reserved23);
	seq_printf(m, "phy_stats_reserved24=%d\n",
		   wifi->stats.phy_stats_reserved24);
	seq_printf(m, "phy_stats_reserved25=%d\n",
		   wifi->stats.phy_stats_reserved25);
	seq_printf(m, "phy_stats_reserved26=%d\n",
		   wifi->stats.phy_stats_reserved26);
	seq_printf(m, "phy_stats_reserved27=%d\n",
		   wifi->stats.phy_stats_reserved27);
	seq_printf(m, "phy_stats_reserved28=%d\n",
		   wifi->stats.phy_stats_reserved28);
	seq_printf(m, "phy_stats_reserved29=%d\n",
		   wifi->stats.phy_stats_reserved29);
	seq_printf(m, "phy_stats_reserved30=%d\n",
		   wifi->stats.phy_stats_reserved30);
	seq_printf(m, "tx_pkts_from_lmac = %d\n",
		   wifi->stats.tx_pkts_from_lmac);
	seq_printf(m, "tx_pkts_tx2tx = %d\n", wifi->stats.tx_pkts_tx2tx);
	seq_printf(m, "tx_pkts_from_rx = %d\n", wifi->stats.tx_pkts_from_rx);
	seq_printf(m, "tx_pkts_ofdm = %d\n", wifi->stats.tx_pkts_ofdm);
	seq_printf(m, "tx_pkts_dsss = %d\n", wifi->stats.tx_pkts_dsss);
	seq_printf(m, "tx_pkts_reached_end_of_fsm = %d\n",
		   wifi->stats.tx_pkts_reached_end_of_fsm);
	seq_printf(m, "tx_unsupported_modulation = %d\n",
		   wifi->stats.tx_unsupported_modulation);
	seq_printf(m, "tx_latest_pkt_from_lmac_or_sifs = %d\n",
		   wifi->stats.tx_latest_pkt_from_lmac_or_sifs);
	seq_printf(m, "tx_abort_bt_confirm_cnt = %d\n",
		   wifi->stats.tx_abort_bt_confirm_cnt);
	seq_printf(m, "tx_abort_txstart_timeout_cnt = %d\n",
		   wifi->stats.tx_abort_txstart_timeout_cnt);
	seq_printf(m, "tx_abort_midBT_cnt = %d\n",
		   wifi->stats.tx_abort_mid_bt_cnt);
	seq_printf(m, "tx_abort_dac_underrun_cnt = %d\n",
		   wifi->stats.tx_abort_dac_underrun_cnt);
	seq_printf(m, "tx_ofdm_symbols_master = %d\n",
		   wifi->stats.tx_ofdm_symbols_master);
	seq_printf(m, "tx_ofdm_symbols_slave1 = %d\n",
		   wifi->stats.tx_ofdm_symbols_slave1);
	seq_printf(m, "tx_ofdm_symbols_slave2 = %d\n",
		   wifi->stats.tx_ofdm_symbols_slave2);
	seq_printf(m, "tx_dsss_symbols = %d\n", wifi->stats.tx_dsss_symbols);
	seq_puts(m, "************* RF Stats ***********\n");
	/*RF output data*/
	seq_puts(m, "rf_calib_data =");
	for (i = 0; i < wifi->stats.rf_calib_data_length; i++)
		seq_printf(m, "%02X", wifi->stats.rf_calib_data[i]);

	seq_puts(m, "\n");
	return 0;
}

static int proc_read_mac_stats(struct seq_file *m, void *v)
{
	unsigned int index;
	unsigned int total_samples = 0;
	unsigned int total_value = 0;
	int total_rssi_samples = 0;
	int total_rssi_value = 0;

	if (ftm) {
		for (index = 0; index < MAX_AUX_ADC_SAMPLES; index++) {
			if (!wifi->params.pdout_voltage[index])
				continue;

			total_value += wifi->params.pdout_voltage[index];
			total_samples++;
		}
	}

	for (index = 0; index < MAX_RSSI_SAMPLES; index++) {

		if (!wifi->params.production_test)
			break;

		if (!wifi->params.rssi_average[index])
			continue;

		total_rssi_value += wifi->params.rssi_average[index];
		total_rssi_samples++;
	}

	seq_puts(m, "************* UMAC STATS ***********\n");
	seq_printf(m, "rx_packet_mgmt_count = %d\n",
		   wifi->stats.rx_packet_mgmt_count);
	seq_printf(m, "rx_packet_data_count = %d\n",
		   wifi->stats.rx_packet_data_count);
	seq_printf(m, "tx_packet_count(HT MCS0) = %d\n",
		   wifi->stats.ht_tx_mcs0_packet_count);
	seq_printf(m, "tx_packet_count(HT MCS1) = %d\n",
		   wifi->stats.ht_tx_mcs1_packet_count);
	seq_printf(m, "tx_packet_count(HT MCS2) = %d\n",
		   wifi->stats.ht_tx_mcs2_packet_count);
	seq_printf(m, "tx_packet_count(HT MCS3) = %d\n",
		   wifi->stats.ht_tx_mcs3_packet_count);
	seq_printf(m, "tx_packet_count(HT MCS4) = %d\n",
		   wifi->stats.ht_tx_mcs4_packet_count);
	seq_printf(m, "tx_packet_count(HT MCS5) = %d\n",
		   wifi->stats.ht_tx_mcs5_packet_count);
	seq_printf(m, "tx_packet_count(HT MCS6) = %d\n",
		   wifi->stats.ht_tx_mcs6_packet_count);
	seq_printf(m, "tx_packet_count(HT MCS7) = %d\n",
		   wifi->stats.ht_tx_mcs7_packet_count);

	if (wifi->params.uccp_num_spatial_streams == 2) {
		seq_printf(m, "tx_packet_count(HT MCS8) = %d\n",
			   wifi->stats.ht_tx_mcs8_packet_count);
		seq_printf(m, "tx_packet_count(HT MCS9) = %d\n",
			   wifi->stats.ht_tx_mcs9_packet_count);
		seq_printf(m, "tx_packet_count(HT MCS10) = %d\n",
			   wifi->stats.ht_tx_mcs10_packet_count);
		seq_printf(m, "tx_packet_count(HT MCS11) = %d\n",
			   wifi->stats.ht_tx_mcs11_packet_count);
		seq_printf(m, "tx_packet_count(HT MCS12) = %d\n",
			   wifi->stats.ht_tx_mcs12_packet_count);
		seq_printf(m, "tx_packet_count(HT MCS13) = %d\n",
			   wifi->stats.ht_tx_mcs13_packet_count);
		seq_printf(m, "tx_packet_count(HT MCS14) = %d\n",
			   wifi->stats.ht_tx_mcs14_packet_count);
		seq_printf(m, "tx_packet_count(HT MCS15) = %d\n",
			   wifi->stats.ht_tx_mcs15_packet_count);
	}
	if (vht_support) {
		seq_printf(m, "tx_packet_count(VHT MCS0) = %d\n",
			   wifi->stats.vht_tx_mcs0_packet_count);
		seq_printf(m, "tx_packet_count(VHT MCS1) = %d\n",
			   wifi->stats.vht_tx_mcs1_packet_count);
		seq_printf(m, "tx_packet_count(VHT MCS2) = %d\n",
			   wifi->stats.vht_tx_mcs2_packet_count);
		seq_printf(m, "tx_packet_count(VHT MCS3) = %d\n",
			   wifi->stats.vht_tx_mcs3_packet_count);
		seq_printf(m, "tx_packet_count(VHT MCS4) = %d\n",
			   wifi->stats.vht_tx_mcs4_packet_count);
		seq_printf(m, "tx_packet_count(VHT MCS5) = %d\n",
			   wifi->stats.vht_tx_mcs5_packet_count);
		seq_printf(m, "tx_packet_count(VHT MCS6) = %d\n",
			   wifi->stats.vht_tx_mcs6_packet_count);
		seq_printf(m, "tx_packet_count(VHT MCS7) = %d\n",
			   wifi->stats.vht_tx_mcs7_packet_count);
		seq_printf(m, "tx_packet_count(VHT MCS8) = %d\n",
			   wifi->stats.vht_tx_mcs8_packet_count);
		seq_printf(m, "tx_packet_count(VHT MCS9) = %d\n",
			   wifi->stats.vht_tx_mcs9_packet_count);
	}
	seq_printf(m, "tx_cmds_from_stack= %d\n",
		   wifi->stats.tx_cmds_from_stack);
	seq_printf(m, "tx_dones_to_stack= %d\n",
		   wifi->stats.tx_dones_to_stack);
	seq_printf(m, "oustanding_cmd_cnt = %d\n",
		   wifi->stats.outstanding_cmd_cnt);
	seq_printf(m, "gen_cmd_send_count = %d\n",
		   wifi->stats.gen_cmd_send_count);
	seq_printf(m, "umac_scan_req = %d\n",
		   wifi->stats.umac_scan_req);
	seq_printf(m, "umac_scan_complete = %d\n",
		   wifi->stats.umac_scan_complete);
	seq_printf(m, "tx_cmd_send_count_single = %d\n",
		   wifi->stats.tx_cmd_send_count_single);
	seq_printf(m, "tx_cmd_send_count_multi = %d\n",
		   wifi->stats.tx_cmd_send_count_multi);
	seq_printf(m, "tx_done_recv_count = %d\n",
		   wifi->stats.tx_done_recv_count);
	if (ftm)
		seq_printf(m, "pdout_val = %d (total samples: %d)\n",
			   total_samples ? (total_value/total_samples) : 0,
			   total_samples);
	if (wifi->params.production_test)
		seq_printf(m,
			   "rssi_average = %d dBm (total rssi samples: %d)\n",
			   total_rssi_samples ?
			   (total_rssi_value/total_rssi_samples) : 0,
			   total_rssi_samples);

	seq_puts(m, "************* LMAC STATS ***********\n");
	/* TX related */
	seq_printf(m, "tx_cmd_cnt =%d\n",
		   wifi->stats.tx_cmd_cnt);
	seq_printf(m, "tx_done_cnt =%d\n",
		   wifi->stats.tx_done_cnt);
	seq_printf(m, "tx_edca_trigger_cnt =%d\n",
		   wifi->stats.tx_edca_trigger_cnt);
	seq_printf(m, "tx_edca_isr_cnt =%d\n",
		   wifi->stats.tx_edca_isr_cnt);
	seq_printf(m, "tx_start_cnt =%d\n",
		   wifi->stats.tx_start_cnt);
	seq_printf(m, "tx_abort_cnt =%d\n",
		   wifi->stats.tx_abort_cnt);
	seq_printf(m, "tx_abort_isr_cnt =%d\n",
		   wifi->stats.tx_abort_isr_cnt);
	seq_printf(m, "tx_underrun_cnt =%d\n",
		   wifi->stats.tx_underrun_cnt);
	seq_printf(m, "tx_rts_cnt =%d\n",
		   wifi->stats.tx_rts_cnt);
	seq_printf(m, "tx_ampdu_cnt =%d\n",
		   wifi->stats.tx_ampdu_cnt);
	seq_printf(m, "tx_mpdu_cnt =%d\n",
		   wifi->stats.tx_mpdu_cnt);

	/* RX related */
	seq_printf(m, "rx_isr_cnt  =%d\n",
		   wifi->stats.rx_isr_cnt);
	seq_printf(m, "rx_ack_cts_to_cnt =%d\n",
		   wifi->stats.rx_ack_cts_to_cnt);
	seq_printf(m, "rx_cts_cnt =%d\n",
		   wifi->stats.rx_cts_cnt);
	seq_printf(m, "rx_ack_resp_cnt =%d\n",
		   wifi->stats.rx_ack_resp_cnt);
	seq_printf(m, "rx_ba_resp_cnt =%d\n",
		   wifi->stats.rx_ba_resp_cnt);
	seq_printf(m, "rx_fail_in_ba_bitmap_cnt =%d\n",
		   wifi->stats.rx_fail_in_ba_bitmap_cnt);
	seq_printf(m, "rx_circular_buffer_free_cnt =%d\n",
		   wifi->stats.rx_circular_buffer_free_cnt);
	seq_printf(m, "rx_mic_fail_cnt =%d\n",
		   wifi->stats.rx_mic_fail_cnt);

	/* HAL related */
	seq_printf(m, "hal_cmd_cnt  =%d\n",
		   wifi->stats.hal_cmd_cnt);
	seq_printf(m, "hal_event_cnt =%d\n",
		   wifi->stats.hal_event_cnt);
	seq_printf(m, "hal_ext_ptr_null_cnt =%d\n",
		   wifi->stats.hal_ext_ptr_null_cnt);

	return 0;

}

static long param_get_val(unsigned char *buf,
			  unsigned char *str,
			  unsigned long *val)
{
	unsigned char *temp;

	if (strstr(buf, str)) {
		temp = strstr(buf, "=") + 1;
		/*To handle the fixed rate 5.5Mbps case*/
		if (!strncmp(temp, "5.5", 3)) {
			*val = 55;
			return 1;
		} else if (!kstrtoul(temp, 0, val)) {
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

static long param_get_sval(unsigned char *buf,
			   unsigned char *str,
			   long *val)
{

	unsigned char *temp;
	if (strstr(buf, str)) {
		temp = strstr(buf, "=") + 1;
		/*To handle the fixed rate 5.5Mbps case*/
		if (!strncmp(temp, "5.5", 3)) {
			*val = 55;
			return 1;
		} else if (!kstrtol(temp, 0, val)) {
			return 1;
		} else {
			return 0;
		}
	} else {
		return 0;
	}

}

static long param_get_match(unsigned char *buf, unsigned char *str)
{

	if (strstr(buf, str))
		return 1;
	else
		return 0;
}
static ssize_t proc_write_config(struct file *file,
				 const char __user *buffer,
				 size_t count,
				 loff_t *ppos)
{
	char buf[(RF_PARAMS_SIZE * 2) + 50];
	unsigned long val;
	long sval;

	if (count >= sizeof(buf))
		count = sizeof(buf) - 1;

	if (copy_from_user(buf, buffer, count))
		return -EFAULT;

	buf[count] = '\0';

	if (param_get_val(buf, "dot11a_support=", &val)) {
		if (((val == 0) || (val == 1)) &&
		    (wifi->params.dot11a_support != val)) {
			wifi->params.dot11a_support = val;

			if ((wifi->params.dot11g_support == 0) &&
			    (wifi->params.dot11a_support == 0)) {
				pr_err("Invalid parameter value. Both bands can't be disabled, at least 1 is needed\n");
			} else {
				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}

				pr_info("Re-initializing UMAC ..with 2.4GHz support %s and 5GHz support %s\n",
					wifi->params.dot11g_support == 0 ?
					"disabled" : "enabled",
					wifi->params.dot11a_support == 0 ?
					"disabled" : "enabled");

				uccp420wlan_init();
			}
		} else
			pr_err("Invalid parameter value\n");
	} else if (param_get_val(buf, "dot11g_support=", &val)) {
		if (((val == 0) || (val == 1)) &&
		    (wifi->params.dot11g_support != val)) {
			wifi->params.dot11g_support = val;

			if ((wifi->params.dot11g_support == 0) &&
			    (wifi->params.dot11a_support == 0)) {
				pr_err("Invalid parameter value. Both bands can't be disabled, at least 1 is needed\n");
			} else {
				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}

				pr_info("Re-initializing UMAC ..with 2.4GHz support %s and 5GHz support %s\n",
					wifi->params.dot11g_support == 0 ?
					"disabled" : "enabled",
					wifi->params.dot11a_support == 0 ?
					"disabled" : "enabled");

				uccp420wlan_init();
			}
		} else
			pr_err("Invalid parameter value\n");
	} else if (param_get_sval(buf, "sensitivity=", &sval)) {
		/*if (sval > -51 || sval < -96 || (sval % 3 != 0))*/
		/*	pr_err("Invalid parameter value\n");*/
		/*else*/
		wifi->params.ed_sensitivity = sval;
	} else if (param_get_val(buf, "auto_sensitivity=", &val)) {
		if ((val == 0) || (val == 1))
			wifi->params.auto_sensitivity = val;
		else
			pr_err("Invalid parameter value.\n");
	} else if (param_get_val(buf, "production_test=", &val)) {
		if ((val == 0) || (val == 1)) {
			if (wifi->params.production_test != val) {
				if (wifi->params.production_test)
					wifi->params.num_vifs = 1;

				wifi->params.production_test = val;

				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}

				pr_err("Re-initializing UMAC ..\n");
				uccp420wlan_init();
			}
		} else
			pr_err("Invalid parameter value\n");
	} else if (param_get_val(buf, "num_vifs=", &val)) {
		if (val > 0 && val <= MAX_VIFS) {
			if (wifi->params.num_vifs != val) {
				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}

				pr_err("Re-initializing UMAC ..\n");
				wifi->params.num_vifs = val;

				uccp420wlan_init();
			}
		}
	} else if (param_get_match(buf, "rf_params=")) {
		conv_str_to_byte(wifi->params.rf_params,
				strstr(buf, "=") + 1,
				RF_PARAMS_SIZE);
	} else if (param_get_val(buf, "rx_packet_mgmt_count=", &val)) {
		wifi->stats.rx_packet_mgmt_count = val;
	} else if (param_get_val(buf, "rx_packet_data_count=", &val)) {
		wifi->stats.rx_packet_data_count = val;
	} else if (param_get_val(buf, "pdout_val=", &val)) {
		wifi->stats.pdout_val = val;
	} else if (param_get_val(buf, "get_stats=", &val)) {
		uccp420wlan_prog_mib_stats();
	} else if (param_get_val(buf, "max_data_size=", &val)) {
		if (wifi->params.max_data_size != val) {
			if ((wifi->params.max_data_size >= 2 * 1024) &&
			    (wifi->params.max_data_size <= (12 * 1024))) {
				wifi->params.max_data_size = val;

				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}

				pr_err("Re-initalizing UCCP420 with %ld as max data size\n",
				       val);

				uccp420wlan_init();
			} else
				pr_err("Invalid Value for max data size: should be (2K-12K)\n");
		}
	} else if (param_get_val(buf, "max_tx_cmds=", &val)) {
		if (val >= 1 || val <= MAX_TX_CMDS)
			wifi->params.max_tx_cmds = val;
	} else if (param_get_val(buf, "disable_power_save=", &val)) {
		if ((val == 0) || (val == 1)) {
			if (val != wifi->params.disable_power_save) {
				wifi->params.disable_power_save = val;

				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}

				pr_err("Re-initalizing UCCP420 with global powerave %s\n",
				       val ? "DISABLED" : "ENABLED");

				uccp420wlan_init();
			}
		}
	} else if (param_get_val(buf, "disable_sm_power_save=", &val)) {
		if ((val == 0) || (val == 1)) {
			if (val != wifi->params.disable_sm_power_save) {
				wifi->params.disable_sm_power_save = val;

				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}

				pr_err("Re-initalizing UCCP420 with smps %s\n",
				       val ? "DISABLED" : "ENABLED");

				uccp420wlan_init();
			}
		}
	} else if (param_get_val(buf, "uccp_num_spatial_streams=", &val)) {
		if (val > 0 && val <= min(MAX_TX_STREAMS, MAX_RX_STREAMS)) {
			if (val != wifi->params.uccp_num_spatial_streams) {
				wifi->params.uccp_num_spatial_streams = val;
				wifi->params.num_spatial_streams = val;
				wifi->params.max_tx_streams = val;
				wifi->params.max_rx_streams = val;
				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}
				pr_err("Re-initalizing UCCP420 with %ld spatial streams\n",
				       val);
				uccp420wlan_init();
			}
		} else
			pr_err("Invalid parameter value: Allowed Range: 1 to %d\n",
			       min(MAX_TX_STREAMS, MAX_RX_STREAMS));
	} else if (param_get_val(buf, "antenna_sel=", &val)) {
		if (val == 1 || val == 2) {
			if (val != wifi->params.antenna_sel) {
				wifi->params.antenna_sel = val;
				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}
				pr_err("Re-initalizing UCCP420 with %ld antenna selection \n",
				       val);
				uccp420wlan_init();
			}
		} else
			pr_err("Invalid parameter value: Allowed Values: 1 or 2\n");
	} else if (param_get_val(buf, "num_spatial_streams=", &val)) {
		if (val > 0 && val <= wifi->params.uccp_num_spatial_streams)
			wifi->params.num_spatial_streams = val;
		else
			pr_err("Invalid parameter value, should be less than or equal to uccp_num_spatial_streams\n");
	} else if (param_get_sval(buf, "mgd_mode_tx_fixed_mcs_indx=", &sval)) {
		if (wifi->params.mgd_mode_tx_fixed_rate == -1) {

			int mcs_indx = wifi->params.mgd_mode_tx_fixed_mcs_indx;

			if (vht_support && (wifi->params.prod_mode_rate_flag &
					    ENABLE_VHT_FORMAT)) {
				if ((sval >= -1) && (sval <= 9)) {
					/* Get_rate will do the MCS holes
					 * validation
					 */
					mcs_indx = sval;
				} else
					pr_err("Invalid parameter value.\n");
			} else {
				if (wifi->params.num_spatial_streams == 2) {
					if ((sval >= -1) && (sval <= 15))
						mcs_indx = sval;
					else
						pr_err("Invalid MIMO HT MCS: %ld\n",
						       sval);
				}
				if (wifi->params.num_spatial_streams == 1) {
					if ((sval >= -1) && (sval <= 7))
						mcs_indx = sval;
					else
						pr_err("Invalid SISO HT MCS: %ld\n",
						       sval);
				}
			}

			wifi->params.mgd_mode_tx_fixed_mcs_indx = mcs_indx;
		} else
			pr_err("Fixed rate other than MCS index is currently set\n");
	} else if (param_get_sval(buf, "mgd_mode_tx_fixed_rate=", &sval)) {
		if (wifi->params.mgd_mode_tx_fixed_mcs_indx == -1) {
			int tx_fixed_rate = wifi->params.mgd_mode_tx_fixed_rate;
			if (wifi->params.dot11g_support == 1 &&
			    ((sval == 1) ||
			     (sval == 2) ||
			     (sval == 55) ||
			     (sval == 11))) {
				tx_fixed_rate = sval;
			} else if ((sval == 6) ||
				   (sval == 9) ||
				   (sval == 12) ||
				   (sval == 18) ||
				   (sval == 24) ||
				   (sval == 36) ||
				   (sval == 48) ||
				   (sval == 54) ||
				   (sval == -1)) {
				tx_fixed_rate = sval;
			} else {
				pr_err("Invalid parameter value.\n");
				return count;
			}
			wifi->params.mgd_mode_tx_fixed_rate = tx_fixed_rate;
		} else
			pr_err("MCS data rate(index) is currently set\n");
	} else if (param_get_sval(buf, "tx_fixed_mcs_indx=", &sval)) {

		do {
			if (wifi->params.production_test != 1) {
				pr_err("Only can be set in production mode\n");
				break;
			}

			if ((wifi->params.num_spatial_streams == 2) &&
			    (sval >= -1) && (sval <= 15))
				wifi->params.tx_fixed_mcs_indx = sval;
			else
				pr_err("Invalid MIMO HT MCS: %ld\n", sval);

			if ((wifi->params.num_spatial_streams == 1) &&
			    (sval >= -1) && (sval <= 7))
				wifi->params.tx_fixed_mcs_indx = sval;
			else
				pr_err("Invalid SISO HT MCS: %ld\n", sval);

		} while (0);

		if (wifi->params.production_test == 1 &&
		    wifi->params.tx_fixed_rate == -1 &&
		    vht_support && (wifi->params.prod_mode_rate_flag &
				    ENABLE_VHT_FORMAT)) {

			if (!((sval >= -1) && (sval <= 9)))
				pr_err("Invalid parameter value.\n");

			if ((sval >= -1) && (sval <= 9))
				wifi->params.tx_fixed_mcs_indx = sval;

			if ((wifi->params.prod_mode_chnl_bw_40_mhz == 0) &&
			    (wifi->params.prod_mode_chnl_bw_80_mhz == 0) &&
			    (sval == 9)) {
				pr_err("Invalid VHT MCS: 20MHZ-MCS9.\n");

				/*Reset to Default*/
				wifi->params.tx_fixed_mcs_indx = 7;
			}
		}

	} else if (param_get_sval(buf, "tx_fixed_rate=", &sval)) {
		if (wifi->params.production_test == 1) {
			if (wifi->params.tx_fixed_mcs_indx == -1) {
				if ((wifi->params.dot11g_support == 1) &&
				    ((sval == 1) ||
				     (sval == 2) ||
				     (sval == 55) ||
				     (sval == 11))) {
					wifi->params.tx_fixed_rate = sval;
				} else if ((sval == 6) ||
					   (sval == 9) ||
					   (sval == 12) ||
					   (sval == 18) ||
					   (sval == 24) ||
					   (sval == 36) ||
					   (sval == 48) ||
					   (sval == 54) ||
					   (sval == -1)) {
					wifi->params.tx_fixed_rate = sval;
				} else {
					pr_err("Invalid parameter value.\n");
					return count;
				}
			} else
				pr_err("MCS data rate(index) is currently set\n");
		} else
			pr_err("Only can be set in production mode.\n");
	} else if (param_get_val(buf, "chnl_bw=", &val)) {
		if (((val == 0) ||
		    (vht_support && (val == 2)) ||
		     (val == 1))) {
			wifi->params.chnl_bw = val;

			if (wifi->hw) {
				uccp420wlan_exit();
				wifi->hw = NULL;
			}

			pr_err("Re-initializing UMAC ..\n");

			uccp420wlan_init();
		} else
			pr_err("Invalid parameter value.\n");
	} else if (param_get_val(buf, "prod_mode_chnl_bw_40_mhz=", &val)) {

		do {
			if (wifi->params.production_test != 1) {
				pr_err("Can be set in only in production mode.\n");
				break;
			}

			if (!((val == 0) || (val == 1))) {
				pr_err("Invalid parameter value.\n");
				break;
			}

			wifi->params.prod_mode_chnl_bw_40_mhz = val;

			if (!vht_support)
				break;

			wifi->params.prod_mode_chnl_bw_80_mhz = 0;
		} while (0);

	} else if (vht_support &&
		   param_get_val(buf, "prod_mode_chnl_bw_80_mhz=", &val)) {
		if (wifi->params.production_test == 1) {
			if ((val == 0) || (val == 1)) {
				wifi->params.prod_mode_chnl_bw_40_mhz = 0;
				wifi->params.prod_mode_chnl_bw_80_mhz = val;
			} else
				pr_err("Invalid parameter value.\n");
		} else
			pr_err("Can be set in only in production mode.\n");
	} else if (param_get_val(buf, "sec_ch_offset_40_plus=", &val)) {
		do {
			if (wifi->params.production_test != 1) {
				pr_err("Can be set in only in production mode.\n");
				break;
			}

			if (!((wifi->params.prod_mode_chnl_bw_40_mhz == 1)
			    || (vht_support &&
				(wifi->params.prod_mode_chnl_bw_80_mhz == 1))
			    )) {
				pr_err("Can be set only when prod_mode_chnl_bw_40_mhz is set.\n");
				break;
			}


			if (wifi->params.sec_ch_offset_40_minus == 1) {
				pr_err("Can be set only when sec_ch_offset_40_minus is not set\n");
				break;
			}

			if (!((val == 0) || (val == 1))) {
				pr_err("Invalid parameter value.\n");
				break;
			}

			wifi->params.sec_ch_offset_40_plus = val;

		} while (0);

	} else if (param_get_val(buf, "sec_ch_offset_40_minus=", &val)) {
		do {
			if (wifi->params.production_test != 1) {
				pr_err("Can be set in only in production mode.\n");
				break;
			}

			if (!((wifi->params.prod_mode_chnl_bw_40_mhz == 1)
			    || (vht_support &&
				(wifi->params.prod_mode_chnl_bw_80_mhz == 1))
			    )) {
				pr_err("Can be set only when prod_mode_chnl_bw_40_mhz is set.\n");
				break;
			}


			if (wifi->params.sec_ch_offset_40_plus == 1) {
				pr_err("Can be set only when sec_ch_offset_40_plus is not set\n");
				break;
			}

			if (!((val == 0) || (val == 1))) {
				pr_err("Invalid parameter value.\n");
				break;
			}

			wifi->params.sec_ch_offset_40_minus = val;

		} while (0);

	} else if (vht_support &&
		   param_get_val(buf, "sec_40_ch_offset_80_plus=", &val)) {
		do {
			if (wifi->params.production_test != 1) {
				pr_err("Can be set in only in production mode.\n");
				break;
			}

			if (!(wifi->params.prod_mode_chnl_bw_80_mhz == 1)) {
				pr_err("Can be set if prod_mode_chnl_bw_80_mhz is set\n");
				break;
			}


			if (wifi->params.sec_40_ch_offset_80_minus == 1) {
				pr_err("Can be set only when sec_40_ch_offset_80_minus is not set\n");
				break;
			}

			if (!((val == 0) || (val == 1))) {
				pr_err("Invalid parameter value.\n");
				break;
			}

			wifi->params.sec_40_ch_offset_80_plus = val;

		} while (0);

	} else if (vht_support &&
		   (param_get_val(buf, "sec_40_ch_offset_80_minus=", &val))) {
		do {
			if (wifi->params.production_test != 1) {
				pr_err("Can be set in only in production mode.\n");
				break;
			}

			if (!(wifi->params.prod_mode_chnl_bw_80_mhz == 1)) {
				pr_err("Can be set if prod_mode_chnl_bw_80_mhz is set\n");
				break;
			}


			if (wifi->params.sec_40_ch_offset_80_plus == 1) {
				pr_err("Can be set only when sec_40_ch_offset_80_plus is not set\n");
				break;
			}

			if (!((val == 0) || (val == 1))) {
				pr_err("Invalid parameter value.\n");
				break;
			}

			wifi->params.sec_40_ch_offset_80_minus = val;

		} while (0);
	} else if (param_get_val(buf, "prod_mode_rate_flag=", &val)) {
		do {
			/*Only first 6 flags are defined currently*/
			if (val > 63)
				pr_err("Invalid parameter value");

			if ((val & ENABLE_VHT_FORMAT) &&
			    (val & ENABLE_11N_FORMAT)) {
				pr_err("Cannot set HT and VHT both.");
				break;
			}

			if ((val & ENABLE_CHNL_WIDTH_40MHZ) &&
			    (val & ENABLE_CHNL_WIDTH_80MHZ)) {
				pr_err("Cannot set 40 and 80 both.");
				break;
			}

			if ((wifi->params.uccp_num_spatial_streams == 1)  &&
			    (val & ENABLE_SGI) &&
			    (val & ENABLE_GREEN_FIELD)) {
				pr_err("Cannot set GreenField when SGI is enabled for SISO");
				break;
			}

			wifi->params.prod_mode_rate_flag = val;
		} while (0);

	} else if (param_get_val(buf, "rate_protection_type=", &val)) {
		/* 0 is None, 1 is RTS/CTS, 2 is for CTS2SELF */
		if ((val == 0) || (val == 1) /*|| (val == 2)*/)
			wifi->params.rate_protection_type = val;
		else
			pr_err("Invalid parameter value");
	} else if (param_get_val(buf, "prod_mode_rate_preamble_type=", &val)) {
		/*0 is short, 1 is Long*/
		if ((val == 0) || (val == 1))
			wifi->params.prod_mode_rate_preamble_type = val;
		else
			pr_err("Invalid parameter value");
	} else if (param_get_val(buf, "prod_mode_stbc_enabled=", &val)) {
		if (val <= 1)
			wifi->params.prod_mode_stbc_enabled = val;
		else
			pr_err("Invalid parameter value\n");
	} else if (param_get_val(buf, "prod_mode_bcc_or_ldpc=", &val)) {
		if (val <= 1)
			wifi->params.prod_mode_bcc_or_ldpc = val;
		else
			pr_err("Invalid parameter value\n");
	} else if (param_get_val(buf, "reset_hal_params=", &val)) {
		if (((struct mac80211_dev *)
		     (wifi->hw->priv))->state != STARTED) {
			if (val != 1)
				pr_err("Invalid parameter value\n");
			else
				hal_ops.reset_hal_params();
		} else
			pr_err("HAL parameters reset can be done only when all interface are down\n");
	} else if (param_get_val(buf, "vht_beamformer_enable=", &val)) {
		do {
			int vht_beamform_period;

			if (wifi->params.vht_beamform_enable != val)
				break;

			if (!((val == VHT_BEAMFORM_ENABLE) ||
			      (val == VHT_BEAMFORM_DISABLE))) {
				pr_err("Invalid VHT Beamforming Enable value should be 1 or 0\n");
				break;
			}

			wifi->params.vht_beamform_enable = val;

			/* If not associated, it will be sent upon
			 * association
			 */
			if (!wifi->params.is_associated)
				break;

			vht_beamform_period = wifi->params.vht_beamform_period;

			uccp420wlan_prog_vht_bform(val, vht_beamform_period);
		} while (0);

	} else if (param_get_val(buf, "vht_beamformer_period=", &val)) {

		do {
			int vht_beamform_enable;

			if (wifi->params.vht_beamform_enable !=
			    VHT_BEAMFORM_ENABLE) {
				pr_err("VHT Beamforming is disabled, please enable it first\n");
				break;
			}

			if (wifi->params.vht_beamform_enable != val)
				break;

			if (!((val > 100) || (val < 10000))) {
				pr_err("Invalid VHT Beamforming Period must be between 100-10000ms\n");
				break;
			}

			wifi->params.vht_beamform_period = val;

			/* If not associated, it will be sent upon
			 * association
			 */
			if (!wifi->params.is_associated)
				break;

			vht_beamform_enable = wifi->params.vht_beamform_period;

			uccp420wlan_prog_vht_bform(vht_beamform_enable, val);
		} while (0);

	} else if (param_get_val(buf, "bg_scan_enable=", &val)) {
		if (wifi->params.bg_scan_enable != val) {
			if ((val == 1) || (val == 0)) {
				wifi->params.bg_scan_enable = val;
				if (wifi->hw) {
					uccp420wlan_exit();
					wifi->hw = NULL;
				}
				pr_err("Re-initializing UMAC ..\n");
				uccp420wlan_init();
			} else
				pr_err("Invalid bg_scan_enable value should be 1 or 0\n");
		}
	} else if (param_get_match(buf, "bg_scan_channel_list=")) {
		conv_str_to_byte(wifi->params.bg_scan_channel_list,
				 strstr(buf, "=") + 1,
				 50);
	} else if (param_get_match(buf, "bg_scan_channel_flags=")) {
		conv_str_to_byte(wifi->params.bg_scan_channel_flags,
				 strstr(buf, "=") + 1,
				 50);
	} else if (param_get_val(buf, "bg_scan_intval=", &val)) {
		if ((val >= 1000) && (val <= 60000))
			wifi->params.bg_scan_intval = val * 1000;/* us */
		else
			pr_err("Invalid bgscan duration/interval value should be between 1000 to 60000 ms.\n");
#if 0
		/*currently not used in LMAC, so don't export to user*/
	} else if (param_get_val(buf, "bg_scan_chan_dur =", &val)) {
		if ((val >= 100) && (val <= 1000))
			wifi->params.bg_scan_chan_dur = val;
		else
			pr_err("Invalid chan duration value should be between 100 to 1000.\n");
	} else if (param_get_val(buf, "bg_scan_serv_chan_dur =", &val)) {
		if ((val >= 100) && (val <= 1000))
			wifi->params.bg_scan_serv_chan_dur = val;
		else
			pr_err("Invalid serv chan duration value should be between 100 to 1000.\n");
#endif
	} else if (param_get_val(buf, "bg_scan_num_channels=", &val)) {
		wifi->params.bg_scan_num_channels = val;
	} else if (param_get_val(buf, "nw_selection=", &val)) {
		if ((val == 1) || (val == 0)) {
			wifi->params.nw_selection = val;
			pr_err("in nw_selection\n");
			uccp420wlan_prog_nw_selection(1, vif_macs[0]);
		} else
			pr_err("Invalid nw selection value should be 1 or 0\n");
	} else if (param_get_val(buf, "scan_type=", &val)) {
		if ((val == 0) || (val == 1))
			wifi->params.scan_type = val;
		else
			pr_err("Invalid scan type value %d, should be 0 or 1\n",
			       (unsigned int)val);
	} else if (ftm && param_get_val(buf, "aux_adc_chain_id=", &val)) {
		memset(wifi->params.pdout_voltage, 0 ,
		       sizeof(char) * MAX_AUX_ADC_SAMPLES);
		if ((val == AUX_ADC_CHAIN1) || (val == AUX_ADC_CHAIN2)) {
			wifi->params.aux_adc_chain_id = val;
			uccp420wlan_prog_aux_adc_chain(val);
		} else
			pr_err("Invalid chain id %d, should be %d or %d\n",
			       (unsigned int) val,
			       AUX_ADC_CHAIN1,
			       AUX_ADC_CHAIN2);
	} else if ((wifi->params.production_test) &&
		    param_get_val(buf, "start_prod_mode=", &val)) {
			unsigned int pri_chnl_num = 0;
			unsigned int chnl_num1 = 0;
			unsigned int chnl_num2 = 0;
			unsigned int freq_band = IEEE80211_BAND_5GHZ;
			unsigned int ch_width = 0;
			int center_freq = 0;
			int cf_offset = 0;
			int is_vht_bw80 = 0;
			int is_vht_bw80_sec_40minus = 0;
			int is_vht_bw80_sec_40plus = 0;
			struct mac80211_dev *dev = wifi->hw->priv;
			pri_chnl_num = val;
			wifi->params.start_prod_mode = val;
			tasklet_init(&dev->proc_tx_tasklet, packet_generation,
				     (unsigned long)dev);
			if (pri_chnl_num < 15)
				freq_band = IEEE80211_BAND_2GHZ;
			else
				freq_band = IEEE80211_BAND_5GHZ;

			center_freq =
			ieee80211_channel_to_frequency(pri_chnl_num,
						       freq_band);
			cf_offset = center_freq;

			if ((wifi->params.prod_mode_chnl_bw_40_mhz == 1) &&
			    (wifi->params.sec_ch_offset_40_minus == 1)) {
				/*  NL80211_CHAN_HT40MINUS */
				ch_width = 2;
				cf_offset = center_freq - 10;
			} else if (wifi->params.prod_mode_chnl_bw_40_mhz == 1) {
				/* NL80211_CHAN_HT40PLUS */
				ch_width = 2;
				cf_offset = center_freq + 10;
			}

			is_vht_bw80 = vht_support &&
				(wifi->params.prod_mode_chnl_bw_80_mhz == 1);

			is_vht_bw80_sec_40minus = is_vht_bw80 &&
				(wifi->params.sec_ch_offset_40_minus == 1);

			is_vht_bw80_sec_40plus = is_vht_bw80 &&
				(wifi->params.sec_ch_offset_40_plus == 1);

			if (is_vht_bw80)
				ch_width = 3;

			if (is_vht_bw80_sec_40minus &&
			    (wifi->params.sec_40_ch_offset_80_minus == 1))
				cf_offset = center_freq - 30;
			else if (is_vht_bw80_sec_40minus &&
				 (wifi->params.sec_40_ch_offset_80_plus == 1))
				cf_offset = center_freq + 10;
			else if (is_vht_bw80_sec_40minus)/* default */
				cf_offset = center_freq - 30;

			if (is_vht_bw80_sec_40plus &&
			    (wifi->params.sec_40_ch_offset_80_minus == 1))
				cf_offset = center_freq - 10;
			else if (is_vht_bw80_sec_40plus &&
				 (wifi->params.sec_40_ch_offset_80_plus == 1))
				cf_offset = center_freq + 30;
			else if (is_vht_bw80_sec_40plus)/* default */
				cf_offset = center_freq - 10;

			chnl_num1 = ieee80211_frequency_to_channel(cf_offset);
			chnl_num2 = 0;

			if ((wifi->params.fw_loading == 1) &&
			     load_fw(dev->hw)) {
				pr_err("%s: Firmware loading failed\n",
				       dev->name);
				goto error;
			 }
			if (!uccp420wlan_core_init(dev, ftm)) {
				uccp420wlan_prog_vif_ctrl(0,
						dev->if_mac_addresses[0].addr,
						IF_MODE_STA_IBSS,
						IF_ADD);
				proc_bss_info_changed(
						dev->if_mac_addresses[0].addr,
						val);
				uccp420wlan_prog_channel(pri_chnl_num,
							 chnl_num1,
							 chnl_num2, ch_width,
							 freq_band);
				skb_queue_head_init(&dev->tx.proc_tx_list[0]);
				wifi->params.init_prod = 1;
			 } else {
				pr_err("LMAC Initialization Failed\n");
				wifi->params.init_prod = 0;
			}

	} else if ((wifi->params.production_test) && (wifi->params.init_prod)
		   && param_get_sval(buf, "stop_prod_mode=", &sval)) {
			struct mac80211_dev *dev = wifi->hw->priv;
			tasklet_kill(&dev->proc_tx_tasklet);
			#if 0
			/* Todo: Enabling this causes RPU Lockup,
			 * need to debug */
			uccp420wlan_prog_vif_ctrl(0,
						  dev->if_mac_addresses[0].addr,
						  IF_MODE_STA_IBSS,
						  IF_REM);
			#endif
			uccp420wlan_core_deinit(dev, 0);
			wifi->params.start_prod_mode = 0;
			wifi->params.pkt_gen_val = 1;
			hal_ops.reset_hal_params();
			wifi->params.init_prod = 0;
	} else if ((wifi->params.production_test) && (wifi->params.init_prod)
		 &&   param_get_sval(buf, "start_packet_gen=", &sval)) {
		struct mac80211_dev *dev = wifi->hw->priv;
		wifi->params.pkt_gen_val = sval;
		if (sval != 0)
			tasklet_schedule(&dev->proc_tx_tasklet);

	} else if ((wifi->params.production_test) && (wifi->params.init_prod)
		 && param_get_sval(buf, "stop_packet_gen=", &sval)) {
			struct mac80211_dev *dev = wifi->hw->priv;
			wifi->params.pkt_gen_val = 1;
			tasklet_kill(&dev->proc_tx_tasklet);
	} else if ((wifi->params.production_test) &&
		    param_get_sval(buf, "payload_length=", &sval)) {
			wifi->params.payload_length = val;
	} else if ((ftm || wifi->params.production_test) &&
		    param_get_sval(buf, "set_tx_power=", &sval)) {
		memset(wifi->params.pdout_voltage, 0 ,
		       sizeof(char) * MAX_AUX_ADC_SAMPLES);
		wifi->params.set_tx_power = sval;
		uccp420wlan_prog_txpower(sval);
#ifdef PERF_PROFILING
	} else if (param_get_val(buf, "driver_tput=", &val)) {
		if ((val == 1) || (val == 0))
			wifi->params.driver_tput = val;
		else
			pr_err("Invalid driver_tput value should be 1 or 0\n");
#endif
	} else if (param_get_val(buf, "fw_loading=", &val)) {
			wifi->params.fw_loading = val;
	} else if (param_get_val(buf, "bt_state=", &val)) {
		if (val == 0 || val == 1) {
			if (val != wifi->params.bt_state) {
				wifi->params.bt_state = val;
				uccp420wlan_prog_btinfo(val);
			}
		} else
			pr_err("Invalid parameter value: Allowed values: 0 or 1\n");
	} else if (param_get_val(buf, "clear_stats=", &val)) {
		uccp420wlan_prog_clear_stats();
	} else if (param_get_val(buf, "disable_beacon_ibss=", &val)) {
		if ((val == 1) || (val == 0))
			wifi->params.disable_beacon_ibss = val;
		else
			pr_err("Invalid driver_tput value should be 1 or 0\n");
	} else
		pr_err("Invalid parameter name: %s\n", buf);
error:
	return count;
}


static int proc_open_config(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_config, NULL);
}


static int proc_open_phy_stats(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_phy_stats, NULL);
}


static int proc_open_mac_stats(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_mac_stats, NULL);
}


static const struct file_operations params_fops_config = {
	.open = proc_open_config,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = proc_write_config,
	.release = single_release
};

static const struct file_operations params_fops_phy_stats = {
	.open = proc_open_phy_stats,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = NULL,
	.release = single_release
};
static const struct file_operations params_fops_mac_stats = {
	.open = proc_open_mac_stats,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = NULL,
	.release = single_release
};
static int proc_init(void)
{
	struct proc_dir_entry *entry;
	int err = 0;
	unsigned int i = 0;
	/*2.4GHz and 5 GHz PD and TX-PWR calibration params*/
	unsigned char rf_params[RF_PARAMS_SIZE * 2];

	strncpy(rf_params,
		"1E00000000002426292A2C2E3237393F454A52576066000000002B2C3033373A3D44474D51575A61656B6F000000002B2C3033373A3D44474D51575A61656B6F000000002B2C3033373A3D44474D51575A61656B6F000000002B2C3033373A3D44474D51575A61656B6F00000000002426292A2C2E3237393F454A52576066000000002B2C3033373A3D44474D51575A61656B6F000000002B2C3033373A3D44474D51575A61656B6F000000002B2C3033373A3D44474D51575A61656B6F000000002B2C3033373A3D44474D51575A61656B6F0808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808",
		(RF_PARAMS_SIZE * 2));

	wifi = kzalloc(sizeof(struct wifi_dev), GFP_KERNEL);
	if (!wifi) {
		err = -ENOMEM;
		goto out;
	}

	wifi->umac_proc_dir_entry = proc_mkdir("uccp420", NULL);
	if (!wifi->umac_proc_dir_entry) {
		pr_err("Failed to create proc dir\n");
		err = -ENOMEM;
		goto  proc_dir_fail;
	}

	entry = proc_create("params", 0644, wifi->umac_proc_dir_entry,
			    &params_fops_config);
	if (!entry) {
		pr_err("Failed to create proc entry\n");
		err = -ENOMEM;
		goto  proc_entry1_fail;
	}

	entry = proc_create("phy_stats", 0444, wifi->umac_proc_dir_entry,
			    &params_fops_phy_stats);
	if (!entry) {
		pr_err("Failed to create proc entry\n");
		err = -ENOMEM;
		goto  proc_entry2_fail;
	}

	entry = proc_create("mac_stats", 0444, wifi->umac_proc_dir_entry,
			    &params_fops_mac_stats);
	if (!entry) {
		pr_err("Failed to create proc entry\n");
		err = -ENOMEM;
		goto  proc_entry3_fail;
	}

	/* Initialize WLAN params */
	memset(&wifi->params, 0, sizeof(struct wifi_params));

	/* TODO: Make this a struct */
	memset(wifi->params.rf_params, 0xFF, sizeof(wifi->params.rf_params));
	conv_str_to_byte(wifi->params.rf_params, rf_params, RF_PARAMS_SIZE);

	if (!rf_params_vpd)
		rf_params_vpd = wifi->params.rf_params;

	memcpy(wifi->params.rf_params_vpd, rf_params_vpd, RF_PARAMS_SIZE);

	wifi->params.is_associated = 0;
	wifi->params.ed_sensitivity = -89;
	wifi->params.auto_sensitivity = 1;
	wifi->params.dot11a_support = 1;
	wifi->params.dot11g_support = 1;
	wifi->params.num_vifs = 2;

	/* Check, if required add it */
	wifi->params.tx_fixed_mcs_indx = -1;
	wifi->params.tx_fixed_rate = -1;
	wifi->params.num_spatial_streams = min(MAX_TX_STREAMS, MAX_RX_STREAMS);
	wifi->params.uccp_num_spatial_streams = min(MAX_TX_STREAMS,
						    MAX_RX_STREAMS);
	wifi->params.antenna_sel = 1;

	if (num_streams_vpd > 0)
		wifi->params.uccp_num_spatial_streams = num_streams_vpd;

	wifi->params.bt_state = 1;
	wifi->params.mgd_mode_tx_fixed_mcs_indx = -1;
	wifi->params.mgd_mode_tx_fixed_rate = -1;
	if (vht_support)
		wifi->params.chnl_bw = WLAN_80MHZ_OPERATION;
	else
		wifi->params.chnl_bw = WLAN_20MHZ_OPERATION;
	wifi->params.max_tx_streams = MAX_TX_STREAMS;
	wifi->params.max_rx_streams = MAX_RX_STREAMS;
	wifi->params.max_data_size  = 8 * 1024;

	wifi->params.vht_beamform_enable = VHT_BEAMFORM_DISABLE;
	wifi->params.vht_beamform_period = 1000; /* ms */
	wifi->params.vht_beamform_support = 0;
	if (vht_support)
		wifi->params.max_tx_cmds = 24;
	else
		wifi->params.max_tx_cmds = 16;
	wifi->params.disable_power_save = 0;
	wifi->params.disable_sm_power_save = 0;
	wifi->params.rate_protection_type = 0; /* Disable protection by def */
	wifi->params.prod_mode_rate_preamble_type = 1; /* LONG */
	wifi->params.prod_mode_stbc_enabled = 0;
	wifi->params.prod_mode_bcc_or_ldpc = 0;
	wifi->params.bg_scan_enable = 0;
	memset(wifi->params.bg_scan_channel_list, 0 , 50);
	memset(wifi->params.bg_scan_channel_flags, 0 , 50);

	if (wifi->params.dot11g_support) {
		wifi->params.bg_scan_num_channels = 3;

		wifi->params.bg_scan_channel_list[i] = 1;
		wifi->params.bg_scan_channel_flags[i++] = ACTIVE;

		wifi->params.bg_scan_channel_list[i] = 6;
		wifi->params.bg_scan_channel_flags[i++] = ACTIVE;

		wifi->params.bg_scan_channel_list[i] = 11;
		wifi->params.bg_scan_channel_flags[i++] = ACTIVE;
	}

	if (wifi->params.dot11a_support) {
		wifi->params.bg_scan_num_channels += 4;

		wifi->params.bg_scan_channel_list[i] = 36;
		wifi->params.bg_scan_channel_flags[i++] = ACTIVE;

		wifi->params.bg_scan_channel_list[i] = 40;
		wifi->params.bg_scan_channel_flags[i++] = ACTIVE;

		wifi->params.bg_scan_channel_list[i] = 44;
		wifi->params.bg_scan_channel_flags[i++] = ACTIVE;

		wifi->params.bg_scan_channel_list[i] = 48;
		wifi->params.bg_scan_channel_flags[i++] = ACTIVE;
	}

	wifi->params.disable_beacon_ibss = 0;
	wifi->params.pkt_gen_val = -1;
	wifi->params.payload_length = 4000;
	wifi->params.start_prod_mode = 0;
	wifi->params.init_prod = 0;
	wifi->params.bg_scan_intval = 5000 * 1000; /* Once in 5 seconds */
	wifi->params.bg_scan_chan_dur = 300; /* Channel spending time */
	wifi->params.bg_scan_serv_chan_dur = 100; /* Oper chan spending time */
	wifi->params.nw_selection = 0;
	wifi->params.scan_type = ACTIVE;
	wifi->params.hw_scan_status = HW_SCAN_STATUS_NONE;
	wifi->params.fw_loading = 1;

	return err;

proc_entry3_fail:
	remove_proc_entry("phy_stats", wifi->umac_proc_dir_entry);
proc_entry2_fail:
	remove_proc_entry("params", wifi->umac_proc_dir_entry);
proc_entry1_fail:
	remove_proc_entry("uccp420", NULL);
proc_dir_fail:
	kfree(wifi);
out:
	return err;

}

static void proc_exit(void)
{
	remove_proc_entry("mac_stats", wifi->umac_proc_dir_entry);
	remove_proc_entry("phy_stats", wifi->umac_proc_dir_entry);
	remove_proc_entry("params", wifi->umac_proc_dir_entry);
	remove_proc_entry("uccp420", NULL);
	kfree(wifi);
}


int _uccp420wlan_80211if_init(void)
{
	int error;
	error = proc_init();
	if (error)
		return error;

	error = uccp420wlan_init();

	return error;
}

void _uccp420wlan_80211if_exit(void)
{
	if (wifi && wifi->hw) {
		uccp420wlan_exit();
		proc_exit();
	}
}
