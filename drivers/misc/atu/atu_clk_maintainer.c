/*
 * Atu Clock Maintainer
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/atu_clk.h>
#include <linux/clk.h>
#include <linux/clocksource.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timecounter.h>
#include <linux/timer.h>
#include <linux/uaccess.h>

#include <uapi/misc/atu_ioctl.h>

#include "atu_clk_maintainer.h"
#include "atu_clk_ntp.h"

static int atu_rate_changed;
#define ATU_UPDATE_TIMER_INTRVL	1
#define ATU_MODE_ON_THE_FLY	0x80000000
#define EVENT_TIMER_RATE_TOLERANCE	512000

/* Structure holding internal clk managing values. */
struct atu_clk_maintainer {
	struct	timespec atu_time;
	struct	timecounter atu_timecntr;
	int	shift;
	u32	mult;
	cycle_t clk_cycles_per_ntp_cycle;
	cycle_t	shifted_ns_per_ntp_cycle;
	s64	shifted_remain_ns_per_ntp_cycle;
	/* NTP_SCALE_SHIFT bit shfted error */
	s64	tm_error;
	/*
	 * Error shift with respect to current clock's
	 * shift i.e (NTP_SCALE_SHIFT - clock shift)
	 */
	int	tm_error_shift;
	/* Char device which holds IOCTL handler */
	struct	miscdevice miscdev;
	/*
	 * The timer structure used to update the elapsed ticks count
	 * at regular interval
	 */
	struct	timer_list atu_timer;
	unsigned long	atu_timer_data;
	struct atu_clk_ntp atu_ntp;
	struct clk *clk_atu;
	spinlock_t atu_clk_lock;
	int event_timer_rate;
	struct notifier_block atu_clk_notifier;
	atomic_t last_ppb;
};

static void atu_time_update(void);
static int atu_adjtimex(struct timex *txc);

static struct atu_clk_maintainer *patu_clk_mtner;

static u64 do_div_round_closest(u64 numerator, u32 denominator)
{
	u64 result = 0;

	result = denominator >> 1;
	result += numerator;
	do_div(result, denominator);

	return result;
}

/*
 * This function updates ATU wall time and
 * reschedules for next ATU wall time update.
 */
static void atu_timer_timeout(unsigned long dat)
{
	atu_time_update();
	add_timer(&patu_clk_mtner->atu_timer);
}

/* This function initialises atu wall time update scheduler */
static void atu_timer_init(void)
{
	init_timer(&patu_clk_mtner->atu_timer);
	patu_clk_mtner->atu_timer.expires  = jiffies + ATU_UPDATE_TIMER_INTRVL;
	patu_clk_mtner->atu_timer.data =
		(unsigned long)&patu_clk_mtner->atu_timer_data;
	patu_clk_mtner->atu_timer.function = atu_timer_timeout;

	add_timer(&patu_clk_mtner->atu_timer);
	pr_debug("ATU Wall Time scheduler started\n");
}

static void atu_timer_exit(void)
{
	del_timer_sync(&patu_clk_mtner->atu_timer);
	pr_debug("ATU Wall Time scheduler removed\n");
}

static int atu_gettimestamp(struct atu_event *event)
{
	struct timespec timeofday;
	unsigned long flags;

	if (event->counter < ATU_MAX_COUNTERS) {
		spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
		if (!patu_clk_mtner->atu_timecntr.cc) {
			spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock,
					       flags);
			return -EFAULT;
		}
		event->timestamp_counter =
			patu_clk_mtner->atu_timecntr.cc->
			read(patu_clk_mtner->atu_timecntr.cc);

		event->timestamp = 0x0;
		event->timekeeping_shift = patu_clk_mtner->shift;
		event->timekeeping_mult = patu_clk_mtner->mult;
		atu_getnstimeofday(&timeofday);
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);

		event->timeofday_sec = timeofday.tv_sec;
		event->timeofday_ns = timeofday.tv_nsec;

		return 0;
	} else {
		return -ERANGE;
	}
}

static void set_frac_pll_adj_freq(int freq)
{
	atomic_set(&patu_clk_mtner->last_ppb, freq);
}

int get_frac_pll_adj_freq(void)
{
	return atomic_read(&patu_clk_mtner->last_ppb);
}
EXPORT_SYMBOL(get_frac_pll_adj_freq);

static long
ioctl_img_atu(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct atu_event event;
	int ret;
	struct timex u_txc;
	struct timeval u_tv;
	struct timespec	u_ts;
	unsigned long flags;

	if (!argp)
		return -EINVAL;

	switch (cmd) {
	default:
		return -EINVAL;

	case ATUIO_GETEVTS:
		if (copy_from_user(&event, argp, sizeof(event)))
			return -EFAULT;

		ret = atu_gettimestamp(&event);
		if (ret)
			return ret;

		if (copy_to_user(argp, &event, sizeof(event)))
			return -EFAULT;
		break;

	case ATUIO_ADJTIMEX:
		if (copy_from_user(&u_txc, argp, sizeof(u_txc)))
			return -EFAULT;

		if (!u_txc.modes) {
			struct timespec	timeofday;
			struct timespec	sys_timeofday;

			spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
			if (!patu_clk_mtner->atu_timecntr.cc) {
				spin_unlock_irqrestore(
					&patu_clk_mtner->atu_clk_lock, flags);
				return -EFAULT;
			}

			/* check for status bit to get clock times */
			if (u_txc.status) {
				atu_getnstimeofday(&timeofday);
				getnstimeofday(&sys_timeofday);
				u_txc.status = 0;
				u_txc.time.tv_sec = timeofday.tv_sec;
				u_txc.time.tv_usec = timeofday.tv_nsec;
				u_txc.maxerror = sys_timeofday.tv_sec;
				u_txc.esterror = sys_timeofday.tv_nsec;
				ret = 0;
			} else {
				/* fill ppb and rate change event */
				u_txc.freq = get_frac_pll_adj_freq();
				u_txc.tick = patu_clk_mtner->event_timer_rate;
				if (atu_rate_changed) {
					u_txc.status = 1;
					atu_rate_changed = 0;
				}
				ret = 0;
			}
			spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock,
									flags);
		} else {
			ret = atu_adjtimex(&u_txc);
		}

		if (copy_to_user(argp, &u_txc, sizeof(u_txc)))
			return -EFAULT;

		if (ret)
			return ret;
		break;

	case ATUIO_SETTIMEOFDAY:
		if (copy_from_user(&u_tv, argp, sizeof(u_tv)))
			return -EFAULT;
		u_ts.tv_sec = u_tv.tv_sec;
		u_ts.tv_nsec = u_tv.tv_usec * NSEC_PER_USEC;
		ret = atu_settimeofday(&u_ts);
		if (ret)
			return ret;
		break;

	case ATUIO_GETTIMESPEC:
		spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
		if (!patu_clk_mtner->atu_timecntr.cc) {
			spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock,
					       flags);
			return -EFAULT;
		}
		atu_getnstimeofday(&u_ts);
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);

		if (copy_to_user(argp, &u_ts, sizeof(u_ts)))
			return -EFAULT;
		break;
	}

	return 0;
}

static const struct file_operations atu_dev_fops = {
	.unlocked_ioctl		= ioctl_img_atu,
};

static int atu_chardev_init(void)
{
	int error;

	patu_clk_mtner->miscdev.minor = MISC_DYNAMIC_MINOR;
	patu_clk_mtner->miscdev.fops = &atu_dev_fops;
	patu_clk_mtner->miscdev.name = "img-atu";
	error = misc_register(&patu_clk_mtner->miscdev);
	if (error) {
		pr_err("Unable to register atu device\n");
		goto err_misc_reg;
	}
	pr_debug("ATU Clock dev added\n");

	return 0;

err_misc_reg:
	return error;
}

static int atu_chardev_remove(void)
{
	misc_deregister(&patu_clk_mtner->miscdev);
	pr_debug("ATU Clock dev removed\n");

	return 0;
}

static void
atu_clk_mtner_setup_internals(struct cyclecounter *patu_cyclecntr,
			      struct clk *clk_atu)
{
	cycle_t clk_cycle;
	u64 tmp, ntp_ns_per_cycle;

	patu_clk_mtner->atu_timecntr.cc = patu_cyclecntr;
	patu_clk_mtner->clk_atu = clk_atu;

	/* Clear the error */
	patu_clk_mtner->tm_error = 0;
	patu_clk_mtner->tm_error_shift = NTP_SCALE_SHIFT -
					patu_clk_mtner->atu_timecntr.cc->shift;

	tmp = NTP_INTERVAL_LENGTH;
	tmp <<= patu_clk_mtner->atu_timecntr.cc->shift;
	ntp_ns_per_cycle = tmp;

	tmp = do_div_round_closest(tmp, patu_clk_mtner->atu_timecntr.cc->mult);
	if (tmp == 0)
		tmp = 1;

	clk_cycle = (cycle_t)tmp;
	patu_clk_mtner->clk_cycles_per_ntp_cycle = clk_cycle;

	patu_clk_mtner->shifted_ns_per_ntp_cycle =
		(u64)clk_cycle * patu_clk_mtner->atu_timecntr.cc->mult;
	patu_clk_mtner->shifted_remain_ns_per_ntp_cycle =
		ntp_ns_per_cycle - patu_clk_mtner->shifted_ns_per_ntp_cycle;

	patu_clk_mtner->shift = patu_clk_mtner->atu_timecntr.cc->shift;

	patu_clk_mtner->mult = patu_clk_mtner->atu_timecntr.cc->mult;

	/* Update cycle_last with current read value */
	patu_clk_mtner->atu_timecntr.cycle_last = patu_clk_mtner->
			atu_timecntr.cc->read(patu_clk_mtner->atu_timecntr.cc);
}

static s64 atu_tm_get_ns(void)
{
	cycle_t ticks_now, ticks_delta;

	/* Read present clock ticks */
	ticks_now = patu_clk_mtner->atu_timecntr.cc->
				read(patu_clk_mtner->atu_timecntr.cc);

	/* Calculate the ticks delta since the last atu_update_clk_time: */
	ticks_delta = (ticks_now - patu_clk_mtner->atu_timecntr.cycle_last) &
			patu_clk_mtner->atu_timecntr.cc->mask;

	/* Convert to nanoseconds */
	return clocksource_cyc2ns(ticks_delta, patu_clk_mtner->mult,
				  patu_clk_mtner->shift);
}

/* It will update the latest clock's tick to the clk time */
static void atu_time_refresh(void)
{
	cycle_t cycle_now, cycle_delta;
	s64 nsec;

	cycle_now = patu_clk_mtner->atu_timecntr.cc->
				read(patu_clk_mtner->atu_timecntr.cc);

	cycle_delta = (cycle_now - patu_clk_mtner->atu_timecntr.cycle_last) &
			patu_clk_mtner->atu_timecntr.cc->mask;
	patu_clk_mtner->atu_timecntr.cycle_last = cycle_now;

	nsec = clocksource_cyc2ns(cycle_delta, patu_clk_mtner->mult,
				  patu_clk_mtner->shift);

	timespec_add_ns(&patu_clk_mtner->atu_time, nsec);
}

void atu_getnstimeofday(struct timespec *ts)
{
	s64 nsecs;

	if (!ts)
		return;
	*ts = patu_clk_mtner->atu_time;
	nsecs = atu_tm_get_ns();
	timespec_add_ns(ts, nsecs);
}

u64 atu_get_current_time(void)
{
	u64 nsecs;
	struct timespec ts;
	unsigned long flags;

	spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
	if (!patu_clk_mtner->atu_timecntr.cc) {
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
		return -EFAULT;
	}
	ts = patu_clk_mtner->atu_time;
	nsecs = atu_tm_get_ns();
	spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);

	nsecs += ((u64)ts.tv_sec * NSEC_PER_SEC) + ((u64)ts.tv_nsec);

	return nsecs;
}
EXPORT_SYMBOL(atu_get_current_time);

int atu_settimeofday(const struct timespec *ts)
{
	unsigned long flags;

	if (ts->tv_nsec >= NSEC_PER_SEC)
		return -EINVAL;

	spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
	if (!patu_clk_mtner->atu_timecntr.cc) {
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
		return -EFAULT;
	}

	/*
	 * Refresh the time so that it will update
	 * clock's last cycle to present value
	 */
	atu_time_refresh();

	patu_clk_mtner->atu_time = *ts;

	patu_clk_mtner->tm_error = 0;
	atu_ntp_reset(&patu_clk_mtner->atu_ntp);

	spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);

	return 0;
}

int atu_tm_add_offset(struct timespec *ts)
{
	if (ts->tv_nsec >= NSEC_PER_SEC)
		return -EINVAL;

	atu_time_refresh();

	patu_clk_mtner->atu_time = timespec_add(patu_clk_mtner->atu_time, *ts);

	patu_clk_mtner->tm_error = 0;

	atu_ntp_reset(&patu_clk_mtner->atu_ntp);

	return 0;
}

unsigned long atu_get_seconds(void)
{
	return patu_clk_mtner->atu_time.tv_sec;
}

static void frc_ticks_to_atu_units(u32 frccnt, u64 *patu)
{
	*patu = ((__u64)frccnt * patu_clk_mtner->mult) >> patu_clk_mtner->shift;
}

static void atu_units_to_frc_ticks(u64 atu, u64 *pfrccnt)
{
	*pfrccnt = do_div_round_closest(atu <<
			patu_clk_mtner->shift, patu_clk_mtner->mult);
}

static void atu_get_cur_atu_frc_pair(u64 *patu, u32 *pfrc)
{
	u64 nsecs;
	struct timespec ts;
	cycle_t ticks_now, ticks_delta;

	ts = patu_clk_mtner->atu_time;

	/* Read present clock ticks */
	ticks_now = patu_clk_mtner->atu_timecntr.cc->
				read(patu_clk_mtner->atu_timecntr.cc);
	ticks_now = ticks_now & patu_clk_mtner->atu_timecntr.cc->mask;

	/* Calculate the ticks delta since the last atu_update_clk_time: */
	ticks_delta = (ticks_now - patu_clk_mtner->atu_timecntr.cycle_last) &
			patu_clk_mtner->atu_timecntr.cc->mask;

	/* Convert to nanoseconds */
	nsecs = clocksource_cyc2ns(ticks_delta, patu_clk_mtner->mult,
				   patu_clk_mtner->shift);

	nsecs += ((u64)ts.tv_sec * NSEC_PER_SEC) + ((u64)ts.tv_nsec);

	*patu = nsecs;
	*pfrc = ticks_now;
}

int frc_to_atu(u32 frc, u64 *patu, s32 dir)
{
	u32 diff = 0, cur_frc;
	u64 cur_atu;
	unsigned long flags;

	if (!patu)
		return -EINVAL;

	spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
	if (!patu_clk_mtner->atu_timecntr.cc) {
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
		return -EFAULT;
	}

	/* Get current atu and frc count */
	atu_get_cur_atu_frc_pair(&cur_atu, &cur_frc);

	if (cur_frc >= frc)
		diff = cur_frc - frc;
	else
		diff = patu_clk_mtner->atu_timecntr.cc->mask +
					1 + cur_frc - frc;
	frc_ticks_to_atu_units(diff, patu);
	spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);

	if (dir == ATU_PAST) {
		*patu = cur_atu - *patu;
		if (*patu < 0)
			return -ERANGE;
	} else {
		*patu = cur_atu + *patu;
	}

	return 0;
}
EXPORT_SYMBOL(frc_to_atu);

int atu_to_frc(u64 atu, u32 *pfrc, u64 min_nsec)
{
	u64 cur_atu, atu_diff, frc_cnt;
	u32 cur_frc;
	unsigned long flags;

	if (!pfrc)
		return -EINVAL;

	spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
	if (!patu_clk_mtner->atu_timecntr.cc) {
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
		return -EFAULT;
	}

	/* Get current atu and frc count */
	atu_get_cur_atu_frc_pair(&cur_atu, &cur_frc);

	atu_diff = atu - cur_atu;

	/* Check for past time and min time diff */
	if (atu < cur_atu || atu_diff < min_nsec) {
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
		return -ERANGE;
	}

	atu_units_to_frc_ticks(atu_diff, &frc_cnt);
	spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);

	/* Check for obtained value is not more than counter rollover value */
	if (frc_cnt > patu_clk_mtner->atu_timecntr.cc->mask)
		return -ERANGE;

	/* Get cycle count val at the given atu time */
	*pfrc = (frc_cnt + cur_frc) &
			patu_clk_mtner->atu_timecntr.cc->mask;

	/* Check with latest time for min time diff */
	if ((atu - min_nsec) < atu_get_current_time())
		return -ERANGE;

	return 0;
}
EXPORT_SYMBOL(atu_to_frc);

void
atu_clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 maxsec)
{
	u64 tmp;
	u32 sft, sftacc = 32;

	/*
	 * Calculate the shift factor which is limiting the conversion
	 * range:
	 */
	tmp = ((u64)maxsec * from) >> 32;
	while (tmp) {
		tmp >>= 1;
		sftacc--;
	}

	/*
	 * Find the conversion shift/mult pair which has the best
	 * accuracy and fits the maxsec conversion range:
	 */
	for (sft = 32; sft > 0; sft--) {
		tmp = (u64)to << sft;
		tmp += from / 2;
		do_div(tmp, from);
		if ((tmp >> sftacc) == 0)
			break;
	}
	*mult = tmp;
	*shift = sft;
}

static void atu_clk_rate_change_on_the_fly(unsigned long int rate)
{
	unsigned long flags;
	u32 mult, shift, mask;
	cycle_t clk_cycle;
	u64 ntp_ns_per_cycle, ntp_ns_per_cycle_div;

	mask = patu_clk_mtner->atu_timecntr.cc->mask;

	clocks_calc_mult_shift(&mult, &shift, rate,
			       NSEC_PER_SEC, DIV_ROUND_UP(mask, rate));

	ntp_ns_per_cycle = (u64)NTP_INTERVAL_LENGTH << shift;
	ntp_ns_per_cycle_div = do_div_round_closest(ntp_ns_per_cycle, mult);

	clk_cycle = ntp_ns_per_cycle_div ? (cycle_t)ntp_ns_per_cycle_div :
					  (cycle_t)1;

	spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);

	patu_clk_mtner->shift = shift;
	patu_clk_mtner->mult = mult;
	patu_clk_mtner->event_timer_rate = rate;

	atu_rate_changed = 1;

	/* Clear the error */
	patu_clk_mtner->tm_error = 0;
	patu_clk_mtner->tm_error_shift = NTP_SCALE_SHIFT - shift;

	patu_clk_mtner->clk_cycles_per_ntp_cycle = clk_cycle;

	patu_clk_mtner->shifted_ns_per_ntp_cycle =
		(u64)clk_cycle * mult;
	patu_clk_mtner->shifted_remain_ns_per_ntp_cycle =
		ntp_ns_per_cycle - patu_clk_mtner->shifted_ns_per_ntp_cycle;

	/* Update cycle_last with current read value */
	patu_clk_mtner->atu_timecntr.cycle_last = patu_clk_mtner->
			atu_timecntr.cc->read(patu_clk_mtner->atu_timecntr.cc);

	spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
}

static int atu_adjtimex(struct timex *txc)
{
	int ret = 0;
	unsigned long flags;

	/* Fractional PLL */
	if (patu_clk_mtner->clk_atu) {
		spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);

		/* check rate change flag */
		if (atu_rate_changed) {
			ret = 0;
			goto unlock_and_return;
		}

		/* Time error correction - ADJ_SETOFFSET */
		if (txc->modes & ADJ_SETOFFSET) {
			ret = atu_set_time_offset(txc);
			goto unlock_and_return;
		}
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);

		/* Rate error correction - ADJ_FREQUENCY */
		if (txc->modes & ADJ_FREQUENCY) {
			unsigned long int rate;
			long int freq;
			int dir;

			freq = txc->freq;
			set_frac_pll_adj_freq(freq);

			if (freq < 0) {
				dir = -1;
				freq = -freq;
			} else  {
				dir = 1;
			}

			rate = patu_clk_mtner->event_timer_rate +
					do_div_round_closest(((u64)freq) *
					patu_clk_mtner->event_timer_rate,
					NSEC_PER_SEC) * dir;

			/* Setting new rate */
			clk_set_rate(patu_clk_mtner->clk_atu, rate);
			txc->freq = rate;
		}

	} else { /* Fixed PLL */
		spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
		if (patu_clk_mtner->atu_timecntr.cc)
			ret = __atu_adjtimex(txc, &patu_clk_mtner->atu_ntp);
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
	}

	return ret;

unlock_and_return:
	spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
	return ret;
}

static int atu_tm_big_adj_clk(s64 error, s64 *clk_cycle, s64 *ticks)
{
	s64 ntp_error, clk_interval;
	u32 look_ahead, shift;
	s32 mult = 1;
	s32 tm_error;

	/*
	 * Correction of about 1msec within about 1 sec
	 * or 2^20 nsec in 2^SHIFT_HZ ticks.
	 */
	tm_error = patu_clk_mtner->tm_error >>
				(NTP_SCALE_SHIFT + 22 - 2 * SHIFT_HZ);

	tm_error = abs(tm_error);

	for (look_ahead = 0; tm_error > 0; look_ahead++)
		tm_error >>= 2;

	ntp_error = get_ntp_shifted_nsecs_per_cycle(&patu_clk_mtner->atu_ntp) >>
				(patu_clk_mtner->tm_error_shift + 1);
	ntp_error -= patu_clk_mtner->shifted_ns_per_ntp_cycle >> 1;

	error = ((error - ntp_error) >> look_ahead) + ntp_error;

	clk_interval = *clk_cycle;
	if (error < 0) {
		error = -error;
		*clk_cycle = -*clk_cycle;
		*ticks = -*ticks;
		mult = -1;
	}
	for (shift = 0;
		error > clk_interval; shift++)
		error >>= 1;

	*clk_cycle <<= shift;
	*ticks <<= shift;
	return mult << shift;
}

static void atu_tm_adj_clk(s64 ticks)
{
	s64 error, clk_cycle;
	int mult;

	clk_cycle = patu_clk_mtner->clk_cycles_per_ntp_cycle;

	error = patu_clk_mtner->tm_error >>
			(patu_clk_mtner->tm_error_shift - 1);

	if (error > clk_cycle) {
		error >>= 3;

		if (likely(error <= clk_cycle))
				mult = 1;
		else
				mult = atu_tm_big_adj_clk(error, &clk_cycle,
							  &ticks);
	} else if (error < -clk_cycle) {
		error >>= 3;

		if (likely(error >= -clk_cycle)) {
				mult = -1;
				clk_cycle = -clk_cycle;
				ticks = -ticks;
		} else {
				mult = atu_tm_big_adj_clk(error, &clk_cycle,
							  &ticks);
		}
	} else {
		return;
	}

		patu_clk_mtner->mult += mult;
		patu_clk_mtner->shifted_ns_per_ntp_cycle += clk_cycle;
		patu_clk_mtner->atu_time.tv_nsec -=
				ticks >> patu_clk_mtner->shift;
		patu_clk_mtner->tm_error -= (clk_cycle - ticks) <<
						patu_clk_mtner->tm_error_shift;
}

static cycle_t calculate_remainder_ticks(cycle_t ticks)
{
	u64 no_cycles = ticks;
	u64 clk_cycle;
	s64 tick_error = 0;

	clk_cycle = patu_clk_mtner->clk_cycles_per_ntp_cycle;

	/* Get the no clk cycles per ntp cycle in the given ticks */
	do_div(no_cycles, clk_cycle);

	/* Subtract the no. of rounded cycles from ticks */
	ticks -= (no_cycles * patu_clk_mtner->clk_cycles_per_ntp_cycle);

	/* Add the no. of clk cycles to the cycle_last */
	patu_clk_mtner->atu_timecntr.cycle_last +=
		(no_cycles * patu_clk_mtner->clk_cycles_per_ntp_cycle);

	/* Add the no.of clk cycles to nano seconds */
	patu_clk_mtner->atu_time.tv_nsec += (no_cycles * patu_clk_mtner->
		shifted_ns_per_ntp_cycle) >> patu_clk_mtner->shift;

	/*
	 * If there is an overflow of nano seconds will update tv_sec and
	 * try to update/sync ntp's params
	 */
	while (patu_clk_mtner->atu_time.tv_nsec >= NSEC_PER_SEC) {
		patu_clk_mtner->atu_time.tv_nsec -= NSEC_PER_SEC;
		patu_clk_mtner->atu_time.tv_sec++;
		atu_ntp_param_update_per_second(&patu_clk_mtner->atu_ntp);
	}

	tick_error += get_ntp_shifted_nsecs_per_cycle(&patu_clk_mtner->atu_ntp);
	tick_error -=
		(patu_clk_mtner->shifted_ns_per_ntp_cycle +
		patu_clk_mtner->shifted_remain_ns_per_ntp_cycle) <<
				(patu_clk_mtner->tm_error_shift);

	/* Add the tick error of no_cycles to ntp error */
	patu_clk_mtner->tm_error += (no_cycles * tick_error);

	/* Return the left over ticks count */
	return ticks;
}

static void atu_update_clk_time(void)
{
	cycle_t ticks;
	cycle_t curticks;

	curticks = patu_clk_mtner->atu_timecntr.cc->
			read(patu_clk_mtner->atu_timecntr.cc);

	ticks = (curticks - patu_clk_mtner->atu_timecntr.cycle_last) &
					patu_clk_mtner->atu_timecntr.cc->mask;

	ticks = calculate_remainder_ticks(ticks);

	/* Correct the clock */
	atu_tm_adj_clk(ticks);

	/* If tv_nsec is -ve we will adjust that as error */
	if (unlikely((s64)patu_clk_mtner->atu_time.tv_nsec < 0)) {
		s64 neg = -(s64)patu_clk_mtner->atu_time.tv_nsec;

		patu_clk_mtner->atu_time.tv_nsec = 0;
		patu_clk_mtner->tm_error +=
			neg << patu_clk_mtner->tm_error_shift;
	}

	while ((patu_clk_mtner->atu_time.tv_nsec >= NSEC_PER_SEC)) {
		patu_clk_mtner->atu_time.tv_nsec -= NSEC_PER_SEC;
		patu_clk_mtner->atu_time.tv_sec++;
		atu_ntp_param_update_per_second(&patu_clk_mtner->atu_ntp);
	}
}

static void atu_time_update(void)
{
	unsigned long flags;

	spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
	if (!patu_clk_mtner->atu_timecntr.cc) {
		spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
		return;
	}
	atu_update_clk_time();
	spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
}

static int atu_clk_notifier_cb(struct notifier_block *nb,
			       unsigned long event, void *data)
{
	struct clk_notifier_data *ndata = data;
	long int diff;

	switch (event) {
	case PRE_RATE_CHANGE:
		diff = abs((int)patu_clk_mtner->event_timer_rate
				 - (int)ndata->new_rate);

		/*
		 *  Assumption is that card driver rate change
		 *  will be more than EVENT_TIMER_RATE_TOLERANCE
		 */
		if (diff > EVENT_TIMER_RATE_TOLERANCE) {
			atu_clk_rate_change_on_the_fly(ndata->new_rate);
			pr_info("ATU rate change %lu\n", ndata->new_rate);
		}
		return NOTIFY_OK;
	case POST_RATE_CHANGE:
	case ABORT_RATE_CHANGE:
		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}
}

int atu_cyclecounter_register(struct cyclecounter *pcc, struct clk *clk_atu)
{
	unsigned long flags;

	if (!pcc) {
		pr_err("%s got NULL pointer\n", __func__);
		return -EINVAL;
	}

	if (clk_atu)
		pr_info("Register Fractional PLL to ATU Clock\n");
	else
		pr_info("Register Fixed PLL to ATU Clock\n");

	if (clk_atu) {
		patu_clk_mtner->event_timer_rate = clk_get_rate(clk_atu);
		patu_clk_mtner->atu_clk_notifier.notifier_call =
				atu_clk_notifier_cb;
		clk_notifier_register(clk_atu,
				      &patu_clk_mtner->atu_clk_notifier);
		pr_info("ATU rate %d\n", patu_clk_mtner->event_timer_rate);
	}

	atu_chardev_init();
	atu_ntp_init(&patu_clk_mtner->atu_ntp);

	spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
	atu_clk_mtner_setup_internals(pcc, clk_atu);
	atu_ntp_reset(&patu_clk_mtner->atu_ntp);
	spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
	atu_timer_init();
	pr_info("ATU Clock Registered for cycle counter:0x%p\n", pcc);

	return 0;
}
EXPORT_SYMBOL(atu_cyclecounter_register);

int atu_cyclecounter_unregister(struct cyclecounter *pcc)
{
	unsigned long flags;

	if (!pcc) {
		pr_err("%s got NULL pointer\n", __func__);
		return -EINVAL;
	}
	if (pcc != patu_clk_mtner->atu_timecntr.cc) {
		pr_err("Invalid input data to %s\n", __func__);
		return -EINVAL;
	}
	if (patu_clk_mtner->clk_atu)
		clk_notifier_unregister(patu_clk_mtner->clk_atu,
					&patu_clk_mtner->atu_clk_notifier);

	atu_timer_exit();
	atu_chardev_remove();
	spin_lock_irqsave(&patu_clk_mtner->atu_clk_lock, flags);
	patu_clk_mtner->atu_timecntr.cc = NULL;
	patu_clk_mtner->clk_atu = NULL;
	spin_unlock_irqrestore(&patu_clk_mtner->atu_clk_lock, flags);
	pr_info("ATU Clock Un-Registered for cycle counter:0x%p\n", pcc);

	return 0;
}
EXPORT_SYMBOL(atu_cyclecounter_unregister);

static int __init atu_tm_init(void)
{
	patu_clk_mtner = kzalloc(sizeof(*patu_clk_mtner), GFP_KERNEL);
	if (!patu_clk_mtner)
		return -ENOMEM;

	/* Initialise the spin lock */
	spin_lock_init(&patu_clk_mtner->atu_clk_lock);

	/* Initialise ATU wall time */
	patu_clk_mtner->atu_time.tv_sec = 0;
	patu_clk_mtner->atu_time.tv_nsec = 0;

	pr_info("ATU Clock Module Loaded\n");

	return 0;
}
module_init(atu_tm_init);

static void __exit atu_tm_exit(void)
{
	if (patu_clk_mtner->atu_timecntr.cc)
		atu_timer_exit();
	atu_chardev_remove();
	kfree(patu_clk_mtner);
	patu_clk_mtner = NULL;
}
module_exit(atu_tm_exit);

MODULE_DESCRIPTION("ATU Clock Maintainer");
MODULE_AUTHOR("Krishna.Badam@imgtec.com");
MODULE_LICENSE("GPL v2");
