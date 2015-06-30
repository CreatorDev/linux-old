/*
 * Atu Clock NTP handler
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/export.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "atu_clk_maintainer.h"
#include "atu_clk_ntp.h"

#define ATU_NTP_MAX_TICK_ADJ		(500LL)		/* usecs */
#define ATU_NTP_MAX_TICK_ADJ_SCALED \
	(((ATU_NTP_MAX_TICK_ADJ * NSEC_PER_USEC) << \
	NTP_SCALE_SHIFT) / NTP_INTERVAL_FREQ)
#define ATU_NTP_DEV_CAP			15000

u64 get_ntp_shifted_nsecs_per_cycle(struct atu_clk_ntp *patu_ntp)
{
	return patu_ntp->shifted_nsecs_per_cycle;
}

static
void atu_ntp_shifted_nsecs_per_cycle_update(struct atu_clk_ntp *patu_ntp)
{
	u64 num_ticks_per_second;
	u64 new_base;
	s32 remainder;

	num_ticks_per_second = (u64)(patu_ntp->cycle_period_usec *
			NSEC_PER_USEC * USER_HZ) << NTP_SCALE_SHIFT;

	num_ticks_per_second += patu_ntp->ntp_tick_adj;

	num_ticks_per_second += patu_ntp->time_freq;

	patu_ntp->nsec_per_cycle = div_u64_rem(num_ticks_per_second,
					 HZ, &remainder) >> NTP_SCALE_SHIFT;
	new_base = div_u64_rem(num_ticks_per_second, NTP_INTERVAL_FREQ,
								&remainder);

	/* Update shifted_nsecs_per_cycle */
	patu_ntp->shifted_nsecs_per_cycle += new_base -
					patu_ntp->shifted_nsecs_per_cycle_ref;

	patu_ntp->shifted_nsecs_per_cycle_ref = new_base;
}

static
s64 atu_calc_freq_adj(struct atu_clk_ntp *patu_ntp, s64 offset, long secs)
{
	s32 remainder;

	/* Check lapsed seconds with in perimitted range of update intervals */
	if (secs < MINSEC || secs > MAXSEC)
		return 0;

	/* If it is in not in FLL mode, we won't adjust frequency */
	if (!(patu_ntp->time_status & STA_FLL))
		return 0;

	return div_s64_rem(offset << (NTP_SCALE_SHIFT - SHIFT_FLL),
							secs, &remainder);
}

static void atu_ntp_offset_update(struct atu_clk_ntp *patu_ntp, s64 offset)
{
	s32 remainder;

	/* Check offset is with in allowed range */
	offset = clamp_val(offset, -MAXPHASE, MAXPHASE);
	patu_ntp->time_offset = div_s64_rem(offset << NTP_SCALE_SHIFT,
				NTP_INTERVAL_FREQ, &remainder);
}

static
void atu_ntp_offset_freq_adjust(struct atu_clk_ntp *patu_ntp, s64 offset)
{
	s64 freq_adj;
	long secs;

	/* Get the update interval time and update ref time */
	secs = atu_get_seconds() - patu_ntp->time_reftime;
	patu_ntp->time_reftime = secs + patu_ntp->time_reftime;

	/* If freq is in locked state, then we wont do freq adjustments */
	if (patu_ntp->time_status & STA_FREQHOLD)
		secs = 0;

	freq_adj = atu_calc_freq_adj(patu_ntp, offset, secs);

	/*
	 * If update interval is long then clamp to some value,
	 * such that it won't mess PLL adjustments too much
	 */
	if (secs > (1 << (SHIFT_PLL + 1 + patu_ntp->time_constant)))
		secs = 1 << (SHIFT_PLL + 1 + patu_ntp->time_constant);

	freq_adj += (offset * secs) <<
			(NTP_SCALE_SHIFT - 2 *
			 (SHIFT_PLL + 2 + patu_ntp->time_constant));

	patu_ntp->time_freq = clamp_val(freq_adj + patu_ntp->time_freq,
					-MAXFREQ_SCALED, MAXFREQ_SCALED);
}

void atu_ntp_reset(struct atu_clk_ntp *patu_ntp)
{
	patu_ntp->time_adjust = 0;
	patu_ntp->time_status |= STA_UNSYNC;
	patu_ntp->time_maxerror = NTP_PHASE_LIMIT;
	patu_ntp->time_esterror = NTP_PHASE_LIMIT;

	atu_ntp_shifted_nsecs_per_cycle_update(patu_ntp);

	/* Update shifted_nsecs_per_cycle to last update value */
	patu_ntp->shifted_nsecs_per_cycle =
		patu_ntp->shifted_nsecs_per_cycle_ref;
	patu_ntp->time_offset = 0;
}

void atu_ntp_param_update_per_second(struct atu_clk_ntp *patu_ntp)
{
	s64 delta;

	patu_ntp->time_maxerror += MAXFREQ / NSEC_PER_USEC;

	if (patu_ntp->time_maxerror > NTP_PHASE_LIMIT) {
		patu_ntp->time_maxerror = NTP_PHASE_LIMIT;
		patu_ntp->time_status |= STA_UNSYNC;
	}

	patu_ntp->shifted_nsecs_per_cycle =
		patu_ntp->shifted_nsecs_per_cycle_ref;

	delta = shift_right(patu_ntp->time_offset,
			SHIFT_PLL + patu_ntp->time_constant);
	patu_ntp->time_offset -= delta;
	patu_ntp->shifted_nsecs_per_cycle += delta;

	if (!patu_ntp->time_adjust)
		return;

	if (patu_ntp->time_adjust > ATU_NTP_MAX_TICK_ADJ) {
		patu_ntp->time_adjust -= ATU_NTP_MAX_TICK_ADJ;
		patu_ntp->shifted_nsecs_per_cycle +=
				ATU_NTP_MAX_TICK_ADJ_SCALED;
		return;
	}

	if (patu_ntp->time_adjust < -ATU_NTP_MAX_TICK_ADJ) {
		patu_ntp->time_adjust += ATU_NTP_MAX_TICK_ADJ;
		patu_ntp->shifted_nsecs_per_cycle -=
				ATU_NTP_MAX_TICK_ADJ_SCALED;
		return;
	}

	patu_ntp->shifted_nsecs_per_cycle += (s64)(patu_ntp->time_adjust *
	     NSEC_PER_USEC / NTP_INTERVAL_FREQ) << NTP_SCALE_SHIFT;

	patu_ntp->time_adjust = 0;
}

static
void atu_ntp_status_update(struct timex *txc, struct atu_clk_ntp *patu_ntp)
{
	/*
	 * If local time status is PLL and ntp's time status FLL,
	 * then update status as not in sync
	 */
	if ((patu_ntp->time_status & STA_PLL) && !(txc->status & STA_PLL)) {
		patu_ntp->time_state = TIME_OK;
		patu_ntp->time_status = STA_UNSYNC;
	}

	/* If PLL is just selected then we have to update the reference time */
	if (!(patu_ntp->time_status & STA_PLL) && (txc->status & STA_PLL))
		patu_ntp->time_reftime = atu_get_seconds();

	/* We are interested only in related status bits */
	patu_ntp->time_status &= STA_RONLY;
	patu_ntp->time_status |= txc->status & ~STA_RONLY;
}

static
void adjtimex_modes_handler(struct timex *txc, struct atu_clk_ntp *patu_ntp)
{
	if (txc->modes & ADJ_STATUS)
		atu_ntp_status_update(txc, patu_ntp);

	if (txc->modes & ADJ_NANO)
		patu_ntp->time_status |= STA_NANO;

	if (txc->modes & ADJ_MICRO)
		patu_ntp->time_status &= ~STA_NANO;

	if (txc->modes & ADJ_MAXERROR)
		patu_ntp->time_maxerror = txc->maxerror;

	if (txc->modes & ADJ_ESTERROR)
		patu_ntp->time_esterror = txc->esterror;

	if (txc->modes & ADJ_FREQUENCY) {
		patu_ntp->time_freq = txc->freq * PPM_SCALE;
		patu_ntp->time_freq = clamp_val(patu_ntp->time_freq,
					-MAXFREQ_SCALED, MAXFREQ_SCALED);
	}

	if (txc->modes & ADJ_TIMECONST) {
		patu_ntp->time_constant = txc->constant;
		if (!(patu_ntp->time_status & STA_NANO))
			patu_ntp->time_constant += 4;
		patu_ntp->time_constant = clamp_val(patu_ntp->time_constant,
								0, MAXTC);
	}

	if (txc->modes & ADJ_OFFSET) {
		s64 offset;
		if (!(patu_ntp->time_status & STA_PLL))
			return;

		offset = txc->offset;

		if (!(patu_ntp->time_status & STA_NANO))
			offset *= NSEC_PER_USEC;

		/* Adjust time_offset for the given offset */
		atu_ntp_offset_update(patu_ntp, offset);

		/* Adjust time_freq for the given offset */
		atu_ntp_offset_freq_adjust(patu_ntp, offset);
	}

	if (txc->modes & ADJ_TICK)
		patu_ntp->cycle_period_usec = txc->tick;

	/*
	 * We need to adjust shifted_nsecs_per_cycle in case of
	 * ADJ_TICK, ADJ_FREQUENCY and ADJ_OFFSET modes
	 */
	if (txc->modes & (ADJ_TICK|ADJ_FREQUENCY|ADJ_OFFSET))
		atu_ntp_shifted_nsecs_per_cycle_update(patu_ntp);
}

int atu_set_time_offset(struct timex *txc)
{
	int result;
	struct timespec offset_time;

	offset_time.tv_sec  = txc->time.tv_sec;
	offset_time.tv_nsec = txc->time.tv_usec;
	if (!(txc->modes & ADJ_NANO))
		offset_time.tv_nsec *= NSEC_PER_USEC;

	result = atu_tm_add_offset(&offset_time);

	return result;
}

int __atu_adjtimex(struct timex *txc, struct atu_clk_ntp *patu_ntp)
{
	struct timespec ts;
	int result;

	if (txc->modes & ADJ_ADJTIME) {
		/*
		 * ADJTIME's single shot must not be used
		 * with any other mode bits
		 */
		if (!(txc->modes & ADJ_OFFSET_SINGLESHOT))
			return -EINVAL;
	} else {
		/* ADJ_TIMEX mode */

		/*
		 * If the tick duaration is deviated more than
		 * 15% then treat it as invalid data
		 */
		if (txc->modes & ADJ_TICK &&
		    (txc->tick <  (NSEC_PER_SEC - ATU_NTP_DEV_CAP)/USER_HZ ||
		     txc->tick > (NSEC_PER_SEC + ATU_NTP_DEV_CAP)/USER_HZ))
			return -EINVAL;
	}

	if (txc->modes & ADJ_SETOFFSET) {
		result = atu_set_time_offset(txc);
		if (result)
			return result;
	}

	if (txc->modes & ADJ_ADJTIME) {
		long save_adjust = patu_ntp->time_adjust;

		/*
		 * This is not part of time adjust, it is a one and time
		 * independent one. After this update will return back old
		 * time_adjust
		 */
		if (!(txc->modes & ADJ_OFFSET_READONLY))
			patu_ntp->time_adjust = txc->offset;

		txc->offset = save_adjust;
	} else {

		if (txc->modes)
			adjtimex_modes_handler(txc, patu_ntp);

		txc->offset = shift_right(patu_ntp->time_offset *
				NTP_INTERVAL_FREQ, NTP_SCALE_SHIFT);

		if (!(patu_ntp->time_status & STA_NANO))
			txc->offset /= NSEC_PER_USEC;
	}

	if (patu_ntp->time_status & (STA_UNSYNC|STA_CLOCKERR))
		result = TIME_ERROR;
	else
		result = TIME_OK;

	/* Fill txc with possible/available data */
	txc->freq = shift_right((patu_ntp->time_freq >> PPM_SCALE_INV_SHIFT) *
				 PPM_SCALE_INV, NTP_SCALE_SHIFT);
	txc->maxerror = patu_ntp->time_maxerror;
	txc->esterror = patu_ntp->time_esterror;
	txc->status = patu_ntp->time_status;
	txc->constant = patu_ntp->time_constant;
	txc->precision = 1;
	txc->tolerance = MAXFREQ_SCALED / PPM_SCALE;
	txc->tick = patu_ntp->cycle_period_usec;
	txc->tai = 0;
	txc->ppsfreq = 0;
	txc->jitter = 0;
	txc->shift = 0;
	txc->stabil = 0;
	txc->jitcnt = 0;
	txc->calcnt = 0;
	txc->errcnt = 0;
	txc->stbcnt = 0;

	/* Update time */
	atu_getnstimeofday(&ts);
	txc->time.tv_sec = ts.tv_sec;
	txc->time.tv_usec = ts.tv_nsec;
	if (!(patu_ntp->time_status & STA_NANO))
		txc->time.tv_usec /= NSEC_PER_USEC;

	return result;
}

void atu_ntp_init(struct atu_clk_ntp *patu_ntp)
{
	/* Initialise with default values */
	patu_ntp->time_state = TIME_OK;
	patu_ntp->time_status = STA_UNSYNC;
	patu_ntp->cycle_period_usec = TICK_USEC;
	patu_ntp->nsec_per_cycle = 0;
	patu_ntp->shifted_nsecs_per_cycle = 0;
	patu_ntp->shifted_nsecs_per_cycle_ref = 0;
	patu_ntp->time_offset = 0;
	patu_ntp->time_constant = 0x2;
	patu_ntp->time_freq = 0;
	patu_ntp->time_maxerror = NTP_PHASE_LIMIT;
	patu_ntp->time_esterror = 0;
	patu_ntp->time_reftime = 0;
	patu_ntp->time_adjust = 0;
	patu_ntp->ntp_tick_adj = 0;

	atu_ntp_reset(patu_ntp);
}
