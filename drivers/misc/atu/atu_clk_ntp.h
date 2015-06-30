/*
 * Atu Clock NTP handler Header File
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#ifndef ATU_NTP_H
#define ATU_NTP_H

struct atu_clk_ntp {
	int	time_state;
	int	time_status;
	unsigned long cycle_period_usec;
	unsigned long nsec_per_cycle;
	u64	shifted_nsecs_per_cycle;
	u64	shifted_nsecs_per_cycle_ref;
	s64	time_offset;
	long	time_constant;
	s64	time_freq;
	long	time_maxerror;
	long	time_esterror;
	long	time_reftime;
	long	time_adjust;
	s64	ntp_tick_adj;
};

struct timex;

extern u64 get_ntp_shifted_nsecs_per_cycle(struct atu_clk_ntp *patu_ntp);
extern void atu_ntp_param_update_per_second(struct atu_clk_ntp *patu_ntp);
extern void atu_ntp_init(struct atu_clk_ntp *patu_ntp);
extern void atu_ntp_reset(struct atu_clk_ntp *patu_ntp);
extern int __atu_adjtimex(struct timex *txc, struct atu_clk_ntp *patu_ntp);
extern int atu_set_time_offset(struct timex *txc);

#endif /* ATU_NTP_H */
