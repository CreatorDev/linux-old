/*
 * Atu Ioctl Header file
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#ifndef ATU_IOCTL_H
#define ATU_IOCTL_H

#include <linux/time.h>
#include <linux/types.h>

#define ATU_MAX_COUNTERS	6
#define ATU_PAST		0
#define ATU_FUTURE		1

struct atu_event {
	u32	counter;
	u32	source;
	u32	timestamp;
	u32	timestamp_counter;
	u32	txtimer;
	u32	timeofday_sec;
	u32	timeofday_ns;
	u32	timekeeping_shift;
	u32	timekeeping_mult;
};

#define ATUIO	(0xF2)
/*get event timestamp*/
#define ATUIO_GETEVTS		_IOWR(ATUIO, 0x42, struct atu_event)
/*set timex adjustments*/
#define ATUIO_ADJTIMEX		_IOWR(ATUIO, 0x43, struct timex)
/*set timeofday*/
#define ATUIO_SETTIMEOFDAY	_IOWR(ATUIO, 0x44, struct timex)
/*get timespec of atu clock*/
#define ATUIO_GETTIMESPEC	_IOWR(ATUIO, 0x45, struct timex)

#endif /* ATU_IOCTL_H */
