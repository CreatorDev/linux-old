/*
 * Atu Clock Maintainer Header File
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#ifndef _ATU_CLK_MAINTAINER_H
#define _ATU_CLK_MAINTAINER_H

#include <linux/clocksource.h>
#include <linux/time.h>

extern int atu_tm_add_offset(struct timespec *ts);
extern unsigned long atu_get_seconds(void);
extern void atu_getnstimeofday(struct timespec *tv);
extern int atu_settimeofday(const struct timespec *ts);

#endif /* _ATU_CLK_MAINTAINER_H */
