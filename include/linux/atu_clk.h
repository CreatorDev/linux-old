/*
 * Atu Clock Header File
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#ifndef _ATU_CLK_H
#define _ATU_CLK_H

#include <linux/time.h>
#include <linux/types.h>

struct cyclecounter;
struct clk;

extern u64 atu_get_current_time(void);
extern int frc_to_atu(u32 frc, u64 *patu, s32 dir);
extern int atu_to_frc(u64 atu, u32 *pfrc, u64 min_nsec);
extern int
atu_cyclecounter_register(struct cyclecounter *pcc, struct clk *clk_atu);
extern int atu_cyclecounter_unregister(struct cyclecounter *pcc);

#endif /* _ATU_CLK_H */
