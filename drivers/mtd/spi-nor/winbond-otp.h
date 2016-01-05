/*
 * Imagination Technologies
 *
 * Copyright (c) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef WINBOND_OTP_H
#define WINBOND_OTP_H

#ifdef CONFIG_MTD_SPI_NOR_WINBOND_OTP
void winbond_otp_register(struct mtd_info *mtd);
#else
static inline void winbond_otp_register(struct mtd_info *mtd) { return; }
#endif

#endif
