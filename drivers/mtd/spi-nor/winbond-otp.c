/*
 * Imagination Technologies
 *
 * Copyright (c) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This driver provides read/write access to the 3 x 256 bytes security
 * registers as user OTP and unique ID of the NOR can be read as factory OTP
 *
 */

#include <linux/types.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/spi-nor.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include "spi-nor-common.h"

#define SECURITY_REG_START_ADDR		0x1000 /*first security register addr*/
#define SECURITY_REG_ADDR_OFFSET	0x1000 /*diff between consecutive reg*/
#define SECURITY_REG_NUM		3 /* number of security registers */
#define SECURITY_REG_SIZE		256 /* bytes per security register */
#define SECURITY_REG_TOTAL_SIZE		(SECURITY_REG_NUM * SECURITY_REG_SIZE)
#define SPI_NOR_UNIQUE_ID_LEN		8 /*number of bytes of unique ID */

/* SPI FLASH opcodes */
#define SPINOR_OP_RD_SR2		0x35 /* Read status register 2 */
#define SPINOR_OP_PR_SECURITY_REG	0x42 /* Program security register */
#define SPINOR_OP_ER_SECURITY_REG	0x44 /* Erase security register */
#define SPINOR_OP_RD_SECURITY_REG	0x48 /* Read security register */
#define SPINOR_OP_RD_UNIQUE_ID		0x4B /* Read unique id */

/* Status register 2 */
#define SR2_LB1_BIT			3 /* security register lock bit 1 */

/* Get start addr of the security reg*/
#define SEC_REG_START_ADDR(addr) (addr & 0x3000)

static inline struct spi_nor *mtd_to_spi_nor(struct mtd_info *mtd)
{
	return mtd->priv;
}

static inline int write_enable(struct spi_nor *nor)
{
	return nor->write_reg(nor, SPINOR_OP_WREN, NULL, 0, 0);
}

static inline int write_disable(struct spi_nor *nor)
{
	return nor->write_reg(nor, SPINOR_OP_WRDI, NULL, 0, 0);
}

static int read_sr(struct spi_nor *nor, u8 opcode, u8 *val)
{
	int ret;

	ret = nor->read_reg(nor, opcode, val, 1);
	if (ret < 0)
		pr_err("error %d reading SR\n", ret);
	return ret;
}

/*
 * Converts address range
 *	0 - 0xFF	-> 0x1000 - 0x10FF
 *	0x100 - 0x1FF	-> 0x2000 - 0x20FF
 *	0x200 - 0x2FF	-> 0x3000 - 0x30FF
 *
 * This func assumes that sanity checks on addr are done and is in valid range
 */
static loff_t translate_addr(loff_t addr)
{
	int i;
	loff_t new_addr = SECURITY_REG_START_ADDR;

	for (i = 0; i < SECURITY_REG_NUM; i++) {
		if (addr < ((i+1)*SECURITY_REG_SIZE)) {
			new_addr |= addr & (SECURITY_REG_SIZE-1);
			break;
		}
		new_addr += SECURITY_REG_ADDR_OFFSET;
	}

	return new_addr;
}

/*
 * Return 3 blocks of 256 bytes security register as user OTP,
 * address of these blocks will be 0, 0x100, 0x200
 * driver will convert these address to actual address while doing
 * read/write
 */
static int winbond_get_user_otp_info(struct mtd_info *mtd, size_t len,
					size_t *retlen,
					struct otp_info *otpinfo)
{
	u8 val;
	int i, ret;
	struct spi_nor *nor = mtd_to_spi_nor(mtd);

	mutex_lock(&nor->lock);
	ret = read_sr(nor, SPINOR_OP_RD_SR2, &val);
	mutex_unlock(&nor->lock);

	if (ret < 0)
		return ret;

	for (i = 0; i < SECURITY_REG_NUM; i++) {
		otpinfo[i].start = i * SECURITY_REG_SIZE;
		otpinfo[i].length = SECURITY_REG_SIZE;
		otpinfo[i].locked = !!(val & BIT(SR2_LB1_BIT + i));
	}

	*retlen = SECURITY_REG_NUM * sizeof(*otpinfo);

	return 0;
}

static int spi_otp_read(struct spi_nor *nor, loff_t from,
					size_t len, size_t *retlen, u_char *buf)
{
	struct spi_nor_xfer_cfg cfg = {
		.cmd = SPINOR_OP_RD_SECURITY_REG,
		.addr = from,
		.addr_width = nor->addr_width,
		.mode = SPI_NOR_NORMAL,
		.dummy_cycles = 8,
	};

	return nor->read_xfer(nor, &cfg, buf, len, retlen);
}

static int spi_otp_write(struct spi_nor *nor, loff_t to,
					size_t len, size_t *retlen, u_char *buf)
{
	struct spi_nor_xfer_cfg cfg = {
		.cmd = SPINOR_OP_PR_SECURITY_REG,
		.addr = to,
		.addr_width = nor->addr_width,
		.mode = SPI_NOR_NORMAL,
	};

	return nor->write_xfer(nor, &cfg, buf, len, retlen);
}

static int spi_otp_erase(struct spi_nor *nor, loff_t offs)
{
	size_t temp_retlen;
	struct spi_nor_xfer_cfg cfg = {
		.cmd = SPINOR_OP_ER_SECURITY_REG,
		.addr = offs,
		.addr_width = nor->addr_width,
		.mode = SPI_NOR_NORMAL,
	};

	return nor->write_xfer(nor, &cfg, NULL, 0, &temp_retlen);
}

static int spi_read_uniqueid(struct spi_nor *nor, u8 *buf)
{
	size_t temp_retlen;
	struct spi_nor_xfer_cfg cfg = {
		.cmd = SPINOR_OP_RD_UNIQUE_ID,
		.addr_width = 0,
		.mode = SPI_NOR_NORMAL,
		.dummy_cycles = 32,
	};

	return nor->read_xfer(nor, &cfg, buf, SPI_NOR_UNIQUE_ID_LEN,
				&temp_retlen);
}


static int winbond_read_user_otp(struct mtd_info *mtd, loff_t from,
					size_t len, size_t *retlen, u_char *buf)
{
	int ret;
	u32 i, read_len, end_addr, sreg_offset;
	loff_t temp_addr;
	struct spi_nor *nor = mtd_to_spi_nor(mtd);

	*retlen = 0;

	if (from < 0 || from >= SECURITY_REG_TOTAL_SIZE
		     || (from + len) > SECURITY_REG_TOTAL_SIZE)
		return -EINVAL;

	if (!len)
		return 0;

	end_addr = from + len;

	ret = spi_nor_lock_and_prep(nor, SPI_NOR_OPS_READ);
	if (ret)
		return ret;

	for (i = from; i < end_addr; i += read_len) {
		sreg_offset = i & (SECURITY_REG_SIZE-1);
		/* if offset not on boundary, read first few bytes */
		if (sreg_offset) {
			/* check if everything has to be read from 1 reg */
			if ((sreg_offset + len) <= SECURITY_REG_SIZE)
				read_len = len;
			else
				read_len = SECURITY_REG_SIZE - sreg_offset;
		}
		/* if it is last chunk, read the remaining bytes */
		else if ((end_addr - i) < SECURITY_REG_SIZE)
			read_len = end_addr - i;
		else
			read_len = SECURITY_REG_SIZE;

		temp_addr = translate_addr(i);
		ret = spi_otp_read(nor, temp_addr, read_len, retlen,
					buf + (i-from));
		if (ret < 0)
			goto error;
	}
error:
	spi_nor_unlock_and_unprep(nor, SPI_NOR_OPS_READ);
	return ret;
}

/*
 * This func assumes that offset is within valid range of security registers,
 * valid offset are 0x1000, 0x2000 or 0x3000
 */
static int winbond_erase_security_reg(struct spi_nor *nor, loff_t offset)
{
	int ret;

	ret = write_enable(nor);
	if (ret < 0)
		return ret;

	ret = spi_nor_wait_till_ready(nor);
	if (ret)
		return ret;

	ret = spi_otp_erase(nor, offset);
	if (ret < 0)
		return ret;

	ret = spi_nor_wait_till_ready(nor);

	return ret;
}

/*
 * This function does read, modify locally, erase and write to the register to
 * be written
 * It doesn't do any range checks on reg_addr, sreg_offset, len
 */
static int winbond_write_security_reg(struct spi_nor *nor, loff_t reg_addr,
					u32 sreg_offset, size_t len,
					size_t *retlen, u_char *buf)
{
	int ret;
	size_t temp_retlen = 0;
	u8 *reg_buffer;

	if (unlikely(sreg_offset + len > SECURITY_REG_SIZE))
		return -EINVAL;

	reg_buffer = kmalloc(SECURITY_REG_SIZE, GFP_KERNEL);
	if (!reg_buffer)
		return -ENOMEM;

	/* read the security register */
	ret = spi_otp_read(nor, reg_addr, SECURITY_REG_SIZE, &temp_retlen,
				reg_buffer);
	if (ret < 0 || temp_retlen != SECURITY_REG_SIZE)
		goto error;

	/* modify the part to be written */
	memcpy(reg_buffer + sreg_offset, buf, len);

	/* erase the security register */
	ret = winbond_erase_security_reg(nor, reg_addr);
	if (ret < 0)
		goto error;

	/* write the security reg*/
	ret = write_enable(nor);
	if (ret < 0)
		goto error;

	ret = spi_nor_wait_till_ready(nor);
	if (ret)
		goto error;

	temp_retlen = 0;

	ret = spi_otp_write(nor, reg_addr, SECURITY_REG_SIZE, &temp_retlen,
				reg_buffer);
	if (ret < 0 || temp_retlen != SECURITY_REG_SIZE)
		goto error;

	ret = spi_nor_wait_till_ready(nor);

	*retlen += len;

error:
	kfree(reg_buffer);
	return ret;
}

static int winbond_write_user_otp(struct mtd_info *mtd, loff_t to,
					size_t len, size_t *retlen, u_char *buf)
{
	int ret;
	u32 i, write_len, end_addr, sreg_offset;
	loff_t temp_addr;
	struct spi_nor *nor = mtd_to_spi_nor(mtd);

	*retlen = 0;

	if (to < 0 || to >= SECURITY_REG_TOTAL_SIZE
		   || (to + len) > SECURITY_REG_TOTAL_SIZE)
		return -EINVAL;

	if (!len)
		return 0;

	end_addr = to + len;

	ret = spi_nor_lock_and_prep(nor, SPI_NOR_OPS_WRITE);
	if (ret)
		return ret;

	for (i = to; i < end_addr; i += write_len) {
		sreg_offset = i & (SECURITY_REG_SIZE-1);
		/* if offset not on boundary, write first few bytes */
		if (sreg_offset) {
			/* check if everything has to be written in 1 reg */
			if ((sreg_offset + len) <= SECURITY_REG_SIZE)
				write_len = len;
			else
				write_len = SECURITY_REG_SIZE - sreg_offset;
		}
		/* if it is last chunk, write the remaining bytes */
		else if ((end_addr - i) < SECURITY_REG_SIZE)
			write_len = end_addr - i;
		else
			write_len = SECURITY_REG_SIZE;

		temp_addr = translate_addr(i);
		ret = winbond_write_security_reg(nor,
					SEC_REG_START_ADDR(temp_addr),
					sreg_offset, write_len,
					retlen,	buf + (i-to));
		if (ret < 0)
			goto error;
	}

error:
	spi_nor_unlock_and_unprep(nor, SPI_NOR_OPS_WRITE);
	return ret;
}

static int winbond_lock_user_otp(struct mtd_info *mtd, loff_t from, size_t len)
{
	int ret;
	u8 sr1, sr2, security_reg_num;
	struct spi_nor *nor = mtd_to_spi_nor(mtd);

	/* allow locking 1 register at a time,
	 * so ensure that len is 256
	 * also check if address is on security register boundary
	 */
	if (len != SECURITY_REG_SIZE || from < 0
		|| from >= SECURITY_REG_TOTAL_SIZE
		|| from & (SECURITY_REG_SIZE - 1))
		return -EINVAL;

	/* find out the security reg to set */
	security_reg_num = from / SECURITY_REG_SIZE;

	if (unlikely(security_reg_num > (SECURITY_REG_NUM-1)))
		return -EINVAL;

	ret = spi_nor_lock_and_prep(nor, SPI_NOR_OPS_LOCK);
	if (ret)
		return ret;

	/* read status registers */
	ret = read_sr(nor, SPINOR_OP_RDSR, &sr1);
	if (ret < 0)
		goto error;

	ret = read_sr(nor, SPINOR_OP_RD_SR2, &sr2);
	if (ret < 0)
		goto error;

	ret = write_enable(nor);
	if (ret < 0)
		goto error;

	/* set the corresponding LB bit in security register 2 */
	sr2 |= BIT(SR2_LB1_BIT + security_reg_num);

	/* write status registers */
	nor->cmd_buf[0] = sr1;
	nor->cmd_buf[1] = sr2;
	ret = nor->write_reg(nor, SPINOR_OP_WRSR, nor->cmd_buf, 2, 0);

	write_disable(nor);

error:
	spi_nor_unlock_and_unprep(nor, SPI_NOR_OPS_LOCK);
	return ret;
}

/*
 * Unique ID of NOR device will be reported as factory OTP
 */
static int winbond_get_fact_otp_info(struct mtd_info *mtd, size_t len,
					size_t *retlen,
					struct otp_info *otpinfo)
{
	otpinfo->start = 0;
	otpinfo->length = SPI_NOR_UNIQUE_ID_LEN;
	otpinfo->locked = 1;

	*retlen = sizeof(*otpinfo);

	return 0;
}

static int winbond_read_fact_otp(struct mtd_info *mtd, loff_t from, size_t len,
					size_t *retlen, u_char *buf)
{
	int ret;

	char unique_id[SPI_NOR_UNIQUE_ID_LEN] = {0};
	struct spi_nor *nor = mtd_to_spi_nor(mtd);

	*retlen = 0;

	if (from < 0 || from >= SPI_NOR_UNIQUE_ID_LEN
		     || (from + len) > SPI_NOR_UNIQUE_ID_LEN)
		return -EINVAL;

	if (!len)
		return 0;

	ret = spi_nor_lock_and_prep(nor, SPI_NOR_OPS_READ);
	if (ret)
		return ret;

	ret = spi_read_uniqueid(nor, unique_id);
	if (ret < 0)
		goto error;

	/* Read complete unique ID,but just copy whatever is requested */
	memcpy(buf, unique_id + from, len);
	*retlen = len;
error:
	spi_nor_unlock_and_unprep(nor, SPI_NOR_OPS_READ);
	return ret;
}

void winbond_otp_register(struct mtd_info *mtd)
{
	struct spi_nor *nor = mtd_to_spi_nor(mtd);

	if (nor->read_xfer && nor->write_xfer) {
		mtd->_get_user_prot_info = winbond_get_user_otp_info;
		mtd->_read_user_prot_reg = winbond_read_user_otp;
		mtd->_write_user_prot_reg = winbond_write_user_otp;
		mtd->_lock_user_prot_reg = winbond_lock_user_otp;
		mtd->_get_fact_prot_info = winbond_get_fact_otp_info;
		mtd->_read_fact_prot_reg = winbond_read_fact_otp;
	} else
		dev_err(nor->dev, "Required nor interfaces "
				"(read_xfer, write_xfer) not defined\n");
}
