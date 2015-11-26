/*
 * PM Suspend to sram memory routine for pistachio Platform.
 *
 * Copyright (C) 2015 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/regdef.h>

/* DDR Register Maps */
#define	DDR_PCTL_SCTL			0xB8180004
#define	DDR_PCTL_SCTL_SLEEP_CMD		0x00000003
#define	DDR_PCTL_SCTL_WKUP_CMD		0x00000004
#define	DDR_PCTL_STAT			0xB8180008
#define	DDR_PCTL_STAT_STL_LOW_PWR	0x00000005
#define	DDR_PCTL_STAT_STL_ACCESS	0x00000003

/* SYS-PLL Top level register */
#define	CR_SYS_PLL_STATUS		0xB8144038
#define	CR_SYS_PLL_CTRL1		0xB814403C
#define	CR_SYS_PLL_FBDIV_MASK		(0xFFF << 6)
#define	CR_SYS_PLL_LOCK			0x00000001
#define	CR_SYS_PLL_MINVCO_FB100		(100 << 6)
#define	CR_SYS_PLL_VCO_FB350		(350 << 6)

/* MIPS TOP level Gate reg */
#define	CR_MIPS_PLL_STATUS		0xB8144000
#define	CR_MIPS_PLL_CTRL1		0xB8144004
#define	CR_MIPS_PLL_FBDIV_MASK		(0xFFF << 6)
#define	CR_MIPS_PLL_FBDIV_MASK_SET_40	(40 << 6)
#define	CR_MIPS_PLL_FBDIV_MASK_SET_80	(80 << 6)
#define	CR_MIPS_PLL_LOCK		0x00000001

#define	CR_TOP_MIPS_CLOCK_GATE		0xB8144104
#define	MIPS_CLOCK_GATE_MASK		0x00000001

/* Top level system register */
#define	CR_DDR_CTRL			0xB8149020
#define	CR_DDR_CLK_MASK			0x00000002

/* External timer dividers */
#define	CR_TOP_COUNTERSLOWDIV1_CTRL		0xB8144914
#define	COUNTERSLOW_DIV1_32K_DIV_VAL		0x0000006F
#define	COUNTERSLOW_DIV1_32K_SCALED_DIV_VAL	0x0000001F

#define	CR_TOP_IRDIV1_CTRL			0xB814491C
#define	IR_DIV1_32K_DIV_VAL			0x00000057
#define	IR_DIV1_DIV1_32K_SCALED_DIV_VAL		0x00000018

#define	CR_TOP_ENETPHYCLKOUT_CTRL		0xB8144230
#define	ENET_PHYCLKOUT_50M_DIV_VAL		0x00000006
#define	ENET_PHYCLKOUT_50M_SCALED_DIV_VAL	0x00000001

.text
FEXPORT(pistachio_sram_suspend)
LEAF(pistachio_sram_suspend)

enter_ddr_self_refresh:
	/* request uPCTL Low pwer state from access state */
	PTR_LI	t0, DDR_PCTL_SCTL
	PTR_LI  t1, DDR_PCTL_SCTL_SLEEP_CMD
	PTR_S	t1, (t0)

	/*
	 * Poll to check if we transitioned
	 * to Low power state
	 */

	PTR_LI	t0, DDR_PCTL_STAT
lower_power_poll:
	PTR_L	t1, (t0)
	and	t2, t1, DDR_PCTL_STAT_STL_LOW_PWR
	bne	t2, DDR_PCTL_STAT_STL_LOW_PWR, lower_power_poll

ddr_clk_gate:
	PTR_LI  t0, CR_DDR_CTRL
	PTR_L	t1, (t0)
	and	t2, t1, ~CR_DDR_CLK_MASK
	PTR_S	t2, (t0)

	/*
	 * We are scaling syspll so we need to scale mips pll as well.
	 * Scaling MIPS to 208Mhz.
	 */
mips_pll_scale:
	/* modify FBDIV 40 => 208MHz */
	PTR_LI	t0, CR_MIPS_PLL_CTRL1
	PTR_L   t1, (t0)
	and	t2, t1, ~CR_MIPS_PLL_FBDIV_MASK
	or	t2, CR_MIPS_PLL_FBDIV_MASK_SET_40
	PTR_S	t2, (t0)

mips_pll_loop:
	PTR_LI	t0, CR_MIPS_PLL_STATUS
	PTR_L	t1, (t0)
	bne	t1, CR_MIPS_PLL_LOCK, mips_pll_loop

sys_pll_scale:
	/*
	 * Scale down sys_pll to 100Mhz from 350Mhz.
	 * Set feedback to 100 to scale.
	 */
	PTR_LI	t0, CR_SYS_PLL_CTRL1
	PTR_L	t1, (t0)
	and	t2, t1, ~CR_SYS_PLL_FBDIV_MASK
	/* FOUTVCO-MIN 400Mhz fb 100 */
	PTR_LI	t3, CR_SYS_PLL_MINVCO_FB100
	and	t3, t3, CR_SYS_PLL_FBDIV_MASK
	or	v0, t3, t2
	PTR_S	v0, (t0)

slow_timer_clk_adj:
	/*
	 * Adjust external slow clock since its on sys_pll
	 * slow_counter prediv runs at 3.125Mhz so using new divider
	 * 0x1F (val-1) (count => 32) we can derive 3.125Mhz from 100Mhz.
	 */
	PTR_LI	t0, CR_TOP_COUNTERSLOWDIV1_CTRL
	PTR_LI	t1, COUNTERSLOW_DIV1_32K_SCALED_DIV_VAL
	PTR_S	t1, (t0)

ir_adj:
	PTR_LI	t0, CR_TOP_IRDIV1_CTRL
	PTR_LI	t1, IR_DIV1_DIV1_32K_SCALED_DIV_VAL
	PTR_S	t1, (t0)

	/* to support wake-on-lan */
enet_adj:
	PTR_LI	t0, CR_TOP_ENETPHYCLKOUT_CTRL
	PTR_LI	t1, ENET_PHYCLKOUT_50M_SCALED_DIV_VAL
	PTR_S	t1, (t0)

pll_lock_loop1:
	PTR_LI	t0, CR_SYS_PLL_STATUS
	PTR_L	t1, (t0)
	bne	t1, CR_SYS_PLL_LOCK, pll_lock_loop1

suspend:
	PTR_LI	t0, CR_TOP_MIPS_CLOCK_GATE
	PTR_L	t1, (t0)
	PTR_LI	t2, ~MIPS_CLOCK_GATE_MASK
	and	v0, t1, t2
	PTR_S	v0, (t0)

resume:
	PTR_LI	t0, CR_TOP_MIPS_CLOCK_GATE
	PTR_L	t1, (t0)
	PTR_LI	t2, MIPS_CLOCK_GATE_MASK
	or	v0, t1, t2
	PTR_S	v0, (t0)

sys_pll_setup:
	/*
	 * Configure sys_pll at 350 Mhz.
	 * Set feedback to 350 => VCO 1400Mhz
	 */
	PTR_LI	t0, CR_SYS_PLL_CTRL1
	PTR_L	t1, (t0)
	and	t2, t1, ~CR_SYS_PLL_FBDIV_MASK
	PTR_LI	t3, CR_SYS_PLL_VCO_FB350
	and	t3, t3, CR_SYS_PLL_FBDIV_MASK
	or	v0, t3, t2
	PTR_S	v0, (t0)

slow_timer_setup:
	PTR_LI	t0, CR_TOP_COUNTERSLOWDIV1_CTRL
	PTR_LI	t1, COUNTERSLOW_DIV1_32K_DIV_VAL
	PTR_S	t1, (t0)

ir_setup:
	PTR_LI	t0, CR_TOP_IRDIV1_CTRL
	PTR_LI	t1, IR_DIV1_32K_DIV_VAL
	PTR_S	t1, (t0)

enet_setup:
	PTR_LI	t0, CR_TOP_ENETPHYCLKOUT_CTRL
	PTR_LI	t1, ENET_PHYCLKOUT_50M_DIV_VAL
	PTR_S	t1, (t0)

pll_lock_loop:
	PTR_LI	t0, CR_SYS_PLL_STATUS
	PTR_L	t1, (t0)
	bne	t1, CR_SYS_PLL_LOCK, pll_lock_loop

	/*
	 * Setup mips pll back to original VCO.
	 * Setting up MIPS to 416 Mhz */
mips_pll_setup:
	/* Modify FBDIV 80 => 416MHz */
	PTR_LI	t0, CR_MIPS_PLL_CTRL1
	PTR_L   t1, (t0)
	and	t2, t1, ~CR_MIPS_PLL_FBDIV_MASK
	or	t2, CR_MIPS_PLL_FBDIV_MASK_SET_80
	PTR_S	t2, (t0)

mips_pll_loop1:
	PTR_LI	t0, CR_MIPS_PLL_STATUS
	PTR_L	t1, (t0)
	bne	t1, CR_MIPS_PLL_LOCK, mips_pll_loop1

ddr_clk_ungate:
	PTR_LI  t0, CR_DDR_CTRL
	PTR_L	t1, (t0)
	or	t2, t1, CR_DDR_CLK_MASK
	PTR_S	t2, (t0)

exit_ddr_self_refresh:
	/* Request DDR uPCTL to access state from low power state */
	PTR_LI	t0, DDR_PCTL_SCTL
	PTR_LI  t1, DDR_PCTL_SCTL_WKUP_CMD
	PTR_S	t1, (t0)

	/*
	 * Poll to check if we transitioned
	 * to access state.
	 */
	PTR_LI	t0, DDR_PCTL_STAT
ddr_access_poll:
	PTR_L	t1, (t0)
	and	t2, t1, DDR_PCTL_STAT_STL_ACCESS
	bne	t2, DDR_PCTL_STAT_STL_ACCESS, ddr_access_poll

	/* start executing from DDR */
	jr	ra

END(pistachio_sram_suspend)

pistachio_sram_suspend_sz:
	EXPORT(pistachio_sram_suspend_sz)
	PTR	.-pistachio_sram_suspend
	.size	pistachio_sram_suspend_sz, PTRSIZE
