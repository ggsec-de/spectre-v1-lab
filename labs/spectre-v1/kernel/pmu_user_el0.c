// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 *
 * pmu_user_el0 -- enable EL0 (userspace) access to the ARMv8 PMU cycle counter
 * PMCCNTR_EL0 on every online CPU.
 *
 * Why the Spectre-v1 lab needs it on Cortex-A76 (Raspberry Pi 5): a Flush+Reload
 * oracle needs a clock that separates an L1 hit from a flushed miss. On this
 * part the two userspace-reachable clocks do not:
 *   - CNTVCT_EL0 ticks at 54 MHz (~18.5 ns). `dc civac` leaves a line in the
 *     last-level cache (~15 ns), so a miss and a hit both measure 0-1 ticks.
 *   - a shared counting-thread counter inverts, because the measurer holding the
 *     counter line stalls the writer core (cache-coherence contention dominates
 *     the delta).
 * The cycle counter PMCCNTR_EL0 (~0.4 ns at 2.4 GHz) separates them cleanly, but
 * it traps to EL1 from userspace unless PMUSERENR_EL0 permits the read. This
 * module sets that bit (and enables + resets the cycle counter) on each CPU.
 *
 * Research use on owned hardware. `rmmod` removes the EL0 access this module
 * grants (it clears PMUSERENR_EL0); it does not otherwise restore the PMU to
 * its exact prior configuration -- it leaves the cycle counter enabled and
 * undivided. A reboot returns the PMU to its default power-on state. This is a
 * privileged enable step the lab loads before measuring, not part of the
 * measured experiment itself.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/smp.h>

/* PMCR_EL0 */
#define PMCR_E   (1U << 0)   /* enable all counters */
#define PMCR_C   (1U << 2)   /* reset the cycle counter */
#define PMCR_D   (1U << 3)   /* clock divider: count every 64 cycles when set */
#define PMCR_LC  (1U << 6)   /* long (64-bit) cycle counter */
/* PMCNTENSET_EL0 */
#define PMCNT_C  (1U << 31)  /* the cycle counter's enable bit */
/* PMUSERENR_EL0 */
#define USERENR_EN (1U << 0) /* EL0 access to the PMU */
#define USERENR_CR (1U << 2) /* EL0 read of the cycle counter */

static void enable_on_cpu(void *info)
{
	u64 pmcr;

	(void)info;
	asm volatile("mrs %0, pmcr_el0" : "=r"(pmcr));
	/* Enable and reset the cycle counter, count every cycle (clear the /64
	 * divider -- it is set on this part by default and makes the counter far
	 * too coarse for Flush+Reload), and count 64-bit so it does not wrap. */
	pmcr |= PMCR_E | PMCR_C | PMCR_LC;
	pmcr &= ~PMCR_D;
	asm volatile("msr pmcr_el0, %0" :: "r"(pmcr));
	asm volatile("msr pmcntenset_el0, %0" :: "r"((u64)PMCNT_C));
	asm volatile("msr pmuserenr_el0, %0" :: "r"((u64)(USERENR_EN | USERENR_CR)));
}

static void disable_on_cpu(void *info)
{
	(void)info;
	asm volatile("msr pmuserenr_el0, %0" :: "r"((u64)0));
}

static int __init pmu_user_el0_init(void)
{
	on_each_cpu(enable_on_cpu, NULL, 1);
	pr_info("pmu_user_el0: EL0 access to PMCCNTR_EL0 enabled on all online CPUs\n");
	return 0;
}

static void __exit pmu_user_el0_exit(void)
{
	on_each_cpu(disable_on_cpu, NULL, 1);
	pr_info("pmu_user_el0: EL0 access to PMCCNTR_EL0 disabled\n");
}

module_init(pmu_user_el0_init);
module_exit(pmu_user_el0_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maciej Gojny, GG Advanced IT Security UG");
MODULE_DESCRIPTION("Enable EL0 access to PMCCNTR_EL0 for Flush+Reload research");
