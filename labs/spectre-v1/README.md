# Spectre v1 lab (x86-64 and AArch64)

Spectre v1, the bounds-check bypass (CVE-2017-5753), reproduced with a
Flush+Reload cache channel. The same C source builds for x86-64 and for AArch64
(Raspberry Pi 5, Cortex-A76). Recorded runs on each tested platform recovered the canary string
`spectre-v1 canary` from a victim gadget, and a barrier control leg shows that
the recovered signal depends on speculative execution.

## Mechanism

A victim gadget guards an array read with a bounds check:

```
if (x < array1_size) tmp = oracle[ enc_cls_of(array1[x]) * STRIDE ];
```

1. **Train.** The branch is trained with in-bounds indices, so the predictor
   learns that the branch is taken.
2. **Flush.** The bound is flushed from the cache, so the comparison stalls.
3. **Speculate.** The malicious index points at the secret. The CPU runs past
   the check and speculatively reads the out-of-bounds byte, which pulls that
   byte's class line into the cache.
4. **Measure.** The architectural result is discarded, but the cache footprint
   remains. Flush+Reload times each class slot; a fast reload identifies the
   6-bit class. A second encoding pass supplies the remaining bits.

The secret is a neutral ASCII string held in this process's own static storage
and read back by the same process. Nothing crosses a privilege or process
boundary.

## Results

Recorded runs, all recovering the full 17-byte string:

| Configuration | Canary recovered | Barrier control |
|---|---|---|
| Intel Core i3-6100 (Skylake), Linux | 17/17 bytes | 0/17 |
| Intel Xeon E3-1245 v2 (Ivy Bridge), WSL2 | 17/17 bytes | 0/17 |
| Raspberry Pi 5, Cortex-A76, Linux | 17/17 bytes | 0/17 |

Sample transcripts are in [`results/`](results/): one positive leg and one
barrier-control leg per platform.

## Controls

| Leg | `CONTROL` | Expected verdict |
|---|---|---|
| positive | `none` | `SPECTRE_LEAK`: all expected low-pass classes have a strict majority |
| control | `lfence` (x86) or `dsb-isb` (AArch64) | `CONTROL_COLD`: no expected low-pass class has a strict majority |

The control leg inserts a serialising barrier between the bounds check and the
array use. Compare both passes and the full reconstructed string with the positive leg.
The control verdict alone tests expected low-pass classes; it does not prove
that every non-training class or the high pass has zero cache hits.

On AArch64, ARM's production mitigation for this bug is
`array_index_mask_nospec` (a `csel` index clamp followed by `csdb`). This demo
does not implement that mitigation. It uses the barrier `dsb sy; isb` as the
control, which is the closest analog of x86 `lfence`.

## AArch64 port

The source is shared; only these primitives differ, selected at compile time:

- **Flush:** x86 `clflush` becomes `dc civac` followed by `dsb ish`.
- **Timer:** x86 `rdtsc` becomes the PMU cycle counter `PMCCNTR_EL0`. This
  counter traps from EL0 unless `PMUSERENR_EL0` permits the read, so the module
  in [`kernel/`](kernel/) must be loaded first. Without it the first read raises
  `SIGILL`. The virtual counter `CNTVCT_EL0` (54 MHz) did not provide enough
  timing separation in the recorded tests: hot and flushed measurements both
  returned 0-1 ticks. These timings do not identify a particular cache level.
- **Reload order:** the slots are reloaded in a fixed scrambled order, not
  ascending. The Cortex-A76 stride prefetcher otherwise warms slots ahead of the
  probe and raises a false-hot noise floor on the control leg.
- **Barrier:** x86 `lfence` becomes `dsb sy; isb`.

Measured on the Raspberry Pi 5 at 2.4 GHz with the `performance` governor:
`cold=222 hot=38 threshold=130` cycles.

## Build and run

x86-64:

```
make
./spectre-v1-oneshot                    # positive leg
CONTROL=lfence ./spectre-v1-oneshot     # barrier control
```

AArch64 (load the cycle-counter module first):

```
make
sh kernel/setup.sh                      # builds and loads pmu_user_el0.ko (sudo)
./spectre-v1-oneshot                    # positive leg
CONTROL=dsb-isb ./spectre-v1-oneshot    # barrier control
```

To revert the module: `sudo rmmod pmu_user_el0`.

Environment variables:

- `CPU=<n>`: logical CPU to pin the process to (default `1`).
- `ROUNDS=<n>`: Flush+Reload rounds per byte (default `16`). Raise it on a noisy
  host if a byte is marginal. This count applies per byte per encoding pass
  (accepted range: `1..4096`).
- `CONTROL=none|lfence|csdb|dsb-isb|barrier`: leg to run (default `none`). Any
  barrier name selects the control leg on either build.
- `SELFTEST=1`: calibrate and decode the first byte, then exit. Its verdict
  scores the low-pass class; inspect the reconstructed byte separately.

Compiler flags are `-O2 -Wall -Wextra -Werror`. Use a 64-bit Linux environment,
GNU make and GCC (or a compatible compiler). The two required headers are included
in this repository. AArch64 also requires matching headers for the running kernel
and permission to load the PMU module. Set `CPU=<n>` to an online logical CPU
allowed by the current affinity mask.

## Two-pass byte reconstruction

The oracle has 64 classes. One measurement carries six bits, not a complete byte.
The low pass encodes `(byte ^ 0x3f) & 0x3f`, recovering bits 5..0. The high pass
first shifts the byte right by two and applies the same encoding, exposing bits
7..2. The decoder combines the low six bits with bits 6 and 7 from the high pass.

## Output

Each run prints a `timing:` line (calibrated cold and hot reload times), one
`byte` line and one `recovered` line per secret byte, and a final verdict:

```
recovered leg=positive bytes=17/17 string="spectre-v1 canary"
verdict: SPECTRE_LEAK
```

The recorded barrier examples print `string="................."` and
`verdict: CONTROL_COLD`. These are measured examples, not guaranteed output on
every host. `SPECTRE_LEAK` scores the expected low-pass classes with more than
half the rounds hot; `recovered ... bytes=N/17` separately compares reconstructed
bytes with the known canary. The high-pass winner currently has no majority or
tie gate, so a printable reconstructed character alone is not proof of recovery.
Inspect the low-pass hit counts, full-byte match count, and paired control.
A dot denotes a nonprintable reconstructed candidate, not an explicit missing
measurement. When every candidate has zero hits, the current argmax selects
class 0 in each pass, reconstructing `0xff`, which is displayed as a dot.

## Limits

- **Decoder coverage.** A byte whose class equals the training value's class
  (63, for training value `0x00`) is excluded from decode, because the in-bounds
  training keeps that class hot. Both passes exclude that class: the combined unsupported byte values are
  `00`, `01`, `02`, `03`, `40`, `80`, and `C0` (hex). The demo secret avoids them.
  The decoder therefore does not recover every possible byte value.
- **Probabilistic recovery.** Results depend on the host. Raise `ROUNDS` if a
  byte is marginal. The barrier control must still read cold.
- **Cache geometry.** The `0x1040` slot stride and 64-class alphabet were tuned
  on an Intel Skylake L1D. They reproduced cleanly on the tested parts; a part
  with different cache geometry may need them retuned.
- **Scope.** This is a demonstration of a published 2018 vulnerability on
  hardware the author owns. It is not a tool for attacking other systems.
