# GGSEC Spectre v1 Lab: x86-64 and Raspberry Pi 5

A cross-platform reproduction of Spectre v1 (bounds-check bypass,
CVE-2017-5753). The same C source runs on x86-64 and on AArch64 (Raspberry Pi 5,
Cortex-A76) and recovers the canary string `spectre-v1 canary` through a
Flush+Reload cache channel.

The lab is in [`labs/spectre-v1/`](labs/spectre-v1/). Start with its
[README](labs/spectre-v1/README.md) for the mechanism, controls, and build steps.

## Results

| Configuration | Canary recovered | Barrier control |
|---|---|---|
| Intel Core i3-6100 (Skylake), Linux | 17/17 bytes | 0/17 |
| Intel Xeon E3-1245 v2 (Ivy Bridge), WSL2 | 17/17 bytes | 0/17 |
| Raspberry Pi 5, Cortex-A76, Linux | 17/17 bytes | 0/17 |

## Layout

```
framework/encode/encode.h    class encoding and slot geometry (shared)
framework/oracle/oracle.h    Flush+Reload primitives per ISA (shared)
labs/spectre-v1/             the lab source, Makefile, and README
labs/spectre-v1/kernel/      cycle-counter module for AArch64
labs/spectre-v1/results/     sample transcripts (positive and control legs)
```

`framework/` contains the two headers the lab needs. The lab builds from this
checkout without anything else.

## Quick start

Use a 64-bit Linux environment with GNU make and GCC (or a compatible compiler).
The x86 example has also been tested under WSL2. On Raspberry Pi, use a 64-bit
AArch64 OS, matching headers for the running kernel, and sudo access to load the
PMU helper. The selected logical CPU (default `1`) must be online and permitted
by your process affinity; override it with `CPU=<n>` when necessary.

x86-64:

```
cd labs/spectre-v1
make
./spectre-v1-oneshot
CONTROL=lfence ./spectre-v1-oneshot
```

AArch64 (Raspberry Pi 5):

```
cd labs/spectre-v1
make
sh kernel/setup.sh
./spectre-v1-oneshot
CONTROL=dsb-isb ./spectre-v1-oneshot
sudo rmmod pmu_user_el0
```

## Scope

This is a reproduction of a published vulnerability on hardware the author owns.
The secret is a neutral string held in the process's own memory. The lab is
intended for education and defensive research, not for attacking other systems.

## License

SPDX-License-Identifier: GPL-2.0-only

Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG

The source, headers and build scripts are licensed under the GNU General Public
License, version 2 only. See [LICENSE](LICENSE).
