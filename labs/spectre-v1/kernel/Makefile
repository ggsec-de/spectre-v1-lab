# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
#
# kbuild for the PMCCNTR_EL0 user-access helper (Spectre-v1 lab, AArch64).
#
# Build:  make            (needs /lib/modules/$(uname -r)/build, i.e. headers)
# Load:   sudo insmod pmu_user_el0.ko     (reverts with: sudo rmmod pmu_user_el0)
# Clean:  make clean
#
# Only meaningful on an AArch64 host; the x86 builds of the lab use rdtsc and
# need no module.
obj-m := pmu_user_el0.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$$PWD modules

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
