#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
# Build and load the PMCCNTR_EL0 user-access module so the Spectre-v1 oracle has
# a cycle-resolution timer on AArch64. Idempotent (reloads if already present).
# Revert with: sudo rmmod pmu_user_el0
set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
mod=pmu_user_el0

if [ "$(uname -m)" != "aarch64" ]; then
	echo "pmu_user_el0: AArch64 only; nothing to do on $(uname -m)" >&2
	exit 0
fi

make -C "$here" >/dev/null
if lsmod | grep -q "^$mod\b"; then
	sudo rmmod "$mod"
fi
sudo insmod "$here/$mod.ko"
echo "pmu_user_el0: loaded; EL0 can now read PMCCNTR_EL0 (sudo rmmod $mod to revert)"
