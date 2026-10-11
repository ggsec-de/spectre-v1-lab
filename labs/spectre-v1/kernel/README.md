# pmu_user_el0 -- EL0 cycle-counter access for the AArch64 lab

A small kernel module for the Spectre v1 lab on AArch64 (Raspberry Pi 5,
Cortex-A76). It enables userspace reads of the PMU cycle counter
`PMCCNTR_EL0` on every online CPU, which the lab's Flush+Reload timer needs.

## Why it is needed

On the tested Cortex-A76, the two userspace-reachable clocks do not separate
an L1 hit from a flushed miss:

- `CNTVCT_EL0` ticks at 54 MHz (about 18.5 ns). The recorded hot and flushed
  reload measurements both returned 0-1 ticks, with insufficient separation.
- A shared counting-thread clock inverts, because the thread holding the
  counter's cache line stalls the writer core.

`PMCCNTR_EL0` (about 0.4 ns at 2.4 GHz) separates them: an L1 hit measured about
38 cycles and a flushed reload about 220. These timings alone do not establish
which cache level served a load. It traps from EL0 unless `PMUSERENR_EL0`
permits the read. This module sets that bit and configures the cycle counter
(`PMCR_EL0`, `PMCNTENSET_EL0`) on each CPU.

## Build and load

```
make                              # needs kernel headers for the running kernel
sudo insmod pmu_user_el0.ko
```

`sh setup.sh` builds the module and loads it, reloading it if it is already
present. It runs only on AArch64 and does nothing on other architectures.

## Revert

```
sudo rmmod pmu_user_el0
```

`rmmod` removes EL0 access to the counter by clearing `PMUSERENR_EL0`. It does
not restore the PMU to its exact prior configuration: the cycle counter stays
enabled and undivided. After a reboot, the boot firmware and kernel configure the PMU again.

## Scope

The module grants EL0 PMU access on CPUs online at load time, enables and resets
the cycle counter, removes its divider, and selects 64-bit counting. Unloading
clears EL0 PMU access on CPUs then online, but does not restore earlier register
values. Keep CPU hotplug and competing PMU/perf users out of the measurement.
The module does not install CPU-hotplug callbacks.
