/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
 *
 * Shared slot/class geometry for the microarchitectural oracle experiments.
 *
 * One source of the encode geometry for both the C reload side and any
 * assembly transient: a .S source (capital S) is run through cpp before the
 * assembler, so it can #include this header and see the same constants. The
 * C-only helper is hidden from the assembler by the __ASSEMBLER__ guard the
 * preprocessor sets when assembling.
 *
 * The 0x1040 stride and 64-class alphabet were tuned on an Intel Skylake L1D;
 * they are not universal constants. The stride keeps 64 class slots out of a
 * single L1D set, and class = (byte ^ 0x3f) & 0x3f keeps the low six bits the
 * transient leaks. They reproduce cleanly on the tested parts (see the lab
 * README); a part whose cache geometry differs may need them retuned.
 */
#ifndef FRAMEWORK_ENCODE_H
#define FRAMEWORK_ENCODE_H

#define ENC_SLOT_SIZE  0x1040            /* bytes between adjacent class slots */
#define ENC_NCLASS     64                /* classes in the 6-bit alphabet */
#define ENC_XOR_KEY    0x3f              /* key folded into the leaked byte */
#define ENC_CLASS_MASK (ENC_NCLASS - 1)  /* 0x3f: mask to a 6-bit class */

#ifndef __ASSEMBLER__
/* class of a byte: fold in the key, keep six bits. Matches the encode the
 * speculative transient performs, which uses the same constants above. */
static inline int enc_cls_of(int byte)
{
    return (byte ^ ENC_XOR_KEY) & ENC_CLASS_MASK;
}
#endif /* __ASSEMBLER__ */

#endif /* FRAMEWORK_ENCODE_H */
