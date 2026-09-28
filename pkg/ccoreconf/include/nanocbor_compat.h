/*
 * SPDX-FileCopyrightText: 2024 RIOT ccoreconf integration
 * SPDX-License-Identifier: MIT
 *
 * Compensates for the int/void mismatch of nanocbor_leave_container()
 * between current ccoreconf and RIOT's pinned NanoCBOR (3e370048).
 *
 * ccoreconf/src/serialization.c calls
 *     if (nanocbor_leave_container(value, &cborArrayValue) < 0) ...
 * but RIOT's pinned nanocbor declares
 *     void nanocbor_leave_container(nanocbor_value_t *, nanocbor_value_t *).
 *
 * Strategy:
 *  - This header is prepended to every ccoreconf translation unit via
 *    -include (set in pkg/ccoreconf/Makefile).
 *  - It includes <nanocbor/nanocbor.h>, which declares the real void-returning
 *    function.
 *  - It then defines a function-like macro with the same name. C resolves
 *    call-site lookups of `nanocbor_leave_container(...)` to the macro,
 *    expanding it to `nanocbor_leave_container_compat(...)`.
 *  - nanocbor_leave_container_compat() is defined in nanocbor_compat.c and
 *    returns int (always 0). It calls the real library symbol through an
 *    asm-label alias (`nanocbor_leave_container_real`) so the linker
 *    resolves it to nanocbor_leave_container in libnanocbor.
 *
 * Result: ccoreconf's source is untouched; the call is rewritten at the
 * preprocessor stage, no source patches, no -Wl,--wrap.
 */
#ifndef CCORECONF_NANOCBOR_COMPAT_H
#define CCORECONF_NANOCBOR_COMPAT_H

#include <nanocbor/nanocbor.h>

#define nanocbor_leave_container(it, container) \
    nanocbor_leave_container_compat((it), (container))

/* Forward declaration for the macro target. The definition lives in
 * nanocbor_compat.c, compiled alongside the ccoreconf sources. */
int nanocbor_leave_container_compat(nanocbor_value_t *it,
                                    nanocbor_value_t *container);

#endif /* CCORECONF_NANOCBOR_COMPAT_H */