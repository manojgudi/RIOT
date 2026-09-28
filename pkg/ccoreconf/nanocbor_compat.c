/*
 * SPDX-FileCopyrightText: 2024 RIOT ccoreconf integration
 * SPDX-License-Identifier: MIT
 */

#include <nanocbor/nanocbor.h>

/*
 * Bind `nanocbor_leave_container_real` to the library symbol
 * `nanocbor_leave_container`. The asm label makes them the same symbol at
 * link time without touching the upstream nanocbor source.
 */
extern void nanocbor_leave_container_real(nanocbor_value_t *it,
                                          nanocbor_value_t *container)
    __asm__("nanocbor_leave_container");

/*
 * The function-like macro in nanocbor_compat.h rewrites every
 * `nanocbor_leave_container(it, c)` call in ccoreconf's source to
 * `nanocbor_leave_container_compat(it, c)`. We always return 0
 * (success) because the underlying nanocbor function is void.
 */
int nanocbor_leave_container_compat(nanocbor_value_t *it,
                                    nanocbor_value_t *container)
{
    nanocbor_leave_container_real(it, container);
    return 0;
}