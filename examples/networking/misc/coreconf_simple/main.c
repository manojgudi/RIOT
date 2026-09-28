/*
 * SPDX-FileCopyrightText: 2024 RIOT ccoreconf integration
 * SPDX-License-Identifier: MIT
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       coreconf_simple: gcoap-based CORECONF server entry point
 *
 * Initialises the gcoap listener with the CORECONF resources defined in
 * server.c. The CoAP shell client is intentionally not compiled in; the
 * reference Python client (`requestCBOR.py`) is used to drive the server
 * in tests.
 *
 * @}
 */

#include <stdio.h>

#include "msg.h"

#include "gcoap_example.h"

/* Defined here because we don't compile the original gcoap shell client. */
uint16_t req_count = 0;

#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

int main(void)
{
    /* RIOT needs a message queue even if we don't spawn threads ourselves. */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    server_init();
    puts("coreconf_simple: gcoap server up");

    /* Block forever; the gcoap stack services requests from its own thread. */
    while (1) {
        /* idle */
    }

    return 0;
}