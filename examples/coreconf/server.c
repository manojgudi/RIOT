/*
 * Copyright (c) 2015-2017 Ken Bannister. All rights reserved.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       gcoap CLI support
 *
 * @author      Ken Bannister <kb2ma@runbox.com>
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#include "fmt.h"
#include "net/gcoap.h"
#include "net/utils.h"

#include "od.h"
#include "sid_prototypes.h"
#include "ccoreconf.h"
#include "fileOperations.h"
#include "hashmap.h"

#include "gcoap_example.h"

#define ENABLE_DEBUG 0
#include "debug.h"

#if IS_USED(MODULE_GCOAP_DTLS)
#include "net/credman.h"
#include "net/dsm.h"
#include "tinydtls_keys.h"

/* Example credential tag for credman. Tag together with the credential type needs to be unique. */
#define GCOAP_DTLS_CREDENTIAL_TAG 10

static const uint8_t psk_id_0[] = PSK_DEFAULT_IDENTITY;
static const uint8_t psk_key_0[] = PSK_DEFAULT_KEY;
static const credman_credential_t credential = {
    .type = CREDMAN_TYPE_PSK,
    .tag = GCOAP_DTLS_CREDENTIAL_TAG,
    .params = {
        .psk = {
            .key = { .s = psk_key_0, .len = sizeof(psk_key_0) - 1, },
            .id = { .s = psk_id_0, .len = sizeof(psk_id_0) - 1, },
        }
    },
};
#endif

static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context);
static ssize_t _stats_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);
static ssize_t _riot_board_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);
static ssize_t _riot_sensor_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);


/* CoAP resources. Must be sorted by path (ASCII order). */
static const coap_resource_t _resources[] = {
    { "/cli/stats", COAP_GET | COAP_PUT, _stats_handler, NULL },
    { "/riot/board", COAP_GET, _riot_board_handler, NULL },
    { "/riot/sensor", COAP_GET, _riot_sensor_handler, NULL}
};

static const char *_link_params[] = {
    ";ct=0;rt=\"count\";obs",
    NULL
};

static gcoap_listener_t _listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
    GCOAP_SOCKET_TYPE_UNDEF,
    _encode_link,
    NULL,
    NULL
};


/* Adds link format params to resource list */
static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context) {
    ssize_t res = gcoap_encode_link(resource, buf, maxlen, context);
    if (res > 0) {
        if (_link_params[context->link_pos]
                && (strlen(_link_params[context->link_pos]) < (maxlen - res))) {
            if (buf) {
                memcpy(buf+res, _link_params[context->link_pos],
                       strlen(_link_params[context->link_pos]));
            }
            return res + strlen(_link_params[context->link_pos]);
        }
    }

    return res;
}

/*
 * Server callback for /cli/stats. Accepts either a GET or a PUT.
 *
 * GET: Returns the count of packets sent by the CLI.
 * PUT: Updates the count of packets. Rejects an obviously bad request, but
 *      allows any two byte value for example purposes. Semantically, the only
 *      valid action is to set the value to 0.
 */
static ssize_t _stats_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx)
{
    (void)ctx;

    /* read coap method type in packet */
    unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));

    switch (method_flag) {
        case COAP_GET:
            gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
            coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
            size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

            /* write the response buffer with the request count value */
            resp_len += fmt_u16_dec((char *)pdu->payload, req_count);
            return resp_len;

        case COAP_PUT:
            /* convert the payload to an integer and update the internal
               value */
            if (pdu->payload_len <= 5) {
                char payload[6] = { 0 };
                memcpy(payload, (char *)pdu->payload, pdu->payload_len);
                req_count = (uint16_t)strtoul(payload, NULL, 10);
                return gcoap_response(pdu, buf, len, COAP_CODE_CHANGED);
            }
            else {
                return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
            }
    }

    return 0;
}

static ssize_t _riot_board_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx)
{
    (void)ctx;
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    /* write the RIOT board name in the response buffer */
    if (pdu->payload_len >= strlen(RIOT_BOARD)) {
        memcpy(pdu->payload, RIOT_BOARD, strlen(RIOT_BOARD));
        return resp_len + strlen(RIOT_BOARD);
    }
    else {
        puts("gcoap_cli: msg buffer too small");
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }
}

static ssize_t _riot_sensor_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx)
{
    (void)ctx;

    /* read coap method type in packet */
    unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));

    char path_tmp[64] = {0} ;
    // Using snprintf to concatenate string and number
	// We will match path_tmp against the query parameters
    snprintf(path_tmp, sizeof(path_tmp), "&sid=%d", SID_HEALTHVALUE);

    unsigned char query_tmp[64] = {0};
    coap_get_uri_query(pdu, query_tmp);

    switch (method_flag) {
        case COAP_GET:
			// Compare if the query parameters is for SID_HEALTHVALUE
            if (! strcmp((char *) query_tmp, path_tmp) ){
                uint32_t healthValue = read_healthValue(1);


			    // The "+1" is for the null terminator
			    int max_chars = snprintf(NULL, 0, "%u", healthValue) + 1;

 			    // Allocate memory for the string
    			char *str_value = (char *)malloc(max_chars);
			    if (str_value == NULL) {
			        // Handle memory allocation failure
		    	    return 1;
			    }
               // Convert uint32_t to string
		       snprintf(str_value, max_chars, "%u", healthValue);
    
                gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
                coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
                size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

                /* write the RIOT board name in the response buffer */
                if (pdu->payload_len >=  strlen(str_value)) {
                    memcpy(pdu->payload, str_value, strlen(str_value));
                    return resp_len + strlen(str_value);
                }
               else {
                    return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
                }
            }
            gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
            coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
            size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

            /* write the response buffer with the request count value */
            resp_len += fmt_u16_dec((char *)pdu->payload, req_count);
            return resp_len;

        case COAP_PUT:
            /* NOT IMPLEMENTED FOR THE DEMO
                Currently returns arbitrary payload */
            if (pdu->payload_len <= 5) {
                char payload[6] = { 0 };
                memcpy(payload, (char *)pdu->payload, pdu->payload_len);
                req_count = (uint16_t)strtoul(payload, NULL, 10);
                return gcoap_response(pdu, buf, len, COAP_CODE_CHANGED);
            }
            else {
                return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
            }
    }

    return 0;
}


void notify_observers(void)
{
    size_t len;
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;

    /* send Observe notification for /cli/stats */
    switch (gcoap_obs_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE,
            &_resources[0])) {
    case GCOAP_OBS_INIT_OK:
        DEBUG("gcoap_cli: creating /cli/stats notification\n");
        coap_opt_add_format(&pdu, COAP_FORMAT_TEXT);
        len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);
        len += fmt_u16_dec((char *)pdu.payload, req_count);
        gcoap_obs_send(&buf[0], len, &_resources[0]);
        break;
    case GCOAP_OBS_INIT_UNUSED:
        DEBUG("gcoap_cli: no observer for /cli/stats\n");
        break;
    case GCOAP_OBS_INIT_ERR:
        DEBUG("gcoap_cli: error initializing /cli/stats notification\n");
        break;
    }
}

void example(json_t *instance);

void server_init(void)
{

    // Load SID in memory and build a key-mapping

   const char *sidFilePath1 =
        "./sensor@unknown.sid";
    const char *configFile2 = "./sensor_instance.json";

    const char *keyMappingString = "key-mapping";
    SIDModelT *sidModel = malloc(sizeof(SIDModelT));

    json_t *sidFile1JSON = readJSON(sidFilePath1);
    json_t *coreconfModel = readJSON(configFile2);

    // Access key-mapping
    json_t *keyMappingJSON = json_object_get(sidFile1JSON, keyMappingString);
    if (!json_is_object(keyMappingJSON)) {
        fprintf(stderr, "Failed %s does not return a JSON map:", keyMappingString);
        return;
    }

    // Build identifierSIDHashMap & sidIdentifierHashMap
    sidModel->identifierSIDHashMap =
        hashmap_new(sizeof(IdentifierSIDT), 0, 0, 0, identifierSIDHash, identifierSIDCompare, NULL, NULL);
    sidModel->sidIdentifierHashMap =
        hashmap_new(sizeof(SIDIdentifierT), 0, 0, 0, sidIdentifierHash, sidIdentifierCompare, NULL, NULL);

    // Build identifierTypeHashMap
    sidModel->identifierTypeHashMap =
        hashmap_new(sizeof(IdentifierTypeT), 0, 0, 0, identifierTypeHash, identifierTypeCompare, NULL, NULL);

    // Build SIDModel 
    buildSIDModel2(sidModel, sidFile1JSON);

    // Build keyMappingHashMap
    sidModel->keyMappingHashMap =
        hashmap_new(sizeof(KeyMappingT), 0, 0, 0, keyMappingHash, keyMappingCompare, NULL, NULL);
    buildKeyMappingHashMap2(sidModel->keyMappingHashMap, sidFile1JSON, sidModel );

    printKeyMappingHashMap(sidModel->keyMappingHashMap);
    printf("---------\n");
    // Print sidModel->identifierSIDHashMap
    printHashMap(sidModel->identifierSIDHashMap, IDENTIFIER_SID);
    printf("---------\n");
    // Print sidModel->sidIdentifierHashMap
    printHashMap(sidModel->sidIdentifierHashMap, SID_IDENTIFIER);
    printf("---------\n");
    // Print sidModel->identifierTypeHashMap
    printHashMap(sidModel->identifierTypeHashMap, IDENTIFIER_TYPE);
    printf("---------\n");


    // Build CORECONF representation of the model file
    lookupSID(coreconfModel, sidModel);

    printf("Print the CORECONF model\n");
    print_json_object(coreconfModel);
    printf("---------\n");



    printf("Everything is loaded\n");
#if IS_USED(MODULE_GCOAP_DTLS)
    int res = credman_add(&credential);
    if (res < 0 && res != CREDMAN_EXIST) {
        /* ignore duplicate credentials */
        printf("gcoap: cannot add credential to system: %d\n", res);
        return;
    }
    sock_dtls_t *gcoap_sock_dtls = gcoap_get_sock_dtls();
    res = sock_dtls_add_credential(gcoap_sock_dtls, GCOAP_DTLS_CREDENTIAL_TAG);
    if (res < 0) {
        printf("gcoap: cannot add credential to DTLS sock: %d\n", res);
    }
#endif

    gcoap_register_listener(&_listener);
}
