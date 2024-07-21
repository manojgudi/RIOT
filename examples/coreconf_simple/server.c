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

#include "fmt.h"
#include "net/gcoap.h"
#include "net/utils.h"
#include "od.h"

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

#include <nanocbor/nanocbor.h>

// Import Coreconf headers
#include "coreconfManipulation.h"
#include "serialization.h"
#include "coreconfTypes.h"

// Import Coreconf Models
#include "coreconf_model_cbor.h"


static ssize_t _encode_link(const coap_resource_t *resource, char *buf, size_t maxlen, coap_link_encoder_ctx_t *context);
static ssize_t _stats_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);
static ssize_t _sid_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);
static ssize_t _riot_board_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);


CoreconfValueT *coreconfModel = NULL;
struct hashmap *clookupHashmap=NULL;
struct hashmap *keyMappingHashMap=NULL;


/* CoAP resources. Must be sorted by path (ASCII order). */
static const coap_resource_t _resources[] = {
    { "/cli/stats", COAP_GET | COAP_PUT | COAP_FETCH, _stats_handler, NULL },
    { "/sid", COAP_FETCH, _sid_handler, NULL },
    { "/riot/board", COAP_GET, _riot_board_handler, NULL },
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
 * Server callback for /sid/. Accepts either a GET or a PUT.
 * FETCH : Fetches the SID and keys from the payload
 */

static ssize_t _sid_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx){
    (void)ctx;


    /* read coap method type in packet */
    unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));

    // Copy the payload into a buffer
    uint8_t requestPayload[MAX_CBOR_REQUEST_PAYLOAD_SIZE] = {0};
    memcpy(requestPayload, (char *)pdu->payload, pdu->payload_len);
    // print the request payload
    printf("Request Payload in CBOR Hex: ");
    for (size_t i = 0; i < pdu->payload_len; i++){
        printf("%02x", requestPayload[i]);
    }
    printf("\n");

    // Import keymapping from the header
    // Read cbor from coreconfModelCBORBuffer
    nanocbor_value_t decoder;
    nanocbor_decoder_init(&decoder, requestPayload, MAX_CBOR_REQUEST_PAYLOAD_SIZE);

    CoreconfValueT *coreconfRequestPayload = cborToCoreconfValue(&decoder, 0);
    printf("\nDeserialized Coreconf: \n");
    printCoreconf(coreconfRequestPayload);
    printf("\n");

    // To hold the traversal results    
    CoreconfValueT* coreconfResponsePayload = createCoreconfArray();

    // Load key-mapping from keyMappingCBORBuffer
    nanocbor_value_t keyMappingDecoder;
    nanocbor_decoder_init(&keyMappingDecoder, keyMappingCBORBuffer, MAX_KEY_MAPPING_SIZE);
    keyMappingHashMap = cborToKeyMappingHashMap(&keyMappingDecoder);
    
    DynamicLongListT *requestKeys = malloc(sizeof(DynamicLongListT));
    //DynamicLongListT *requestKeys_ = malloc(sizeof(DynamicLongListT));
    initializeDynamicLongList(requestKeys);

    uint64_t requestSID = 0;

    switch (method_flag) {
        case COAP_GET:{
            gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
            coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
            size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

            /* write the response buffer with the request count value */
            resp_len += fmt_u16_dec((char *)pdu->payload, req_count);
            return resp_len;
        }
        case COAP_FETCH:{
            /* Fetch the payload (request SID and keys 
                Payload will be in the format:
                [REQUESTED_SID_1, [REQUEST_SID2, REQUESTED_SID2_KEY1, REQUESTED_SID2_KEY2..]..]
                according to https://datatracker.ietf.org/doc/html/draft-ietf-core-comi-11#section-4.2.4
            */

            // TODO Build the CLookup hashmap from CoreconfModel as traversal mutates the clookupHashmap, can you fix ccoreconf to not mutate the clookupHashmap?
            buildCLookupHashmapFromCoreconf(coreconfModel, clookupHashmap, 0, 0);

            // Iterate through the requestPayload
            size_t arrayLength = coreconfRequestPayload->data.array_value->size;

            // Check if the arrayLength MAX_PERMISSIBLE_TRAVERSAL_REQUESTS
            if (arrayLength > MAX_PERMISSIBLE_TRAVERSAL_REQUESTS){
                printf("Too many SIDs requested in a single requests\n");
                return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
            }

             for (size_t i = 0; i < arrayLength; i++) {
                // Each element of the array is a separate traversal request
                CoreconfValueT *requestElement = &(coreconfRequestPayload->data.array_value->elements[i]);
                if (requestElement->type == CORECONF_UINT_64){
                    // Query the coreconf model for an individual SID request
                    requestSID = requestElement->data.u64;
                    // Find the requirement for the SID
                    PathNodeT *pathNodes = findRequirementForSID(requestSID, clookupHashmap, keyMappingHashMap);

                    // NULL Check for pathNodes
                    if (pathNodes == NULL){
                        printf("SID not found in the coreconf model\n");
                        // Move to the next requested SID
                        continue;
                    }

                    // Print the PathNodeT
                    printf("To reach your SID, the following SIDs  are traversed: \n");
                    printPathNode(pathNodes);
                    printf("---------\n");

                    // Examine the coreconf model value
                    CoreconfValueT *examinedValue = examineCoreconfValue(coreconfModel, requestKeys, pathNodes);

                    // NULL Check for examinedValue
                    if (examinedValue == NULL){
                        printf("Couldn't find any results after the traversal\n");
                        // Move to the next requested SID
                        continue;
                    }

                    printf("Coreconf subtree after traversal: \n");
                    printCoreconf(examinedValue);
                    printf("---------\n");
                    addToCoreconfArray(coreconfResponsePayload, examinedValue);

                } else if (requestElement->type == CORECONF_ARRAY){
                    // The first element of the array is the request SID, the rest are SID keys
                    CoreconfValueT *requestSIDElement = &(requestElement->data.array_value->elements[0]);
                    requestSID = requestSIDElement->data.u64;

                    // Iterate through the rest of the array
                    for (size_t j = 1; j < requestElement->data.array_value->size; j++){
                        CoreconfValueT *requestKeyElement = &(requestElement->data.array_value->elements[j]);
                        addLong(requestKeys, requestKeyElement->data.u64);
                    }

                    // Find the requirement for the SID
                    PathNodeT *pathNodes = findRequirementForSID(requestSID, clookupHashmap, keyMappingHashMap);
                    
                    // NULL Check for pathNodes
                    if (pathNodes == NULL){
                        printf("SID not found in the coreconf model\n");
                        // Move to the next requested SID
                        continue;
                    }

                    // Print the PathNodeT
                    printf("To reach your SID, the following SIDs  are traversed: \n");
                    printPathNode(pathNodes);
                    printf("---------\n");

                    // Examine the coreconf model value
                    CoreconfValueT *examinedValue = examineCoreconfValue(coreconfModel, requestKeys, pathNodes);

                    // NULL Check for examinedValue
                    if (examinedValue == NULL){
                        printf("Couldn't find any results after the traversal\n");
                        // Move to the next requested SID
                        continue;
                    }
                    printf("Coreconf subtree after traversal: \n");
                    printCoreconf(examinedValue);
                    printf("---------\n");
                    addToCoreconfArray(coreconfResponsePayload, examinedValue);  
                }
             }

            printf("Start serialization\n");

            // Serialize the response payload
            uint8_t responsePayloadBuffer[MAX_CBOR_RESPONSE_PAYLOAD_SIZE] = {0};
            nanocbor_encoder_t encoder;
            nanocbor_encoder_init(&encoder, responsePayloadBuffer, MAX_CBOR_RESPONSE_PAYLOAD_SIZE);
            printf("Encoder initialized\n  ");

            coreconfToCBOR(coreconfResponsePayload, &encoder);
            size_t responsePayloadSize = nanocbor_encoded_len(&encoder);

            // Print the response payload
            printf("Response Payload in CBOR Hex: ");
            for (size_t i = 0; i < responsePayloadSize; i++){
                printf("%02x", responsePayloadBuffer[i]);
            }

            // Send the response payload
            gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
            coap_opt_add_format(pdu, COAP_FORMAT_CBOR);
            size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);
            memcpy(pdu->payload, responsePayloadBuffer, responsePayloadSize);
            return resp_len + responsePayloadSize;
        }

    }

    return 0;
}

/*
Default implementation 
 * Server callback for /cli/stats. Accepts either a GET or a PUT.
 *
 * GET: Returns the count of packets sent by the CLI.
 * PUT: Updates the count of packets. Rejects an obviously bad request, but
 *      allows any two byte value for example purposes. Semantically, the only
 *      valid action is to set the value to 0.
 */
static ssize_t _stats_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx){
    (void)ctx;

    /* read coap method type in packet */
    unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));

    switch (method_flag) {
        case COAP_GET:{
            gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
            coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
            size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

            /* write the response buffer with the request count value */
            resp_len += fmt_u16_dec((char *)pdu->payload, req_count);
            return resp_len;
        }

        case COAP_PUT:{
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

    }
    return 0;
}

/*
Default implementation 
*/
static ssize_t _riot_board_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx){
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

void notify_observers(void){
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

void server_init(void){
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

    // Initialize the coreconf model and keymapping required for coreconf traversal from the routes

    // Import keymapping from the header
    // Read cbor from coreconfModelCBORBuffer
    nanocbor_value_t decoder;
    nanocbor_decoder_init(&decoder, coreconfModelCBORBuffer, MAX_CORECONF_BUFFER_SIZE);

    coreconfModel = cborToCoreconfValue(&decoder, 0);
    printf("\nDeserialized Coreconf: \n");
    printCoreconf(coreconfModel);
    printf("\n");

    // Load key-mapping from keyMappingCBORBuffer
    nanocbor_value_t keyMappingDecoder;
    nanocbor_decoder_init(&keyMappingDecoder, keyMappingCBORBuffer, MAX_CORECONF_BUFFER_SIZE);
    keyMappingHashMap = cborToKeyMappingHashMap(&keyMappingDecoder);
    printf("Key Mapping: \n");
    printKeyMappingHashMap(keyMappingHashMap);
    printf("\n");

    // Build Chump Lookup hashmap for faster lookups
    clookupHashmap = hashmap_new(sizeof(CLookupT), 0, 0, 0, clookupHash, clookupCompare, NULL, NULL);

    // Build the CLookup hashmap from CoreconfModel
    buildCLookupHashmapFromCoreconf(coreconfModel, clookupHashmap, 0, 0);
    printf("Chump lookup built: \n");
    printCLookupHashmap(clookupHashmap);
    printf("\nInitialized server\n");

    gcoap_register_listener(&_listener);
    return;
}
