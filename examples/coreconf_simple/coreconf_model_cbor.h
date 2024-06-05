
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Default definitions of buffer sizes used by RIOT application, safe to ignore
#define MAX_CORECONF_BUFFER_SIZE 4096
#define MAX_KEY_MAPPING_SIZE 128
#define MAX_CBOR_REQUEST_PAYLOAD_SIZE 32
#define MAX_CBOR_RESPONSE_PAYLOAD_SIZE 128
#define MAX_PERMISSIBLE_TRAVERSAL_REQUESTS 5


const uint8_t coreconfModelCBORBuffer[] =   {0xa1, 0x19, 0x03, 0xe8, 0xa2, 0x0c, 0xa1, 0x01, 0x82, 0xa2, 0x02, 0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfb, 0x40, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa2, 0x02, 0xfb, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfb, 0x40, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xa1, 0x01, 0x82, 0xa3, 0x03, 0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xfb, 0x41, 0x2e, 0x24, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfb, 0x40, 0x8f, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa3, 0x3, 0xfb, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xfb, 0x41, 0x2a, 0xbf, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x1, 0xfb, 0x40, 0x8f, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00};


const uint8_t keyMappingCBORBuffer[] = {0xa2, 0x19, 0x03, 0xf5, 0x81, 0x19, 0x03, 0xf7, 0x19, 0x03, 0xf0, 0x81, 0x19, 0x03, 0xf3};
