import asyncio
import aiocoap.resource as resource
import aiocoap
import cbor2
from pprint import pprint
async def coap_post_cbor(uri, data):

    print("Sending a COAP Request with payload: ")
    pprint(data)
    print("-------\n\n\n")
    # Encode the data to CBOR format
    cbor_data = cbor2.dumps(data)

    # Create the CoAP request
    context = await aiocoap.Context.create_client_context()
    request = aiocoap.Message(code=aiocoap.FETCH, uri=uri, payload=cbor_data)
    request.opt.content_format = 60  # 60 is the media type for CBOR

    # Send the request and wait for the response
    response = await context.request(request).response

    print('Response CBOR code:', response.code)

    cborPayload = response.payload
    coreconfData = cbor2.loads(cborPayload)
    print("For mere mortals who can't read CBOR, it is:")
    pprint(coreconfData)


if __name__ == "__main__":
    # NOTE dont forget to estabilish tap0 as documented here:
        # https://github.com/RIOT-OS/RIOT/tree/master/examples/gnrc_networking
        # Check ./startap.sh
    uri = "coap://[fe80::cc66:c2ff:fe36:62fe%tap0]/sid" # NOTE Put correct tap0 IPv6


    # Payload as specified:
        # https://datatracker.ietf.org/doc/html/draft-ietf-core-comi-11#section-4.2.4
    data = [60005, [60007, 0]]

    asyncio.run(coap_post_cbor(uri, data))

