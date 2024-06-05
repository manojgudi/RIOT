# CORECONF Simple Example

## About

This is an example RIOT application which uses [ccoreconf library](https://github.com/manojgudi/ccoreconf/) to showcase a coreconf tree traversal.
Let us look at the steps required to build this RIOT application. If you directly want to build and test the application, go to the *Testing* section.

### Write your YANG Model

For any coreconf application, it is essential we develop an underlying YANG model first. For this example, we use this [simple YANG model](https://github.com/manojgudi/ccoreconf/blob/main/samples/simple_yang/sensor.yang) to describe a basic sensor which sends readings and its own health/battery status. The sensor would typically send its readings in json data as shown in this [json data file](https://github.com/manojgudi/ccoreconf/blob/main/samples/simple_yang/sensor_instance.json).

### Generate SID and generating stubs

Each YANG model requires SIDs (Schema IDentifiers) to be generated so that we can standardize the identifiers (URIs) and eventually convert the data instance into a concise coreconf format.
These SIDs can also be used to generate a C code stubs which can be later utilized when building embedded application.

Take a look at [this README](https://github.com/manojgudi/ccoreconf/blob/main/tools/README.md) on how to use tools (such as pyang and stubs-generator) to generate SID and C prototype stubs.

### Generate CBOR Model Header file

The data instance is stored as an uint8_t array in coreconf format (which is serialized in CBOR format). The key mapping from the .sid file is also stored as a uint8_t array in coreconf format (which is serialized to CBOR as well).

To generate these uint8_t array, we can use the tool provided with ccoreconf called [generateCBORDumps.py](https://github.com/manojgudi/ccoreconf/blob/main/tools/generateCBORDumps.py)

Before it's used, we need some python requirements to be installed, which can be done using
```py
$ pip -r requirements.txt
```

Optionally, *for some reason if pycoreconf gives you an error, you can install following tested version of pycoreconf*

```py
$ pip install git+https://github.com/manojgudi/pycoreconf
```

generateCBORDumps.py requires 3 arguments, namely:

1. Data instance file which is in json
2. SID file generated using pyang
3. Header file name where the uint8_t arrays will be written to.

We can run the tool using the command for [sensor_instance.json](https://github.com/manojgudi/ccoreconf/blob/main/samples/simple_yang/sensor_instance.json) and [sensor@unknown_numerical.sid](https://github.com/manojgudi/ccoreconf/blob/main/samples/simple_yang/sensor%40unknown_numerical.sid) files-
```
$ python3 generateCBORDumps.py ../samples/simple_yang/sensor_instance.json ../samples/simple_yang/sensor@unknown_numerical.sid coreconf_model_cbor.h
```

The generated file should look like this:
```c

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Default definitions of buffer sizes used by RIOT application, safe to ignore
#define MAX_CORECONF_BUFFER_SIZE 4096
#define MAX_KEY_MAPPING_SIZE 128
#define MAX_CBOR_REQUEST_PAYLOAD_SIZE 32
#define MAX_CBOR_RESPONSE_PAYLOAD_SIZE 128
#define MAX_PERMISSIBLE_TRAVERSAL_REQUESTS 5




const uint8_t coreconfModelCBORBuffer[] = {0xa1, 0x19, 0x03, 0xe8, 0xa2, 0x0c, 0xa1, 0x01, 0x82, 0xa2, 0x02, 0x01, 0x01, 0x19, 0x04, 0x00, 0xa2, 0x02, 0x02, 0x01, 0x19, 0x08, 0x00, 0x07, 0xa1, 0x01, 0x82, 0xa3, 0x03, 0x01, 0x02, 0x1a, 0x00, 0x0f, 0x12, 0x06, 0x01, 0x19, 0x03, 0xea, 0xa3, 0x03, 0x02, 0x02, 0x1a, 0x00, 0x0d, 0x5f, 0xff, 0x01, 0x19, 0x03, 0xeb};


const uint8_t keyMappingCBORBuffer[] = {0xa2, 0x19, 0x03, 0xf5, 0x81, 0x19, 0x03, 0xf7, 0x19, 0x03, 0xf0, 0x81, 0x19, 0x03, 0xf3};

```

### Create a route 

To use coreconf with RIOT OS (with gcoap server), we need two data structures to be initialized and loaded at the start of this server- *coreconfModel* which is _CoreconfValueT\*_ struct pointer generated from *coreconfModelCBORBuffer*, and _keyMappingHashMap\*_ struct pointer generated from *keyMappingCBORBuffer*. Both the *uint8_t* buffers were generated using generateCBORDumps.py tool above. 

To implement a COAP_FETCH type of route, we need additional data structure to be built during runtime- *clookup*.

A complete example of COAP_FETCH implementation is shown with the route *_sid_handler* with comments in [server.c](https://github.com/manojgudi/RIOT/blob/coreconf-integration/examples/coreconf_simple/server.c) of the coreconf-simple RIOT application.

### Test


The coreconf model and key mapping both are already generated and stored in *coreconf_model_cbor.h* files for the [sensor.yang file](https://github.com/manojgudi/ccoreconf/blob/main/samples/simple_yang/sensor.yang) with [sensor_instance.json](https://github.com/manojgudi/ccoreconf/blob/main/samples/simple_yang/sensor_instance.json) and [sensor@unknown_numerical.sid](https://github.com/manojgudi/ccoreconf/blob/main/samples/simple_yang/sensor%40unknown_numerical.sid).

A simple COAP client is also included in [requestCBOR.py](https://github.com/manojgudi/RIOT/blob/coreconf-integration/examples/coreconf_simple/requestCBOR.py) file which has two request SID keys in its request payload-
*[1008, [1013, 2]]*

1. The client needs to get all the health readings leaves from the emebedded system, so it requests the subtree matching the SID = 1008.
2. The client needs data readings leaf where the readingIndex (SID=1015) has the value 2, so it creates an array *[1013, 2]* where 2 is the **sid key**.


The RIOT application can be build and emulated natively using the commands:
```sh
$ cd $RIOT_WORKING_DIR/examples/coreconf_simple/
$ CORECONF_SIMPLE_WORKING_DIR=`pwd`
$ make
$ make term
```

Assuming the tap0 interface has been setup correctly (required to acquire IPv6 for the emulated embedded system) as explained here in [gnrc_networking](https://github.com/RIOT-OS/RIOT/tree/master/examples/gnrc_networking), the client python application can be setup using a simple requirements.txt file:
```sh
$ cd $CORECONF_SIMPLE_WORKING_DIR/
$ pip install -r requirements.txt
$ python3 requestCBOR.py # DONT FORGET to put the correct IPV6 corresponding to the tap0 where the emulated device will attach.
```

You should see something like this as response (encoded in CBOR and in coreconf format):

```js
[{
    1008: [{1: 1002.0, 2: 987654.0, 3: 1.0},
           {1: 1003.0, 2: 876543.0, 3: 2.0}]
 },
 {
    1013: {1: 2048.0, 2: 2.0}
 }]
```

Where the first element of the CBOR response containing the subtree for the first request with SID = 1008. Similarly, the second element is the subtree obtained for SID 1013 with sid key = 2.

[Screenshot](https://drive.google.com/file/d/1wT39EmNiaNzCn6bviKYYM2mKM_p7XgnN/view?usp=sharing)