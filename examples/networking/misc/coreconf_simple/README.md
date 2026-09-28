# coreconf_simple

A RIOT application that exposes a CORECONF data tree via [gcoap][1]. The
core data model comes from `coreconf_model_cbor.h` (a CBOR dump of a
sensor YANG instance). Clients fetch sub-trees from the device by sending
a CoAP `FETCH /sid` with a CBOR payload listing the SIDs (and optional
list-keys) they want.

The CORECONF processing itself is provided by the `ccoreconf` package.

[1]: https://doc.riot-os.org/group__net__gcoap.html

## Architecture

- `main.c` — boots RIOT, runs `server_init()`, then drops into the gcoap
  shell.
- `server.c` — registers three CoAP resources:
  - `GET|PUT|FETCH /cli/stats` — trivial counter (from the gcoap example).
  - `GET /riot/board` — returns the RIOT board name.
  - `FETCH /sid` — accepts a CBOR array `[<sid> | [<sid>, keys...], ...]`,
    looks up the requested sub-trees in the loaded CoreconfModel, and
    returns them as a CBOR array.
- `coreconf_model_cbor.h` — pre-generated CBOR buffers
  (`coreconfModelCBORBuffer`, `keyMappingCBORBuffer`) and the size macros
  the server uses.
- `requestCBOR.py` — a small `aiocoap` client that POSTs the
  `[1008, [1013, 2]]` query and pretty-prints the CBOR response.
- `startap.sh` — creates the `tap0` interface the RIOT `native` board
  attaches to.

## Build & run (emulated RIOT native)

```sh
cd examples/networking/misc/coreconf_simple
# First-time only: set up tap0 so the emulated device gets an IPv6 link-local.
sudo ./startap.sh
# Build (PKG_SOURCE_LOCAL_CCORECONF points RIOT's pkg system at our local
# ccoreconf checkout so we don't depend on the network during dev):
PKG_SOURCE_LOCAL_CCORECONF=$HOME/projects/ccoreconf make BOARD=native
./bin/native/coreconf_simple.elf
```

You should see (among the RIOT boot banner):

```
gcoap example app
All up, running the shell now
```

## Send a request

In another terminal, with `tap0` already up:

```sh
cd examples/networking/misc/coreconf_simple
pip install -r requirements.txt   # aiocoap, cbor2
# Use the link-local that RIOT printed on startup, e.g.
python3 requestCBOR.py
# Edit the URI inside requestCBOR.py if your fe80:: differs.
```

The client sends a CoAP FETCH to `/sid` with the CBOR payload
`[1008, [1013, 2]]`. The server looks up SID `1008` (the first element)
and SID `1013` with list-key `2` (the second element), encodes the
resulting sub-trees, and returns them as a CBOR array. See the source
and the upstream README for the exact protocol mapping.

## Files

| File                   | Purpose                                         |
|------------------------|-------------------------------------------------|
| `Makefile`             | Build rules (USEMODULE/USEPKG)                  |
| `main.c`               | Entry point; runs `server_init()`               |
| `server.c`             | gcoap resources and the `/sid` handler          |
| `gcoap_example.h`      | Shared declarations (`server_init`, `req_count`)|
| `coreconf_model_cbor.h`| CBOR buffers for the model + key mapping        |
| `requestCBOR.py`       | Reference aiocoap client                        |
| `requirements.txt`     | aiocoap, cbor2                                  |
| `startap.sh`           | `sudo ip tuntap add tap0 ...`                   |
| `Makefile.slip`        | (unused on native; for SAMR21 6LoWPAN setups)   |
| `Makefile.ci`          | (unused; CI-board blacklist)                    |
| `README-gcoap.md`      | Inherited from the gcoap example                |
| `README-slip.md`       | Inherited from the gcoap example                |