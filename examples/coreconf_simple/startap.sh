#!/bin/bash
sudo ip tuntap add tap0 mode tap user ${USER}
sudo ip link set tap0 up
