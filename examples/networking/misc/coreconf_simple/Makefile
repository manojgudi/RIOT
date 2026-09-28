# Default Makefile, for host native GNRC-based networking

# name of your application
APPLICATION = coreconf_simple

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../../../..

# Packages
USEPKG += ccoreconf

# Include packages that pull up and auto-init the link layer.
USEMODULE += netdev_default

# use GNRC by default
LWIP_IPV4 ?= 0
LWIP_IPV6 ?= 0

ifeq (,$(filter 1, $(LWIP_IPV4) $(LWIP_IPV6)))
  USEMODULE += auto_init_gnrc_netif
  # Specify the mandatory networking modules
  USEMODULE += gnrc_ipv6_default
  # Additional networking modules that can be dropped if not needed
  USEMODULE += gnrc_icmpv6_echo
else
  USEMODULE += lwip_netdev

  ifeq (1,$(LWIP_IPV4))
    USEMODULE += ipv4_addr

    USEMODULE += lwip_arp
    USEMODULE += lwip_ipv4
    USEMODULE += lwip_dhcp_auto
    CFLAGS += -DETHARP_SUPPORT_STATIC_ENTRIES=1
  endif

  ifeq (1,$(LWIP_IPV6))
    USEMODULE += ipv6_addr

    USEMODULE += lwip_ipv6
    USEMODULE += lwip_ipv6_autoconfig
  endif
endif

USEMODULE += gcoap

# Required by gcoap example
USEMODULE += od
USEMODULE += fmt
USEMODULE += netutils
USEMODULE += random

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# ZEP (IEEE 802.15.4 over UDP) is unused on native Ethernet; left for parity
# with the upstream example in case someone wants to experiment.
USE_ZEP ?= 0
ZEP_PORT_BASE ?= 17754
ifeq (1,$(USE_ZEP))
  USEMODULE += socket_zep
endif

include $(RIOTBASE)/Makefile.include

# Increase from default for confirmable block2 follow-on requests
ifndef CONFIG_KCONFIG_MODULE_GCOAP
GCOAP_RESEND_BUFS_MAX ?= 2
CFLAGS += -DCONFIG_GCOAP_RESEND_BUFS_MAX=$(GCOAP_RESEND_BUFS_MAX)
endif

# Boards without enough RAM/flash to host ccoreconf + nanocbor + gcoap.
BOARD_INSUFFICIENT_MEMORY := \
    arduino-duemilanove \
    arduino-leonardo \
    arduino-mega2560 \
    arduino-nano \
    arduino-uno \
    atmega328p \
    atmega328p-xplained-mini \
    atmega8 \
    atxmega-a3bu-xplained \
    bluepill-stm32f030c8 \
    i-nucleo-lrwan1 \
    msb-430 \
    msb-430h \
    nucleo-c031c6 \
    nucleo-f030r8 \
    nucleo-f031k6 \
    nucleo-f042k6 \
    nucleo-f303k8 \
    nucleo-f334r8 \
    nucleo-l011k4 \
    nucleo-l031k6 \
    nucleo-l053r8 \
    olimex-msp430-h1618 \
    samd10-xmini \
    saml10-xpro \
    saml11-xpro \
    slstk3400a \
    stk3200 \
    stm32f030f4-demo \
    stm32f0discovery \
    stm32f7508-dk \
    stm32g0316-disco \
    stm32l0538-disco \
    telosb \
    waspmote-pro \
    weact-g030f6 \
    z1 \
    #