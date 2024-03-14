PKG_NAME=coreconf
PKG_URL=https://github.com/manojgudi/ccoreconf
PKG_VERSION=d76dbae4a60f4a2cd753aa2b92526f3a34b3c436
PKG_LICENSE=GPL-v3.0

USEPKG+=nanocbor

include $(RIOTBASE)/pkg/pkg.mk

all:
	+$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(RIOTBASE)/Makefile.base MODULE=$(PKG_NAME)

