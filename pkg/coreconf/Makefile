PKG_NAME=coreconf
PKG_URL=https://github.com/manojgudi/ccoreconf
PKG_VERSION=551905f4495db697f6852bb6e9bb6039ef8259bc
PKG_LICENSE=GPL-v3.0

USEPKG+=nanocbor

include $(RIOTBASE)/pkg/pkg.mk

all:
	+$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(RIOTBASE)/Makefile.base MODULE=$(PKG_NAME)

