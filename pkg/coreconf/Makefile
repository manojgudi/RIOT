PKG_NAME=coreconf
PKG_URL=https://github.com/manojgudi/ccoreconf
PKG_VERSION=714be2e79051c93c7f5470fa1daae6ab0c7ae123
PKG_LICENSE=GPL-v3.0

USEPKG+=nanocbor

include $(RIOTBASE)/pkg/pkg.mk

all:
	+$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(RIOTBASE)/Makefile.base MODULE=$(PKG_NAME)

