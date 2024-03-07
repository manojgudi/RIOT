PKG_NAME=coreconf
PKG_URL=https://github.com/manojgudi/ccoreconf
PKG_VERSION=e8485afddffbf5c6cdb52a91f1f20360c5d14ad1
PKG_LICENSE=GPL-v3.0

USEPKG+=nanocbor

include $(RIOTBASE)/pkg/pkg.mk

all:
	+$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(RIOTBASE)/Makefile.base MODULE=$(PKG_NAME)

