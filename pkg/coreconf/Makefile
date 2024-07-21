PKG_NAME=coreconf
PKG_URL=https://github.com/manojgudi/ccoreconf
PKG_VERSION=8df369da477b4c86fba01ca11f3e703282ef3aab
PKG_LICENSE=GPL-v3.0

USEPKG+=nanocbor

include $(RIOTBASE)/pkg/pkg.mk

all:
	+$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(RIOTBASE)/Makefile.base MODULE=$(PKG_NAME)

