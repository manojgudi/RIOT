PKG_NAME    = ccoreconf
PKG_URL     = https://github.com/manojgudi/ccoreconf
PKG_VERSION = db3de906186cb37ba2f31a9a0ec5c4a4e01df6b9
PKG_LICENSE = MIT

include $(RIOTBASE)/pkg/pkg.mk

# Pre-included header that rewrites ccoreconf's
# `nanocbor_leave_container()` call sites to an int-returning shim. The
# matching implementation lives in `nanocbor_compat.c` which is dropped
# into $(PKG_SOURCE_DIR)/src/ before the build runs.  Appended to (not
# replacing) CFLAGS, so the board's CPU flags still apply.
CFLAGS += -include $(PKG_DIR)/include/nanocbor_compat.h

all: $(PKG_SOURCE_DIR)/src/nanocbor_compat.c
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(RIOTBASE)/Makefile.base MODULE=$(PKG_NAME)

# The compat shim doesn't belong to upstream ccoreconf, so we copy it into
# the build source tree at build time. `git clean -xdff` during pkg-prepare
# would otherwise drop it; re-copying here keeps both clean and
# incremental builds working.
$(PKG_SOURCE_DIR)/src/nanocbor_compat.c: $(PKG_DIR)/nanocbor_compat.c
	$(Q)cp $< $@