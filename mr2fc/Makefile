#
# Copyright (C) 2013-2016 
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mr2fc
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/mr2fc
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=mr2fc
  DEPENDS:= +libmsg +libpthread +libevent2 +libjson-c +libopenssl +libgcrypt +libcurl +libshm +libper_auth +libuci
endef

define Package/mr2fc/description
	message recieve and forward center
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		INS="-I$(STAGING_DIR)/usr/include/ -I$(STAGING_DIR)/usr/include/json-c/" \
		LIBS="-lmsg -lpthread -levent -ljson-c -lssl -lcrypto -lcurl -lper_auth -lshm -luci" \
		LDFLAGS="$(EXTRA_LDFLAGS)" \
		CXXFLAGS="$(TARGET_CFLAGS) $(EXTRA_CPPFLAGS)" \
		$(TARGET_CONFIGURE_OPTS) \
		CROSS="$(TARGET_CROSS)" \
		ARCH="$(ARCH)" \
		$(1);
endef

define Package/mr2fc/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mr2fc $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,mr2fc))
