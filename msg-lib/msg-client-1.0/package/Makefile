#
# Copyright (C) 2013-2016 
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=msg_client
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/msg_client
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=msg_client
  DEPENDS:= +libmsg +libpthread
endef

define Package/msg_client/description
	cominucate as a client in linux
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		INS="-I$(STAGING_DIR)/usr/include/msg/" \
		LIBS="-lmsg -lpthread" \
		LDFLAGS="$(EXTRA_LDFLAGS)" \
		CXXFLAGS="$(TARGET_CFLAGS) $(EXTRA_CPPFLAGS)" \
		$(TARGET_CONFIGURE_OPTS) \
		CROSS="$(TARGET_CROSS)" \
		ARCH="$(ARCH)" \
		$(1);
endef

define Package/msg_client/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/msg_client $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,msg_client))
