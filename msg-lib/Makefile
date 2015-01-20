#
# Copyright (C) 2006-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=msg
PKG_VERSION:=0.1.0.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/libmsg
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=A message communicat library
endef

define Package/libmsg/description
 MSG is a message communicat library for OpenRouter APP.
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/msg.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/libmsg.so $(1)/usr/lib/
endef

define Package/libmsg/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libmsg.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libmsg))
