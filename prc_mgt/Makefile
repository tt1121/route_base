#
# Copyright (C) 2013-2016 
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=prc_mgt
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/prc_mgt
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Application process management
  MAINTAINER:=LiShengming <lishengming@i-move.cn>
  DEPENDS:= +libmsg +libjson-c +libpthread +libshm +libper_auth +libuci
endef

define Package/prc_mgt/description
	manage process in system
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		INS="-I$(STAGING_DIR)/usr/include/ -I$(STAGING_DIR)/usr/include/json-c/" \
		LIBS="-lmsg -lpthread -lshm -ljson-c -lper_auth -luci" \
		LDFLAGS="$(EXTRA_LDFLAGS)" \
		CXXFLAGS="$(TARGET_CFLAGS) $(EXTRA_CPPFLAGS)" \
		$(TARGET_CONFIGURE_OPTS) \
		CROSS="$(TARGET_CROSS)" \
		ARCH="$(ARCH)" \
		$(1);
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/prc_mgt.h $(1)/usr/include/
endef

define Package/prc_mgt/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/prc_mgt $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/prc_mgt
	$(INSTALL_DATA) ./files/mr2fc.info $(1)/usr/prc_mgt/mr2fc
	$(INSTALL_DATA) ./files/msg_server.info $(1)/usr/prc_mgt/msg_server
	$(INSTALL_DATA) ./files/prcs_boot_list.info $(1)/usr/prc_mgt/prcs_boot_list
endef

$(eval $(call BuildPackage,prc_mgt))
