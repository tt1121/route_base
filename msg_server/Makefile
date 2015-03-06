include $(TOPDIR)/rules.mk

PKG_NAME:=msg_server
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/msg_server
  SECTION:=net
  CATEGORY:=Base system
  TITLE:=msg_server
  DEPENDS:=+libjson-c +libuci +libmsg +libper_auth +libcurl +libudev +msg-lib +libspeedtest +libpthread +libwizard +liblogic
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += \
        -I$(STAGING_DIR)/usr/include/json-c/ \
	-I$(STAGING_DIR)/usr/include/curl/ \
        -I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += -L$(STAGING_DIR)/lib -ludev -L$(STAGING_DIR)/usr/lib -lmsg -ljson-c -lper_auth -ljson-c -limove -lcurl -lpthread -lspeedtest -lwizard -luci -llogic

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
	CC="$(TARGET_CC)" \
	CFLAGS="$(TARGET_CFLAGS)" \
	LDFLAGS="$(TARGET_LDFLAGS)" \
	all
endef

define Package/msg_server/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/msg_server $(1)/usr/sbin
endef

$(eval $(call BuildPackage,msg_server))
