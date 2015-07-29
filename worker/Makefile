include $(TOPDIR)/rules.mk

PKG_NAME:=worker
PKG_RELEASE:=0.1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/worker
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=WiWo -- Wireless Worker
	DEPENDS:=+libpcap
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/worker/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/worker $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/workermon $(1)/bin/
endef

$(eval $(call BuildPackage,worker))

