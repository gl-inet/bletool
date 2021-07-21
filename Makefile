 ###################################################################
 # Copyright 2020 GL-iNet. https://www.gl-inet.com/
 # 
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 # http://www.apache.org/licenses/LICENSE-2.0
 # 
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
 ####################################################################
include $(TOPDIR)/rules.mk

PKG_NAME:=gl-bletool
PKG_VERSION:=0.0.6


include $(INCLUDE_DIR)/package.mk

define Package/gl-bletool
	SECTION:=base
	CATEGORY:=gl-inet
	TITLE:=GL inet BLE driver(debug only)
	DEPENDS:=  +libjson-c +libuci +libpthread +libreadline +libncurses +libuci
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/gl
	$(CP) $(PKG_BUILD_DIR)/lib/gl_bleapi.h $(1)/usr/include/gl
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/exe/libglbleapi.so $(1)/usr/lib/
endef

define Package/gl-bletool/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/exe/bletool $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/include/gl
	$(CP) $(PKG_BUILD_DIR)/lib/gl_bleapi.h $(1)/usr/include/gl
	$(INSTALL_DIR) $(1)/usr/lib/gl
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/exe/libglbleapi.so $(1)/usr/lib/gl
	$(LN) /usr/lib/gl/libglbleapi.so $(1)/usr/lib/
	# $(INSTALL_DIR) $(1)/etc/init.d
	# $(INSTALL_BIN) ./files/gl_bletool.init $(1)/etc/init.d/bledaemon
endef
$(eval $(call BuildPackage,gl-bletool))
