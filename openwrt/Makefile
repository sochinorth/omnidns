#
# OpenWrt package for omnidns.
#
# Use from an SDK/buildroot by symlinking this directory:
#   ln -s /path/to/omnidns/openwrt package/omnidns
#   make package/omnidns/compile V=s
# The source tree is taken from the parent directory of this Makefile.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=omnidns
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

OMNIDNS_SRC:=$(realpath $(CURDIR))/..

define Package/omnidns
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=Policy-aware DNS proxy with fake-IP policy routing
  DEPENDS:=+libubox +libuci +libmnl +libnftnl \
	+kmod-nft-core +kmod-nft-nat
endef

define Package/omnidns/description
  omnidns answers LAN DNS clients, evaluates every name (and every alias in
  the resolution chain) against an ordered ruleset, and either blocks,
  forwards to rule-specific upstreams, or answers with synthesized fake IPs
  that nftables translates back to the real address while applying an fwmark
  for policy routing.
endef

define Package/omnidns/conffiles
/etc/config/omnidns
/etc/omnidns.d/
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(OMNIDNS_SRC)/CMakeLists.txt $(OMNIDNS_SRC)/src $(PKG_BUILD_DIR)/
endef

define Package/omnidns/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config $(1)/etc/omnidns.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/omnidns $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/omnidns.init $(1)/etc/init.d/omnidns
	$(INSTALL_CONF) ./files/omnidns.config $(1)/etc/config/omnidns
	$(INSTALL_DATA) ./files/omnidns.d/* $(1)/etc/omnidns.d/
endef

$(eval $(call BuildPackage,omnidns))
