obj-m += rdkfmac.o
rdkfmac-objs += \
	rdkfmac_netdev.o \
	rdkfmac_mac80211.o \
	rdkfmac_cdev.o \
	rdkfmac_bus.o \
	rdkfmac_cmd.o \
	rdkfmac_cfg80211.o \
	status.o \
	scan.o \
	util.o \
	chan.o \
	mlme.o trace.o \
	tx.o \
	sta_info.o \
	iface.o \
	driver-ops.o \
	rate.o \
	key.o \
	aes_cmac.o \
	aes_gmac.o \
	wep.o \
	fils_aead.o \
	wpa.o \
	tkip.o\
	wme.o \
	aead_api.o \
	michael.o \
	rx.o \
	ibss.o \
	ht.o agg-tx.o agg-rx.o \
	vht.o \
	he.o \
	tdls.o \
	offchannel.o \
	ocb.o \
	spectmgmt.o \
	pm.o \
	status.o \
	ethtool.o \
	airtime.o

rdkfmac-$(CONFIG_MAC80211_LEDS) += led.o

rdkfmac-$(CONFIG_MAC80211_MESH) += \
	mesh.o \
	mesh_pathtbl.o \
	mesh_plink.o \
	mesh_hwmp.o \
	mesh_sync.o \
	mesh_ps.o

CFLAGS_tx.o := -Wno-unused-function
