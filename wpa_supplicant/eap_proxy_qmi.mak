CFLAGS += -DSIM_AKA_IDENTITY_IMSI
CFLAGS += -DSIM_AKA_IMSI_RAW_ENABLED

CFLAGS += $(shell $(PKG_CONFIG) --cflags qmi qmi-framework)

LIBS += $(shell $(PKG_CONFIG) --libs qmi qmi-framework) -lpthread

# EAP-AKA' (enable CONFIG_PCSC, if EAP-AKA' is used).
# This requires CONFIG_EAP_AKA to be enabled, too.
# This is supported only in B Family devices.
CONFIG_EAP_AKA_PRIME=y

ifdef CONFIG_EAP_PROXY_AKA_PRIME
CFLAGS += -DCONFIG_EAP_PROXY_AKA_PRIME
endif

ifdef CONFIG_EAP_PROXY_DUAL_SIM
CFLAGS += -DCONFIG_EAP_PROXY_DUAL_SIM
endif
