CFLAGS += -DSIM_AKA_IDENTITY_IMSI
CFLAGS += -DSIM_AKA_IMSI_RAW_ENABLED

CFLAGS += $(shell $(PKG_CONFIG) --cflags qmi)

LIBS += $(shell $(PKG_CONFIG) --libs qmi)

# EAP-AKA' (enable CONFIG_PCSC, if EAP-AKA' is used).
# This requires CONFIG_EAP_AKA to be enabled, too.
# This is supported only in B Family devices.
CONFIG_EAP_AKA_PRIME=y

