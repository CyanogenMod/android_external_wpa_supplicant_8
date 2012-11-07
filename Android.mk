ifndef WPA_SUPPLICANT_VERSION
WPA_SUPPLICANT_VERSION := VER_0_8_X
endif
ifeq ($(WPA_SUPPLICANT_VERSION),VER_0_8_X)
    include $(call all-subdir-makefiles)
endif
