BOARD ?= qemu_x86

ifeq ($(SECURE),1)
CONF_FILE = prj_secure.conf
else
CONF_FILE = prj.conf
endif

include ${ZEPHYR_BASE}/Makefile.inc
include $(ZEPHYR_BASE)/samples/net/common/Makefile.ipstack
