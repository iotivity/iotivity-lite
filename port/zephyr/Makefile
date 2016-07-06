KERNEL_TYPE = nano
BOARD ?= qemu_x86

ifeq ($(SECURE),1)
CONF_FILE = prj_secure.conf
else
CONF_FILE = prj.conf
endif

QEMU_EXTRA_FLAGS=-serial none -serial unix:/tmp/slip.sock

include ${ZEPHYR_BASE}/Makefile.inc
include $(ZEPHYR_BASE)/samples/net/common/Makefile.ipstack

