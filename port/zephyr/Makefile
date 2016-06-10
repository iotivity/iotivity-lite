KERNEL_TYPE = nano
BOARD ?= qemu_x86
CONF_FILE = prj.conf

QEMU_EXTRA_FLAGS=-serial none -serial unix:/tmp/slip.sock

include ${ZEPHYR_BASE}/Makefile.inc
include $(ZEPHYR_BASE)/samples/net/common/Makefile.ipstack

