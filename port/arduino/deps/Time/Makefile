include ../../setup.mk

ARDUINO_TIME_SRC  = $(wildcard $(ARDUINO_DIR)/libraries/Time/*.cpp)

LOCAL_CPP_SRCS += $(ARDUINO_TIME_SRC)
VPATH=$(ARDUINO_DIR)/libraries/Time:

ifeq ($(ARCH),avr)
	include ../../avr.mk
else ifeq ($(ARCH),sam)
	include ../../sam.mk
else ifeq ($(ARCH),samd)
	include ../../samd.mk
else
$(error Target Architecture must be define to proceed!)
endif

build-$(BOARD_TAG)/libarduino-time.a: $(LOCAL_OBJS)
	$(AR) rcs $@ $(LOCAL_OBJS)

