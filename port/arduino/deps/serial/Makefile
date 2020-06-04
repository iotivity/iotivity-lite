###iotivity contrained sources
include ../../setup.mk 

SRC=$(wildcard ./*.cpp) 

LOCAL_CPP_SRCS += $(SRC) 

ifeq ($(ARCH),avr)
	include ../../avr.mk
else ifeq ($(ARCH),sam)
	include ../../sam.mk
else ifeq ($(ARCH),samd)
	include ../../samd.mk
else
$(error Target Architecture must be define to proceed!)	
endif

build-$(BOARD_TAG)/libarduino-serial.a: $(LOCAL_OBJS)
	$(AR) rcs $@ $(LOCAL_OBJS)
	

