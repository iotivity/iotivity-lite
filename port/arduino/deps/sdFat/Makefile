###iotivity contrained sources
include ../../setup.mk 

SRC=$(wildcard ./*.cpp) 

LOCAL_CPP_SRCS += $(SRC) 
CORE_HEADERS      +=-I$(ARDUINO_DIR)/libraries/SdFat/src/FatLib

CXXFLAGS += $(CORE_HEADERS)

ifeq ($(ARCH),avr)
	include ../../avr.mk
else ifeq ($(ARCH),sam)
	include ../../sam.mk
else ifeq ($(ARCH),samd)
	include ../../samd.mk
else
$(error Target Architecture must be define to proceed!)	
endif

build-$(BOARD_TAG)/libarduino-sdfat.a: $(LOCAL_OBJS)
	$(AR) rcs $@ $(LOCAL_OBJS)
	

