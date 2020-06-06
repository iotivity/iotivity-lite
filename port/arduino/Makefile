include setup.mk

ROOT_DIR =../..

ifneq ($(ARCH),avr)
ifneq ($(ARCH),samd)
ifneq ($(ARCH),sam)
$(error Target Architecture must be define to proceed!)
endif
endif
endif

ifeq ($(APP),server)
  LOCAL_CPP_SRCS 	+= server_arduino.cpp
  CXXFLAGS 	+= -DOC_SERVER
  TARGET = $(ARCH)_server
ifeq ($(XMEM),1)
  CXXFLAGS 		    += -DOC_XMEM
endif
else ifeq ($(APP),client)
  CXXFLAGS 	+= -DOC_CLIENT
ifeq ($(XMEM),1)
  CXXFLAGS 	+= -DOC_XMEM
endif
  LOCAL_CPP_SRCS 	+= client_arduino.cpp
  TARGET = $ARCH_client
else
$(error Must define an app server/client to proceed!)
endif

ifeq ($(DYNAMIC),1)
	CXXFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifeq ($(XMEM),1)
	CXXFLAGS += -DOC_XMEM
endif

ifeq ($(IPV4),1)
	CXXFLAGS += -DOC_IPV4
endif


### Iotivity contrained includes
ifeq ($(ARCH),avr)
	DEPS_HEADERS +=$(addprefix -Ideps/, pRNG wiz5500 serial sdFat)
else
	DEPS_HEADERS +=$(addprefix -Ideps/, wiz5500 serial sdFat)
endif
CORE_HEADERS +=$(addprefix -I$(ROOT_DIR)/, . messaging/coap util util/pt include  api port security deps/mbedtls/include/mbedtls)
LIB_HEADERS  +=-I$(ARDUINO_DIR)/libraries/SdFat/src/FatLib
CXXFLAGS += $(DEPS_HEADERS) $(CORE_HEADERS) $(LIB_HEADERS) -Iadapter -Iapps/include

ifeq ($(NO_MAIN),1)
	CXXFLAGS += -DNO_MAIN
endif

ifeq ($(SECURE),1)
	CXXFLAGS	+=$(addprefix -I$(ROOT_DIR)/deps/mbedtls/, include include/mbedtls)
	CXXFLAGS	+= -DOC_SECURITY
endif

SERVER_ARCHIVE 	= build-$(BOARD_TAG)/libarduino-adapter.a
TIME_ARCHIVE 	= build-$(BOARD_TAG)/libarduino-time.a
WIZ5500_ARCHIVE = build-$(BOARD_TAG)/libarduino-wiz5500.a
SERIAL_ARCHIVE 	= build-$(BOARD_TAG)/libarduino-serial.a
SDFAT_ARCHIVE 	= build-$(BOARD_TAG)/libarduino-sdfat.a

DEPS_OBJ += $(TIME_ARCHIVE) $(WIZ5500_ARCHIVE) $(SDFAT_ARCHIVE) $(SERIAL_ARCHIVE)

ifeq ($(ARCH),avr)
	PRNG_ARCHIVE 	= build-$(BOARD_TAG)/libarduino-prng.a
endif
DEPS_OBJ += $(PRNG_ARCHIVE)

SERVER_OBJ     = adapter/build-$(BOARD_TAG)/libarduino-adapter.a
OTHER_OBJS    += $(SERVER_OBJ)

ifeq ($(ARCH),avr)
OTHER_OBJS 		+= deps/pRNG/$(PRNG_ARCHIVE)
endif
OTHER_OBJS 		+= deps/Time/$(TIME_ARCHIVE)
OTHER_OBJS 		+= deps/wiz5500/$(WIZ5500_ARCHIVE)
OTHER_OBJS 		+= deps/serial/$(SERIAL_ARCHIVE)
OTHER_OBJS 		+= deps/sdFat/$(SDFAT_ARCHIVE)

VPATH=apps/server:$(ROOT_DIR)/apps:

ifeq ($(ARCH),avr)
	include avr.mk

else ifeq ($(ARCH),sam)
	include sam.mk

else ifeq ($(ARCH),samd)
	include samd.mk
else
$(error Target Architecture must be define to proceed!)
endif


$(SERVER_OBJ): $(DEPS_OBJ)
	$(MAKE) -C adapter $(SERVER_ARCHIVE)

$(PRNG_ARCHIVE):
	$(MAKE) -C deps/pRNG $@

$(TIME_ARCHIVE):
	$(MAKE) -C deps/Time  $@

$(WIZ5500_ARCHIVE):
	$(MAKE) -C deps/wiz5500 $@

$(SERIAL_ARCHIVE) :
	$(MAKE) -C deps/serial $@

$(SDFAT_ARCHIVE):
	$(MAKE) -C deps/sdFat $@

clean::
	$(MAKE) -C adapter clean
ifeq ($(ARCH),avr)
	$(MAKE) -C deps/pRNG clean
endif
	$(MAKE) -C deps/Time clean
	$(MAKE) -C deps/wiz5500 clean
	$(MAKE) -C deps/serial clean
	$(MAKE) -C deps/sdFat clean
