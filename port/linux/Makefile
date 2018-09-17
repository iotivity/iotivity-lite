CC = gcc
SED = sed
INSTALL = install
OS = linux
ROOT_DIR = ../..
OUT_DIR = $(ROOT_DIR)/port/$(OS)
CHECK_SCRIPT = ../../tools/check.py
VERSION_MAJOR = 1
VERSION_MINOR = 0
VERSION = $(VERSION_MAJOR).$(VERSION_MINOR)
ARCH := $(shell arch)

DESTDIR ?= /usr/local
install_bin_dir?=${DESTDIR}/opt/iotivity-constrained/bin/
prefix = $(DESTDIR)
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
pkgconfigdir = $(libdir)/pkgconfig
EXTRA_CFLAGS =

MBEDTLS_DIR := $(ROOT_DIR)/deps/mbedtls
GTEST_DIR = $(ROOT_DIR)/deps/gtest
GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h
GTEST = gtest_build
GTEST_CPPFLAGS += -isystem $(GTEST_DIR)/include
TEST_CXXFLAGS += -g -Wall -Wextra -pthread -std=c++0x -fpermissive -DOC_SERVER -DOC_CLIENT -fprofile-arcs -ftest-coverage
HEADER_DIR = -I$(ROOT_DIR)/include \
             -I$(ROOT_DIR) \
             -I$(OUT_DIR)
SECURITY_HEADERS = -I$(ROOT_DIR)/security \
                   -I$(MBEDTLS_DIR)/include
MESSAGING_HEADERS = -I$(ROOT_DIR)/messaging/coap
API_TEST_DIR = $(ROOT_DIR)/api/unittest
API_TEST_OBJ_DIR = $(API_TEST_DIR)/obj
API_TEST_SRC_FILES := $(wildcard $(API_TEST_DIR)/*.cpp)
API_TEST_OBJ_FILES := $(patsubst $(API_TEST_DIR)/%.cpp,$(API_TEST_OBJ_DIR)/%.o,$(API_TEST_SRC_FILES))

SECURITY_TEST_DIR = $(ROOT_DIR)/security/unittest
SECURITY_TEST_OBJ_DIR = $(SECURITY_TEST_DIR)/obj
SECURITY_TEST_SRC_FILES := $(wildcard $(SECURITY_TEST_DIR)/*.cpp)
SECURITY_TEST_OBJ_FILES := $(patsubst $(SECURITY_TEST_DIR)/%.cpp,$(SECURITY_TEST_OBJ_DIR)/%.o,$(SECURITY_TEST_SRC_FILES))

SECURITY_V2_TEST_DIR = $(ROOT_DIR)/security/unittest
SECURITY_V2_TEST_OBJ_DIR = $(SECURITY_V2_TEST_DIR)/obj_v2
SECURITY_V2_TEST_SRC_FILES := $(wildcard $(SECURITY_V2_TEST_DIR)/*.cpp)
SECURITY_V2_TEST_OBJ_FILES := $(patsubst $(SECURITY_V2_TEST_DIR)/%.cpp,$(SECURITY_V2_TEST_OBJ_DIR)/%.o,$(SECURITY_V2_TEST_SRC_FILES))

PLATFORM_TEST_DIR = $(ROOT_DIR)/port/unittest
PLATFORM_TEST_OBJ_DIR = $(PLATFORM_TEST_DIR)/obj
PLATFORM_TEST_SRC_FILES := $(wildcard $(PLATFORM_TEST_DIR)/*.cpp)
PLATFORM_TEST_OBJ_FILES := $(patsubst $(PLATFORM_TEST_DIR)/%.cpp,$(PLATFORM_TEST_OBJ_DIR)/%.o,$(PLATFORM_TEST_SRC_FILES))
STORAGE_TEST_DIR = storage_test
$(shell mkdir -p $(STORAGE_TEST_DIR))

MESSAGING_TEST_DIR = $(ROOT_DIR)/messaging/coap/unittest
MESSAGING_TEST_OBJ_DIR = $(MESSAGING_TEST_DIR)/obj
MESSAGING_TEST_SRC_FILES := $(wildcard $(MESSAGING_TEST_DIR)/*.cpp)
MESSAGING_TEST_OBJ_FILES := $(patsubst $(MESSAGING_TEST_DIR)/%.cpp,$(MESSAGING_TEST_OBJ_DIR)/%.o,$(MESSAGING_TEST_SRC_FILES))

EASYSETUP_TEST_DIR = $(ROOT_DIR)/service/easy-setup/unittest
EASYSETUP_TEST_OBJ_DIR = $(EASYSETUP_TEST_DIR)/obj
EASYSETUP_TEST_SRC_FILES := $(wildcard $(EASYSETUP_TEST_DIR)/*.cpp)
EASYSETUP_TEST_OBJ_FILES := $(patsubst $(EASYSETUP_TEST_DIR)/%.cpp,$(EASYSETUP_TEST_OBJ_DIR)/%.o,$(EASYSETUP_TEST_SRC_FILES))

CA_TEST_DIR = $(ROOT_DIR)/service/cloud-access/unittest
CA_TEST_OBJ_DIR = $(CA_TEST_DIR)/obj
CA_TEST_SRC_FILES := $(wildcard $(CA_TEST_DIR)/*.cpp)
CA_TEST_OBJ_FILES := $(patsubst $(CA_TEST_DIR)/%.cpp,$(CA_TEST_OBJ_DIR)/%.o,$(CA_TEST_SRC_FILES))

RD_CLIENT_TEST_DIR = $(ROOT_DIR)/service/resource-directory/client/unittest
RD_CLIENT_TEST_OBJ_DIR = $(RD_CLIENT_TEST_DIR)/obj
RD_CLIENT_TEST_SRC_FILES := $(wildcard $(RD_CLIENT_TEST_DIR)/*.cpp)
RD_CLIENT_TEST_OBJ_FILES := $(patsubst $(RD_CLIENT_TEST_DIR)/%.cpp,$(RD_CLIENT_TEST_OBJ_DIR)/%.o,$(RD_CLIENT_TEST_SRC_FILES))

FOTA_TEST_DIR = $(ROOT_DIR)/service/fota/unittest
FOTA_TEST_OBJ_DIR = $(FOTA_TEST_DIR)/obj
FOTA_TEST_SRC_FILES := $(wildcard $(FOTA_TEST_DIR)/*.cpp)
FOTA_TEST_OBJ_FILES := $(patsubst $(FOTA_TEST_DIR)/%.cpp,$(FOTA_TEST_OBJ_DIR)/%.o,$(FOTA_TEST_SRC_FILES))

UNIT_TESTS = apitest platformtest messagingtest cloudaccesstest rdclienttest fotatest

ifeq ($(EASYSETUP),1)
UNIT_TESTS += easysetuptest
endif

DTLS_TAG ?= mbedtls-2.7.0
DTLS= 	aes.c		aesni.c 	asn1parse.c	asn1write.c	base64.c	\
	bignum.c	ccm.c		cipher.c	cipher_wrap.c	\
	cmac.c		ctr_drbg.c	des.c		dhm.c		ecdh.c		ecdsa.c		\
	ecjpake.c	ecp.c		ecp_curves.c	entropy.c	entropy_poll.c	error.c		\
	gcm.c		havege.c	hmac_drbg.c	md.c		md2.c		md4.c		\
	md5.c		md_wrap.c	oid.c		padlock.c	\
	pem.c		pk.c		pk_wrap.c	pkcs12.c	pkcs5.c		pkparse.c	\
	pkwrite.c	platform.c	ripemd160.c	sha1.c		sha256.c	\
	sha512.c	threading.c	timing.c	version.c	version_features.c		\
	xtea.c  	pkcs11.c 	x509.c 		x509_crt.c	debug.c		net_sockets.c	\
	ssl_cache.c	ssl_ciphersuites.c		ssl_cli.c	ssl_cookie.c			\
	ssl_srv.c	ssl_ticket.c	ssl_tls.c

ifneq ($(CODE_SIZE_OPT),1)
DTLS += arc4.c blowfish.c camellia.c rsa.c rsa_internal.c
endif
DTLSFLAGS=-I../../deps/mbedtls/include -D__OC_RANDOM

CBOR=../../deps/tinycbor/src/cborencoder.c ../../deps/tinycbor/src/cborencoder_close_container_checked.c ../../deps/tinycbor/src/cborparser.c# ../../deps/tinycbor/src/cbortojson.c ../../deps/tinycbor/src/cborpretty.c ../../deps/tinycbor/src/cborparser_dup_string.c


SRC_COMMON=$(wildcard ../../util/*.c) ${CBOR}
SRC=$(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/linux/*.c)
SRC_CA=$(wildcard ../../service/cloud-access/src/*.c)
SRC_RD_CLIENT=$(wildcard ../../service/resource-directory/client/src/*.c)
SRC_FOTA=$(wildcard ../../service/fota/src/*.c)

ifeq ($(CODE_SIZE_OPT),1)
SRC +=../../port/oc_log.c
endif

HEADERS = $(wildcard ../../include/*.h)
HEADERS += ../../port/linux/config.h

HEADERS_COAP = $(wildcard ../../messaging/coap/*.h)
HEADERS_UTIL = $(wildcard ../../util/*.h)
HEADERS_UTIL_PT = $(wildcard ../../util/pt/*.h)
HEADERS_PORT = $(wildcard ../../port/*.h)
HEADERS_TINYCBOR = $(wildcard ../../deps/tinycbor/src/*.h)

CFLAGS=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../ -I../../ -I../../include/ -std=gnu99 -Wall -Wextra #-Wl,-Map,client.map
CFLAGS_CA=-I../../service/cloud-access/include
CFLAGS_RD_CLIENT=-I../../service/resource-directory/client/include
CFLAGS_FOTA=-I../../service/fota/include
OBJ_COMMON=$(addprefix obj/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix obj/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix obj/server/,$(filter-out oc_obt.o,$(notdir $(SRC:.c=.o))))
OBJ_CLIENT_SERVER=$(addprefix obj/client_server/,$(notdir $(SRC:.c=.o)))
OBJ_CA=$(addprefix obj/ca/,$(notdir $(SRC_CA:.c=.o)))
OBJ_RD_CLIENT=$(addprefix obj/rd_client/,$(notdir $(SRC_RD_CLIENT:.c=.o)))
OBJ_FOTA=$(addprefix obj/fota/,$(notdir $(SRC_FOTA:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../port/:../../deps/tinycbor/src/:../../deps/mbedtls/library:../../service/easy-setup/enrollee/:../../service/easy-setup/enrollee/samsung/:../../service/cloud-access/src/:../../service/resource-directory/client/src/:../../service/fota/src/:../../service/st-app-fw/src/:../../service/st-app-fw/src/port/linux:
LIBS?= -lm -pthread -lrt

SAMPLES = server simpleserver \
	  server_collections_linux smart_home_server_linux multi_device_server

ifneq ($(CODE_SIZE_OPT),1)
SAMPLES += server_block_linux client simpleclient temp_sensor cloud_linux client_collections_linux client_block_linux multi_device_client smart_lock client_multithread_linux server_multithread_linux
ifeq ($(MFG),1)
CFLAGS += -DOC_MFG
SAMPLES += mfg_server
endif
endif

ifeq ($(EASYSETUP),1)
SAMPLES += easysetup_linux sc_easysetup_linux
endif

ifeq ($(ST_APP_FW),1)
ifneq ($(EASYSETUP),1)
$(error To use ST_APP_FW you should include EASYSETUP flag also.)
endif
SAMPLES += st_things
endif

ifeq ($(CATOOL),1)
CFLAGS += -DOC_MFG -DOC_CRED_TOOL
SAMPLES = mfg_server add_ca_tool
endif

ifeq ($(SECURE),1)

# AUTH_OPTION = 0   - root ca check is disabled for any TLS connection
# AUTH_OPTION = 1   - preload manufacturer certificate chain to TLS context & and remove it after OTM
# AUTH_OPTION = 2   - preload manufacturer certificate chain to TLS context
#
# default: AUTH_OPTION = 1

ifndef AUTH_OPTION
AUTH_OPTION=1
endif

ifeq ($(AUTH_OPTION),0)
#enable mbedtls patch to skip cert verification
CFLAGS += -DOC_SKIP_CERT
else
#preload hardcoded certchain to TLS context
CFLAGS += -DOC_LOAD_CA

ifeq ($(AUTH_OPTION),1)
#remove all certchains from TLS context after OTM
CFLAGS += -DOC_UNLOAD_CERT
endif

ifeq ($(AUTH_OPTION),2)
#remove all certchains from TLS context after OTM
CFLAGS +=  -DOC_MFG
endif

endif
SAMPLES += rpk_server
UNIT_TESTS += securitytest securitytest_v2
endif

OBT = onboarding_tool

ifeq ($(EASYSETUP),1)
	SRC_ES=$(wildcard ../../service/easy-setup/enrollee/*.c ../../service/easy-setup/enrollee/samsung/*.c)
	CFLAGS_ES=-I../../service/easy-setup/enrollee/include -I../../service/easy-setup/enrollee/ -I../../port -I../../service/easy-setup/enrollee/include/samsung/
	CFLAGS_ES+= -DEASYSETUP
	OBJ_ES=$(addprefix obj/es/,$(notdir $(SRC_ES:.c=.o)))
endif

ifeq ($(ST_APP_FW),1)
	SRC_ST=$(wildcard ../../service/st-app-fw/src/*.c ../../service/st-app-fw/src/port/linux/*.c)
	CFLAGS_ST=-I../../service/st-app-fw/include
	CFLAGS_ST+= -DST_APP_FW
	OBJ_ST=$(addprefix obj/st/,$(notdir $(SRC_ST:.c=.o)))
endif

ifeq ($(DEBUG),1)
	CFLAGS += -DOC_DEBUG -g -O0
ifeq ($(DEBUG_TLS),1)
	CFLAGS += -DOC_DEBUG_TLS
endif
else
	CFLAGS += -Wl,--gc-sections
endif

ifeq ($(DYNAMIC),1)
	EXTRA_CFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifneq ($(SECURE),0)
	SRC += $(addprefix ../../security/,oc_acl.c oc_cred.c oc_doxm.c oc_pstat.c oc_tls.c oc_svr.c oc_store.c oc_otm_state.c)
	SRC_COMMON += $(addprefix $(MBEDTLS_DIR)/library/,${DTLS})
	MBEDTLS_PATCH_FILE := $(MBEDTLS_DIR)/patched.txt
ifeq ($(DYNAMIC)$(CODE_SIZE_OPT),10)
	SRC += ../../security/oc_obt.c
	SAMPLES += ${OBT}
else
	SRC_COMMON += $(MBEDTLS_DIR)/library/memory_buffer_alloc.c
endif
	CFLAGS += ${DTLSFLAGS}
	EXTRA_CFLAGS += -DOC_SECURITY
	VPATH += ../../security/:../../deps/mbedtls/library:
endif

ifneq ($(IPV4),0)
	EXTRA_CFLAGS += -DOC_IPV4
endif

ifneq ($(TCP),0)
	EXTRA_CFLAGS += -DOC_TCP
endif

ifneq ($(OIC),0)
	EXTRA_CFLAGS += -DOC_SPEC_VER_OIC
endif

ifeq ($(STATE_MODEL), 1)
	EXTRA_CFLAGS += -DSTATE_MODEL
endif

CFLAGS += $(EXTRA_CFLAGS)

ifeq ($(MEMTRACE),1)
	CFLAGS += -DOC_MEMORY_TRACE
endif


ifeq ($(CODE_SIZE_OPT),1)
	CFLAGS += -DST_APP_OPTIMIZATION
	CFLAGS += -DST_MBEDTLS_OPT
	CFLAGS += -DST_OC_CLIENT_OPT
	CFLAGS += -DST_OC_INTROSPECTION_OPT
	CFLAGS += -DST_OC_PERIODIC_OPT
	CFLAGS += -DST_OC_CON_RES_OPT
	CFLAGS += -DSC_ES_OPT
endif

## This MOCK_WIFI_SCAN flag prevents jsnkins failure in unit test case by sudo wifi scan return
ifneq ($(MOCK_WIFI_SCAN),0)
	CFLAGS += -DMOCK_WIFI_SCAN
else
	IWLIB = -liw
endif

## Some unit test cases fail on the Jenkins verification step which are related with wifi driver.
## This JENKINS_BLOCK flag will make these unit test case skipped from execution in Jenkins
ifeq ($(JENKINS_BLOCK), 1)
	TEST_CXXFLAGS += -DJENKINS_BLOCK
endif

SAMPLES_CREDS = $(addsuffix _creds, ${SAMPLES} ${OBT})

CONSTRAINED_LIBS = libiotivity-constrained-server.a libiotivity-constrained-client.a \
		   libiotivity-constrained-server.so libiotivity-constrained-client.so \
		   libiotivity-constrained-client-server.a libiotivity-constrained-client-server.so \
           libiotivity-constrained-easysetup.a \
		   libiotivity-constrained-cloudaccess.a libiotivity-constrained-cloudaccess.so \
		   libiotivity-constrained-rd-client.a libiotivity-constrained-rd-client.so \
		   libiotivity-constrained-fota.a libiotivity-constrained-fota.so

PC = iotivity-constrained-client.pc iotivity-constrained-server.pc \
     iotivity-constrained-client-server.pc


ifeq ($(ST_APP_FW),1)

	CONSTRAINED_LIBS += libst-app-framework.a libst-app-framework.so

	ST_DEVICE_DEF=../../apps/st_app/json/st_device_def
	ST_JSON_FILE := $(wildcard ../../apps/st_app/json/*.json)
	ST_DEVICE_DEF_HEADER=../../apps/st_app/$(OS)/st_device_def.h
ifeq ($(ARCH), x86_64)
	JSON_TO_CBOR=$(ROOT_DIR)/tools/json/json2cbor
else
	JSON_TO_CBOR=$(ROOT_DIR)/tools/json/json2cbor_32
endif

	ST_APP_TEST_DIR = $(ROOT_DIR)/service/st-app-fw/unittest
	ST_APP_TEST_OBJ_DIR = $(ST_APP_TEST_DIR)/obj
	ST_APP_TEST_SRC_FILES := $(wildcard $(ST_APP_TEST_DIR)/*.cpp)
	ST_APP_TEST_OBJ_FILES := $(patsubst $(ST_APP_TEST_DIR)/%.cpp,$(ST_APP_TEST_OBJ_DIR)/%.o,$(ST_APP_TEST_SRC_FILES))

	HEADER_DIR +=-I$(ROOT_DIR)/apps/st_app/$(OS)
	UNIT_TESTS += stapptest

endif


all: $(CONSTRAINED_LIBS) $(SAMPLES) $(PC)

test: $(UNIT_TESTS)
	set -e
	for test in $^ ; do ./$${test} || exit $? ; done

.PHONY: test clean

$(GTEST):
	$(MAKE) --directory=$(GTEST_DIR)/make

$(API_TEST_OBJ_DIR)/%.o: $(API_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(HEADER_DIR) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

apitest: $(API_TEST_OBJ_FILES) libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS)  $(HEADER_DIR) -l:gtest_main.a -liotivity-constrained-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@
l:gtest_main.a -liotivity-constrained-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(SECURITY_TEST_OBJ_DIR)/%.o: $(SECURITY_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(SECURITY_HEADERS) -c $< -o $@

securitytest: $(SECURITY_TEST_OBJ_FILES) libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS)  $(HEADER_DIR) -l:gtest_main.a -liotivity-constrained-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(SECURITY_V2_TEST_OBJ_DIR)/%.o: $(SECURITY_V2_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(SECURITY_HEADERS) -DOC_SPEC_VER_OIC -c $< -o $@

securitytest_v2: $(SECURITY_V2_TEST_OBJ_FILES) libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS)  $(HEADER_DIR) -l:gtest_main.a -liotivity-constrained-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(MESSAGING_TEST_OBJ_DIR)/%.o: $(MESSAGING_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(MESSAGING_HEADERS) -c $< -o $@

messagingtest: $(MESSAGING_TEST_OBJ_FILES) libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS)  $(HEADER_DIR) -l:gtest_main.a -liotivity-constrained-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(PLATFORM_TEST_OBJ_DIR)/%.o: $(PLATFORM_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

platformtest: $(PLATFORM_TEST_OBJ_FILES) libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -l:gtest_main.a -liotivity-constrained-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(ST_APP_TEST_OBJ_DIR)/%.o: $(ST_APP_TEST_DIR)/%.cpp prep_st_app_fw_json_present prep_st_app_fw_create_device_def 
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(CFLAGS_ST) $(CFLAGS_ES) $(CFLAGS_FOTA) -I$(ROOT_DIR) -I$(OUT_DIR) -I$(ROOT_DIR)/deps/tinycbor/src -c -lpthread $< -o $@

stapptest: $(ST_APP_TEST_OBJ_FILES) libst-app-framework.a | $(GTEST)
	@mkdir -p st_things_creds
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(CFLAGS_ST) $(CFLAGS_ES) $(CFLAGS_FOTA) -l:gtest_main.a -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

ifeq ($(EASYSETUP),1)
$(EASYSETUP_TEST_OBJ_DIR)/%.o: $(EASYSETUP_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(CFLAGS_ES) $(HEADER_DIR) -I$(ROOT_DIR) -I$(OUT_DIR) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

easysetuptest: $(EASYSETUP_TEST_OBJ_FILES) libiotivity-constrained-easysetup.a libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(CFLAGS_ES) $(HEADER_DIR) -l:gtest_main.a -liotivity-constrained-client-server -liotivity-constrained-easysetup -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@
endif

$(CA_TEST_OBJ_DIR)/%.o: $(CA_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(HEADER_DIR) $(CFLAGS_CA) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

cloudaccesstest: $(CA_TEST_OBJ_FILES) libiotivity-constrained-cloudaccess.a libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(HEADER_DIR) $(CFLAGS_CA) -l:gtest_main.a -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(RD_CLIENT_TEST_OBJ_DIR)/%.o: $(RD_CLIENT_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(HEADER_DIR) $(CFLAGS_RD_CLIENT) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

rdclienttest: $(RD_CLIENT_TEST_OBJ_FILES) libiotivity-constrained-rd-client.a libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(HEADER_DIR) $(CFLAGS_RD_CLIENT) -l:gtest_main.a -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(FOTA_TEST_OBJ_DIR)/%.o: $(FOTA_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(HEADER_DIR) $(CFLAGS_FOTA) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

fotatest: $(FOTA_TEST_OBJ_FILES) libiotivity-constrained-fota.a libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(HEADER_DIR) $(CFLAGS_FOTA) -l:gtest_main.a -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

${SRC} ${SRC_COMMON}: $(MBEDTLS_PATCH_FILE)

obj/es/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} ${CFLAGS_ES} -DOC_SERVER


obj/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS}

obj/server/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} -DOC_SERVER

obj/client/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} -DOC_CLIENT

obj/client_server/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} -DOC_CLIENT -DOC_SERVER

obj/ca/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} ${CFLAGS_CA}

obj/rd_client/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} ${CFLAGS_RD_CLIENT}

obj/fota/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} ${CFLAGS_FOTA}

obj/st/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} ${CFLAGS_ES} ${CFLAGS_CA} ${CFLAGS_RD_CLIENT} ${CFLAGS_FOTA} ${CFLAGS_ST} -DOC_CLIENT -DOC_SERVER

libiotivity-constrained-server.a: $(OBJ_COMMON) $(OBJ_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_SERVER)

libiotivity-constrained-server.so: $(OBJ_COMMON) $(OBJ_SERVER)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_SERVER) $(LIBS)

libiotivity-constrained-client.a: $(OBJ_COMMON) $(OBJ_CLIENT)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT)

libiotivity-constrained-client.so: $(OBJ_COMMON) $(OBJ_CLIENT)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_CLIENT) $(LIBS)

libiotivity-constrained-client-server.a: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)

libiotivity-constrained-client-server.so: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(LIBS)

libiotivity-constrained-easysetup.a: $(OBJ_ES) libiotivity-constrained-server.a
	$(AR) -rcs $@ $(OBJ_ES)

libiotivity-constrained-cloudaccess.a: $(OBJ_CA)
	$(AR) -rcs $@ $(OBJ_CA)

libiotivity-constrained-cloudaccess.so: $(OBJ_CA)
	$(CC) -shared -o $@ $(OBJ_CA) $(LIBS)

libiotivity-constrained-rd-client.a: $(OBJ_RD_CLIENT)
	$(AR) -rcs $@ $(OBJ_RD_CLIENT)

libiotivity-constrained-rd-client.so: $(OBJ_RD_CLIENT)
	$(CC) -shared -o $@ $(OBJ_RD_CLIENT) $(LIBS)

libiotivity-constrained-fota.a: $(OBJ_FOTA)
	$(AR) -rcs $@ $(OBJ_FOTA)

libiotivity-constrained-fota.so: $(OBJ_FOTA)
	$(CC) -shared -o $@ $(OBJ_FOTA) $(LIBS)

libst-app-framework.a: $(OBJ_ST) $(OBJ_ES) $(OBJ_CA) $(OBJ_RD_CLIENT) $(OBJ_FOTA) $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)
	$(AR) -rcs $@  $(OBJ_ST) $(OBJ_ES) $(OBJ_CA) $(OBJ_RD_CLIENT) $(OBJ_FOTA) $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)

libst-app-framework.so: $(OBJ_ST) $(OBJ_ES) $(OBJ_CA) $(OBJ_RD_CLIENT) $(OBJ_FOTA) $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)
	$(CC) -shared -o $@ $(OBJ_ST) $(OBJ_ES) $(OBJ_CA) $(OBJ_RD_CLIENT) $(OBJ_FOTA) $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(LIBS)

server: libiotivity-constrained-server.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/client_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

smart_lock: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/smart_lock_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

temp_sensor: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/temp_sensor_client_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

simpleserver: libiotivity-constrained-server.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/simpleserver.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS}  ${LIBS}

simpleclient: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/simpleclient.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

mfg_server: libiotivity-constrained-server.a
	@mkdir -p $@_creds
	@cp ../../apps/acl_0 $@_creds/acl_0
	@cp ../../apps/pstat_0 $@_creds/pstat_0
	@cp ../../apps/mfgserver_cred $@_creds/cred_0
	${CC} -o $@ ../../apps/secure_server.c libiotivity-constrained-server.a -DOC_SERVER -DOC_MFG ${CFLAGS}  ${LIBS}

add_ca_tool: libiotivity-constrained-server.a
	${CC} -o $@ ../../apps/add_ca_tool.c libiotivity-constrained-server.a -DOC_SERVER -DOC_MFG -DOC_CRED_TOOL ${CFLAGS}  ${LIBS}

rpk_server: libiotivity-constrained-server.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/secure_server.c libiotivity-constrained-server.a -DOC_SERVER -DOC_RPK ${CFLAGS}  ${LIBS}

client_collections_linux: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/client_collections_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_collections_linux: libiotivity-constrained-server.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_collections_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client_block_linux: libiotivity-constrained-client.a
	${CC} -o $@ ../../apps/client_block_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_block_linux: libiotivity-constrained-server.a
	${CC} -o $@ ../../apps/server_block_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

smart_home_server_linux: libiotivity-constrained-server.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/smart_home_server_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

multi_device_server: libiotivity-constrained-server.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/multi_device_server_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

multi_device_client: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/multi_device_client_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

easysetup_linux: libiotivity-constrained-client-server.a libiotivity-constrained-easysetup.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/easysetup_linux.c libiotivity-constrained-server.a libiotivity-constrained-easysetup.a -DOC_SERVER ${CFLAGS} ${CFLAGS_ES} ${LIBS}	

sc_easysetup_linux: libiotivity-constrained-client-server.a libiotivity-constrained-easysetup.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/sc_easysetup_linux.c libiotivity-constrained-server.a libiotivity-constrained-easysetup.a -DOC_SERVER ${CFLAGS} ${CFLAGS_ES} ${LIBS}	

${OBT}: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../onboarding_tool/obtmain.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

cloud_linux: libiotivity-constrained-client-server.a libiotivity-constrained-cloudaccess.a libiotivity-constrained-rd-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/cloud_linux.c libiotivity-constrained-client-server.a libiotivity-constrained-cloudaccess.a libiotivity-constrained-rd-client.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${CFLAGS_CA} ${CFLAGS_RD_CLIENT} ${LIBS}

server_multithread_linux: libiotivity-constrained-server.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_multithread_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client_multithread_linux: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/client_multithread_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

st_things: prep_st_app_fw_json_present prep_st_app_fw_create_device_def $(ST_JSON_FILE) libst-app-framework.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/st_app/linux/st_ref_app.c  \
			libst-app-framework.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${CFLAGS_FOTA} ${CFLAGS_ST} ${LIBS} ${IWLIB}

prep_st_app_fw_json_present:
ifneq ("$(wildcard $(ST_DEVICE_DEF_HEADER))","")
else
ifneq ("$(wildcard $(ST_JSON_FILE))", "")
else
	$(error please use proper json file in apps/st_app/json)
endif
ifneq ($(words $(ST_JSON_FILE)), 1)
	$(error please use 1 json file in apps/st_app/json)
endif
endif

prep_st_app_fw_create_device_def:
	$(info make new st_device_def file using $(ST_JSON_FILE))
	$(shell $(JSON_TO_CBOR) $(ST_JSON_FILE) > $(ST_DEVICE_DEF))
	$(shell xxd -i $(ST_DEVICE_DEF) > $(ST_DEVICE_DEF_HEADER))
	$(shell sed -i 's/_.*st_device_def/st_device_def/g' $(ST_DEVICE_DEF_HEADER))

iotivity-constrained-server.pc: iotivity-constrained-server.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),' \
		-e 's,@version@,$(VERSION),' \
		-e 's,@extra_cflags@,$(EXTRA_CFLAGS),'

iotivity-constrained-client.pc: iotivity-constrained-client.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),' \
		-e 's,@version@,$(VERSION),' \
		-e 's,@extra_cflags@,$(EXTRA_CFLAGS),'

iotivity-constrained-client-server.pc: iotivity-constrained-client-server.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),' \
		-e 's,@version@,$(VERSION),' \
		-e 's,@extra_cflags@,$(EXTRA_CFLAGS),'

ifneq ($(SECURE),0)
MBEDTLS_PATCHES ?= $(sort $(wildcard ../../patches/*.patch))
ifeq ($(AUTH_OPTION),0)
MBEDTLS_PATCHES += $(sort $(wildcard ../../patches/*.off))
endif
${MBEDTLS_DIR}/.git:
	git submodule update --init ${@D}

$(MBEDTLS_PATCH_FILE): ${MBEDTLS_DIR}/.git ${MBEDTLS_PATCHES}
	if [ -d ${MBEDTLS_DIR} ]; then \
	cd ${MBEDTLS_DIR} && \
	git clean -fdx . && \
	git reset --hard && \
	git fetch && \
	git reset --hard ${DTLS_TAG} && \
	cd -; \
	fi && \
	git submodule update --init && \
	cd ${MBEDTLS_DIR} && \
	for patch in $(MBEDTLS_PATCHES); do patch -r - -s -N -p1 < $${patch} ; done && \
	echo "Patches applied in $^" > ${@F}
endif

clean:
	rm -rf obj $(PC) $(CONSTRAINED_LIBS) $(API_TEST_OBJ_FILES) $(SECURITY_TEST_OBJ_FILES) $(PLATFORM_TEST_OBJ_FILES) $(ST_APP_TEST_OBJ_FILES) $(EASYSETUP_TEST_OBJ_FILES) $(CA_TEST_OBJ_FILES) $(RD_CLIENT_TEST_OBJ_FILES) $(FOTA_TEST_OBJ_FILES) $(UNIT_TESTS) $(STORAGE_TEST_DIR) $(shell find ../../ -name obj) securitytest_v2 securitytest easysetuptest rpk_server stapptest

cleanall: clean
	rm -rf ${all} $(SAMPLES) $(TESTS) ${OBT} ${SAMPLES_CREDS} $(MBEDTLS_PATCH_FILE) $(ST_DEVICE_DEF) $(ST_DEVICE_DEF_HEADER)
	${MAKE} -C ${GTEST_DIR}/make clean

distclean: cleanall

install: $(SAMPLES) $(PC) $(CONSTRAINED_LIBS)
	$(INSTALL) -d $(bindir)
	$(INSTALL) -d $(libdir)
	$(INSTALL) -d $(includedir)/iotivity-constrained
	$(INSTALL) -d $(includedir)/iotivity-constrained/port
	$(INSTALL) -d $(includedir)/iotivity-constrained/util
	$(INSTALL) -d $(includedir)/iotivity-constrained/util/pt
	$(INSTALL) -d $(includedir)/iotivity-constrained/messaging/coap
	$(INSTALL) -d $(includedir)/iotivity-constrained/deps/tinycbor/src/
	$(INSTALL) -d $(pkgconfigdir)
	$(INSTALL) -m 644 $(HEADERS) $(includedir)/iotivity-constrained/
	$(INSTALL) -m 644 $(HEADERS_PORT) $(includedir)/iotivity-constrained/port
	$(INSTALL) -m 644 $(HEADERS_UTIL) $(includedir)/iotivity-constrained/util
	$(INSTALL) -m 644 $(HEADERS_UTIL_PT) $(includedir)/iotivity-constrained/util/pt
	$(INSTALL) -m 644 $(HEADERS_COAP) $(includedir)/iotivity-constrained/messaging/coap
	$(INSTALL) -m 644 $(HEADERS_TINYCBOR) $(includedir)/iotivity-constrained/deps/tinycbor/src
	$(INSTALL) -m 644 $(PC) $(pkgconfigdir)
	$(INSTALL) -m 644 $(CONSTRAINED_LIBS) $(libdir)
ifneq ($(SECURE),1)
	rm $(includedir)/iotivity-constrained/oc_security.h
endif
# Installing the samples
	$(INSTALL) -d ${install_bin_dir}
	$(INSTALL) $(SAMPLES) ${install_bin_dir}

############# TESTS ##########################
TESTS = \
	tests/client_init_linux_test \
	tests/server_init_linux_test \
	tests/client_get_linux_test

tests/client_init_linux_test: libiotivity-constrained-client.a
	@mkdir -p $(@D)
	$(CC) -o $@ ../../tests/client_init_linux.c \
		libiotivity-constrained-client.a \
		-DOC_CLIENT $(CFLAGS) $(LIBS)

tests/server_init_linux_test: libiotivity-constrained-server.a
	@mkdir -p $(@D)
	$(CC) -o $@ ../../tests/server_init_linux.c \
		libiotivity-constrained-server.a \
		-DOC_SERVER $(CFLAGS) $(LIBS)

tests/client_get_linux_test: libiotivity-constrained-client-server.a
	@mkdir -p $(@D)
	$(CC) -o $@ ../../tests/client_get_linux.c \
		libiotivity-constrained-client-server.a -DOC_SERVER \
		-DOC_CLIENT $(CFLAGS) $(LIBS)

check: $(TESTS)
	$(Q)$(PYTHON) $(CHECK_SCRIPT) --tests="$(TESTS)"
