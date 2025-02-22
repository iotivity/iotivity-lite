export CC = gcc
SED = sed
INSTALL = install
export OS = linux
ROOT_DIR = ../..
SWIG_DIR = ${ROOT_DIR}/swig
OUT_DIR = $(ROOT_DIR)/port/$(OS)
CHECK_SCRIPT = ../../tools/check.py
# project version: 2.2.5.16
VERSION_MAJOR = 2
VERSION_MINOR = 2
VERSION_PATCH = 5
VERSION_BUILD = 16
VERSION = $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH).$(VERSION_BUILD)
DYNAMIC ?= 1
export SECURE ?= 1
export PKI ?= 1
ifeq ($(SECURE),0)
	PKI = 0
endif
export OSCORE ?= 1
INTROSPECTION ?= 1
export IDD ?= 1
export ETAG ?= 0
export JSON_ENCODER ?= 0
DESTDIR ?= /usr/local
install_bin_dir ?= ${DESTDIR}/opt/iotivity-lite/bin/
prefix = $(DESTDIR)
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
pkgconfigdir = $(libdir)/pkgconfig
EXTRA_CFLAGS = -DOC_SIMPLE_MAIN_LOOP
ifeq ($(ASAN),1)
	EXTRA_CFLAGS += -fsanitize=address
endif
ifeq ($(TSAN),1)
	EXTRA_CFLAGS += -fsanitize=thread
endif
BUILD_SAMPLES ?= 1
TEST ?= 1
# use v3.6.2 as default
MBEDTLS_FORCE_3_5_0 ?= 0

TINYCBOR_DIR := $(ROOT_DIR)/deps/tinycbor
MBEDTLS_DIR := $(ROOT_DIR)/deps/mbedtls
GTEST_DIR = $(ROOT_DIR)/deps/gtest
GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h
GTEST = gtest_build
GTEST_CPPFLAGS += -isystem $(GTEST_DIR)/include
TEST_CXXFLAGS += -g -Wall -Wextra -pthread -std=c++17 -fpermissive -DOC_SERVER -DOC_CLIENT -fprofile-arcs -ftest-coverage
HEADER_DIR = -I$(ROOT_DIR)/include \
             -I$(ROOT_DIR) \
             -I$(TINYCBOR_DIR)/src \
             -I$(OUT_DIR)
SECURITY_HEADERS = -I$(ROOT_DIR)/security \
                   -I$(MBEDTLS_DIR)/include
MESSAGING_HEADERS = -I$(ROOT_DIR)/messaging/coap
COMMON_TEST_DIR := $(ROOT_DIR)/tests/gtest
COMMON_TEST_COAP_DIR := $(COMMON_TEST_DIR)/coap
COMMON_TEST_TLS_DIR := $(COMMON_TEST_DIR)/tls
COMMON_TEST_OBJ_DIR := $(COMMON_TEST_DIR)/obj
COMMON_TEST_COAP_OBJ_DIR := $(COMMON_TEST_COAP_DIR)/obj
COMMON_TEST_TLS_OBJ_DIR := $(COMMON_TEST_TLS_DIR)/obj
COMMON_TEST_SRC_FILES := $(wildcard $(COMMON_TEST_DIR)/*.cpp $(COMMON_TEST_COAP_DIR)/*.cpp $(COMMON_TEST_TLS_DIR)/*.cpp)
COMMON_TEST_OBJ_FILES := $(patsubst $(COMMON_TEST_DIR)/%.cpp,$(COMMON_TEST_OBJ_DIR)/%.o,$(COMMON_TEST_SRC_FILES))
COMMON_TEST_OBJ_FILES := $(patsubst $(COMMON_TEST_COAP_DIR)/%.cpp,$(COMMON_TEST_COAP_OBJ_DIR)/%.o,$(COMMON_TEST_OBJ_FILES))
COMMON_TEST_OBJ_FILES := $(patsubst $(COMMON_TEST_TLS_DIR)/%.cpp,$(COMMON_TEST_OBJ_DIR)/%.o,$(COMMON_TEST_OBJ_FILES))
API_TEST_DIR = $(ROOT_DIR)/api/unittest
API_TEST_DISCOVERY_DIR = $(API_TEST_DIR)/discovery
API_TEST_ENCODER_DIR = $(API_TEST_DIR)/encoder
API_TEST_OBJ_DIR = $(API_TEST_DIR)/obj
API_TEST_DISCOVERY_OBJ_DIR = $(API_TEST_DISCOVERY_DIR)/obj
API_TEST_ENCODER_OBJ_DIR = $(API_TEST_ENCODER_DIR)/obj
API_TEST_SRC_FILES := $(wildcard $(API_TEST_DIR)/*.cpp $(API_TEST_DISCOVERY_DIR)/*.cpp $(API_TEST_ENCODER_DIR)/*.cpp)
API_TEST_OBJ_FILES := $(patsubst $(API_TEST_DIR)/%.cpp,$(API_TEST_OBJ_DIR)/%.o,$(API_TEST_SRC_FILES))
API_TEST_OBJ_FILES := $(patsubst $(API_TEST_DISCOVERY_DIR)/%.cpp,$(API_TEST_ENCODER_OBJ_DIR)/%.o,$(API_TEST_OBJ_FILES))
API_TEST_OBJ_FILES := $(patsubst $(API_TEST_ENCODER_DIR)/%.cpp,$(API_TEST_ENCODER_OBJ_DIR)/%.o,$(API_TEST_OBJ_FILES))
SECURITY_TEST_DIR = $(ROOT_DIR)/security/unittest
SECURITY_TEST_OBJ_DIR = $(SECURITY_TEST_DIR)/obj
SECURITY_TEST_SRC_FILES := $(wildcard $(SECURITY_TEST_DIR)/*.cpp)
SECURITY_TEST_OBJ_FILES := $(patsubst $(SECURITY_TEST_DIR)/%.cpp,$(SECURITY_TEST_OBJ_DIR)/%.o,$(SECURITY_TEST_SRC_FILES))
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

CLOUD_TEST_DIR = $(ROOT_DIR)/api/cloud/unittest
CLOUD_TEST_OBJ_DIR = $(CLOUD_TEST_DIR)/obj
CLOUD_TEST_STORAGE_DIR = storage_cloud
$(shell mkdir -p $(CLOUD_TEST_STORAGE_DIR))
CLOUD_TEST_SRC_FILES := $(wildcard $(CLOUD_TEST_DIR)/*.cpp)
CLOUD_TEST_OBJ_FILES := $(patsubst $(CLOUD_TEST_DIR)/%.cpp,$(CLOUD_TEST_OBJ_DIR)/%.o,$(CLOUD_TEST_SRC_FILES))

UNIT_TESTS = apitest platformtest securitytest messagingtest

DTLS = aes.c	asn1parse.c	asn1write.c	aria.c	base64.c	bignum_core.c	bignum.c \
	ccm.c	cipher.c	cipher_wrap.c	cmac.c		constant_time.c	ctr_drbg.c	debug.c \
	ecdh.c	ecdsa.c	ecjpake.c	ecp.c	ecp_curves.c	entropy_poll.c	entropy.c	error.c \
	gcm.c	md.c	net_sockets.c	nist_kw.c	oid.c pem.c	pk.c	pk_wrap.c	pkcs5.c \
	pkparse.c	pkwrite.c	platform.c	platform_util.c		rsa.c	rsa_alt_helpers.c \
	sha1.c	sha256.c	sha512.c	timing.c	ssl_ciphersuites.c	ssl_client.c	ssl_cookie.c \
	ssl_debug_helpers_generated.c	ssl_msg.c	ssl_tls.c	ssl_tls12_client.c	ssl_tls12_server.c \
	x509.c	x509_create.c	x509_crt.c	x509_csr.c	x509write.c	x509write_csr.c x509write_crt.c

ifeq ($(MBEDTLS_FORCE_3_5_0),0)
	DTLS += pk_ecc.c
endif

DTLSFLAGS=-I../../deps/mbedtls/include -Wno-error=unused

CBOR_DIR=../../deps/tinycbor/src
CBOR=$(CBOR_DIR)/cborencoder.c $(CBOR_DIR)/cborencoder_close_container_checked.c \
	$(CBOR_DIR)/cborencoder_float.c $(CBOR_DIR)/cborparser.c $(CBOR_DIR)/cborparser_float.c
# $(CBOR_DIR)/cbortojson.c $(CBOR_DIR)/cborpretty.c $(CBOR_DIR)/cborparser_dup_string.c


PYTHON_DIR=../../python
#SRC_PYTHON=../../python/oc_python.c
SRC_PYTHON=$(wildcard $(PYTHON_DIR)/*.c)
#PYTHON=oc_python.c

ifeq ($(PKI),1)
	CTIMESTAMP=../../api/c-timestamp/timestamp_tm.c
endif

CTIMESTAMP+=../../api/c-timestamp/timestamp_compare.c ../../api/c-timestamp/timestamp_format.c ../../api/c-timestamp/timestamp_valid.c ../../api/c-timestamp/timestamp_parse.c

ifneq ($(MEMORY_TRACE),1)
SRC_UTIL:=$(filter-out %_mem_trace.c,$(wildcard ../../util/*.c))
else
SRC_UTIL:=$(wildcard ../../util/*.c)
endif
ifeq ($(JSON_ENCODER),1)
SRC_UTIL+=$(wildcard ../../util/jsmn/*.c)
endif
SRC_COMMON:=${CBOR} ${CTIMESTAMP} ${SRC_UTIL}
SRC_API:=$(wildcard ../../api/*.c)
ifneq ($(INTROSPECTION),1)
SRC_API:=$(filter-out %oc_introspection.c,${SRC_API})
endif
ifneq ($(ETAG),1)
SRC_API:=$(filter-out %oc_etag.c,${SRC_API})
endif
ifneq ($(JSON_ENCODER),1)
SRC_API:=$(filter-out %oc_rep_decode_json.c %oc_rep_encode_json.c,${SRC_API})
endif
SRC:=${SRC_API} $(wildcard ../../messaging/coap/*.c ../../port/linux/*.c)
SRC_PORT_COMMON:=$(wildcard ../../port/common/*.c ../../port/common/posix/*.c)
SRC_CLIENT:=$(wildcard ../../api/client/*.c)
SRC_CLOUD:=$(wildcard ../../api/cloud/*.c)

HEADERS := $(wildcard ../../include/*.h)
HEADERS += ../../port/linux/oc_config.h
ifneq ($(INTROSPECTION),1)
HEADERS:=$(filter-out %oc_introspection.h %server_introspection.dat.h,${HEADERS})
else
ifeq ($(IDD),1)
HEADERS:=$(filter-out %server_introspection.dat.h,${HEADERS})
else
HEADERS:=$(filter-out %oc_introspection.h,${HEADERS})
endif
endif
ifneq ($(ETAG),1)
HEADERS:=$(filter-out %oc_etag.h,${HEADERS})
endif
HEADERS_COAP := $(filter-out %_internal.h,$(wildcard ../../messaging/coap/*.h))
HEADERS_UTIL := $(filter-out %_internal.h,$(wildcard ../../util/*.h))
HEADERS_UTIL_PT := $(filter-out %_internal.h,$(wildcard ../../util/pt/*.h))
HEADERS_PORT := $(filter-out %_internal.h,$(wildcard ../../port/*.h))
HEADERS_TINYCBOR := $(addprefix ../../deps/tinycbor/src/,cbor.h cborjson.h tinycbor-version.h)

WARNING_FLAGS=-Wall -Wextra -Werror -Wno-error=deprecated-declarations -pedantic
CFLAGS_CLOUD=-I../../api/cloud -DOC_CLIENT -DOC_SERVER
CFLAGS=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../../include/ -I../../ -I../../deps/tinycbor/src -I../../api -std=gnu99 $(WARNING_FLAGS) #-Wl,-Map,client.map
# TODO: check if it is possible to make -ffreestanding flag work with c++ targets
CXXFLAGS+=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../../include/ -I../../ -I../../deps/tinycbor/src $(WARNING_FLAGS) #-Wl,-Map,client.map
OBJ_COMMON=$(addprefix obj/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_PORT_COMMON=$(addprefix obj/port/,$(notdir $(SRC_PORT_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix obj/client/,$(notdir $(SRC:.c=.o) $(SRC_CLIENT:.c=.o)))
OBJ_SERVER=$(addprefix obj/server/,$(filter-out oc_obt.o oc_obt_otm_justworks.o oc_obt_otm_randompin.o oc_obt_otm_cert.o oc_obt_otm_streamlined_onboarding.o oc_obt_certs.o,$(notdir $(SRC:.c=.o))))
OBJ_CLOUD=$(addprefix obj/cloud/,$(notdir $(SRC_CLOUD:.c=.o)))
OBJ_CLIENT_SERVER=$(addprefix obj/client_server/,$(notdir $(SRC:.c=.o) $(SRC_CLIENT:.c=.o)))
OBJ_PYTHON=$(addprefix obj/python/,$(notdir $(SRC_PYTHON:.c=.o)))

# $(info    OBJ_PYTHON is $(OBJ_PYTHON))
# $(info    SRC_PYTHON is $(SRC_PYTHON))

VPATH=../../api/:../../api/client/:../../api/cloud/:../../api/c-timestamp:../../messaging/coap/:
VPATH+=../../python/:
VPATH+=../../util/:../../util/jsmn/:
VPATH+=../../deps/tinycbor/src/:../../deps/mbedtls/library:
LIBS?= -lm -pthread -lrt

# check OC_HAVE_TIME_H in oc_config.h
HAVE_OC_TIME_H := $(shell ($(CC) -include ../../port/linux/oc_config.h -E -dM - < /dev/null | grep -w OC_HAVE_TIME_H > /dev/null) && echo 1 || echo 0)

SAMPLES = server client temp_sensor simpleserver simpleserver_pki simpleclient client_collections_linux server_collections_linux server_block_linux client_block_linux \
	server_certification_tests smart_home_server_linux multi_device_server multi_device_client smart_lock server_multithread_linux client_multithread_linux client_certification_tests \
	server_rules secure_mcast_client secure_mcast_server1 secure_mcast_server2 simpleserver-resourcedefaults

ifeq ($(V6DNS),1)
	EXTRA_CFLAGS += -DOC_DNS_LOOKUP_IPV6
endif

ifeq ($(CREATE),1)
	EXTRA_CFLAGS += -DOC_COLLECTIONS_IF_CREATE
endif

#ifeq ($(COLLECTIONS),1)
#	EXTRA_CFLAGS += -DOC_COLLECTIONS
#endif

ifeq ($(MNT),1)
	EXTRA_CFLAGS += -DOC_MNT
endif

ifeq ($(SWUPDATE),1)
	SAMPLES += smart_home_server_with_mock_swupdate
endif


ifeq ($(WKCORE),1)
	EXTRA_CFLAGS += -DOC_WKCORE
endif

ifeq ($(CLOUD),1)
	EXTRA_CFLAGS += -DOC_CLOUD
	TCP=1
	IPV4=1
	SAMPLES += cloud_client cloud_server cloud_tests cloud_proxy
	UNIT_TESTS += cloudtest
endif

OBT = onboarding_tool

ifeq ($(DEBUG),1)
	EXTRA_CFLAGS += -DOC_LOG_MAXIMUM_LEVEL=8 -g -O0 
else
	CFLAGS += -Wl,--gc-sections
	CXXFLAGS += -Wl,--gc-sections
endif

ifeq ($(MEMORY_TRACE), 1)
	EXTRA_CFLAGS += -DOC_MEMORY_TRACE
endif

ifeq ($(PKI),1)
	EXTRA_CFLAGS += -DOC_PKI
endif

ifeq ($(DYNAMIC),1)
	EXTRA_CFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifeq ($(INTROSPECTION),1)
	EXTRA_CFLAGS += -DOC_INTROSPECTION
ifeq ($(IDD),1)
	EXTRA_CFLAGS += -DOC_IDD_API
endif
	SAMPLES += introspectionclient
endif

ifeq ($(SWUPDATE),1)
	EXTRA_CFLAGS += -DOC_SOFTWARE_UPDATE
	export SWUPDATE
endif

ifeq ($(PLGD_DEV_TIME),1)
	EXTRA_CFLAGS += -DPLGD_DEV_TIME
endif

# for PUSH NOTIFICATION
ifeq ($(PUSH), 1)
	EXTRA_CFLAGS += -DOC_PUSH
	SAMPLES += push_originserver_multithread_linux push_targetserver_multithread_linux push_configurator_multithread_linux
ifeq ($(PUSH_DEBUG), 1)
	EXTRA_CFLAGS += -DOC_PUSHDEBUG
endif
endif

ifneq ($(SECURE),0)
	SRC += $(addprefix ../../security/,oc_ace.c	oc_acl.c oc_acl_util.c oc_ael.c oc_audit.c oc_certs.c oc_certs_generate.c oc_certs_validate.c \
			oc_cred.c oc_cred_util.c oc_csr.c oc_doxm.c oc_entropy.c oc_keypair.c oc_oscore_engine.c oc_oscore_crypto.c \
			 oc_oscore_context.c oc_pki.c oc_pstat.c oc_roles.c oc_sdi.c oc_security.c oc_sp.c oc_store.c oc_svr.c oc_tls.c)
	SRC_COMMON += $(addprefix $(MBEDTLS_DIR)/library/,${DTLS})
	MBEDTLS_PATCH_FILE := $(MBEDTLS_DIR)/patched.txt
ifeq ($(DYNAMIC),1)
	SRC += ../../security/oc_obt.c ../../security/oc_obt_otm_justworks.c \
		../../security/oc_obt_otm_randompin.c ../../security/oc_obt_otm_cert.c ../../security/oc_obt_certs.c
	SAMPLES += ${OBT}
else
	SRC_COMMON += $(MBEDTLS_DIR)/library/memory_buffer_alloc.c
endif
	CFLAGS += ${DTLSFLAGS}
	CXXFLAGS += ${DTLSFLAGS}
	TEST_CXXFLAGS += ${DTLSFLAGS}
	EXTRA_CFLAGS += -DOC_SECURITY
	VPATH += ../../security/:../../deps/mbedtls/library:
endif

ifeq ($(OSCORE),1)
	EXTRA_CFLAGS += -DOC_OSCORE
endif

ifeq ($(IPV4),1)
	EXTRA_CFLAGS += -DOC_IPV4
endif

ifeq ($(TCP),1)
	EXTRA_CFLAGS += -DOC_TCP
endif

ifeq ($(JAVA),1)
	SWIG = swig
endif

ifeq ($(REP_ENCODING_REALLOC),1)
	EXTRA_CFLAGS += -DOC_REP_ENCODING_REALLOC
endif

ifeq ($(OICRES_OBSERVABLE),1)
	EXTRA_CFLAGS += -DOC_DISCOVERY_RESOURCE_OBSERVABLE
endif

ifeq ($(ETAG),1)
	EXTRA_CFLAGS += -DOC_ETAG
endif

ifeq ($(JSON_ENCODER),1)
	EXTRA_CFLAGS += -DOC_JSON_ENCODER
endif

ifeq ($(CROSS),1)
	export CC = arm-linux-gnueabihf-gcc
endif

CFLAGS += $(EXTRA_CFLAGS)
CXXFLAGS += $(EXTRA_CFLAGS)

CONSTRAINED_LIBS = libiotivity-lite-server.a libiotivity-lite-client.a \
		   libiotivity-lite-server.so libiotivity-lite-client.so \
		   libiotivity-lite-client-server.so libiotivity-lite-client-server.a

PC = iotivity-lite-client.pc iotivity-lite-server.pc \
     iotivity-lite-client-server.pc

all: $(CONSTRAINED_LIBS) $(PC) $(SWIG)

ifeq ($(HAVE_OC_TIME_H),1)

ifeq ($(BUILD_SAMPLES),1)
SAMPLES_CREDS = $(addsuffix _creds, ${SAMPLES} ${OBT})

all: $(SAMPLES)
endif # BUILD_SAMPLES

ifeq ($(TEST),1)

all: $(UNIT_TESTS)

test: all
	LD_LIBRARY_PATH=./ ./apitest
	LD_LIBRARY_PATH=./ ./messagingtest
	LD_LIBRARY_PATH=./ ./platformtest
	LD_LIBRARY_PATH=./ ./securitytest
ifeq ($(CLOUD),1)
	LD_LIBRARY_PATH=./ ./cloudtest
endif

endif # TEST

endif # HAVE_OC_TIME_H

.PHONY: test clean

$(GTEST):
	$(MAKE) --directory=$(GTEST_DIR)/make

$(COMMON_TEST_OBJ_DIR)/%.o: $(COMMON_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

$(COMMON_TEST_COAP_OBJ_DIR)/%.o: $(COMMON_TEST_COAP_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

$(COMMON_TEST_TLS_OBJ_DIR)/%.o: $(COMMON_TEST_TLS_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

$(API_TEST_OBJ_DIR)/%.o: $(API_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -c $< -o $@

$(API_TEST_DISCOVERY_OBJ_DIR)/%.o: $(API_TEST_DISCOVERY_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -c $< -o $@

$(API_TEST_ENCODER_OBJ_DIR)/%.o: $(API_TEST_ENCODER_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -c $< -o $@

apitest: $(API_TEST_OBJ_FILES) $(COMMON_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $^ -o $@ $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -L$(OUT_DIR) -L$(GTEST_DIR)/make -l:gtest_main.a -liotivity-lite-client-server -lpthread

$(SECURITY_TEST_OBJ_DIR)/%.o: $(SECURITY_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $< -o $@ $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(SECURITY_HEADERS) -c

securitytest: $(SECURITY_TEST_OBJ_FILES) $(COMMON_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS)  $(HEADER_DIR) -l:gtest_main.a -liotivity-lite-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(PLATFORM_TEST_OBJ_DIR)/%.o: $(PLATFORM_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $< -o $@ $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -c

platformtest: $(PLATFORM_TEST_OBJ_FILES) $(COMMON_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -l:gtest_main.a -liotivity-lite-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(CLOUD_TEST_OBJ_DIR)/%.o: $(CLOUD_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(CFLAGS_CLOUD) -I$(ROOT_DIR)/service/cloud/src -c $< -o $@

cloudtest: $(CLOUD_TEST_OBJ_FILES) $(COMMON_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(CFLAGS_CLOUD) -l:gtest_main.a -liotivity-lite-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(MESSAGING_TEST_OBJ_DIR)/%.o: $(MESSAGING_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(MESSAGING_HEADERS) -c $< -o $@

messagingtest: $(MESSAGING_TEST_OBJ_FILES) $(COMMON_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS)  $(HEADER_DIR) -l:gtest_main.a -liotivity-lite-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

copy_pki_certs:
	@mkdir -p pki_certs
	@cp ../../apps/pki_certs/*.pem pki_certs/

copy_idd_files:
	@cp ../../apps/smart_home_server_linux_IDD.cbor .
	@cp ../../apps/server_certification_tests_IDD.cbor .
	@cp ../../apps/client_certification_tests_IDD.cbor .
	@cp ../../apps/server_rules_IDD.cbor .
	@cp ../../apps/cloud_proxy_IDD.cbor .

${SRC} ${SRC_COMMON} ${SRC_PORT_COMMON} ${SRC_CLIENT}: $(MBEDTLS_PATCH_FILE)

obj/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS}

obj/port/%.o: ../../port/common/%.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS}

obj/port/%.o: ../../port/common/posix/%.c
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

obj/cloud/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} ${CFLAGS_CLOUD}

obj/python/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} -DOC_CLIENT

ifeq ($(INTROSPECTION),1)
obj/server/oc_introspection.o: ../../include/server_introspection.dat.h
obj/client/oc_introspection.o: ../../include/server_introspection.dat.h
obj/client_server/oc_introspection.o: ../../include/server_introspection.dat.h
endif

libiotivity-lite-server.a: $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_SERVER)

libiotivity-lite-server.so: $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_SERVER)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_SERVER) $(LIBS)

libiotivity-lite-client.a: $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT)

libiotivity-lite-client.so: $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT) $(LIBS)

libiotivity-lite-client-server.a: $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)

libiotivity-lite-client-python.so: $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT) $(OBJ_PYTHON)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT) $(OBJ_PYTHON) $(LIBS)
	cp $@ ../../python

libiotivity-lite-client-server.so: $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD) $(LIBS)

server: libiotivity-lite-server.a $(ROOT_DIR)/apps/server_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client: libiotivity-lite-client.a $(ROOT_DIR)/apps/client_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/client_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

smart_lock: libiotivity-lite-client.a $(ROOT_DIR)/apps/smart_lock_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/smart_lock_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

client_certification_tests: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/client_certification_tests.c copy_idd_files
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/client_certification_tests.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${LIBS}

temp_sensor: libiotivity-lite-client.a $(ROOT_DIR)/apps/temp_sensor_client_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/temp_sensor_client_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

simpleserver: libiotivity-lite-server.a $(ROOT_DIR)/apps/simpleserver.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/simpleserver.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS}  ${LIBS}

secure_mcast_server1: libiotivity-lite-server.a $(ROOT_DIR)/apps/secure_mcast_server1.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/secure_mcast_server1.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS}  ${LIBS}

secure_mcast_server2: libiotivity-lite-server.a $(ROOT_DIR)/apps/secure_mcast_server2.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/secure_mcast_server2.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS}  ${LIBS}

simpleserver_pki: libiotivity-lite-server.a $(ROOT_DIR)/apps/simpleserver_pki.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/simpleserver_pki.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS}  ${LIBS}

simpleserver-resourcedefaults: libiotivity-lite-server.a $(ROOT_DIR)/apps/simpleserver_pki.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/simpleserver-resourcedefaults.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS}  ${LIBS}

simpleclient: libiotivity-lite-client.a $(ROOT_DIR)/apps/simpleclient.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/simpleclient.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

secure_mcast_client: libiotivity-lite-client.a $(ROOT_DIR)/apps/secure_mcast_client.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/secure_mcast_client.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

introspectionclient: libiotivity-lite-client.a $(ROOT_DIR)/apps/introspectionclient.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/introspectionclient.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

client_collections_linux: libiotivity-lite-client.a $(ROOT_DIR)/apps/client_collections_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/client_collections_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_collections_linux: libiotivity-lite-server.a $(ROOT_DIR)/apps/server_collections_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_collections_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client_block_linux: libiotivity-lite-client.a $(ROOT_DIR)/apps/client_block_linux.c
	${CC} -o $@ ../../apps/client_block_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_block_linux: libiotivity-lite-server.a $(ROOT_DIR)/apps/server_block_linux.c
	${CC} -o $@ ../../apps/server_block_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

server_rules: libiotivity-lite-server.a $(ROOT_DIR)/apps/server_rules.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_rules.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

server_certification_tests: libiotivity-lite-server.a $(ROOT_DIR)/apps/server_certification_tests.c copy_pki_certs copy_idd_files
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_certification_tests.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${CFLAGS_CLOUD} ${LIBS}

smart_home_server_linux: libiotivity-lite-server.a $(ROOT_DIR)/apps/smart_home_server_linux.c copy_pki_certs copy_idd_files
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/smart_home_server_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

smart_home_server_with_mock_swupdate: libiotivity-lite-server.a $(ROOT_DIR)/apps/smart_home_server_with_mock_swupdate.cpp
	@mkdir -p $@_creds
	${CXX} -o $@ ../../apps/smart_home_server_with_mock_swupdate.cpp libiotivity-lite-server.a -DOC_SERVER ${CXXFLAGS} ${LIBS}

multi_device_server: libiotivity-lite-server.a $(ROOT_DIR)/apps/multi_device_server_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/multi_device_server_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

multi_device_client: libiotivity-lite-client.a $(ROOT_DIR)/apps/multi_device_client_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/multi_device_client_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

cloud_server: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/cloud_server.c copy_pki_certs
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/cloud_server.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${CFLAGS_CLOUD}  ${LIBS}

cloud_client: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/cloud_client.c copy_pki_certs
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/cloud_client.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${CFLAGS_CLOUD}  ${LIBS}

cloud_tests: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/cloud_certification_tests.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/cloud_certification_tests.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${CFLAGS_CLOUD} ${LIBS}

cloud_proxy: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/cloud_proxy.c copy_pki_certs copy_idd_files
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/cloud_proxy.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${CFLAGS_CLOUD}  ${LIBS}

${OBT}: libiotivity-lite-client.a $(ROOT_DIR)/onboarding_tool/obtmain.c copy_pki_certs
	@mkdir -p $@_creds
	${CC} -o $@ ../../onboarding_tool/obtmain.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_multithread_linux: libiotivity-lite-server.a $(ROOT_DIR)/apps/server_multithread_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_multithread_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client_multithread_linux: libiotivity-lite-client.a $(ROOT_DIR)/apps/client_multithread_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/client_multithread_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

# push notification samples
push_originserver_multithread_linux: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/push_originserver_multithread_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/$@.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${LIBS}

push_targetserver_multithread_linux: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/push_targetserver_multithread_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/$@.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS}  ${LIBS}

push_configurator_multithread_linux: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/push_configurator_multithread_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/$@.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS}  ${LIBS}

iotivity-lite-server.pc: iotivity-lite-server.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),' \
		-e 's,@version@,$(VERSION),' \
		-e 's,@extra_requires@,,' \
		-e 's,@extra_cflags@,-I$${includedir}/iotivity-lite/tinycbor $(EXTRA_CFLAGS),' \
		-e 's,@extra_libs@,$(EXTRA_LIBS),'

iotivity-lite-client.pc: iotivity-lite-client.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),' \
		-e 's,@version@,$(VERSION),' \
		-e 's,@extra_requires@,,' \
		-e 's,@extra_cflags@,-I$${includedir}/iotivity-lite/tinycbor $(EXTRA_CFLAGS),' \
		-e 's,@extra_libs@,$(EXTRA_LIBS),'

iotivity-lite-client-server.pc: iotivity-lite-client-server.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),' \
		-e 's,@version@,$(VERSION),' \
		-e 's,@extra_requires@,,' \
		-e 's,@extra_cflags@,-I$${includedir}/iotivity-lite/tinycbor $(EXTRA_CFLAGS),' \
		-e 's,@extra_libs@,$(EXTRA_LIBS),'

swig: $(CONSTRAINED_LIBS) $(OBJ_COMMON) $(OBJ_PORT_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)
	${MAKE} -C ${SWIG_DIR}

ifneq ($(SECURE),0)

${MBEDTLS_DIR}/.git:
	git submodule update --init ${@D}

ifeq ($(MBEDTLS_FORCE_3_5_0),1)
MBEDTLS_TAG := v3.5.0
MBEDTLS_PATCHES := $(sort $(wildcard ../../patches/mbedtls/3.5/*.patch) $(wildcard ../../patches/mbedtls/3.5/make/*.patch))
else
MBEDTLS_TAG := v3.6.2
MBEDTLS_PATCHES := $(sort $(wildcard ../../patches/mbedtls/3.6/*.patch) $(wildcard ../../patches/mbedtls/3.6/make/*.patch))
endif

$(MBEDTLS_PATCH_FILE): ${MBEDTLS_DIR}/.git ${MBEDTLS_PATCHES}
	if [ -d ${MBEDTLS_DIR} ]; then \
		cd ${MBEDTLS_DIR} && \
		git clean -fdx . && \
		git reset --hard && \
		(git fetch --unshallow --tags || git fetch --all) && \
		git checkout "${MBEDTLS_TAG}" && \
		([ "${MBEDTLS_TAG}" = "v3.5.0" ] || git submodule update --init) && \
		cd - && \
		git add -u ${MBEDTLS_DIR} ; \
	fi && \
	git submodule update --init && \
	git reset HEAD ${MBEDTLS_DIR} && \
	cd ${MBEDTLS_DIR} && \
	for patch in $(MBEDTLS_PATCHES); do patch -r - -s -N -p1 < $${patch} ; done && \
	echo "Patches applied in $^" > ${@F}

endif

clean:
	rm -rf obj $(PC) $(CONSTRAINED_LIBS) $(COMMON_TEST_OBJ_FILES) $(API_TEST_OBJ_FILES) $(SECURITY_TEST_OBJ_FILES) $(PLATFORM_TEST_OBJ_FILES) $(MESSAGING_TEST_OBJ_FILES) $(UNIT_TESTS) $(STORAGE_TEST_DIR) $(CLOUD_TEST_OBJ_FILES) $(CLOUD_TEST_STORAGE_DIR) $(RD_CLIENT_TEST_OBJ_FILES)
	rm -rf $(COMMON_TEST_OBJ_DIR)/*.gcda $(COMMON_TEST_TLS_OBJ_DIR)/*.gcda $(API_TEST_OBJ_DIR)/*.gcda $(API_TEST_ENCODER_OBJ_DIR)/*.gcda $(SECURITY_TEST_OBJ_DIR)/*.gcda $(PLATFORM_TEST_OBJ_DIR)/*.gcda $(MESSAGING_TEST_OBJ_DIR)/*.gcda
	rm -rf pki_certs smart_home_server_linux_IDD.cbor server_certification_tests_IDD.cbor client_certification_tests_IDD.cbor server_rules_IDD.cbor cloud_proxy_IDD.cbor

cleanall: clean
	rm -rf ${all} $(SAMPLES) $(TESTS) ${OBT} ${SAMPLES_CREDS} $(MBEDTLS_PATCH_FILE) *.o
	${MAKE} -C ${GTEST_DIR}/make clean
	${MAKE} -C ${SWIG_DIR} clean

distclean: cleanall

install: $(SAMPLES) $(PC) $(CONSTRAINED_LIBS)
	$(INSTALL) -d $(bindir)
	$(INSTALL) -d $(libdir)
	$(INSTALL) -d $(includedir)/iotivity-lite
	$(INSTALL) -d $(includedir)/iotivity-lite/port
	$(INSTALL) -d $(includedir)/iotivity-lite/util
	$(INSTALL) -d $(includedir)/iotivity-lite/util/pt
	$(INSTALL) -d $(includedir)/iotivity-lite/messaging/coap
	$(INSTALL) -d $(includedir)/iotivity-lite/tinycbor
	$(INSTALL) -d $(pkgconfigdir)
	$(INSTALL) -m 644 $(HEADERS) $(includedir)/iotivity-lite/
	$(INSTALL) -m 644 $(HEADERS_PORT) $(includedir)/iotivity-lite/port
	$(INSTALL) -m 644 $(HEADERS_UTIL) $(includedir)/iotivity-lite/util
	$(INSTALL) -m 644 $(HEADERS_UTIL_PT) $(includedir)/iotivity-lite/util/pt
	$(INSTALL) -m 644 $(HEADERS_COAP) $(includedir)/iotivity-lite/messaging/coap
	$(INSTALL) -m 644 $(HEADERS_TINYCBOR) $(includedir)/iotivity-lite/tinycbor
	$(INSTALL) -m 644 $(PC) $(pkgconfigdir)
	$(INSTALL) -m 644 $(CONSTRAINED_LIBS) $(libdir)
# Installing the samples
	$(INSTALL) -d ${install_bin_dir}
	$(INSTALL) $(SAMPLES) ${install_bin_dir}

############# TESTS ##########################
TESTS = \
	tests/client_init_linux_test \
	tests/server_init_linux_test \
	tests/client_get_linux_test

tests/client_init_linux_test: libiotivity-lite-client.a
	@mkdir -p $(@D)
	$(CC) -o $@ ../../tests/client_init_linux.c \
		libiotivity-lite-client.a \
		-DOC_CLIENT $(CFLAGS) $(LIBS)

tests/server_init_linux_test: libiotivity-lite-server.a
	@mkdir -p $(@D)
	$(CC) -o $@ ../../tests/server_init_linux.c \
		libiotivity-lite-server.a \
		-DOC_SERVER $(CFLAGS) $(LIBS)

tests/client_get_linux_test: libiotivity-lite-client-server.a
	@mkdir -p $(@D)
	$(CC) -o $@ ../../tests/client_get_linux.c \
		libiotivity-lite-client-server.a -DOC_SERVER \
		-DOC_CLIENT $(CFLAGS) $(LIBS)

check: $(TESTS)
	$(Q)$(PYTHON) $(CHECK_SCRIPT) --tests="$(TESTS)"
