export CC = gcc
SED = sed
INSTALL = install
export OS = linux
ROOT_DIR = ../..
SWIG_DIR = ${ROOT_DIR}/swig
OUT_DIR = $(ROOT_DIR)/port/$(OS)
CHECK_SCRIPT = ../../tools/check.py
VERSION_MAJOR = 1
VERSION_MINOR = 0
VERSION = $(VERSION_MAJOR).$(VERSION_MINOR)
DYNAMIC ?= 1
export SECURE ?= 1
export PKI ?= 1
export OSCORE ?= 1
IDD ?= 1
DESTDIR ?= /usr/local
install_bin_dir?=${DESTDIR}/opt/iotivity-lite/bin/
prefix = $(DESTDIR)
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
pkgconfigdir = $(libdir)/pkgconfig
EXTRA_CFLAGS =
ifeq ($(ASAN),1)
	EXTRA_CFLAGS += -fsanitize=address
endif

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
CLOUD_TEST_SRC_FILES := $(wildcard $(CLOUD_TEST_DIR)/*.cpp)
CLOUD_TEST_OBJ_FILES := $(patsubst $(CLOUD_TEST_DIR)/%.cpp,$(CLOUD_TEST_OBJ_DIR)/%.o,$(CLOUD_TEST_SRC_FILES))

UNIT_TESTS = apitest platformtest securitytest messagingtest

DTLS= 	aes.c		aesni.c 	arc4.c  	asn1parse.c	asn1write.c	base64.c	\
	bignum.c	blowfish.c	camellia.c	ccm.c		cipher.c	cipher_wrap.c	\
	cmac.c		ctr_drbg.c	des.c		dhm.c		ecdh.c		ecdsa.c		\
	ecjpake.c	ecp.c		ecp_curves.c	entropy.c	entropy_poll.c	error.c		\
	gcm.c		havege.c	hmac_drbg.c	md.c		md2.c		md4.c		\
	md5.c		md_wrap.c	oid.c		padlock.c	\
	pem.c		pk.c		pk_wrap.c	pkcs12.c	pkcs5.c		pkparse.c	\
	pkwrite.c	platform.c	ripemd160.c	rsa.c		sha1.c		sha256.c	\
	sha512.c	threading.c	timing.c	version.c	version_features.c		\
	xtea.c  	pkcs11.c 	x509.c 		x509_crt.c	debug.c		net_sockets.c	\
	ssl_cache.c	ssl_ciphersuites.c		ssl_cli.c	ssl_cookie.c	platform_util.c	\
	ssl_srv.c	ssl_ticket.c	ssl_tls.c	rsa_internal.c	x509write_csr.c\
	x509write_crt.c	x509_create.c	x509_csr.c
DTLSFLAGS=-I../../deps/mbedtls/include -D__OC_RANDOM

CBOR=../../deps/tinycbor/src/cborencoder.c ../../deps/tinycbor/src/cborencoder_close_container_checked.c ../../deps/tinycbor/src/cborparser.c# ../../deps/tinycbor/src/cbortojson.c ../../deps/tinycbor/src/cborpretty.c ../../deps/tinycbor/src/cborparser_dup_string.c

ifeq ($(PKI),1)
	CTIMESTAMP=../../api/c-timestamp/timestamp_tm.c
endif

CTIMESTAMP+=../../api/c-timestamp/timestamp_format.c ../../api/c-timestamp/timestamp_valid.c ../../api/c-timestamp/timestamp_parse.c

SRC_COMMON=$(wildcard ../../util/*.c) ${CBOR} ${CTIMESTAMP}
SRC=$(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/linux/*.c)
SRC_CLOUD=$(wildcard ../../api/cloud/*.c)

HEADERS = $(wildcard ../../include/*.h)
HEADERS += ../../port/linux/oc_config.h

HEADERS_COAP = $(wildcard ../../messaging/coap/*.h)
HEADERS_UTIL = $(wildcard ../../util/*.h)
HEADERS_UTIL_PT = $(wildcard ../../util/pt/*.h)
HEADERS_PORT = $(wildcard ../../port/*.h)
HEADERS_TINYCBOR = $(wildcard ../../deps/tinycbor/src/*.h)

CFLAGS_CLOUD=-I../../api/cloud
CFLAGS=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../../include/ -I../../ -std=gnu99 -Wall -Wextra -Werror -pedantic #-Wl,-Map,client.map
CXXFLAGS+=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../../include/ -I../../ -Wall -Wextra -Werror -pedantic #-Wl,-Map,client.map
OBJ_COMMON=$(addprefix obj/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix obj/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix obj/server/,$(filter-out oc_obt.o oc_obt_otm_justworks.o oc_obt_otm_randompin.o oc_obt_otm_cert.o oc_obt_certs.o,$(notdir $(SRC:.c=.o))))
OBJ_CLOUD=$(addprefix obj/cloud/,$(notdir $(SRC_CLOUD:.c=.o)))
OBJ_CLIENT_SERVER=$(addprefix obj/client_server/,$(notdir $(SRC:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:../../deps/mbedtls/library:../../api/c-timestamp:../../service/cloud/src/:../../service/resource-directory/client/src/:
LIBS?= -lm -pthread -lrt

SAMPLES = server client temp_sensor simpleserver simpleserver_pki simpleclient client_collections_linux introspectionclient\
	  server_collections_linux server_block_linux client_block_linux server_certification_tests smart_home_server_linux multi_device_server multi_device_client smart_lock server_multithread_linux client_multithread_linux client_certification_tests server_rules secure_mcast_client secure_mcast_server1 secure_mcast_server2

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



ifeq ($(CLOUD),1)
#	UNIT_TESTS += cloudtest
endif
ifeq ($(CLOUD),1)
	CFLAGS += -DOC_CLOUD
	TCP=1
	IPV4=1
	SAMPLES += cloud_client cloud_server cloud_tests
endif

OBT = onboarding_tool

ifeq ($(DEBUG),1)
	EXTRA_CFLAGS += -DOC_DEBUG -g -O0
ifeq ($(DEBUG_TLS),1)
	EXTRA_CFLAGS += -DOC_DEBUG_TLS
endif
else
	CFLAGS += -Wl,--gc-sections
	CXXFLAGS += -Wl,--gc-sections
endif

ifeq ($(PKI),1)
	EXTRA_CFLAGS += -DOC_PKI
endif

ifeq ($(DYNAMIC),1)
	EXTRA_CFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifeq ($(IDD), 1)
	EXTRA_CFLAGS += -DOC_IDD_API
endif

ifeq ($(SWUPDATE),1)
	EXTRA_CFLAGS += -DOC_SOFTWARE_UPDATE
	export SWUPDATE
endif

ifneq ($(SECURE),0)
	SRC += $(addprefix ../../security/,oc_acl.c oc_cred.c oc_doxm.c oc_pstat.c oc_tls.c oc_svr.c oc_store.c oc_pki.c oc_certs.c oc_sp.c oc_keypair.c oc_csr.c oc_roles.c oc_ael.c oc_audit.c oc_sdi.c oc_oscore_engine.c oc_oscore_crypto.c oc_oscore_context.c)
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

CFLAGS += $(EXTRA_CFLAGS)
CXXFLAGS += $(EXTRA_CFLAGS)

ifeq ($(MEMTRACE),1)
	CFLAGS += -DOC_MEMORY_TRACE
endif

SAMPLES_CREDS = $(addsuffix _creds, ${SAMPLES} ${OBT})

CONSTRAINED_LIBS = libiotivity-lite-server.a libiotivity-lite-client.a \
		   libiotivity-lite-server.so libiotivity-lite-client.so \
		   libiotivity-lite-client-server.so libiotivity-lite-client-server.a

PC = iotivity-lite-client.pc iotivity-lite-server.pc \
     iotivity-lite-client-server.pc

all: $(CONSTRAINED_LIBS) $(SAMPLES) $(PC) $(UNIT_TESTS) $(SWIG)

test: all
	LD_LIBRARY_PATH=./ ./apitest
	LD_LIBRARY_PATH=./ ./messagingtest
	LD_LIBRARY_PATH=./ ./platformtest
	LD_LIBRARY_PATH=./ ./securitytest

.PHONY: test clean

$(GTEST):
	$(MAKE) --directory=$(GTEST_DIR)/make

$(API_TEST_OBJ_DIR)/%.o: $(API_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

apitest: $(API_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $^ -o $@ $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -L$(OUT_DIR) -L$(GTEST_DIR)/make -l:gtest_main.a -liotivity-lite-client-server -lpthread

$(SECURITY_TEST_OBJ_DIR)/%.o: $(SECURITY_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $< -o $@ $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(SECURITY_HEADERS) -c

securitytest: $(SECURITY_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS)  $(HEADER_DIR) -l:gtest_main.a -liotivity-lite-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(PLATFORM_TEST_OBJ_DIR)/%.o: $(PLATFORM_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $< -o $@ $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -I$(ROOT_DIR)/deps/tinycbor/src -c

platformtest: $(PLATFORM_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) -l:gtest_main.a -liotivity-lite-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(CLOUD_TEST_OBJ_DIR)/%.o: $(CLOUD_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(CFLAGS_CLOUD) -I$(ROOT_DIR)/service/cloud/src -I$(ROOT_DIR)/deps/tinycbor/src -c $< -o $@

cloudtest: $(CLOUD_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(CFLAGS_CLOUD) -l:gtest_main.a -liotivity-lite-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

$(MESSAGING_TEST_OBJ_DIR)/%.o: $(MESSAGING_TEST_DIR)/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS) $(HEADER_DIR) $(MESSAGING_HEADERS) -c $< -o $@

messagingtest: $(MESSAGING_TEST_OBJ_FILES) libiotivity-lite-client-server.a | $(GTEST)
	$(CXX) $(GTEST_CPPFLAGS) $(TEST_CXXFLAGS) $(EXTRA_CFLAGS)  $(HEADER_DIR) -l:gtest_main.a -liotivity-lite-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@

copy_pki_certs:
	@mkdir -p pki_certs
	@cp ../../apps/pki_certs/*.pem pki_certs/

copy_idd_files:
	@cp ../../apps/smart_home_server_linux_IDD.cbor .
	@cp ../../apps/server_certification_tests_IDD.cbor .
	@cp ../../apps/client_certification_tests_IDD.cbor .
	@cp ../../apps/server_rules_IDD.cbor .

${SRC} ${SRC_COMMON}: $(MBEDTLS_PATCH_FILE)

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

obj/cloud/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} ${CFLAGS_CLOUD}

obj/server/oc_introspection.o: ../../include/server_introspection.dat.h
obj/client/oc_introspection.o: ../../include/server_introspection.dat.h
obj/client_server/oc_introspection.o: ../../include/server_introspection.dat.h

libiotivity-lite-server.a: $(OBJ_COMMON) $(OBJ_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_SERVER)

libiotivity-lite-server.so: $(OBJ_COMMON) $(OBJ_SERVER)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_SERVER) $(LIBS)

libiotivity-lite-client.a: $(OBJ_COMMON) $(OBJ_CLIENT)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT)

libiotivity-lite-client.so: $(OBJ_COMMON) $(OBJ_CLIENT)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_CLIENT) $(LIBS)

libiotivity-lite-client-server.a: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)

libiotivity-lite-client-server.so: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)
	$(CC) -shared -o $@ $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD) $(LIBS)

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
	${CXX} -o $@ ../../apps/smart_home_server_with_mock_swupdate.cpp libiotivity-lite-server.a -DOC_SERVER ${CXXFLAGS} ${LIBS} -lboost_system -lcppnetlib-uri

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

${OBT}: libiotivity-lite-client.a $(ROOT_DIR)/onboarding_tool/obtmain.c copy_pki_certs
	@mkdir -p $@_creds
	${CC} -o $@ ../../onboarding_tool/obtmain.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_multithread_linux: libiotivity-lite-server.a $(ROOT_DIR)/apps/server_multithread_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_multithread_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client_multithread_linux: libiotivity-lite-client.a $(ROOT_DIR)/apps/client_multithread_linux.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/client_multithread_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

iotivity-lite-server.pc: iotivity-lite-server.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),' \
		-e 's,@version@,$(VERSION),' \
		-e 's,@extra_cflags@,$(EXTRA_CFLAGS),'

iotivity-lite-client.pc: iotivity-lite-client.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),' \
		-e 's,@version@,$(VERSION),' \
		-e 's,@extra_cflags@,$(EXTRA_CFLAGS),'

iotivity-lite-client-server.pc: iotivity-lite-client-server.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),' \
		-e 's,@version@,$(VERSION),' \
		-e 's,@extra_cflags@,$(EXTRA_CFLAGS),'

swig: $(CONSTRAINED_LIBS) $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)
	${MAKE} -C ${SWIG_DIR}

ifneq ($(SECURE),0)
MBEDTLS_PATCHES ?= $(sort $(wildcard ../../patches/*.patch))
${MBEDTLS_DIR}/.git:
	git submodule update --init ${@D}

$(MBEDTLS_PATCH_FILE): ${MBEDTLS_DIR}/.git ${MBEDTLS_PATCHES}
	if [ -d ${MBEDTLS_DIR} ]; then \
	cd ${MBEDTLS_DIR} && \
	git clean -fdx . && \
	git reset --hard && \
	cd -; \
	fi && \
	git submodule update --init && \
	cd ${MBEDTLS_DIR} && \
	for patch in $(MBEDTLS_PATCHES); do patch -r - -s -N -p1 < $${patch} ; done && \
	echo "Patches applied in $^" > ${@F}
endif

clean:
	rm -rf obj $(PC) $(CONSTRAINED_LIBS) $(API_TEST_OBJ_FILES) $(SECURITY_TEST_OBJ_FILES) $(PLATFORM_TEST_OBJ_FILES) $(MESSAGING_TEST_OBJ_FILES) $(UNIT_TESTS) $(STORAGE_TEST_DIR) $(CLOUD_TEST_OBJ_FILES) $(RD_CLIENT_TEST_OBJ_FILES)
	rm -rf $(API_TEST_OBJ_DIR)/*.gcda $(SECURITY_TEST_OBJ_DIR)/*.gcda $(PLATFORM_TEST_OBJ_DIR)/*.gcda $(MESSAGING_TEST_OBJ_DIR)/*.gcda
	rm -rf pki_certs smart_home_server_linux_IDD.cbor server_certification_tests_IDD.cbor client_certification_tests_IDD.cbor server_rules_IDD.cbor

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
	$(INSTALL) -d $(includedir)/iotivity-lite/deps/tinycbor/src/
	$(INSTALL) -d $(pkgconfigdir)
	$(INSTALL) -m 644 $(HEADERS) $(includedir)/iotivity-lite/
	$(INSTALL) -m 644 $(HEADERS_PORT) $(includedir)/iotivity-lite/port
	$(INSTALL) -m 644 $(HEADERS_UTIL) $(includedir)/iotivity-lite/util
	$(INSTALL) -m 644 $(HEADERS_UTIL_PT) $(includedir)/iotivity-lite/util/pt
	$(INSTALL) -m 644 $(HEADERS_COAP) $(includedir)/iotivity-lite/messaging/coap
	$(INSTALL) -m 644 $(HEADERS_TINYCBOR) $(includedir)/iotivity-lite/deps/tinycbor/src
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
