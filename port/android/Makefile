# Port for native Android compilation (without Java).
# Tested NDK versions:
# API	Android version
#  19	4.4
#  21	5.0
#  23	6.0
#  24	7.0
#
# API version 24 is closest to regular Linux so far.
# With API 24 the Android port is almost identical to the Linux port
# except for the removal of the unsupported pthread_cancel and that
# the IP adapter assures that interfaces have multicast and broadcast
# enabled to avoid 3G/4G/5G interfaces.
#
# It is expected that higher versions then API 24 should work without any
# further modifications.
#
# Download NDK: https://developer.android.com/ndk/downloads/index.html
# Unzip downloaded package.
# Choose architecture and API level.
# cd <NDK>/build/tools
# ./make_standalone_toolchain.py --arch <architecture> --api <level> --install-dir <path>
# For example: ./make_standalone_toolchain.py --arch arm --api 23 --install-dir ~/android-arm-23
# This makefile uses then the NDK in <install-dir>.
# For further setup see: https://developer.android.com/ndk/guides/standalone_toolchain.html
#
# Either set ANDROID_API and ANDROID_BASE in this makefile
# or invoke like this: make NDK_HOME=/opt/android-ndk ANDROID_API=23
#
# Example Usage:  make IPV4=1 DEBUG=1
#
# The default JAVA=1 build is recomended for Android builds. Its is possible to
# only build and run native code. There may be write access problems when using
# SECURITY=1 and a native only build. The following instructions are intended
# for native only builds.
#
# Testing compilations on non-rooted Android phones:
# - Enable USB debugging on your phone.
# - Install ADB or Android Studio
# - adb start-server
#   Your phone should query now if you trust the computer. Hit OK.
# - adb push simpleclient /data/local/tmp/
#   Most likely your phone gives you in /data/local some more permissions
#   Non-rooted devices are a bit restrictive what you can do in the file system.
# - adb shell
# - cd /data/local/tmp
# - chmod 755 simpleclient
#   It was observed that the file has read-write permissions only after the upload
#   on Android 7.
# - In a different terminal window start simpleserver on your developer box.
# - ./simpleclient
# - Kill client with Ctrl-C or Ctrl-\
# - exit
# - *** DISABLE USB debugging!!! *** (security issue if left on)
#
# Note: On regular Android phones the server versions will not be found
#       (ie. simpleserver will not be discovered). But the clients
#       should work.
#

# Location of the installation directory and the API level.
export OS=android
export ANDROID_API := 23
ifeq (${NDK_HOME},)
export ANDROID_BASE := "${HOME}/android-arm-${ANDROID_API}"
else
export ANDROID_BASE := "${NDK_HOME}"
endif

ifeq ($(ANDROID_ABI),armeabi)
export ANDROID_HOST := arm-linux-androideabi-
endif
ifeq ($(ANDROID_ABI),x86_64)
export ANDROID_HOST := x86_64-linux-android-
endif
ifeq ($(ANDROID_ABI),arm64-v8a)
export ANDROID_HOST := aarch64-linux-android-
endif

# Compiler prefix

export ANDROID_HOST ?= arm-linux-androideabi-

BIN_BASE := ${ANDROID_BASE}/bin/${ANDROID_HOST}
ifeq ($(origin CC),default)
export CC := ${BIN_BASE}gcc
endif
ifeq ($(origin AR),default)
AR := ${BIN_BASE}ar
endif
RM ?= rm
MKDIR ?= mkdir


ifeq (${MYGITHUB_ACTIONS}, true)
export HOST_TAG := linux-x86_64
#GITHUBBASE := /usr/local/lib/android/sdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/${HOST_TAG}/bin
GITHUBBASE := /usr/local/lib/android/sdk/ndk/21.4.7075529/toolchains/llvm/prebuilt/${HOST_TAG}/bin
#21.4.7075529
#             /usr/local/lib/android/sdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/linux-x86_64/bin
export CC :=  ${GITHUBBASE}/aarch64-linux-android23-clang
AR := ${GITHUBBASE}/aarch64-linux-android-ar
endif


DYNAMIC ?= 1
export SECURE ?= 1
export PKI ?= 1
IPV4 ?= 1
export TCP ?= 1

export CLOUD ?= 1


# unlike other IoTivity-lite builds Android assumes we want to build Java by
# default. It also assumes the use of OC_IDD_API is used by default.
JAVA ?= 1
export IDD ?= 1

ROOT_DIR = ../..
SWIG_DIR = $(ROOT_DIR)/swig
OBJDIR ?= ./${ANDROID_HOST}obj
MBEDTLS_DIR := $(ROOT_DIR)/deps/mbedtls

DTLS= \
	aes.c		aesni.c		asn1parse.c	asn1write.c	base64.c		\
	bignum.c	camellia.c	ccm.c		cipher.c	cipher_wrap.c	\
	cmac.c		ctr_drbg.c	des.c		dhm.c		ecdh.c		ecdsa.c			\
	ecjpake.c	ecp.c		ecp_curves.c			entropy.c	entropy_poll.c	\
	error.c		gcm.c		hmac_drbg.c	md.c		\
	md5.c		oid.c		padlock.c	pem.c			            \
	pk.c		pk_wrap.c	pkcs12.c	pkcs5.c		pkparse.c	pkwrite.c		\
	platform.c	ripemd160.c	rsa.c		sha1.c		sha256.c	sha512.c		\
	threading.c	timing.c	version.c	version_features.c		\
	x509.c 		x509_crt.c	debug.c		net_sockets.c				\
	ssl_cache.c	ssl_ciphersuites.c		ssl_cli.c	ssl_cookie.c				\
	ssl_srv.c	ssl_ticket.c			ssl_tls.c	\
	x509write_csr.c			x509write_crt.c			x509_create.c				\
	x509_csr.c	platform_util.c ssl_msg.c constant_time.c \
	nist_kw.c aria.c rsa_alt_helpers.c

DTLSFLAGS=-I../../deps/mbedtls/include -D__OC_RANDOM

CBOR=../../deps/tinycbor/src/cborencoder.c ../../deps/tinycbor/src/cborencoder_close_container_checked.c ../../deps/tinycbor/src/cborencoder_float.c ../../deps/tinycbor/src/cborparser.c ../../deps/tinycbor/src/cborparser_float.c# ../../deps/tinycbor/src/cbortojson.c ../../deps/tinycbor/src/cborpretty.c ../../deps/tinycbor/src/cborparser_dup_string.c

ifeq ($(PKI),1)
	CTIMESTAMP=../../api/c-timestamp/timestamp_tm.c
endif

CTIMESTAMP+=../../api/c-timestamp/timestamp_format.c ../../api/c-timestamp/timestamp_valid.c ../../api/c-timestamp/timestamp_parse.c

SRC_COMMON:=$(wildcard ../../util/*.c) ${CBOR} ${CTIMESTAMP}
SRC:=$(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/android/*.c)
SRC_CLOUD=$(wildcard ../../api/cloud/*.c)

# From API level 24 on Android supports getifaddrs itself.
ifeq ($(shell if [ ${ANDROID_API} -gt 23 ]; then echo gt; fi),gt)
	SRC:=$(filter-out ../../port/android/ifaddrs-android.c,${SRC})
endif

HEADERS = $(wildcard ../../include/*.h)
HEADERS += ../../port/android/oc_config.h

HEADERS_COAP = $(wildcard ../../messaging/coap/*.h)
HEADERS_UTIL = $(wildcard ../../util/*.h)
HEADERS_UTIL_PT = $(wildcard ../../util/pt/*.h)
HEADERS_PORT = $(wildcard ../../port/*.h)
HEADERS_TINYCBOR = $(wildcard ../../deps/tinycbor/src/*.h)

CFLAGS_CLOUD=-I../../api/cloud
CFLAGS?=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-strict-overflow -I./ -I../../include/ -I../../ -std=gnu99 -Wall -DLONG_BIT=64 -D__ANDROID_API__=${ANDROID_API}
OBJ_COMMON=$(addprefix ${OBJDIR}/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix ${OBJDIR}/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix ${OBJDIR}/server/,$(filter-out oc_obt.o oc_obt_otm_justworks.o oc_obt_otm_randompin.o oc_obt_otm_cert.o oc_obt_certs.o,$(notdir $(SRC:.c=.o))))
ifeq ($(CLOUD),1)
OBJ_CLOUD=$(addprefix ${OBJDIR}/cloud/,$(notdir $(SRC_CLOUD:.c=.o)))
else
OBJ_CLOUD =
endif
OBJ_CLIENT_SERVER=$(addprefix ${OBJDIR}/client_server/,$(notdir $(SRC:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:../../deps/mbedtls/library:../../api/c-timestamp:
LIBS?= -lm -llog

# Skip building the native samples if JAVA=1
ifneq ($(JAVA), 1)
	NATIVE_SAMPLES := server client temp_sensor simpleserver simpleclient client_collections_linux \
	  server_collections_linux server_block_linux client_block_linux smart_home_server_linux multi_device_server multi_device_client \
	  smart_lock server_multithread_linux client_multithread_linux
endif

ifeq ($(CLOUD),1)
	CFLAGS += -DOC_CLOUD
	TCP=1
	IPV4=1
	SAMPLES += cloud_server cloud_tests
endif

OBT = onboarding_tool

ifeq ($(CLOUD),1)
	CFLAGS += -DOC_CLOUD
	TCP=1
	IPV4=1
	#NATIVE_SAMPLES += cloud_linux cloud_tests
endif

ifeq ($(DEBUG),1)
	CFLAGS += -g -O0
	EXTRA_CFLAGS += -DOC_DEBUG
ifeq ($(DEBUG_TLS),1)
	EXTRA_CFLAGS += -DOC_DEBUG_TLS
endif
else

# don't use these options on github
ifeq (${MYGITHUB_ACTIONS}, false)
	CFLAGS += -Wl,--gc-sections
endif

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
	SRC += $(addprefix ../../security/,oc_acl.c oc_cred.c oc_doxm.c oc_pstat.c \
		oc_tls.c oc_svr.c oc_store.c oc_pki.c oc_certs.c oc_sp.c oc_keypair.c \
		oc_csr.c oc_roles.c oc_audit.c oc_ael.c oc_sdi.c)
	SRC_COMMON += $(addprefix $(MBEDTLS_DIR)/library/,${DTLS})
	MBEDTLS_PATCH_FILE := $(MBEDTLS_DIR)/patched.txt
ifeq ($(DYNAMIC),1)
	SRC += ../../security/oc_obt.c \
		../../security/oc_obt_otm_justworks.c \
		../../security/oc_obt_otm_randompin.c \
		../../security/oc_obt_otm_cert.c \
		../../security/oc_obt_certs.c
# skip building the native onboarding tool if JAVA=1
ifneq ($(JAVA),1)
	NATIVE_SAMPLES += ${OBT}
endif
else
	SRC_COMMON += $(MBEDTLS_DIR)/library/memory_buffer_alloc.c
endif
	CFLAGS += ${DTLSFLAGS} -DOC_SECURITY
	VPATH += ../../security/:../../deps/mbedtls/library:
endif

ifeq ($(IPV4),1)
	EXTRA_CFLAGS += -DOC_IPV4
endif

ifeq ($(TCP),1)
	EXTRA_CFLAGS += -DOC_TCP
endif

CFLAGS += $(EXTRA_CFLAGS)

CONSTRAINED_LIBS = libiotivity-lite-server.a libiotivity-lite-client.a \
		    libiotivity-lite-client-server.a

ifeq ($(JAVA), 1)
	SWIG = swig
endif

all: $(CONSTRAINED_LIBS) $(NATIVE_SAMPLES) $(SWIG)

.PHONY: clean

${SRC} ${SRC_COMMON}: $(MBEDTLS_PATCH_FILE)

${OBJDIR}/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS}

${OBJDIR}/server/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} -DOC_SERVER

${OBJDIR}/client/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} -DOC_CLIENT

${OBJDIR}/client_server/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} -DOC_CLIENT -DOC_SERVER

${OBJDIR}/cloud/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} ${CFLAGS_CLOUD}

libiotivity-lite-server.a: $(OBJ_COMMON) $(OBJ_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_SERVER)

libiotivity-lite-client.a: $(OBJ_COMMON) $(OBJ_CLIENT)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT)

libiotivity-lite-client-server.a: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)

server: libiotivity-lite-server.a
	${CC} -o $@ ../../apps/server_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client: libiotivity-lite-client.a
	${CC} -o $@ ../../apps/client_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

smart_lock: libiotivity-lite-client.a
	${CC} -o $@ ../../apps/smart_lock_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

temp_sensor: libiotivity-lite-client.a
	${CC} -o $@ ../../apps/temp_sensor_client_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

simpleserver: libiotivity-lite-server.a
	${CC} -o $@ ../../apps/simpleserver.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS}  ${LIBS}

simpleclient: libiotivity-lite-client.a
	${CC} -o $@ ../../apps/simpleclient.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

client_collections_linux: libiotivity-lite-client.a
	${CC} -o $@ ../../apps/client_collections_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_collections_linux: libiotivity-lite-server.a
	${CC} -o $@ ../../apps/server_collections_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client_block_linux: libiotivity-lite-client.a
	${CC} -o $@ ../../apps/client_block_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_block_linux: libiotivity-lite-server.a
	${CC} -o $@ ../../apps/server_block_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

smart_home_server_linux: libiotivity-lite-server.a
	${CC} -o $@ ../../apps/smart_home_server_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

multi_device_server: libiotivity-lite-server.a
	${CC} -o $@ ../../apps/multi_device_server_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

multi_device_client: libiotivity-lite-client.a
	${CC} -o $@ ../../apps/multi_device_client_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

cloud_server: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/cloud_server.c
	${CC} -o $@ ../../apps/cloud_server.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${CFLAGS_CLOUD}  ${LIBS}

cloud_tests: libiotivity-lite-client-server.a $(ROOT_DIR)/apps/cloud_certification_tests.c
	${CC} -o $@ ../../apps/cloud_certification_tests.c libiotivity-lite-client-server.a -DOC_CLIENT -DOC_SERVER ${CFLAGS} ${CFLAGS_CLOUD} ${LIBS}

${OBT}: libiotivity-lite-client.a
	${CC} -o $@ ../../onboarding_tool/obtmain.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_multithread_linux: libiotivity-lite-server.a
	${CC} -o $@ ../../apps/server_multithread_linux.c libiotivity-lite-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client_multithread_linux: libiotivity-lite-client.a
	${CC} -o $@ ../../apps/client_multithread_linux.c libiotivity-lite-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

swig: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CLOUD)
	${MAKE} -C ${SWIG_DIR}

ifneq ($(SECURE),0)
MBEDTLS_PATCHES ?= $(sort $(wildcard ../../patches/*.patch) $(wildcard ../../patches/make/*.patch))
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
	$(RM) -rf ${OBJDIR} $(CONSTRAINED_LIBS)
	${MAKE} -C ${SWIG_DIR} clean

cleanall: clean
	$(RM) -rf ${all} $(SAMPLES) $(OBT) $(MBEDTLS_PATCH_FILE)

distclean: cleanall
