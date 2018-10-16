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
# or invoke like this: make NDK_HOME=/opt/android-ndk ANDROID_API=24

# Location of the installation directory and the API level.
ANDROID_API := 19
ifeq (${NDK_HOME},)
ANDROID_BASE := "${HOME}/android-arm-${ANDROID_API}"
else
ANDROID_BASE := "${NDK_HOME}"
endif
# Compiler prefix
ANDROID_HOST := arm-linux-androideabi-

BIN_BASE := ${ANDROID_BASE}/bin/${ANDROID_HOST}
ifeq ($(origin CC),default)
CC := ${BIN_BASE}gcc
endif
ifeq ($(origin AR),default)
AR := ${BIN_BASE}ar
endif
RM ?= rm
MKDIR ?= mkdir

ROOT_DIR = ../..
OBJDIR ?= ./${ANDROID_HOST}obj
MBEDTLS_DIR := $(ROOT_DIR)/deps/mbedtls

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
	ssl_cache.c	ssl_ciphersuites.c		ssl_cli.c	ssl_cookie.c			\
	ssl_srv.c	ssl_ticket.c	ssl_tls.c	rsa_internal.c
DTLSFLAGS=-I../../deps/mbedtls/include -D__OC_RANDOM

CBOR=../../deps/tinycbor/src/cborencoder.c ../../deps/tinycbor/src/cborencoder_close_container_checked.c ../../deps/tinycbor/src/cborparser.c# ../../deps/tinycbor/src/cbortojson.c ../../deps/tinycbor/src/cborpretty.c ../../deps/tinycbor/src/cborparser_dup_string.c

SRC_COMMON:=$(wildcard ../../util/*.c) ${CBOR}
SRC:=$(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/android/*.c)

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

CFLAGS?=-fPIE -pie -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../../include/ -I../../ -std=gnu99 -Wall -D__ANDROID_API__=${ANDROID_API}
OBJ_COMMON=$(addprefix ${OBJDIR}/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix ${OBJDIR}/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix ${OBJDIR}/server/,$(filter-out oc_obt.o,$(notdir $(SRC:.c=.o))))
OBJ_CLIENT_SERVER=$(addprefix ${OBJDIR}/client_server/,$(notdir $(SRC:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:../../deps/mbedtls/library:
LIBS?= -lm

SAMPLES := server client temp_sensor simpleserver simpleclient client_collections_linux \
	  server_collections_linux server_block_linux client_block_linux smart_home_server_linux multi_device_server multi_device_client \
	  smart_lock server_multithread_linux client_multithread_linux

OBT = onboarding_tool

ifeq ($(DEBUG),1)
	CFLAGS += -DOC_DEBUG -g -O0
else
	CFLAGS += -Wl,--gc-sections
endif

ifeq ($(DYNAMIC),1)
	CFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifneq ($(SECURE),0)
	SRC += $(addprefix ../../security/,oc_acl.c oc_cred.c oc_doxm.c oc_pstat.c oc_tls.c oc_svr.c oc_store.c)
	SRC_COMMON += $(addprefix $(MBEDTLS_DIR)/library/,${DTLS})
	MBEDTLS_PATCH_FILE := $(MBEDTLS_DIR)/patched.txt
ifeq ($(DYNAMIC),1)
	SRC += ../../security/oc_obt.c
	SAMPLES += ${OBT}
else
	SRC_COMMON += $(MBEDTLS_DIR)/library/memory_buffer_alloc.c
endif
	CFLAGS += ${DTLSFLAGS} -DOC_SECURITY
	VPATH += ../../security/:../../deps/mbedtls/library:
endif

ifeq ($(IPV4),1)
	CFLAGS += -DOC_IPV4
endif

ifeq ($(TCP),1)
	EXTRA_CFLAGS += -DOC_TCP
endif

CONSTRAINED_LIBS = libiotivity-constrained-server.a libiotivity-constrained-client.a \
		    libiotivity-constrained-client-server.a

all: $(CONSTRAINED_LIBS) $(SAMPLES)

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

libiotivity-constrained-server.a: $(OBJ_COMMON) $(OBJ_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_SERVER)

libiotivity-constrained-client.a: $(OBJ_COMMON) $(OBJ_CLIENT)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT)

libiotivity-constrained-client-server.a: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)

server: libiotivity-constrained-server.a
	${CC} -o $@ ../../apps/server_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client: libiotivity-constrained-client.a
	${CC} -o $@ ../../apps/client_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

smart_lock: libiotivity-constrained-client.a
	${CC} -o $@ ../../apps/smart_lock_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

temp_sensor: libiotivity-constrained-client.a
	${CC} -o $@ ../../apps/temp_sensor_client_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

simpleserver: libiotivity-constrained-server.a
	${CC} -o $@ ../../apps/simpleserver.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS}  ${LIBS}

simpleclient: libiotivity-constrained-client.a
	${CC} -o $@ ../../apps/simpleclient.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

client_collections_linux: libiotivity-constrained-client.a
	${CC} -o $@ ../../apps/client_collections_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_collections_linux: libiotivity-constrained-server.a
	${CC} -o $@ ../../apps/server_collections_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client_block_linux: libiotivity-constrained-client.a
	${CC} -o $@ ../../apps/client_block_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_block_linux: libiotivity-constrained-server.a
	${CC} -o $@ ../../apps/server_block_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

smart_home_server_linux: libiotivity-constrained-server.a
	${CC} -o $@ ../../apps/smart_home_server_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

multi_device_server: libiotivity-constrained-server.a
	${CC} -o $@ ../../apps/multi_device_server_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

multi_device_client: libiotivity-constrained-client.a
	${CC} -o $@ ../../apps/multi_device_client_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

${OBT}: libiotivity-constrained-client.a
	${CC} -o $@ ../../onboarding_tool/obtmain.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_multithread_linux: libiotivity-constrained-server.a
	${CC} -o $@ ../../apps/server_multithread_linux.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client_multithread_linux: libiotivity-constrained-client.a
	${CC} -o $@ ../../apps/client_multithread_linux.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

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
	$(RM) -rf ${OBJDIR} $(CONSTRAINED_LIBS)

cleanall: clean
	$(RM) -rf ${all} $(SAMPLES) $(OBT) $(MBEDTLS_PATCH_FILE)

distclean: cleanall
