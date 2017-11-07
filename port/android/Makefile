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

# Location of the installation directory and the API level.
ANDROID_API := 19
ANDROID_BASE := "${HOME}/android-arm-${ANDROID_API}"
# Compiler prefix
ANDROID_HOST := arm-linux-androideabi-

# Additional option:
# IOT_NAME_SUFFIX: Suffix for libraries and binaries

BIN_BASE := ${ANDROID_BASE}/bin/${ANDROID_HOST}
ifeq ($(origin CC),default)
CC := ${BIN_BASE}gcc
endif
ifeq ($(origin AR),default)
AR := ${BIN_BASE}ar
endif
RM ?= rm
MKDIR ?= mkdir

OBJDIR ?= ./${ANDROID_HOST}obj$(IOT_NAME_SUFFIX)

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
	ssl_srv.c	ssl_ticket.c	ssl_tls.c
DTLSFLAGS=-I../../deps/mbedtls/include -D__OC_RANDOM

CBOR=../../deps/tinycbor/src/cborencoder.c ../../deps/tinycbor/src/cborencoder_close_container_checked.c ../../deps/tinycbor/src/cborparser.c #../../deps/tinycbor/src/cbortojson.c ../../deps/tinycbor/src/cborpretty.c ../../deps/tinycbor/src/cborparser_dup_string.c

SRC_COMMON=$(wildcard ../../util/*.c) ${CBOR}
SRC=$(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/android/*.c)

HEADERS = $(wildcard ../../include/*.h)
HEADERS += ../../port/android/config.h

HEADERS_COAP = $(wildcard ../../messaging/coap/*.h)
HEADERS_UTIL = $(wildcard ../../util/*.h)
HEADERS_UTIL_PT = $(wildcard ../../util/pt/*.h)
HEADERS_PORT = $(wildcard ../../port/*.h)
HEADERS_TINYCBOR = $(wildcard ../../deps/tinycbor/src/*.h)

CFLAGS?=-fPIE -pie -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../../include/ -I../../ -std=gnu99 -Wall -D__ANDROID_API__=${ANDROID_API} #-Wextra -Werror -pedantic #-Wl,-Map,client.map
OBJ_COMMON=$(addprefix ${OBJDIR}/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix ${OBJDIR}/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix ${OBJDIR}/server/,$(filter-out oc_obt.o,$(notdir $(SRC:.c=.o))))
OBJ_CLIENT_SERVER=$(addprefix ${OBJDIR}/client_server/,$(notdir $(SRC:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:../../deps/mbedtls/library:
LIBS?= -lm

SAMPLES := server client temp_sensor simpleserver simpleclient client_collections_linux \
	  server_collections_linux server_block_linux client_block_linux smart_home_server_linux multi_device_server multi_device_client \
	  client_scenes_linux server_scenes_linux

ifneq ($(IOT_NAME_SUFFIX),)
SAMPLES := $(addsuffix $(IOT_NAME_SUFFIX),$(SAMPLES))
endif

OBT = onboarding_tool

ifeq ($(DEBUG),1)
	CFLAGS += -DOC_DEBUG -g -O0
else
	CFLAGS += -Wl,--gc-sections
endif

ifeq ($(DYNAMIC),1)
	CFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifeq ($(SECURE),1)
	SRC += oc_acl.c oc_cred.c oc_doxm.c oc_pstat.c oc_dtls.c oc_svr.c oc_store.c
ifeq ($(DYNAMIC),1)
	SRC_COMMON += ${DTLS}
	SRC += oc_obt.c
	SAMPLES += ${OBT}
else
	SRC_COMMON += ${DTLS} memory_buffer_alloc.c
endif
	CFLAGS += ${DTLSFLAGS} -DOC_SECURITY
	VPATH += ../../security/:../../deps/mbedtls/library:
endif

ifeq ($(IPV4),1)
	CFLAGS += -DOC_IPV4
endif

CONSTRAINED_LIBS = libiotivity-constrained-server$(IOT_NAME_SUFFIX).a libiotivity-constrained-client$(IOT_NAME_SUFFIX).a \
		    libiotivity-constrained-client-server$(IOT_NAME_SUFFIX).a

all: $(CONSTRAINED_LIBS) $(SAMPLES)
default: all

.PHONY: clean

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

libiotivity-constrained-server$(IOT_NAME_SUFFIX).a: $(OBJ_COMMON) $(OBJ_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_SERVER)

libiotivity-constrained-client$(IOT_NAME_SUFFIX).a: $(OBJ_COMMON) $(OBJ_CLIENT)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT)

libiotivity-constrained-client-server$(IOT_NAME_SUFFIX).a: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)

server$(IOT_NAME_SUFFIX): libiotivity-constrained-server$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/server_linux.c libiotivity-constrained-server$(IOT_NAME_SUFFIX).a -DOC_SERVER ${CFLAGS} ${LIBS}

client$(IOT_NAME_SUFFIX): libiotivity-constrained-client$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/client_linux.c libiotivity-constrained-client$(IOT_NAME_SUFFIX).a -DOC_CLIENT ${CFLAGS} ${LIBS}

temp_sensor$(IOT_NAME_SUFFIX): libiotivity-constrained-client$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/temp_sensor_client_linux.c libiotivity-constrained-client$(IOT_NAME_SUFFIX).a -DOC_CLIENT ${CFLAGS} ${LIBS}

simpleserver$(IOT_NAME_SUFFIX): libiotivity-constrained-server$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/simpleserver.c libiotivity-constrained-server$(IOT_NAME_SUFFIX).a -DOC_SERVER ${CFLAGS}  ${LIBS}

simpleclient$(IOT_NAME_SUFFIX): libiotivity-constrained-client$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/simpleclient.c libiotivity-constrained-client$(IOT_NAME_SUFFIX).a -DOC_CLIENT ${CFLAGS}  ${LIBS}

client_collections_linux$(IOT_NAME_SUFFIX): libiotivity-constrained-client$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/client_collections_linux.c libiotivity-constrained-client$(IOT_NAME_SUFFIX).a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_collections_linux$(IOT_NAME_SUFFIX): libiotivity-constrained-server$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/server_collections_linux.c libiotivity-constrained-server$(IOT_NAME_SUFFIX).a -DOC_SERVER ${CFLAGS} ${LIBS}

client_block_linux$(IOT_NAME_SUFFIX): libiotivity-constrained-client$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/client_block_linux.c libiotivity-constrained-client$(IOT_NAME_SUFFIX).a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_block_linux$(IOT_NAME_SUFFIX): libiotivity-constrained-server$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/server_block_linux.c libiotivity-constrained-server$(IOT_NAME_SUFFIX).a -DOC_SERVER ${CFLAGS} ${LIBS}

smart_home_server_linux$(IOT_NAME_SUFFIX): libiotivity-constrained-server$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/smart_home_server_linux.c libiotivity-constrained-server$(IOT_NAME_SUFFIX).a -DOC_SERVER ${CFLAGS} ${LIBS}

multi_device_server$(IOT_NAME_SUFFIX): libiotivity-constrained-server$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/multi_device_server_linux.c libiotivity-constrained-server$(IOT_NAME_SUFFIX).a -DOC_SERVER ${CFLAGS} ${LIBS}

multi_device_client$(IOT_NAME_SUFFIX): libiotivity-constrained-client$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../apps/multi_device_client_linux.c libiotivity-constrained-client$(IOT_NAME_SUFFIX).a -DOC_CLIENT ${CFLAGS}  ${LIBS}

server_scenes_linux$(IOT_NAME_SUFFIX): ../../apps/server_scenes_linux.c libiotivity-constrained-server$(IOT_NAME_SUFFIX).a
	${CC} -o $@ $< libiotivity-constrained-server$(IOT_NAME_SUFFIX).a -DOC_SERVER ${CFLAGS} ${LIBS}

client_scenes_linux$(IOT_NAME_SUFFIX): ../../apps/client_scenes_linux.c libiotivity-constrained-client$(IOT_NAME_SUFFIX).a
	${CC} -o $@ $< libiotivity-constrained-client$(IOT_NAME_SUFFIX).a -DOC_CLIENT ${CFLAGS} ${LIBS}

${OBT}: libiotivity-constrained-client$(IOT_NAME_SUFFIX).a
	${CC} -o $@ ../../onboarding_tool/obtmain.c libiotivity-constrained-client$(IOT_NAME_SUFFIX).a -DOC_CLIENT ${CFLAGS}  ${LIBS}

clean:
	$(RM) -rf ${OBJDIR} $(CONSTRAINED_LIBS)

cleanall: clean
	$(RM) -rf ${all} $(SAMPLES) $(OBT)
