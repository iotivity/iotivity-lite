# Download NDK: https://developer.android.com/ndk/downloads/index.html
# Unzip downloaded package.
# Choose architecture and API level.
# cd <NDK>/build/tools
# ./make_standalone_toolchain.py --arch <architecture> --api <level> --install-dir <path>
# For example: ./make_standalone_toolchain.py --arch arm --api 23 --install-dir ~/android-arm
# For further setup see: https://developer.android.com/ndk/guides/standalone_toolchain.html

# Location of the install-dir. Remember to adapt ANDROID_API below as well!
ANDROID_BASE := "${HOME}/android-arm-19"
ANDROID_API := 19
# Compiler prefix
ANDROID_HOST := arm-linux-androideabi-

BIN_BASE := ${ANDROID_BASE}/bin/${ANDROID_HOST}
ifeq ($(origin CC),default)
CC := ${BIN_BASE}gcc
endif
ifeq ($(origin AR),default)
AR := ${BIN_BASE}ar
endif
SED ?= sed
RM ?= rm
MKDIR ?= mkdir

OBJDIR ?= ./${ANDROID_HOST}obj

DTLS=../../deps/tinydtls/ccm.c ../../deps/tinydtls/hmac.c ../../deps/tinydtls/netq.c ../../deps/tinydtls/peer.c ../../deps/tinydtls/dtls_time.c ../../deps/tinydtls/session.c ../../deps/tinydtls/sha2/sha2.c ../../deps/tinydtls/ecc/ecc.c ../../deps/tinydtls/aes/rijndael.c ../../deps/tinydtls/crypto.c ../../deps/tinydtls/dtls.c
DTLSFLAGS=-DDTLSV12 -DWITH_SHA256 -DDTLS_CHECK_CONTENTTYPE -DWITH_OCF -I../../deps/tinydtls -DNDEBUG

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
OBJ_SERVER=$(addprefix ${OBJDIR}/server/,$(notdir $(SRC:.c=.o)))
OBJ_CLIENT_SERVER=$(addprefix ${OBJDIR}/client_server/,$(notdir $(SRC:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:
LIBS?= -lm

ifeq ($(DEBUG),1)
	CFLAGS += -DOC_DEBUG -g -O0
else
	CFLAGS += -Wl,--gc-sections
endif

ifeq ($(DYNAMIC),1)
	CFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifeq ($(SECURE),1)
	SRC += $(wildcard ../../security/*.c)
	SRC_COMMON += ${DTLS}
	CFLAGS += ${DTLSFLAGS} -DOC_SECURITY
	VPATH += ../../security/:../../deps/tinydtls/:../../deps/tinydtls/aes/:../../deps/tinydtls/sha2/:../../deps/tinydtls/ecc/:
endif

ifeq ($(IPV4),1)
	CFLAGS += -DOC_IPV4
endif

SAMPLES = server client temp_sensor simpleserver simpleclient client_collections_linux \
	  server_collections_linux server_block_linux client_block_linux smart_home_server_linux
CONSTRAINED_LIBS = libiotivity-constrained-server.a libiotivity-constrained-client.a \
		    libiotivity-constrained-client-server.a

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

clean:
	$(RM) -rf ${OBJDIR} $(PC) $(CONSTRAINED_LIBS)

cleanall: clean
	$(RM) -rf ${all} $(SAMPLES) $(TESTS)
