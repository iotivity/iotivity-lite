CC=gcc

DTLS=../../deps/tinydtls/ccm.c ../../deps/tinydtls/hmac.c ../../deps/tinydtls/netq.c ../../deps/tinydtls/peer.c ../../deps/tinydtls/dtls_time.c ../../deps/tinydtls/session.c ../../deps/tinydtls/sha2/sha2.c ../../deps/tinydtls/ecc/ecc.c ../../deps/tinydtls/aes/rijndael.c ../../deps/tinydtls/crypto.c ../../deps/tinydtls/dtls.c
DTLSFLAGS=-DDTLSV12 -DWITH_SHA256 -DDTLS_CHECK_CONTENTTYPE -DWITH_OCF -I../../deps/tinydtls -DNDEBUG

CBOR=../../deps/tinycbor/src/cborencoder.c ../../deps/tinycbor/src/cborencoder_close_container_checked.c ../../deps/tinycbor/src/cborparser.c #../../deps/tinycbor/src/cbortojson.c ../../deps/tinycbor/src/cborpretty.c ../../deps/tinycbor/src/cborparser_dup_string.c

SRC_COMMON=$(wildcard ../../util/*.c) ${CBOR}
SRC=$(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/linux/*.c)

#Using all compiler flags that the Zephyr build system uses to test
#that this implemenetation can withstand a high level of optimization.
CFLAGS=-fno-asynchronous-unwind-tables -fno-omit-frame-pointer -Wall -Wno-format-zero-length -Wno-main -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -Wno-unused-but-set-variable -fno-reorder-functions -fno-defer-pop -Wno-pointer-sign -fno-strict-overflow -Werror=implicit-int -I./ -I../../include/ -I../../  -Wall -std=gnu99 #-Wl,-Map,client.map
OBJ_COMMON=$(addprefix obj/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix obj/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix obj/server/,$(notdir $(SRC:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:

ifeq ($(DEBUG),1)
	CFLAGS += -DOC_DEBUG -g
else
	CFLAGS += -Wl,--gc-sections
endif

ifeq ($(SECURE),1)
	SRC += $(wildcard ../../security/*.c)
	SRC_COMMON += ${DTLS}
	CFLAGS += ${DTLSFLAGS} -DOC_SECURITY
	VPATH += ../../security/:../../deps/tinydtls/:../../deps/tinydtls/aes/:../../deps/tinydtls/sha2/:../../deps/tinydtls/ecc/:
endif

all=server client temp_sensor simpleserver simpleclient

install_bin_dir?=${DESTDIR}/opt/iotivity-constrained/bin/

.PHONY: clean

all: ${all}

obj/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS}

obj/server/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} -DOC_SERVER

obj/client/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS} -DOC_CLIENT

server: ${OBJ_COMMON} ${OBJ_SERVER}
	echo ${OBJ_COMMON}
	${CC} -o $@ ${OBJ_COMMON} ${OBJ_SERVER} ../../apps/server_linux.c -DOC_SERVER ${CFLAGS} -lm -pthread

client: ${OBJ_COMMON} ${OBJ_CLIENT}
	${CC} -o $@ ${OBJ_COMMON} ${OBJ_CLIENT} ../../apps/client_linux.c -DOC_CLIENT ${CFLAGS} -lm -pthread

temp_sensor: ${OBJ_COMMON} ${OBJ_CLIENT}
	${CC} -o $@ ${OBJ_COMMON} ${OBJ_CLIENT} ../../apps/temp_sensor_client_linux.c -DOC_CLIENT ${CFLAGS} -lm -pthread

simpleserver: ${OBJ_COMMON} ${OBJ_SERVER}
	${CC} -o $@ ${OBJ_COMMON} ${OBJ_SERVER} ../../apps/simpleserver.c -DOC_SERVER ${CFLAGS} -lm -pthread

simpleclient: ${OBJ_COMMON} ${OBJ_CLIENT}
	${CC} -o $@ ${OBJ_COMMON} ${OBJ_CLIENT} ../../apps/simpleclient.c -DOC_CLIENT ${CFLAGS} -lm -pthread

clean:
	rm -rf obj

cleanall: clean
	rm -rf ${all}

install: ${all}
	install -d ${install_bin_dir}
	install $^ ${install_bin_dir}
