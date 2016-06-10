CC=gcc

DTLS=../../deps/tinydtls/ccm.c deps/tinydtls/hmac.c deps/tinydtls/netq.c deps/tinydtls/peer.c deps/tinydtls/dtls_time.c deps/tinydtls/session.c deps/tinydtls/sha2/sha2.c deps/tinydtls/ecc/ecc.c deps/tinydtls/aes/rijndael.c deps/tinydtls/crypto.c deps/tinydtls/dtls.c
DTLSFLAGS=-DDTLSV12 -DWITH_SHA256 -DDTLS_CHECK_CONTENTTYPE -DWITH_OCF -I../../deps/tinydtls -DNDEBUG

CBOR=../../deps/tinycbor/cborencoder.c deps/tinycbor/cborencoder_close_container_checked.c deps/tinycbor/cborparser.c

SRC=$(wildcard ../../messaging/coap/*.c ../../util/*.c ../../api/*.c ../../port/linux/*.c) ${CBOR}

#Using all compiler flags that the Zephyr build system uses to test
#that this implemenetation can withstand a high level of optimization.
CFLAGS=-fno-asynchronous-unwind-tables -fno-omit-frame-pointer -Wall -Wno-format-zero-length -Wno-main -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -Wno-unused-but-set-variable -fno-reorder-functions -fno-defer-pop -Wno-pointer-sign -fno-strict-overflow -Werror=implicit-int -I./ -I../../include/ -I../../  -Wall -std=gnu99 #-Wl,-Map,client.map
OBJ=$(addprefix obj/,$(notdir $(SRC:.c=.o)))

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG -g
endif

ifeq ($(SECURE),1)
SRC += $(wildcard ../../security/*.c) ${DTLS}
CFLAGS += ${DTLSFLAGS} -DOC_SECURITY
endif

ifeq ($(CLIENT),1)
CFLAGS += -DOC_CLIENT
endif

ifeq ($(SERVER),1)
CFLAGS += -DOC_SERVER
endif

.PHONY: clean output_dir
all: output_dir ${OBJ}

output_dir:
	mkdir -p obj/
obj/%.o: ../../util/%.c
	${CC} -c -o $@ $< ${CFLAGS}
obj/%.o: ../../api/%.c
	${CC} -c -o $@ $< ${CFLAGS}
obj/%.o: ../../messaging/coap/%.c
	${CC} -c -o $@ $< ${CFLAGS} 
obj/%.o: ../../deps/tinycbor/%.c
	${CC} -c -o $@ $< ${CFLAGS}
obj/%.o: %.c
	${CC} -c -o $@ $< ${CFLAGS}
obj/%.o: ../../security/%.c
	${CC} -c -o $@ $< ${CFLAGS}
obj/%.o: ../../deps/tinydtls/%.c
	${CC} -c -o $@ $< ${CFLAGS}
obj/%.o: ../../deps/tinydtls/aes/%.c
	${CC} -c -o $@ $< ${CFLAGS}
obj/%.o: ../../deps/tinydtls/sha2/%.c
	${CC} -c -o $@ $< ${CFLAGS}
obj/%.o: ../../deps/tinydtls/ecc/%.c
	${CC} -c -o $@ $< ${CFLAGS}
server: output_dir ${OBJ}
	${CC} -o $@ ${OBJ} ../../apps/server.c ${CFLAGS} -lm
client: output_dir ${OBJ}
	${CC} -o $@ ${OBJ} ../../apps/client.c ${CFLAGS} -lm
clean:
	rm -rf obj/* server client
