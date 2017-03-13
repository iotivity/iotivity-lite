CC = gcc
SED = sed
INSTALL = install

DESTDIR ?= /usr/local
install_bin_dir?=${DESTDIR}/opt/iotivity-constrained/bin/
prefix = $(DESTDIR)
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
pkgconfigdir = $(libdir)/pkgconfig

DTLS=../../deps/tinydtls/ccm.c ../../deps/tinydtls/hmac.c ../../deps/tinydtls/netq.c ../../deps/tinydtls/peer.c ../../deps/tinydtls/dtls_time.c ../../deps/tinydtls/session.c ../../deps/tinydtls/sha2/sha2.c ../../deps/tinydtls/ecc/ecc.c ../../deps/tinydtls/aes/rijndael.c ../../deps/tinydtls/crypto.c ../../deps/tinydtls/dtls.c
DTLSFLAGS=-DDTLSV12 -DWITH_SHA256 -DDTLS_CHECK_CONTENTTYPE -DWITH_OCF -I../../deps/tinydtls -DNDEBUG

CBOR=../../deps/tinycbor/src/cborencoder.c ../../deps/tinycbor/src/cborencoder_close_container_checked.c ../../deps/tinycbor/src/cborparser.c #../../deps/tinycbor/src/cbortojson.c ../../deps/tinycbor/src/cborpretty.c ../../deps/tinycbor/src/cborparser_dup_string.c

SRC_COMMON=$(wildcard ../../util/*.c) ${CBOR}
SRC=$(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/linux/*.c)

HEADERS = $(wildcard ../../include/*.h)
HEADERS += ../../port/linux/config.h

HEADERS_COAP = $(wildcard ../../messaging/coap/*.h)
HEADERS_UTIL = $(wildcard ../../util/*.h)
HEADERS_UTIL_PT = $(wildcard ../../util/pt/*.h)
HEADERS_PORT = $(wildcard ../../port/*.h)
HEADERS_TINYCBOR = $(wildcard ../../deps/tinycbor/src/*.h)

CFLAGS=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../../include/ -I../../ -std=gnu99 -Wall #-Wextra -Werror -pedantic #-Wl,-Map,client.map
OBJ_COMMON=$(addprefix obj/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix obj/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix obj/server/,$(notdir $(SRC:.c=.o)))
OBJ_CLIENT_SERVER=$(addprefix obj/client_server/,$(notdir $(SRC:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:
LIBS?= -lm -pthread -lrt

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
	  server_collections_linux server_block_linux client_block_linux
CONSTRAINED_LIBS = libiotivity-constrained-server.a libiotivity-constrained-client.a \
		   libiotivity-constrained-server.so libiotivity-constrained-client.so \
		   libiotivity-constrained-client-server.so libiotivity-constrained-client-server.a
PC = iotivity-constrained-client.pc iotivity-constrained-server.pc \
     iotivity-constrained-client-server.pc

all: $(CONSTRAINED_LIBS) $(SAMPLES) $(PC)

.PHONY: clean

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

iotivity-constrained-server.pc: iotivity-constrained-server.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),'

iotivity-constrained-client.pc: iotivity-constrained-client.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),'

iotivity-constrained-client-server.pc: iotivity-constrained-client-server.pc.in
	$(SED) > $@ < $< \
		-e 's,@prefix@,$(prefix),' \
		-e 's,@exec_prefix@,$(exec_prefix),' \
		-e 's,@libdir@,$(libdir),' \
		-e 's,@includedir@,$(includedir),'

clean:
	rm -rf obj $(PC) $(CONSTRAINED_LIBS)

cleanall: clean
	rm -rf ${all} $(SAMPLES)

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
# Installing the samples
	$(INSTALL) -d ${install_bin_dir}
	$(INSTALL) $(SAMPLES) ${install_bin_dir}
