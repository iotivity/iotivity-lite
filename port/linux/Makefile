CC = gcc
SED = sed
INSTALL = install
CHECK_SCRIPT = ../../tools/check.py

DESTDIR ?= /usr/local
install_bin_dir?=${DESTDIR}/opt/iotivity-constrained/bin/
prefix = $(DESTDIR)
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
pkgconfigdir = $(libdir)/pkgconfig

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

CBOR=../../deps/tinycbor/src/cborencoder.c ../../deps/tinycbor/src/cborencoder_close_container_checked.c ../../deps/tinycbor/src/cborparser.c# ../../deps/tinycbor/src/cbortojson.c ../../deps/tinycbor/src/cborpretty.c ../../deps/tinycbor/src/cborparser_dup_string.c

SRC_COMMON=$(wildcard ../../util/*.c) ${CBOR}
SRC=$(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/linux/*.c)

HEADERS = $(wildcard ../../include/*.h)
HEADERS += ../../port/linux/config.h

HEADERS_COAP = $(wildcard ../../messaging/coap/*.h)
HEADERS_UTIL = $(wildcard ../../util/*.h)
HEADERS_UTIL_PT = $(wildcard ../../util/pt/*.h)
HEADERS_PORT = $(wildcard ../../port/*.h)
HEADERS_TINYCBOR = $(wildcard ../../deps/tinycbor/src/*.h)

CFLAGS=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../../include/ -I../../ -std=gnu99 -Wall -Wextra -Werror -pedantic #-Wl,-Map,client.map
OBJ_COMMON=$(addprefix obj/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix obj/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix obj/server/,$(filter-out oc_obt.o,$(notdir $(SRC:.c=.o))))
OBJ_CLIENT_SERVER=$(addprefix obj/client_server/,$(notdir $(SRC:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:../../deps/mbedtls/library:
LIBS?= -lm -pthread -lrt

SAMPLES = server client temp_sensor simpleserver simpleclient client_collections_linux \
	  server_collections_linux server_block_linux client_block_linux smart_home_server_linux multi_device_server multi_device_client smart_lock

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

ifeq ($(TCP),1)
	CFLAGS += -DOC_TCP
endif

SAMPLES_CREDS = $(addsuffix _creds, ${SAMPLES} ${OBT})

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

${OBT}: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../onboarding_tool/obtmain.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

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
	rm -rf ${all} $(SAMPLES) $(TESTS) ${OBT} ${SAMPLES_CREDS}

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
