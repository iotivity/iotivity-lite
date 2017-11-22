CC = gcc
SED = sed

OPENTHREAD_PATH=../../../openthread
OPENTHREAD_LIB_PATH=../../../openthread/output/x86_64-unknown-linux-gnu/lib
OPENTHREAD_BOARD=posix

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
SRC=$(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/openthread/*.c)
SRC_CPP=$(wildcard ../../port/openthread/*.cpp)

HEADERS = $(wildcard ../../include/*.h)
HEADERS += ../../port/openthread/config.h

HEADERS_COAP = $(wildcard ../../messaging/coap/*.h)
HEADERS_UTIL = $(wildcard ../../util/*.h)
HEADERS_UTIL_PT = $(wildcard ../../util/pt/*.h)
HEADERS_PORT = $(wildcard ../../port/*.h)
HEADERS_TINYCBOR = $(wildcard ../../deps/tinycbor/src/*.h)

CFLAGS  = -Wall -Wextra -Werror -fPIC 
CFLAGS += -I./ -I../../include/ -I../../ -I../
CFLAGS += -I${OPENTHREAD_PATH} -I${OPENTHREAD_PATH}/output/include -I${OPENTHREAD_PATH}/src/core
CFLAGS += -I${OPENTHREAD_PATH}/third_party/mbedtls/repo.patched/include

CFLAGS += -DOPENTHREAD_FTD

OBJ_COMMON=$(addprefix obj/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CPP=$(addprefix obj/cpp/,$(notdir $(SRC_CPP:.cpp=.o)))
OBJ_CLIENT=$(addprefix obj/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix obj/server/,$(notdir $(SRC:.c=.o)))
OBJ_CLIENT_SERVER=$(addprefix obj/client_server/,$(notdir $(SRC:.c=.o)))
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:../../deps/mbedtls/library:
LIBS?= -L${OPENTHREAD_LIB_PATH} -lopenthread-ftd -lopenthread-${OPENTHREAD_BOARD} \
	   -lmbedcrypto -lopenthread-diag -lstdc++ 

SAMPLES = client server

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

SAMPLES_CREDS = $(addsuffix _creds, ${SAMPLES} ${OBT})

CONSTRAINED_LIBS = libiotivity-constrained-server.a libiotivity-constrained-client.a \
				   libiotivity-constrained-client-server.a

all: $(CONSTRAINED_LIBS) $(SAMPLES)

.PHONY: clean

obj/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ $< ${CFLAGS}

obj/cpp/%.o: %.cpp
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

libiotivity-constrained-server.a: $(OBJ_COMMON) $(OBJ_SERVER) $(OBJ_CPP)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_SERVER) $(OBJ_CPP)

libiotivity-constrained-client.a: $(OBJ_COMMON) $(OBJ_CLIENT) $(OBJ_CPP)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT) $(OBJ_CPP)

libiotivity-constrained-client-server.a: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CPP)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT_SERVER) $(OBJ_CPP)

server: libiotivity-constrained-server.a ../../apps/server_openthread.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/server_openthread.c libiotivity-constrained-server.a -DOC_SERVER ${CFLAGS} ${LIBS}

client: libiotivity-constrained-client.a ../../apps/client_openthread.c
	@mkdir -p $@_creds
	${CC} -o $@ ../../apps/client_openthread.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS} ${LIBS}

${OBT}: libiotivity-constrained-client.a
	@mkdir -p $@_creds
	${CC} -o $@ ../../onboarding_tool/obtmain.c libiotivity-constrained-client.a -DOC_CLIENT ${CFLAGS}  ${LIBS}

clean:
	rm -rf obj $(PC) $(CONSTRAINED_LIBS)

cleanall: clean
	rm -rf ${all} $(SAMPLES) $(TESTS) ${OBT} ${SAMPLES_CREDS}
