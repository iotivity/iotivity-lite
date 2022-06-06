include ../setup.mk

ROOT_DIR =../../..
MBEDTLS_DIR := $(ROOT_DIR)/deps/mbedtls

DTLS += aes.c  aesni.c 	asn1parse.c	asn1write.c	base64.c  bignum.c \
	camellia.c	ccm.c  cipher.c	cipher_wrap.c	 cmac.c  ctr_drbg.c	des.c  \
	dhm.c  ecdh.c  ecdsa.c	ecjpake.c	ecp.c  ecp_curves.c	entropy.c	entropy_poll.c	error.c		\
	gcm.c  hmac_drbg.c	md.c  md5.c  oid.c	 padlock.c	pem.c\
	pk.c	pk_wrap.c	pkcs12.c	pkcs5.c		pkparse.c	 pkwrite.c	platform.c	ripemd160.c	rsa.c\
	sha1.c	sha256.c	sha512.c	threading.c	timing.c	version.c	version_features.c		\
	x509.c 	x509_crt.c	debug.c	 net_sockets.c  ssl_cache.c	ssl_ciphersuites.c \
	ssl_cli.c	ssl_cookie.c	 ssl_srv.c	ssl_ticket.c	ssl_tls.c	x509write_csr.c\
	x509write_crt.c	x509_create.c	platform_util.c ssl_msg.c constant_time.c \
	nist_kw.c aria.c rsa_alt_helpers.c

DTLSFLAGS=$(addprefix -I$(ROOT_DIR)/, security deps/mbedtls/include) -D__OC_RANDOM

CBOR+=$(addprefix $(ROOT_DIR)/deps/tinycbor/src/, cborencoder.c cborencoder_close_container_checked.c cborparser.c)

SRC_COMMON=$(wildcard  $(ROOT_DIR)/util/*.c) $(CBOR)
SRC=$(wildcard $(ROOT_DIR)/messaging/coap/*.c $(ROOT_DIR)/api/*.c *.c )

# Arduino ethernet and iotivity constrained includes

LIB_HEADERS   =-I$(ARDUINO_DIR)/libraries/Ethernet2/src/utility -I$(ARDUINO_DIR)/libraries/SdFat/src/FatLib
DEPS_HEADERS  =$(addprefix -I../deps/, pRNG  wiz5500 sdFat serial)
CORE_HEADERS  =$(addprefix -I$(ROOT_DIR)/, messaging/coap util util/pt include  api port .)
CFLAGS += -I. $(CORE_HEADERS) $(LIB_HEADERS) $(DEPS_HEADERS)

ifeq ($(VERBOSE),1)
	CFLAGS += -DOC_DEBUG -DOC_LOG_L1
else ifeq ($(VERBOSE),2)
	CFLAGS += -DOC_DEBUG  -DOC_LOG_L2
endif

ifeq ($(DYNAMIC),1)
	CFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifeq ($(SECURE),1)
	SEC_SRC += $(addprefix $(ROOT_DIR)/security/, oc_acl.c oc_cred.c oc_doxm.c oc_pstat.c \
	              oc_tls.c oc_svr.c oc_store.c oc_pki.c oc_certs.c oc_sp.c oc_keypair.c oc_csr.c oc_roles.c)
	SRC += $(SEC_SRC)
	SRC_COMMON += $(addprefix $(MBEDTLS_DIR)/library/,${DTLS})
	MBEDTLS_PATCH_FILE := $(MBEDTLS_DIR)/patched.txt
ifneq ($(DYNAMIC),1)
	SRC_COMMON +=$(MBEDTLS_DIR)/library/memory_buffer_alloc.c
endif
	CFLAGS += ${DTLSFLAGS} -DOC_SECURITY
endif

ifeq ($(IPV4),1)
	CFLAGS += -DOC_IPV4
endif

ifeq ($(COLLECTIONS),1)
	CFLAGS += -DOC_COLLECTIONS
endif

ifeq ($(APP),server)
	CFLAGS 	+= -DOC_SERVER
endif

ifeq ($(APP),client)
	CFLAGS 	+= -DOC_CLIENT
endif

LOCAL_C_SRCS += $(SRC_COMMON)
LOCAL_C_SRCS += $(SRC)

${SRC} ${SRC_COMMON}: $(MBEDTLS_PATCH_FILE)

VPATH=$(ROOT_DIR)/messaging/coap/:$(ROOT_DIR)/util/:$(ROOT_DIR)/api/:$(ROOT_DIR)/deps/tinycbor/src/:$(MBEDTLS_DIR)/library:$(ROOT_DIR)/security:

ifeq ($(ARCH),avr)
	include ../avr.mk

else ifeq ($(ARCH),sam)
	include ../sam.mk

else ifeq ($(ARCH),samd)
	include ../samd.mk

else
$(error Target Architecture must be define to proceed!)
endif

build-$(BOARD_TAG)/libarduino-adapter.a: $(LOCAL_OBJS)
	$(AR) rcs $@ $(LOCAL_OBJS)

ifneq ($(SECURE),0)
MBEDTLS_PATCHES = $(sort $(wildcard ../../../patches/*.patch) $(wildcard ../../patches/make/*.patch))
MBEDTLS_ARDUINO_PATCH=../patches/mbedtls_arduino.patch
$(MBEDTLS_PATCH_FILE):$(MBEDTLS_PATCHES) $(MBEDTLS_ARDUINO_PATCH)
	if [ -d ${MBEDTLS_DIR} ]; then \
	cd ${MBEDTLS_DIR} && \
	git clean -fdx  && \
	git reset --hard && \
	cd -; \
	fi && \
	git submodule update --init && \
	cd ${MBEDTLS_DIR} && \
	for patch in $(MBEDTLS_PATCHES); do patch -r - -s -N -p1 < `echo $${patch} | sed 's/..\///'`; done && \
	patch -r - -s -N -p1 < `echo $(MBEDTLS_ARDUINO_PATCH) | sed 's/..\/\(.*\)/..\/..\/port\/arduino\/\1/'` && \
	echo "Patches applied in $^" > ${@F}
endif

