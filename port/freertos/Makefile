#!/usr/bin/make -f
# -*- makefile -*-
# ex: set tabstop=4 noexpandtab:
#{
# Copyright 2018 Samsung Electronics France SAS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#}

port?=$(shell basename -- "${CURDIR}")
DESTDIR ?=
extradir?=${DESTDIR}/${libdir}/iotivity-constrained/
prefix ?= /usr
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
libdir ?= $(exec_prefix)/lib
includedir ?= $(prefix)/include
pkgconfigdir ?= $(libdir)/pkgconfig
topdir?=../..
portdir?=${topdir}/port/${port}

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
DTLSFLAGS=-I${topdir}/deps/mbedtls/include -D__OC_RANDOM

CBOR=${topdir}/deps/tinycbor/src/cborencoder.c ${topdir}/deps/tinycbor/src/cborencoder_close_container_checked.c ${topdir}/deps/tinycbor/src/cborparser.c
MBEDTLS_DIR := ${topdir}/deps/mbedtls

SRC_COMMON=$(wildcard ${topdir}/util/*.c) ${CBOR}
SRC=$(wildcard ${topdir}/messaging/coap/*.c ${topdir}/api/*.c ${portdir}/*.c)

HEADERS = $(wildcard ${topdir}/include/*.h)
HEADERS += ${portdir}/config.h

HEADERS_COAP = $(wildcard ${topdir}/messaging/coap/*.h)
HEADERS_UTIL = $(wildcard ${topdir}/util/*.h)
HEADERS_UTIL_PT = $(wildcard ${topdir}/util/pt/*.h)
HEADERS_PORT = $(wildcard ${topdir}/port/*.h)
HEADERS_TINYCBOR = $(wildcard ${topdir}/deps/tinycbor/*.h)

CFLAGS=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -std=gnu99
topdir?=${topdir}/

OBJ_COMMON=$(addprefix obj/,$(notdir $(SRC_COMMON:.c=.o)))
OBJ_CLIENT=$(addprefix obj/client/,$(notdir $(SRC:.c=.o)))
OBJ_SERVER=$(addprefix obj/server/,$(filter-out oc_obt.o,$(notdir $(SRC:.c=.o))))
OBJ_CLIENT_SERVER=$(addprefix obj/client_server/,$(notdir $(SRC:.c=.o)))
VPATH=${topdir}/messaging/coap/:${topdir}/util/:${topdir}/api/:${topdir}/deps/tinycbor/src/:${topdir}/deps/mbedtls/library:
LIBS?=

SAMPLES?= 

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
	MBEDTLS_PATCH_FILE := $(MBEDTLS_DIR)/patched.txt
ifeq ($(DYNAMIC),1)
	SRC_COMMON += ${DTLS}
	SRC += oc_obt.c
else
	SRC_COMMON += ${DTLS} memory_buffer_alloc.c
endif
	CFLAGS += ${DTLSFLAGS} -DOC_SECURITY
	VPATH += ${topdir}/security/:${topdir}/deps/mbedtls/library:
endif

CFLAGS+=-I${topdir}/include/ -I${topdir}
CFLAGS+=-I.

ifeq ($(IPV4),1)
	CFLAGS += -DOC_IPV4
endif

ifeq ($(TCP),1)
	CFLAGS += -DOC_TCP
endif

CFLAGS += -DSTATE_MODEL

SAMPLES_CREDS = $(addsuffix _creds, ${SAMPLES}

CONSTRAINED_LIBS = libiotivity-constrained-server.a libiotivity-constrained-client.a \
libiotivity-constrained-client-server.a


all: $(MBEDTLS_PATCH_FILE) $(CONSTRAINED_LIBS) $(SAMPLES)

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

libiotivity-constrained-client.a: $(OBJ_COMMON) $(OBJ_CLIENT)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT)

libiotivity-constrained-client-server.a: $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)
	$(AR) -rcs $@ $(OBJ_COMMON) $(OBJ_CLIENT_SERVER)


ifeq ($(SECURE),1)
$(MBEDTLS_PATCH_FILE):
	git submodule update --init && \
	cd $(MBEDTLS_DIR) && \
	git clean -fdx . && \
	git reset --hard && \
	patch -r - -s -N -p1 < ${topdir}/patches/mbedtls_ocf_patch_1 && \
	patch -r - -s -N -p1 < ${topdir}/patches/mbedtls_iotivity_constrained_patch_2 && \
	echo patches applied > $(MBEDTLS_PATCH_FILE)
endif

clean:
	rm -rf obj $(CONSTRAINED_LIBS)

cleanall: clean
	rm -rf ${all} $(SAMPLES) $(TESTS) ${SAMPLES_CREDS} $(MBEDTLS_PATCH_FILE)

distclean: cleanall

test:
	@echo "TODO: https://jira.iotivity.org/browse/LITE-4"
