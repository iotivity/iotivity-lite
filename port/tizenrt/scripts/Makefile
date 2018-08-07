###########################################################################
#
# Copyright 2016 Samsung Electronics All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
###########################################################################

-include $(TOPDIR)/.config
-include $(TOPDIR)/Make.defs

IOTCONS_ROOT_DIR = $(TOPDIR)/../external/iotivity-constrained/iotivity-constrained

MBEDTLS_DIR=$(IOTCONS_ROOT_DIR)/deps/mbedtls
OS_HEADER  := $(TOPDIR)/include
WIFI_HEADER := $(TOPDIR)/../framework/include
SLSI_HEADER := $(TOPDIR)/../external/include

DTLS_TAG ?= mbedtls-2.7.0
DTLS=   aes.c       aesni.c     arc4.c      asn1parse.c asn1write.c base64.c    \
	bignum.c    blowfish.c  camellia.c  ccm.c       cipher.c    cipher_wrap.c   \
	cmac.c      ctr_drbg.c  des.c       dhm.c       ecdh.c      ecdsa.c     \
	ecjpake.c   ecp.c       ecp_curves.c    entropy.c   entropy_poll.c  error.c     \
	gcm.c       havege.c    hmac_drbg.c md.c        md2.c       md4.c       \
	md5.c       md_wrap.c   oid.c       padlock.c   \
	pem.c       pk.c        pk_wrap.c   pkcs12.c    pkcs5.c     pkparse.c   \
	pkwrite.c   platform.c  ripemd160.c rsa.c       sha1.c      sha256.c    \
	sha512.c    threading.c timing.c    version.c   version_features.c      \
	xtea.c      pkcs11.c    x509.c      x509_crt.c  debug.c     net_sockets.c   \
	ssl_cache.c ssl_ciphersuites.c      ssl_cli.c   ssl_cookie.c            \
	ssl_srv.c   ssl_ticket.c    ssl_tls.c   rsa_internal.c

DTLSFLAGS=-I$(MBEDTLS_DIR)/include/ -D__OC_RANDOM

ifeq ($(CONFIG_IOTLITE_DYNAMIC),y)
	CFLAGS += -DOC_DYNAMIC_ALLOCATION
endif

ifeq ($(CONFIG_IOTLITE_SECURE),y)
	CSRCS   += $(addprefix $(IOTCONS_ROOT_DIR)/security/,oc_acl.c oc_cred.c oc_doxm.c oc_pstat.c oc_tls.c oc_svr.c oc_store.c oc_otm_state.c)
	OSRCS_C += $(IOTCONS_ROOT_DIR)/security/oc_acl.o) \
			+= $(IOTCONS_ROOT_DIR)/security/oc_cred.o) \
			+= $(IOTCONS_ROOT_DIR)/security/oc_doxm.o) \
			+= $(IOTCONS_ROOT_DIR)/security/oc_pstat.o) \
			+= $(IOTCONS_ROOT_DIR)/security/oc_tls.o) \
			+= $(IOTCONS_ROOT_DIR)/security/oc_svr.o) \
			+= $(IOTCONS_ROOT_DIR)/security/oc_store.o) \
			+= $(IOTCONS_ROOT_DIR)/security/oc_otm_state.o)

	CSRCS	+= $(addprefix $(MBEDTLS_DIR)/library/,${DTLS})
	MBEDTLS_PATCH_FILE := $(MBEDTLS_DIR)/patched.txt
ifeq ($(CONFIG_IOTLITE_DYNAMIC),y)
	CSRCS += $(IOTCONS_ROOT_DIR)/security/oc_obt.c
	OSRCS_C += iotivity-constrained/security/oc_obt.o
else
	CSRCS += $(MBEDTLS_DIR)/library/memory_buffer_alloc.c
	OSRCS_C += $(MBEDTLS_DIR)/library/memory_buffer_alloc.o
endif
	CFLAGS += ${DTLSFLAGS}
	OSRCS_C += $(wildcard $(MBEDTLS_DIR)/library/*.o)
	CFLAGS += -DOC_SECURITY

	VPATH += $(IOTCONS_ROOT_DIR)/security/:$(MBEDTLS_DIR)/library:
endif

ifeq ($(CONFIG_IOTLITE_CLOUD_ACCESS),y)
	CSRCS += iotivity-constrained/service/cloud-access/src/cloud_access.c
	OSRCS_C += iotivity-constrained/service/cloud-access/src/cloud_access.o
ifeq ($(CONFIG_IOTLITE_RD),y)
	CSRCS += iotivity-constrained/service/resource-directory/client/src/rd_client.c
	OSRCS_C += iotivity-constrained/service/resource-directory/client/src/rd_client.o
endif
	CFLAGS  += -Iiotivity-constrained/service/cloud-access/include \
			   -Iiotivity-constrained/service/resource-directory/client/include
endif

CSRCS		+= iotivity-constrained/deps/tinycbor/src/cborencoder.c \
			   iotivity-constrained/deps/tinycbor/src/cborencoder_close_container_checked.c \
			   iotivity-constrained/deps/tinycbor/src/cborparser.c \
			   $(wildcard iotivity-constrained/util/*.c) \
			   $(wildcard iotivity-constrained/messaging/coap/*.c) \
			   $(wildcard iotivity-constrained/api/*.c) \
			   $(wildcard iotivity-constrained/port/tizenrt/*.c)

OSRCS_C		+= iotivity-constrained/deps/tinycbor/src/cborencoder.o \
			   iotivity-constrained/deps/tinycbor/src/cborencoder_close_container_checked.o \
			   iotivity-constrained/deps/tinycbor/src/cborparser.o \
			   $(wildcard iotivity-constrained/util/*.o) \
			   $(wildcard iotivity-constrained/messaging/coap/*.o) \
			   $(wildcard iotivity-constrained/api/*.o) \
			   $(wildcard iotivity-constrained/port/tizenrt/*.o)

ifeq ($(CONFIG_IOTLITE_EASYSETUP), y)
CSRCS		+= $(wildcard iotivity-constrained/service/easy-setup/enrollee/*.c) \
			   $(wildcard iotivity-constrained/service/easy-setup/enrollee/samsung/sc_easysetup.c)
OSRCS_C		+= $(wildcard iotivity-constrained/service/easy-setup/enrollee/*.o) \
			   $(wildcard iotivity-constrained/service/easy-setup/enrollee/samsung/sc_easysetup.o)
CFLAGS		+= -Iiotivity-constrained/service/easy-setup/enrollee/include \
		    -Iiotivity-constrained/service/easy-setup/enrollee
endif

ifeq ($(CONFIG_IOTLITE_ST_APP_FW),y)
CSRCS       += $(wildcard iotivity-constrained/service/st-app-fw/src/*.c) \
			   $(wildcard iotivity-constrained/service/st-app-fw/src/port/tizenrt/*.c)
OSRCS_C     += $(wildcard iotivity-constrained/service/st-app-fw/src/*.o) \
			   $(wildcard iotivity-constrained/service/st-app-fw/src/port/tizenrt/*.o)
CFLAGS      += -Iiotivity-constrained/service/st-app-fw/include
endif

ifeq ($(CONFIG_IOTLITE_FOTA),y)
CSRCS       += $(wildcard iotivity-constrained/service/fota/src/*.c)
OSRCS_C     += $(wildcard iotivity-constrained/service/fota/src/*.o)
EXTRA_CFLAGS=-Iiotivity-constrained/service/fota/include
endif

CFLAGS += -DST_APP_FW
CFLAGS += -DWIFI_SCAN_IN_SOFT_AP_SUPPORTED


ifeq ($(CONFIG_IOTLITE_IPV4),y)
	EXTRA_CFLAGS += -DOC_IPV4
endif

ifeq ($(CONFIG_IOTLITE_DEBUG),y)
	EXTRA_CFLAGS += -DOC_DEBUG
endif

ifeq ($(CONFIG_IOTLITE_TCP),y)
	EXTRA_CFLAGS += -DOC_TCP
endif

ifeq ($(CONFIG_WIFI_MANAGER),y)
	EXTRA_CFLAGS += -DTIZEN_RT_WIFI_MANAGER
endif

ifeq ($(CONFIG_IOTLITE_SECURE),y)
ifneq ($(CONFIG_IOTLITE_AUTH_OPTION),n)
CFLAGS += -DOC_LOAD_CA
ifeq ($(CONFIG_IOTLITE_AUTH_OPTION),y)
CFLAGS += -DOC_UNLOAD_CERT
endif
else
CFLAGS += -DOC_SKIP_CERT
endif
endif

ifeq ($(CONFIG_IOTLITE_OPTIMIZE),y)
	CFLAGS += -DST_APP_OPTIMIZATION
endif


EXTRA_CFLAGS += -I$(WIFI_HEADER)
EXTRA_CFLAGS += -I$(SLSI_HEADER)
CFLAGS:=$(filter-out -Wshadow,$(CFLAGS))
CFLAGS:=$(filter-out -Wundef,$(CFLAGS))
CFLAGS += -D__TIZENRT__ -DOC_SPEC_VER_OIC -DOC_CLIENT -DOC_SERVER -DOC_PROCESS_CONF_NO_OC_PROCESS_NAMES=0 -DOC_PROCESS_CONF_STATS=0 -std=gnu99
EXTRA_CFLAGS += -I$(OS_HEADER)
CFLAGS += $(EXTRA_CFLAGS)
CFLAGS		+= -Itinycbor/src/ \
			   -Iiotivity-constrained/ \
			   -Iiotivity-constrained/include \
			   -Iiotivity-constrained/security \
			   -Iiotivity-constrained/port \
			   -Iiotivity-constrained/port/tizenrt \
			   -Iiotivity-constrained/util

AOBJS		= $(ASRCS:.S=$(OBJEXT))
COBJS		= $(CSRCS:.c=$(OBJEXT))

SRCS		= $(ASRCS) $(CSRCS)
OBJS		= $(AOBJS) $(COBJS)

ifeq ($(CONFIG_WINDOWS_NATIVE),y)
  BIN		= ..\libexternal$(LIBEXT)
else
ifeq ($(WINTOOL),y)
  BIN		= ..\\libexternal$(LIBEXT)
else
  BIN		= ../libexternal$(LIBEXT)
endif
endif

DEPPATH	= --dep-path .

# Common build

VPATH		= $(MBEDTLS_DIR)/library:

ifeq ($(CONFIG_IOTLITE_SECURE),y)
MBEDTLS_PATCHES ?= $(sort $(wildcard $(IOTCONS_ROOT_DIR)/patches/*.patch))
${MBEDTLS_DIR}/.git:
	git submodule update --init ${@D}

$(MBEDTLS_PATCH_FILE): ${MBEDTLS_DIR}/.git ${MBEDTLS_PATCHES}
	if [ -d ${MBEDTLS_DIR}  ]; then \
	cd ${MBEDTLS_DIR} && \
	git clean -fdx . && \
	git reset --hard && \
	git fetch && \
	git reset --hard ${DTLS_TAG} && \
	cd -; \
	fi && \
	git submodule update --init && \
	cd ${MBEDTLS_DIR} && \
	for patch in $(MBEDTLS_PATCHES); do patch -r - -s -N -p1 < $${patch} ; done && \
	echo "Patches applied in $^" > ${@F}
endif

all: .built
.PHONY: depend clean distclean

$(AOBJS): %$(OBJEXT): %.S
	$(call ASSEMBLE, $<, $@)

$(COBJS): %$(OBJEXT): %.c
	$(call COMPILE, $<, $@)

.built: $(OBJS)
	$(call ARCHIVE, $(BIN), $(OBJS))
	$(Q) touch .built

.depend: Makefile $(SRCS)
	$(Q) $(MKDEP) $(DEPPATH) "$(CC)" -- $(CFLAGS) -- $(SRCS) >Make.dep
	$(Q) touch $@

depend: .depend

clean:
	$(call DELFILE, .built)
	$(call CLEAN)
	rm -f $(OBJS)

distclean: clean
	$(call DELFILE, Make.dep)
	$(call DELFILE, .depend)

-include Make.dep
