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

ASRCS		=
CSRCS		=

CSRCS		+= iotivity-constrained/deps/tinycbor/src/cborencoder.c \
			   iotivity-constrained/deps/tinycbor/src/cborencoder_close_container_checked.c \
			   iotivity-constrained/deps/tinycbor/src/cborparser.c \
			   $(wildcard iotivity-constrained/util/*.c) \
			   $(wildcard iotivity-constrained/messaging/coap/*.c) \
			   $(wildcard iotivity-constrained/api/*.c) \
			   $(wildcard iotivity-constrained/port/tizenrt/*.c) \
			   iotivity-constrained/security/oc_acl.c \
			   iotivity-constrained/security/oc_cred.c \
			   iotivity-constrained/security/oc_doxm.c \
			   iotivity-constrained/security/oc_pstat.c \
			   iotivity-constrained/security/oc_svr.c \
			   iotivity-constrained/security/oc_store.c\
			   iotivity-constrained/security/oc_obt.c

OSRCS_C		+= iotivity-constrained/deps/tinycbor/src/cborencoder.o \
			   iotivity-constrained/deps/tinycbor/src/cborencoder_close_container_checked.o \
			   iotivity-constrained/deps/tinycbor/src/cborparser.o \
			   $(wildcard iotivity-constrained/util/*.o) \
			   $(wildcard iotivity-constrained/messaging/coap/*.o) \
			   $(wildcard iotivity-constrained/api/*.o) \
			   $(wildcard iotivity-constrained/port/tizenrt/*.o) \
			   iotivity-constrained/security/oc_acl.o \
			   iotivity-constrained/security/oc_cred.o \
			   iotivity-constrained/security/oc_doxm.o \
			   iotivity-constrained/security/oc_pstat.o \
			   iotivity-constrained/security/oc_svr.o \
			   iotivity-constrained/security/oc_store.o\
			   iotivity-constrained/security/oc_obt.o

CFLAGS:=$(filter-out -Wshadow,$(CFLAGS))
CFLAGS:=$(filter-out -Wundef,$(CFLAGS))
#-DOC_COLLECTIONS
CFLAGS 		+= -D__TIZENRT__ -DOC_TCP -DOC_CLIENT -DOCF_12 -DOC_IPV4 -DOC_DEBUG -DOC_SERVER -DOC_DYNAMIC_ALLOCATION -DOC_PROCESS_CONF_NO_OC_PROCESS_NAMES=0 -DOC_PROCESS_CONF_STATS=0 -std=gnu99
CFLAGS		+= -Itinycbor/src/ \
			   -Iiotivity-constrained/ \
			   -Iiotivity-constrained/include \
			   -Iiotivity-constrained/security \
			   -Iiotivity-constrained/port \
			   -Iiotivity-constrained/port/tizenrt

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

VPATH		=

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
