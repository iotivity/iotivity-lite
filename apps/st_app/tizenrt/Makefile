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
include $(APPDIR)/Make.defs

# Hello, World! built-in application info

APPNAME = stapp
FUNCNAME = $(APPNAME)_main
PRIORITY = SCHED_PRIORITY_DEFAULT
STACKSIZE = 8192
THREADEXEC = TASH_EXECMD_ASYNC

# Hello, World! Example

IOTCON_BASE_DIR = $(APPDIR)/../external/iotivity-constrained/iotivity-constrained

CFLAGS += -I$(IOTCON_BASE_DIR)/
CFLAGS += -I$(IOTCON_BASE_DIR)/include
CFLAGS += -I$(IOTCON_BASE_DIR)/port/tizenrt
CFLAGS += -I$(IOTCON_BASE_DIR)/port/
CFLAGS += -I$(IOTCON_BASE_DIR)/security
CFLAGS += -I$(IOTCON_BASE_DIR)/service/easy-setup/enrollee
CFLAGS += -I$(IOTCON_BASE_DIR)/service/easy-setup/enrollee/include
CFLAGS += -I$(IOTCON_BASE_DIR)/service/easy-setup/enrollee/include/samsung
CFLAGS += -I$(IOTCON_BASE_DIR)/service/cloud-access/include
CFLAGS += -I$(IOTCON_BASE_DIR)/service/resource-directory/client/include
CFLAGS += -I$(IOTCON_BASE_DIR)/service/st-app-fw/include

CFLAGS += -D__TIZENRT__ -DOC_SECURITY -DOC_CLIENT -DOC_IPV4 -DOC_DEBUG -DOC_SERVER -DOC_DYNAMIC_ALLOCATION -DOC_PROCESS_CONF_NO_OC_PROCESS_NAMES=0 -DOC_PROCESS_CONF_STATS=0 -std=gnu99


ASRCS =
CSRCS =

MAINSRC = tizenrt/st_ref_app.c tizenrt/port_tinyara.c

ifeq ($(CONFIG_IOTLITE_ST_APP_FW),y)
	ST_DEVICE_DEF= ./json/st_device_def
	ST_JSON_FILE := $(wildcard ./json/*.json)
	ST_DEVICE_DEF_HEADER=./tizenrt/st_device_def.h
ifeq ($(CONFIG_IOTLITE_ARCH), x86_64)
	JSON_TO_CBOR=$(IOTCON_BASE_DIR)/tools/json/json2cbor
else
	JSON_TO_CBOR=$(IOTCON_BASE_DIR)/tools/json/json2cbor_32
endif
	HEADER_DIR +=-I./tizenrt/
endif

prep_st_app_fw_json_present:
ifneq ("$(wildcard $(ST_DEVICE_DEF_HEADER))","")
else
ifneq ("$(wildcard $(ST_JSON_FILE))", "")
else
	$(error please use proper json file in apps/st_app/json)
endif
ifneq ($(words $(ST_JSON_FILE)), 1)
	$(error please use 1 json file in apps/st_app/json)
endif
endif

prep_st_app_fw_create_device_def: prep_st_app_fw_json_present
	$(info make new st_device_def file using $(ST_JSON_FILE))
	$(shell $(JSON_TO_CBOR) $(ST_JSON_FILE) > $(ST_DEVICE_DEF))
	$(shell xxd -i $(ST_DEVICE_DEF) > $(ST_DEVICE_DEF_HEADER))
	$(shell sed -i 's/_.*st_device_def/st_device_def/g' $(ST_DEVICE_DEF_HEADER))

AOBJS = $(ASRCS:.S=$(OBJEXT))
COBJS = $(CSRCS:.c=$(OBJEXT))
MAINOBJ = $(MAINSRC:.c=$(OBJEXT))

SRCS = $(ASRCS) $(CSRCS) $(MAINSRC)
OBJS = $(AOBJS) $(COBJS)

ifneq ($(CONFIG_BUILD_KERNEL),y)
  OBJS += $(MAINOBJ)
endif

ifeq ($(CONFIG_WINDOWS_NATIVE),y)
  BIN = ..\..\libapps$(LIBEXT)
else
ifeq ($(WINTOOL),y)
  BIN = ..\\..\\libapps$(LIBEXT)
else
  BIN = ../../libapps$(LIBEXT)
endif
endif

ifeq ($(WINTOOL),y)
  INSTALL_DIR = "${shell cygpath -w $(BIN_DIR)}"
else
  INSTALL_DIR = $(BIN_DIR)
endif

CONFIG_EXAMPLES_STAPP_PROGNAME ?= iotlite$(EXEEXT)
PROGNAME = $(CONFIG_EXAMPLES_STAPP_PROGNAME)

ROOTDEPPATH = --dep-path .

# Common build

VPATH =

all: .built
.PHONY: clean depend distclean

$(AOBJS): %$(OBJEXT): %.S
	$(call ASSEMBLE, $<, $@)

$(COBJS) $(MAINOBJ): %$(OBJEXT): %.c
	$(call COMPILE, $<, $@)

.built: $(OBJS)
	$(call ARCHIVE, $(BIN), $(OBJS))
	@touch .built

ifeq ($(CONFIG_BUILD_KERNEL),y)
$(BIN_DIR)$(DELIM)$(PROGNAME): $(OBJS) $(MAINOBJ)
	@echo "LD: $(PROGNAME)"
	$(Q) $(LD) $(LDELFFLAGS) $(LDLIBPATH) -o $(INSTALL_DIR)$(DELIM)$(PROGNAME) $(ARCHCRT0OBJ) $(MAINOBJ) $(LDLIBS)
	$(Q) $(NM) -u  $(INSTALL_DIR)$(DELIM)$(PROGNAME)

install: $(BIN_DIR)$(DELIM)$(PROGNAME)

else
install:

endif

ifeq ($(CONFIG_BUILTIN_APPS)$(CONFIG_EXAMPLES_STAPP),yy)
$(BUILTIN_REGISTRY)$(DELIM)$(FUNCNAME).bdat: $(DEPCONFIG) Makefile
	$(Q) $(call REGISTER,$(APPNAME),$(FUNCNAME),$(THREADEXEC),$(PRIORITY),$(STACKSIZE))

context: $(BUILTIN_REGISTRY)$(DELIM)$(FUNCNAME).bdat

else
context:

endif

.depend: Makefile $(SRCS)
	@$(MKDEP) $(ROOTDEPPATH) "$(CC)" -- $(CFLAGS) -- $(SRCS) >Make.dep
	@touch $@

depend: json_file_create .depend

clean:
	$(call DELFILE, .built)
	$(call CLEAN)

distclean: clean
	$(call DELFILE, Make.dep)
	$(call DELFILE, .depend)

json_file_create: prep_st_app_fw_create_device_def
	echo "json file created"

-include Make.dep
.PHONY: preconfig
preconfig:
