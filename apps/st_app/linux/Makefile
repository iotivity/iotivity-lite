# This Makefile can build only with prebuilt script
# After you make prebuilt forder in ${workspace}/prebuilt,
# You can use this makefile to build st_things app.
# (You can find ${workspace}/tools/make_prebuilt.py)

CC = gcc
CFLAGS=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../ -I../../ -I../../include/ -std=gnu99 -Wall -Wextra #-Wl,-Map,client.map
CFLAGS += -I./include
LIBS?= -lm -pthread -lrt
ROOT_DIR = ..
ARCH := $(shell arch)

DEVICE_DEF=$(ROOT_DIR)/prebuilt/json/st_device_def
JSON_FILE := $(wildcard $(ROOT_DIR)/prebuilt/json/*.json)
DEVICE_DEF_HEADER=$(ROOT_DIR)/prebuilt/include/st_device_def.h
ifeq ($(ARCH), x86_64)
	JSON_TO_CBOR=$(ROOT_DIR)/tools/json/json2cbor
else
	JSON_TO_CBOR=$(ROOT_DIR)/tools/json/json2cbor_32
endif

all: st_things

st_things: make_device_def
	@mkdir -p $@_creds
	${CC} -o $@ st_ref_app.c  \
			lib/libst-app-framework.a ${CFLAGS} ${LIBS}

make_device_def: validate_json
	$(info make new st_device_def file using $(JSON_FILE))
	$(shell $(JSON_TO_CBOR) $(JSON_FILE) > $(DEVICE_DEF))
	$(shell xxd -i $(DEVICE_DEF) > $(DEVICE_DEF_HEADER))
	$(shell sed -i 's/_.*st_device_def/st_device_def/g' $(DEVICE_DEF_HEADER))

validate_json:
ifneq ("$(wildcard $(DEVICE_DEF_HEADER))","")
else
ifneq ("$(wildcard $(JSON_FILE))", "")
else
	$(error please use proper json file in json)
endif
ifneq ($(words $(JSON_FILE)), 1)
	$(error please use 1 json file in json)
endif
endif

clean:
	rm -rf $(ROOT_DIR)/prebuilt/st_things $(ROOT_DIR)/prebuilt/st_things_creds

cleanall: clean
	rm -rf $(ROOT_DIR)/prebuilt/include/st_device_def.h $(ROOT_DIR)/prebuilt/json/st_device_def