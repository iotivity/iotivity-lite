OPENTHREAD_PATH = ../../../openthread
OPENTHREAD_BOARD = posix
OPENTHREAD_LIB_PATH = ${OPENTHREAD_PATH}/output/${OPENTHREAD_BOARD}/lib

include Makefile-${OPENTHREAD_BOARD}

PATH_OBJ = output/${OPENTHREAD_BOARD}/obj
PATH_BIN = output/${OPENTHREAD_BOARD}/bin

CBOR = \
	../../deps/tinycbor/src/cborencoder.c \
	../../deps/tinycbor/src/cborencoder_close_container_checked.c \
	../../deps/tinycbor/src/cborparser.c
# ../../deps/tinycbor/src/cbortojson.c
# ../../deps/tinycbor/src/cborpretty.c
# ../../deps/tinycbor/src/cborparser_dup_string.c

SRC_COMMON =  $(wildcard ../../util/*.c) ${CBOR} 
SRC_COMMON += $(wildcard ../../messaging/coap/*.c ../../api/*.c ../../port/openthread/*.c*)

SRC_CLIENT = $(SRC_COMMON) ../../apps/client_openthread.c
SRC_SERVER = $(SRC_COMMON) ../../apps/server_openthread.c

OBJ_CLIENT = $(addprefix ${PATH_OBJ}/client/, $(addsuffix .o, $(basename $(notdir $(SRC_CLIENT)))))
OBJ_SERVER = $(addprefix ${PATH_OBJ}/server/, $(addsuffix .o, $(basename $(notdir $(SRC_SERVER)))))

CFLAGS += -Wall -Wextra
CFLAGS += -I./ -I../../include/ -I../../ -I../
CFLAGS += -I${OPENTHREAD_PATH} -I${OPENTHREAD_PATH}/output/include -I${OPENTHREAD_PATH}/src/core
CFLAGS += -I${OPENTHREAD_PATH}/third_party/mbedtls/repo.patched/include
CFLAGS += -DOPENTHREAD_FTD 

VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:../../apps:

LIBS = -L${OPENTHREAD_LIB_PATH} -lopenthread-ftd -lmbedcrypto \
       -lopenthread-${OPENTHREAD_BOARD} -lopenthread-diag ${BOARD_LIBS}

ifeq ($(RETARGET),1)
	CFLAGS += -DOC_RETARGET
endif

ifeq ($(DEBUG),1)
	CFLAGS += -DOC_DEBUG -g -O0
else
	CFLAGS += -g -O0
endif

ifeq ($(SECURE),1)
	SRC_COMMON += oc_acl.c oc_cred.c oc_doxm.c oc_pstat.c oc_dtls.c oc_svr.c oc_store.c
	SRC_COMMON += memory_buffer_alloc.c
	CFLAGS += -DOC_SECURITY
endif

CXXFLAGS := ${CFLAGS}

CFLAGS += -std=c99

SAMPLES = ${PATH_BIN}/server ${PATH_BIN}/client

all: $(SAMPLES)

.PHONY: clean cleanall

-include ${PATH_OBJ}/*.d
-include ${PATH_OBJ}/client/*.d
-include ${PATH_OBJ}/server/*.d

${PATH_OBJ}/server/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ ${CFLAGS} -DOC_SERVER -MMD $<

${PATH_OBJ}/server/%.o: %.cpp
	@mkdir -p ${@D}
	${CC} -c -o $@ ${CXXFLAGS} -DOC_SERVER -MMD $<

${PATH_OBJ}/client/%.o: %.c
	@mkdir -p ${@D}
	${CC} -c -o $@ ${CFLAGS} -DOC_CLIENT -MMD $<

${PATH_OBJ}/client/%.o: %.cpp
	@mkdir -p ${@D}
	${CC} -c -o $@ ${CXXFLAGS} -DOC_CLIENT -MMD $<

${PATH_BIN}/server: ${OBJ_SERVER}
	@mkdir -p ${@D}
	${CC} -o $@ $(OBJ_SERVER) ${CFLAGS} ${LDFLAGS} ${LIBS}

${PATH_BIN}/client: ${OBJ_CLIENT}
	@mkdir -p ${@D}
	${CC} -o $@ $(OBJ_CLIENT) ${CFLAGS} ${LDFLAGS} ${LIBS}

clean:
	rm -rf ${PATH_OBJ}

cleanall: clean
	rm -rf ${PATH_BIN}

