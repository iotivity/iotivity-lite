ifeq ($(CLIENT),1)
	APP_SRC = ../../apps/client_riot.c
else
	APP_SRC = ../../apps/server_riot.c
	SERVER=1
endif

APPLICATION = ocf_app

#Set RIOTBASE appropriately below.
RIOTBASE ?= ${HOME}/RIOT/
BOARD ?= native

BOARD_INSUFFICIENT_MEMORY := airfy-beacon chronos msb-430 msb-430h nrf51dongle \
                          nrf6310 nucleo-f103 nucleo-f334 pca10000 pca10005 spark-core \
                          stm32f0discovery telosb weio wsn430-v1_3b wsn430-v1_4 \
                          yunjia-nrf51822 z1 nucleo-f072

USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6
USEMODULE += gnrc_conn_udp
USEMODULE += pthread
USEMODULE += gnrc_ndp_router
USEMODULE += gnrc_icmpv6_echo
USEMODULE += gnrc_ipv6_router_default
#USEMODULE += gnrc_rpl
#USEMODULE += auto_init_gnrc_rpl

CFLAGS = -std=gnu99 -I./ -I../../include/ -I../../ #-fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow

CBOR = ../../deps/tinycbor/src/cborencoder.c ../../deps/tinycbor/src/cborencoder_close_container_checked.c ../../deps/tinycbor/src/cborparser.c

DTLS=../../deps/tinydtls/ccm.c ../../deps/tinydtls/hmac.c ../../deps/tinydtls/netq.c ../../deps/tinydtls/peer.c ../../deps/tinydtls/dtls_time.c ../../deps/tinydtls/session.c ../../deps/tinydtls/sha2/sha2.c ../../deps/tinydtls/ecc/ecc.c ../../deps/tinydtls/aes/rijndael.c ../../deps/tinydtls/crypto.c ../../deps/tinydtls/dtls.c

DTLSFLAGS=-DDTLSV12 -DWITH_SHA256 -DDTLS_CHECK_CONTENTTYPE -DWITH_OCF -I../../deps/tinydtls -DNDEBUG

SRC_COMMON = $(wildcard ../../util/*.c) ${CBOR}
SRC = $(wildcard ../../messaging/coap/*.c ../../api/*.c)
VPATH=../../messaging/coap/:../../util/:../../api/:../../deps/tinycbor/src/:

ifeq ($(CLIENT),1)
	CFLAGS += -DOC_CLIENT
endif

ifeq ($(SERVER),1)
	CFLAGS += -DOC_SERVER
endif

ifeq ($(SECURE),1)
	SRC += $(wildcard ../../security/*.c)
	SRC_COMMON += ${DTLS}
	CFLAGS += ${DTLSFLAGS} -DOC_SECURITY
	VPATH += ../../security/:../../deps/tinydtls/:../../deps/tinydtls/aes/:../../deps/tinydtls/sha2/:../../deps/tinydtls/ecc/:
endif

ifeq ($(DEBUG),1)
	CFLAGS += -DOC_DEBUG -g
endif

APP_OBJ = $(APP_SRC:.c=.o)
OBJ_COMMON = $(SRC_COMMON:.c=.o)
OBJ_FRAMEWORK = $(SRC:.c=.o)
APPDEPS += ${OBJ_COMMON} ${OBJ_FRAMEWORK} ${APP_OBJ}

include $(RIOTBASE)/Makefile.include

${APP_OBJ}: ${APP_SRC}
	${CC} -c -o $@ $< ${CFLAGS} ${INCLUDES}

%.o: %.c
	${CC} -c -o $@ $< ${CFLAGS}

clean: clean_iotivity_constrained

clean_iotivity_constrained:
	rm -rf ${OBJ_COMMON} ${OBJ_FRAMEWORK} ${APP_OBJ}

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 0

