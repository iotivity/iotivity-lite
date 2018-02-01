#Set CONTIKI appropriately below to point to the root of your Contiki source.
CONTIKI = ${HOME}/contiki

ifeq ($(CLIENT),1)
	CONTIKI_PROJECT = client_contiki
else
	CONTIKI_PROJECT = server_contiki
	SERVER=1
endif

all: $(CONTIKI_PROJECT)

PROJECTDIRS += ./ ../../include ../../ ../../api ../../messaging/coap ../../apps ../../deps/tinycbor/src ../../util

PROJECT_SOURCEFILES += oc_buffer.c oc_discovery.c oc_main.c oc_ri.c oc_client_api.c oc_network_events.c oc_server_api.c oc_core_res.c oc_helpers.c oc_rep.c oc_uuid.c cborencoder.c cborencoder_close_container_checked.c cborparser.c oc_etimer.c oc_memb.c oc_process.c oc_list.c oc_mmem.c oc_timer.c coap.c separate.c engine.c transactions.c observe.c ipadapter.c oc_clock.c oc_random.c abort.c storage.c oc_blockwise.c oc_base64.c oc_endpoint.c oc_introspection.c

CONTIKI_WITH_RPL = 1
CONTIKI_WITH_IPV6 = 1

include $(CONTIKI)/Makefile.include

CFLAGS += -std=gnu99 -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -Wl,--gc-sections

ifeq ($(CLIENT),1)
	CFLAGS += -DOC_CLIENT
endif

ifeq ($(SERVER),1)
	CFLAGS += -DOC_SERVER
endif

ifeq ($(DEBUG),1)
	CFLAGS += -DOC_DEBUG -g
endif
