#ccflags-y += ${PROJECTINCLUDE}
ccflags-y += -I${ZEPHYR_BASE}/net/ip
ccflags-y +=-I${ZEPHYR_BASE}/net/ip/contiki
ccflags-y +=-I${ZEPHYR_BASE}/net/ip/contiki/os/lib
ccflags-y +=-I${ZEPHYR_BASE}/net/ip/contiki/os

ccflags-y += -I. -I../../../include -I../../../ -DDTLSV12 -DWITH_SHA256 -DDTLS_CHECK_CONTENTTYPE -DWITH_OCF -I../../../deps/tinydtls -DOC_SERVER -DNDEBUG #-DOC_SECURITY#-DOC_CLIENT

obj-y += ../../../apps/server.o
#obj-y += ../../../apps/sensor_interrupt_server_zephyr.o

obj-y += ../../../deps/tinycbor/src/cborencoder_close_container_checked.o \
         ../../../deps/tinycbor/src/cborencoder.o \
         ../../../deps/tinycbor/src/cborparser.o \
         ../../../messaging/coap/engine.o \
         ../../../messaging/coap/coap.o \
         ../../../messaging/coap/transactions.o \
         ../../../messaging/coap/separate.o \
         ../../../messaging/coap/observe.o \
         ../../../util/oc_memb.o \
         ../../../util/oc_etimer.o \
         ../../../util/oc_list.o \
         ../../../util/oc_process.o \
         ../../../util/oc_timer.o \
         ../../../util/oc_mmem.o \
         ../../../api/oc_discovery.o \
         ../../../api/oc_main.o \
         ../../../api/oc_buffer.o \
         ../../../api/oc_server_api.o \
         ../../../api/oc_client_api.o \
         ../../../api/oc_helpers.o \
         ../../../api/oc_ri.o \
         ../../../api/oc_rep.o \
         ../../../api/oc_uuid.o \
         ../../../api/oc_core_res.o \
         ../../../api/oc_network_events.o \
         ipadapter.o \
         random.o \
         clock.o \
         abort.o \
#         ../../../deps/tinydtls/ccm.o \
#         ../../../deps/tinydtls/hmac.o \
#         ../../../deps/tinydtls/netq.o \
#         ../../../deps/tinydtls/peer.o \
#         ../../../deps/tinydtls/dtls_time.o \
#         ../../../deps/tinydtls/session.o \
#         ../../../deps/tinydtls/sha2/sha2.o \
#         ../../../deps/tinydtls/ecc/ecc.o \
#         ../../../deps/tinydtls/aes/rijndael.o \
#         ../../../deps/tinydtls/crypto.o \
#         ../../../deps/tinydtls/dtls.o \
#         ../../../security/oc_acl.o \
#         ../../../security/oc_cred.o \
#         ../../../security/oc_doxm.o \
#         ../../../security/oc_dtls.o \
#         ../../../security/oc_pstat.o \
#         ../../../security/oc_store.o \
#         ../../../security/oc_svr.o \
         storage.o
