ccflags-y += -I${ZEPHYR_BASE}/net/ip
ccflags-y +=-I${ZEPHYR_BASE}/net/ip/contiki
ccflags-y +=-I${ZEPHYR_BASE}/net/ip/contiki/os/lib
ccflags-y +=-I${ZEPHYR_BASE}/net/ip/contiki/os
ccflags-y +=-I. -I../../include -I../../ -D__OC_RANDOM -I../../deps/mbedtls/include

ifeq ($(SECURE),1)
ccflags-y += -DOC_SECURITY
endif

ifeq ($(DEBUG),1)
ccflags-y += -DOC_DEBUG
endif

ifeq ($(CLIENT),1)
ccflags-y += -DOC_CLIENT
obj-y += ../../../apps/client_zephyr.o
else
ccflags-y += -DOC_SERVER
obj-y += ../../../apps/server_zephyr.o
#obj-y += ../../../apps/sensor_interrupt_server_zephyr.o
endif

ifeq ($(CONFIG_NET_L2_BT),y)
# TODO: Instead of using ipss sample module, implement Bluetooth init functionality.
ccflags-y +=-I${ZEPHYR_BASE}/samples/bluetooth
obj-y += ipss.o
src/ipss.c: ${ZEPHYR_BASE}/samples/bluetooth/gatt/ipss.c
	cp $< $@
endif

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
         ../../../api/oc_endpoint.o \
         ../../../api/oc_core_res.o \
         ../../../api/oc_network_events.o \
         ../../../api/oc_blockwise.o \
         ../../../api/oc_base64.o \
         ipadapter.o \
         random.o \
         clock.o \
         abort.o

ifeq ($(SECURE),1)
obj-y += ../../../deps/mbedtls/library/aes.o \
         ../../../deps/mbedtls/library/aesni.o \
         ../../../deps/mbedtls/library/arc4.o \
         ../../../deps/mbedtls/library/asn1parse.o \
         ../../../deps/mbedtls/library/asn1write.o \
         ../../../deps/mbedtls/library/base64.o \
         ../../../deps/mbedtls/library/bignum.o \
         ../../../deps/mbedtls/library/blowfish.o \
         ../../../deps/mbedtls/library/camellia.o \
         ../../../deps/mbedtls/library/ccm.o \
         ../../../deps/mbedtls/library/cipher.o \
         ../../../deps/mbedtls/library/cipher_wrap.o \
         ../../../deps/mbedtls/library/cmac.o \
         ../../../deps/mbedtls/library/ctr_drbg.o \
         ../../../deps/mbedtls/library/des.o \
         ../../../deps/mbedtls/library/dhm.o \
         ../../../deps/mbedtls/library/ecdh.o \
         ../../../deps/mbedtls/library/ecdsa.o \
         ../../../deps/mbedtls/library/ecjpake.o \
         ../../../deps/mbedtls/library/ecp.o \
         ../../../deps/mbedtls/library/ecp_curves.o \
         ../../../deps/mbedtls/library/entropy.o \
         ../../../deps/mbedtls/library/entropy_poll.o \
         ../../../deps/mbedtls/library/error.o \
         ../../../deps/mbedtls/library/gcm.o \
         ../../../deps/mbedtls/library/havege.o \
         ../../../deps/mbedtls/library/hmac_drbg.o \
         ../../../deps/mbedtls/library/md.o \
         ../../../deps/mbedtls/library/md2.o \
         ../../../deps/mbedtls/library/md4.o \
         ../../../deps/mbedtls/library/md5.o \
         ../../../deps/mbedtls/library/md_wrap.o \
         ../../../deps/mbedtls/library/oid.o \
         ../../../deps/mbedtls/library/padlock.o \
         ../../../deps/mbedtls/library/pem.o \
         ../../../deps/mbedtls/library/pk.o \
         ../../../deps/mbedtls/library/pk_wrap.o \
         ../../../deps/mbedtls/library/pkcs12.o \
         ../../../deps/mbedtls/library/pkcs5.o \
         ../../../deps/mbedtls/library/pkparse.o \
         ../../../deps/mbedtls/library/pkwrite.o \
         ../../../deps/mbedtls/library/platform.o \
         ../../../deps/mbedtls/library/ripemd160.o \
         ../../../deps/mbedtls/library/rsa.o \
         ../../../deps/mbedtls/library/sha1.o \
         ../../../deps/mbedtls/library/sha256.o \
         ../../../deps/mbedtls/library/sha512.o \
         ../../../deps/mbedtls/library/threading.o \
         ../../../deps/mbedtls/library/timing.o \
         ../../../deps/mbedtls/library/version.o \
         ../../../deps/mbedtls/library/version_features.o \
         ../../../deps/mbedtls/library/xtea.o \
         ../../../deps/mbedtls/library/pkcs11.o \
         ../../../deps/mbedtls/library/x509.o \
         ../../../deps/mbedtls/library/x509_crt.o \
         ../../../deps/mbedtls/library/net_sockets.o \
         ../../../deps/mbedtls/library/ssl_cache.o \
         ../../../deps/mbedtls/library/ssl_ciphersuites.o \
         ../../../deps/mbedtls/library/ssl_cli.o \
         ../../../deps/mbedtls/library/ssl_cookie.o \
         ../../../deps/mbedtls/library/ssl_srv.o \
         ../../../deps/mbedtls/library/ssl_ticket.o \
         ../../../deps/mbedtls/library/ssl_tls.o \
         ../../../deps/mbedtls/library/memory_buffer_alloc.o \
         ../../../security/oc_acl.o \
         ../../../security/oc_cred.o \
         ../../../security/oc_doxm.o \
         ../../../security/oc_dtls.o \
         ../../../security/oc_pstat.o \
         ../../../security/oc_store.o \
         ../../../security/oc_svr.o \
         storage.o
endif
