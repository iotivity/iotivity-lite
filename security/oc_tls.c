/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifdef OC_SECURITY
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/timing.h"
#include "mbedtls/oid.h"
#include "mbedtls/pkcs5.h"
#ifdef OC_DEBUG
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#endif /* OC_DEBUG */

#include "api/oc_events.h"
#include "config.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_endpoint.h"
#include "oc_pstat.h"
#include "oc_session_events.h"
#include "oc_svr.h"
#include "oc_tls.h"
#include "oc_doxm.h"
#include "oc_security.h"

#define PBKDF_ITERATIONS 1000

OC_PROCESS(oc_tls_handler, "TLS Process");
OC_MEMB(tls_peers_s, oc_tls_peer_t, OC_MAX_TLS_PEERS);
OC_LIST(tls_peers);

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context ctr_drbg_ctx;
static mbedtls_ssl_cookie_ctx cookie_ctx;
#ifdef OC_DYNAMIC_ALLOCATION
#include "util/oc_mem.h"

static mbedtls_ssl_config *server_conf;
#ifdef OC_TCP
static mbedtls_ssl_config *server_conf_tls;
#endif /* OC_TCP */
#else  /* OC_DYNAMIC_ALLOCATION */
#define MBEDTLS_ALLOC_BUF_SIZE (20000)
#ifdef OC_TCP
static mbedtls_ssl_config server_conf_tls[OC_MAX_NUM_DEVICES];
#endif /* OC_TCP */
static mbedtls_ssl_config server_conf[OC_MAX_NUM_DEVICES];
static unsigned char alloc_buf[MBEDTLS_ALLOC_BUF_SIZE];
#include "mbedtls/memory_buffer_alloc.h"
#endif /* !OC_DYNAMIC_ALLOCATION */
#ifdef OC_CLIENT
#ifdef OC_TCP
static mbedtls_ssl_config client_conf_tls[1];
#endif /* OC_TCP */
static mbedtls_ssl_config client_conf[1];
#endif /* OC_CLIENT */
#define PERSONALIZATION_STR "IoTivity-Constrained"

#define CCM_MAC_KEY_LENGTH (0)
#define CBC_IV_LENGTH (0)
#define CCM_IV_LENGTH (4)
#define GCM_IV_LENGTH (12)
#define AES128_KEY_LENGTH (16)
#define AES256_KEY_LENGTH (32)
#define SHA256_MAC_KEY_LENGTH (32)
#define SHA384_MAC_KEY_LENGTH (48)

static const int ciphers[12] = {
  MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
  MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256,
  0
};
#ifdef OC_CLIENT
static const int anon_ciphers[12] = {
  MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
  MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
  MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256,
  0
};
#endif /* OC_CLIENT */

#ifdef OC_DEBUG
static void
oc_mbedtls_debug(void *ctx, int level, const char *file, int line,
                 const char *str)
{
  (void)ctx;
#if defined(OC_DEBUG_TLS)
  (void)level;
#else
  if (level == 1)
#endif
  {
    PRINT("mbedtls_log: %s:%04d: %s", file, line, str);
  }
}
#endif /* OC_DEBUG */

static oc_sec_get_cpubkey_and_token g_oc_sec_get_cpubkey_and_token = NULL;
static oc_sec_get_own_key g_oc_sec_get_own_key = NULL;

static int
oc_tls_prf(const uint8_t *secret, size_t secret_len, uint8_t *output,
           size_t output_len, size_t num_message_fragments, ...);

static bool
is_peer_active(oc_tls_peer_t *peer)
{
  oc_tls_peer_t *p = (oc_tls_peer_t *)oc_list_head(tls_peers);
  while (p != NULL) {
    if (p == peer) {
      return true;
    }
    p = p->next;
  }
  return false;
}

static oc_event_callback_retval_t oc_tls_inactive(void *data);

static void
oc_tls_free_peer(oc_tls_peer_t *peer, bool inactivity_cb)
{
  OC_DBG("\noc_tls: removing peer");

#ifdef OC_TCP
  if (peer->endpoint.flags & TCP) {
    oc_connectivity_end_session(&peer->endpoint);
  } else
#endif /* OC_TCP */
  {
    oc_handle_session(&peer->endpoint, OC_SESSION_DISCONNECTED);
  }

  if (!inactivity_cb) {
    oc_ri_remove_timed_event_callback(peer, oc_tls_inactive);
  }
  mbedtls_ssl_free(&peer->ssl_ctx);
  oc_message_t *message = (oc_message_t *)oc_list_pop(peer->send_q);
  while (message != NULL) {
    oc_message_unref(message);
    message = (oc_message_t *)oc_list_pop(peer->send_q);
  }
  message = (oc_message_t *)oc_list_pop(peer->recv_q);
  while (message != NULL) {
    oc_message_unref(message);
    message = (oc_message_t *)oc_list_pop(peer->recv_q);
  }
  oc_etimer_stop(&peer->timer.fin_timer);
  oc_list_remove(tls_peers, peer);
  oc_memb_free(&tls_peers_s, peer);
}

static oc_tls_peer_t *
oc_tls_get_peer(oc_endpoint_t *endpoint)
{
  oc_tls_peer_t *peer = oc_list_head(tls_peers);
  while (peer != NULL) {
    if (oc_endpoint_compare(&peer->endpoint, endpoint) == 0) {
      return peer;
    }
    peer = peer->next;
  }
  return NULL;
}

void
oc_tls_remove_peer(oc_endpoint_t *endpoint)
{
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (peer) {
    oc_tls_free_peer(peer, false);
  }
}

static void
oc_tls_handler_schedule_read(oc_tls_peer_t *peer)
{
  oc_process_post(&oc_tls_handler, oc_events[TLS_READ_DECRYPTED_DATA], peer);
}

#ifdef OC_CLIENT
static void
oc_tls_handler_schedule_write(oc_tls_peer_t *peer)
{
  oc_process_post(&oc_tls_handler, oc_events[TLS_WRITE_APPLICATION_DATA], peer);
}
#endif /* OC_CLIENT */

static oc_event_callback_retval_t
oc_tls_inactive(void *data)
{
  OC_DBG("oc_tls: DTLS inactivity callback");
  oc_tls_peer_t *peer = (oc_tls_peer_t *)data;
  if (is_peer_active(peer)) {
    oc_clock_time_t time = oc_clock_time();
    time -= peer->timestamp;
    if (time < (oc_clock_time_t)OC_DTLS_INACTIVITY_TIMEOUT *
                 (oc_clock_time_t)OC_CLOCK_SECOND) {
      OC_DBG("oc_tls: Resetting DTLS inactivity callback");
      return OC_EVENT_CONTINUE;
    }
    mbedtls_ssl_close_notify(&peer->ssl_ctx);
    oc_tls_free_peer(peer, true);
  }
  OC_DBG("oc_tls: Terminating DTLS inactivity callback");
  return OC_EVENT_DONE;
}

static int
ssl_recv(void *ctx, unsigned char *buf, size_t len)
{
  oc_tls_peer_t *peer = (oc_tls_peer_t *)ctx;
  oc_message_t *message = (oc_message_t *)oc_list_head(peer->recv_q);
  if (message) {
    size_t recv_len = 0;
#ifdef OC_TCP
    if (message->endpoint.flags & TCP) {
      recv_len = message->length - message->read_offset;
      recv_len = (recv_len < len) ? recv_len : len;
      memcpy(buf, message->data + message->read_offset, recv_len);
      message->read_offset += recv_len;
      if (message->read_offset == message->length) {
        oc_list_remove(peer->recv_q, message);
        oc_message_unref(message);
      }
    } else
#endif /* OC_TCP */
    {
      recv_len = (message->length < len) ? message->length : len;
      memcpy(buf, message->data, recv_len);
      oc_list_remove(peer->recv_q, message);
      oc_message_unref(message);
    }
    return recv_len;
  }
  return MBEDTLS_ERR_SSL_WANT_READ;
}

static int
ssl_send(void *ctx, const unsigned char *buf, size_t len)
{
  oc_tls_peer_t *peer = (oc_tls_peer_t *)ctx;
  peer->timestamp = oc_clock_time();
  oc_message_t message;
#ifdef OC_DYNAMIC_ALLOCATION
  message.data = oc_mem_malloc(OC_PDU_SIZE);
  if (!message.data)
    return 0;
#endif /* OC_DYNAMIC_ALLOCATION */
  memcpy(&message.endpoint, &peer->endpoint, sizeof(oc_endpoint_t));
  size_t send_len = (len < (unsigned)OC_PDU_SIZE) ? len : (unsigned)OC_PDU_SIZE;
  memcpy(message.data, buf, send_len);
  message.length = send_len;
  int ret = oc_send_buffer(&message);
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(message.data);
#endif /* OC_DYNAMIC_ALLOCATION */
  return ret;
}

static void
check_retr_timers(void)
{
  oc_tls_peer_t *peer = (oc_tls_peer_t *)oc_list_head(tls_peers), *next;
  while (peer != NULL) {
    next = peer->next;
    if (peer->ssl_ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
      if (oc_etimer_expired(&peer->timer.fin_timer)) {
        int ret = mbedtls_ssl_handshake(&peer->ssl_ctx);
        if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
          mbedtls_ssl_session_reset(&peer->ssl_ctx);
          if (peer->role == MBEDTLS_SSL_IS_SERVER &&
              mbedtls_ssl_set_client_transport_id(
                  &peer->ssl_ctx, (const unsigned char *)&peer->endpoint.addr,
                  sizeof(peer->endpoint.addr)) != 0) {
            oc_tls_free_peer(peer, false);
            peer = next;
            continue;
          }
        }
        if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
#ifdef OC_DEBUG
          char buf[256];
          mbedtls_strerror(ret, buf, 256);
          OC_ERR("oc_tls: mbedtls_error: %s", buf);
#endif /* OC_DEBUG */
          oc_tls_free_peer(peer, false);
        }
      }
    }
    peer = next;
  }
}

static void
ssl_set_timer(void *ctx, uint32_t int_ms, uint32_t fin_ms)
{
  if (fin_ms != 0) {
    oc_tls_retr_timer_t *timer = (oc_tls_retr_timer_t *)ctx;
    timer->int_ticks = (oc_clock_time_t)((int_ms * OC_CLOCK_SECOND) / 1.e03);
    oc_etimer_stop(&timer->fin_timer);
    timer->fin_timer.timer.interval =
        (oc_clock_time_t)((fin_ms * OC_CLOCK_SECOND) / 1.e03);
    OC_PROCESS_CONTEXT_BEGIN(&oc_tls_handler);
    oc_etimer_restart(&timer->fin_timer);
    OC_PROCESS_CONTEXT_END(&oc_tls_handler);
  }
}

static int
get_psk_cb(void *data, mbedtls_ssl_context *ssl, const unsigned char *identity,
           size_t identity_len)
{
  (void)data;
  (void)identity_len;
  OC_DBG("oc_tls: In PSK callback");
  oc_tls_peer_t *peer = oc_list_head(tls_peers);
  while (peer != NULL) {
    if (&peer->ssl_ctx == ssl) {
      break;
    }
    peer = peer->next;
  }
  if (peer) {
    OC_DBG("oc_tls: Found peer object");
    oc_sec_cred_t *cred =
        oc_sec_find_cred((oc_uuid_t *)identity, peer->endpoint.device);
    if (cred) {
      OC_DBG("oc_tls: Found peer credential");
      memcpy(peer->uuid.id, identity, 16);
      OC_DBG("oc_tls: Setting the key:");
      OC_LOGbytes(cred->key, 16);
      if (mbedtls_ssl_set_hs_psk(ssl, cred->key, 16) != 0) {
        return -1;
      }
      OC_DBG("oc_tls: Set peer credential to SSL handle");
      return 0;
    }
    else {
      unsigned char psk[16] = { 0x0 };
      int psk_len = 0;
      if (oc_sec_get_rpk_psk(0, psk, &psk_len) != true) {
        return -1;
      }
      if (mbedtls_ssl_set_hs_psk(ssl, psk, psk_len) != 0) {
        return -1;
      }
      return 0;
    }
  }
  return -1;
}

static int
ssl_get_timer(void *ctx)
{
  oc_tls_retr_timer_t *timer = (oc_tls_retr_timer_t *)ctx;
  if (timer->fin_timer.timer.interval == 0)
    return -1;
  if (oc_etimer_expired(&timer->fin_timer)) {
    timer->fin_timer.timer.interval = 0;
    timer->int_ticks = 0;
    return 2;
  } else if (oc_clock_time() >
             (timer->fin_timer.timer.start + timer->int_ticks)) {
    return 1;
  }
  return 0;
}

static oc_tls_peer_t *
oc_tls_add_peer(oc_endpoint_t *endpoint, int role)
{
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (!peer) {
    peer = oc_memb_alloc(&tls_peers_s);
    if (peer) {
      OC_DBG("oc_tls: Allocating new peer");
      memcpy(&peer->endpoint, endpoint, sizeof(oc_endpoint_t));
      OC_LIST_STRUCT_INIT(peer, recv_q);
      OC_LIST_STRUCT_INIT(peer, send_q);
      peer->next = 0;
      peer->role = role;
      memset(&peer->timer, 0, sizeof(oc_tls_retr_timer_t));
      mbedtls_ssl_init(&peer->ssl_ctx);

      mbedtls_ssl_config *conf = 0;
#ifdef OC_CLIENT
      if (role == MBEDTLS_SSL_IS_CLIENT) {
        if (endpoint->flags & TCP) {
#ifdef OC_TCP
          OC_DBG("oc_tls: initializing TLS client");
          conf = &client_conf_tls[0];
#endif /* OC_TCP */
        } else {
          OC_DBG("oc_tls: initializing DTLS client");
          conf = &client_conf[0];
        }
      } else
#endif /* OC_CLIENT */
      {
        if (endpoint->flags & TCP) {
#ifdef OC_TCP
          OC_DBG("oc_tls: initializing TLS server");
          conf = &server_conf_tls[endpoint->device];
#endif /* OC_TCP */
        } else {
          OC_DBG("oc_tls: initializing DTLS server");
          conf = &server_conf[endpoint->device];
        }
      }

      int err = mbedtls_ssl_setup(&peer->ssl_ctx, conf);

      if (err != 0) {
        OC_ERR("oc_tls: error in mbedtls_ssl_setup: %d", err);
        oc_memb_free(&tls_peers_s, peer);
        return NULL;
      }

      mbedtls_ssl_set_bio(&peer->ssl_ctx, peer, ssl_send, ssl_recv, NULL);

      if (role == MBEDTLS_SSL_IS_SERVER &&
          mbedtls_ssl_set_client_transport_id(
              &peer->ssl_ctx, (const unsigned char *)&endpoint->addr,
              sizeof(endpoint->addr)) != 0) {
        oc_memb_free(&tls_peers_s, peer);
        return NULL;
      }
      oc_list_add(tls_peers, peer);

      if (!(endpoint->flags & TCP)) {
        mbedtls_ssl_set_timer_cb(&peer->ssl_ctx, &peer->timer, ssl_set_timer,
                                 ssl_get_timer);
        oc_ri_add_timed_event_callback_seconds(
          peer, oc_tls_inactive, (oc_clock_time_t)OC_DTLS_INACTIVITY_TIMEOUT);
      }
    } else {
      OC_WRN("TLS peers exhausted");
    }
  }
  return peer;
}

#if defined(OC_DYNAMIC_ALLOCATION)
static void
oc_sec_free_certs_chain(mbedtls_ssl_key_cert *kc)
{
  while (kc) {
    mbedtls_x509_crt_free(kc->cert);
    oc_mem_free(kc->cert);
    mbedtls_pk_free(kc->key);
    oc_mem_free(kc->key);
    kc = kc->next;
  }
}
#if defined(OC_UNLOAD_CERT)
void
oc_sec_unload_own_certs(int device)
{
  oc_sec_free_certs_chain(server_conf[device].key_cert);
}
#endif // defined(OC_UNLOAD_CERT)
#endif // defined(OC_DYNAMIC_ALLOCATION)

void
oc_tls_shutdown(void)
{
  oc_tls_peer_t *p = oc_list_pop(tls_peers);
  while (p != NULL) {
    oc_tls_free_peer(p, false);
    p = oc_list_pop(tls_peers);
  }
#ifdef OC_CLIENT
  if (oc_core_get_num_devices() >= 1) {
    mbedtls_ssl_config_free(client_conf);
#ifdef OC_TCP
    mbedtls_ssl_config_free(client_conf_tls);
#endif /* OC_TCP */
  }
#endif /* OC_CLIENT */
  int device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
#ifdef OC_DYNAMIC_ALLOCATION
    if (server_conf[device].ca_chain) {
      mbedtls_x509_crt_free(server_conf[device].ca_chain);
      oc_mem_free(server_conf[device].ca_chain);
      server_conf[device].ca_chain = NULL;
    }
    oc_sec_free_certs_chain(server_conf[device].key_cert);
#endif // OC_DYNAMIC_ALLOCATION
    mbedtls_ssl_config_free(&server_conf[device]);
#ifdef OC_TCP
    mbedtls_ssl_config_free(&server_conf_tls[device]);
#endif /* OC_TCP */
  }
#ifdef OC_DYNAMIC_ALLOCATION
  if (server_conf) {
    oc_mem_free(server_conf);
  }
#ifdef OC_TCP
  if (server_conf_tls) {
    oc_mem_free(server_conf_tls);
  }
#endif /* OC_TCP */
#endif /* OC_DYNAMIC_ALLOCATION */
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_ssl_cookie_free(&cookie_ctx);
  mbedtls_entropy_free(&entropy_ctx);
}

int
oc_tls_init_context(void)
{
  if (oc_core_get_num_devices() < 1) {
    goto dtls_init_err;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  server_conf = (mbedtls_ssl_config *)oc_mem_calloc(oc_core_get_num_devices(),
                                                    sizeof(mbedtls_ssl_config));
#ifdef OC_TCP
  server_conf_tls = (mbedtls_ssl_config *)oc_mem_calloc(
    oc_core_get_num_devices(), sizeof(mbedtls_ssl_config));
#endif /* OC_TCP */
#else  /* OC_DYNAMIC_ALLOCATION */
  mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef OC_DEBUG
  mbedtls_debug_set_threshold(4);
#endif /* OC_DEBUG */

  mbedtls_entropy_init(&entropy_ctx);
  mbedtls_ssl_cookie_init(&cookie_ctx);
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
  if (mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx,
                            (const unsigned char *)PERSONALIZATION_STR,
                            strlen(PERSONALIZATION_STR)) != 0) {
    goto dtls_init_err;
  }
  if (mbedtls_ssl_cookie_setup(&cookie_ctx, mbedtls_ctr_drbg_random,
                               &ctr_drbg_ctx) != 0) {
    goto dtls_init_err;
  }
  int i;

#ifdef OC_TCP
#define mbedtls_config_tls(func_name, conf, index, ...)                        \
  do {                                                                         \
    func_name(&conf##_tls[index], __VA_ARGS__);                                \
  } while (0)
#else /* OC_TCP */
#define mbedtls_config_tls(func_name, conf, index, ...)                        \
  do {                                                                         \
  } while (0)
#endif /* !OC_TCP */

#define mbedtls_config(func_name, conf, index, ...)                            \
  do {                                                                         \
    func_name(&conf[index], __VA_ARGS__);                                      \
    mbedtls_config_tls(func_name, conf, index, __VA_ARGS__);                   \
  } while (0)

  for (i = 0; i < oc_core_get_num_devices(); i++) {
    mbedtls_ssl_config_init(&server_conf[i]);
    if (mbedtls_ssl_config_defaults(&server_conf[i], MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
      goto dtls_init_err;
    }
    oc_uuid_t *device_id = oc_core_get_device_id(i);
    if (mbedtls_ssl_conf_psk(&server_conf[i], device_id->id, 1, device_id->id,
                             16) != 0) {
      goto dtls_init_err;
    }
#ifdef OC_DEBUG
    mbedtls_ssl_conf_dbg(&server_conf[i], oc_mbedtls_debug, stdout);
#endif /* OC_DEBUG */
#ifdef OC_TCP
    mbedtls_ssl_config_init(&server_conf_tls[i]);
    if (mbedtls_ssl_config_defaults(&server_conf_tls[i], MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
      goto dtls_init_err;
    }
    if (mbedtls_ssl_conf_psk(&server_conf_tls[i], device_id->id, 1,
                             device_id->id, 16) != 0) {
      goto dtls_init_err;
    }
#ifdef OC_DEBUG
    mbedtls_ssl_conf_dbg(&server_conf_tls[i], oc_mbedtls_debug, stdout);
#endif /* OC_DEBUG */
#endif /* OC_TCP */
    mbedtls_config(mbedtls_ssl_conf_rng, server_conf, i,
                   mbedtls_ctr_drbg_random, &ctr_drbg_ctx);
    mbedtls_config(mbedtls_ssl_conf_min_version, server_conf, i,
                   MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_config(mbedtls_ssl_conf_ciphersuites, server_conf, i, ciphers);
    mbedtls_config(mbedtls_ssl_conf_authmode, server_conf, i,
                   MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_config(mbedtls_ssl_conf_psk_cb, server_conf, i, get_psk_cb, NULL);

    mbedtls_ssl_conf_dtls_cookies(&server_conf[i], mbedtls_ssl_cookie_write,
                                  mbedtls_ssl_cookie_check, &cookie_ctx);
    mbedtls_ssl_conf_handshake_timeout(&server_conf[i], 2500, 20000);
  }

#ifdef OC_CLIENT
  mbedtls_ssl_config_init(&client_conf[0]);
  if (mbedtls_ssl_config_defaults(&client_conf[0], MBEDTLS_SSL_IS_CLIENT,
                                  MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    goto dtls_init_err;
  }
  oc_uuid_t *device_id = oc_core_get_device_id(0);
  if (mbedtls_ssl_conf_psk(&client_conf[0], device_id->id, 1, device_id->id,
                           16) != 0) {
    goto dtls_init_err;
  }
#ifdef OC_DEBUG
  mbedtls_ssl_conf_dbg(&client_conf[0], oc_mbedtls_debug, stdout);
#endif /* OC_DEBUG */
#ifdef OC_TCP
  mbedtls_ssl_config_init(&client_conf_tls[0]);
  if (mbedtls_ssl_config_defaults(&client_conf_tls[0], MBEDTLS_SSL_IS_CLIENT,
                                  MBEDTLS_SSL_TRANSPORT_STREAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    goto dtls_init_err;
  }
  if (mbedtls_ssl_conf_psk(&client_conf_tls[0], device_id->id, 1, device_id->id,
                           16) != 0) {
    goto dtls_init_err;
  }
#ifdef OC_DEBUG
  mbedtls_ssl_conf_dbg(&client_conf_tls[0], oc_mbedtls_debug, stdout);
#endif /* OC_DEBUG */
#endif /* OC_TCP */
  mbedtls_config(mbedtls_ssl_conf_rng, client_conf, 0, mbedtls_ctr_drbg_random,
                 &ctr_drbg_ctx);
  mbedtls_config(mbedtls_ssl_conf_min_version, client_conf, 0,
                 MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_config(mbedtls_ssl_conf_ciphersuites, client_conf, 0, ciphers);
  mbedtls_config(mbedtls_ssl_conf_psk_cb, client_conf, 0, get_psk_cb, NULL);

  mbedtls_ssl_conf_handshake_timeout(&client_conf[0], 2500, 20000);
#endif /* OC_CLIENT */
  return 0;
dtls_init_err:
  OC_ERR("oc_tls: TLS initialization error");
  oc_tls_shutdown();
  return -1;
}

#ifdef OC_MFG
bool
oc_sec_load_mfg_certs(int device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  int i = 0, j = 0, ret = 0;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    oc_sec_creds_t *creds = oc_sec_get_creds(device);
    oc_sec_cred_t *c = (oc_sec_cred_t *)oc_list_head(creds->creds);
    while (c != NULL) {
      if (c->mfgtrustcalen != 0) {
        mbedtls_x509_crt *cacert =
          (mbedtls_x509_crt *)oc_mem_malloc(sizeof(mbedtls_x509_crt));
        if (!cacert) {
          goto tls_certs_load_err;
        }
        mbedtls_x509_crt_init(cacert);
        ret = mbedtls_x509_crt_parse(
          cacert, (const unsigned char *)c->mfgtrustca, c->mfgtrustcalen);
        if (ret < 0) {
          OC_ERR(
            " failed\n  !  mbedtls_x509_crt_parse caCert returned -0x%x\n\n",
            -ret);
          oc_mem_free(cacert);
          goto tls_certs_load_err;
        } else {
          OC_DBG("oc_tls: mfgtrustca loaded ");
        }
        mbedtls_ssl_conf_ca_chain(&server_conf[i], cacert, NULL);
#ifdef OC_CLIENT
#ifdef OC_TCP
        mbedtls_ssl_conf_ca_chain(&client_conf_tls[0], cacert, NULL);
#endif /* OC_TCP */
        mbedtls_ssl_conf_ca_chain(&client_conf[0], cacert, NULL);
#endif /* OC_CLIENT */
      }
      c = c->next;
    }
    mbedtls_pk_context *pkey = NULL;
    c = (oc_sec_cred_t *)oc_list_head(creds->creds);
    while (c != NULL) {
      if (c->mfgkeylen != 0) {
         pkey = (mbedtls_pk_context *)oc_mem_malloc(sizeof(mbedtls_pk_context));
        if (!pkey) {
          goto tls_certs_load_err;
        }
        mbedtls_pk_init(pkey);
        ret = mbedtls_pk_parse_key(pkey, (const unsigned char *)c->mfgkey,
                                   c->mfgkeylen, NULL, 0);
        if (ret < 0) {
          OC_ERR(" failed\n  !  mbedtls_pk_parse_key returned -0x%x\n\n", -ret);
          oc_mem_free(pkey);
          goto tls_certs_load_err;
        } else {
          OC_DBG("oc_tls: mfgkey loaded ");
        }
        break;
      }
      c = c->next;
    }
    c = (oc_sec_cred_t *)oc_list_head(creds->creds);
    if (c == NULL && pkey) {
      oc_mem_free(pkey);
    }
    while (c != NULL) {
      for (j = 0; j < c->ownchainlen; j++) {
        if (c->mfgowncertlen != 0) {
          mbedtls_x509_crt *owncert =
            (mbedtls_x509_crt *)oc_mem_malloc(sizeof(mbedtls_x509_crt));
          if (!owncert) {
            goto tls_certs_load_err;
          }
          mbedtls_x509_crt_init(owncert);
          ret = mbedtls_x509_crt_parse(owncert,
                                       (const unsigned char *)c->mfgowncert[j],
                                       c->mfgowncertlen[j]);
          if (ret < 0) {
            OC_ERR(
              " failed\n  !  mbedtls_x509_crt_parse mfgCert returned -0x%x\n\n",
              -ret);
            oc_mem_free(owncert);
            if (pkey) {
              oc_mem_free(pkey);
            }
            goto tls_certs_load_err;
          } else {
            OC_DBG("oc_tls: mfgowncert loaded ");
          }
          ret = mbedtls_ssl_conf_own_cert(&server_conf[i], owncert, pkey);
#ifdef OC_CLIENT
#ifdef OC_TCP
          ret = mbedtls_ssl_conf_own_cert(&client_conf_tls[0], owncert, pkey);
#endif /* OC_TCP */
          ret = mbedtls_ssl_conf_own_cert(&client_conf[0], owncert, pkey);
#endif /* OC_CLIENT */
          if (ret < 0) {
            OC_ERR(" failed\n  !  mbedtls_ssl_conf_own_cert returned -0x%x\n\n",
                   -ret);
            goto tls_certs_load_err;
          }
        }
      }
      c = c->next;
    }
  }
  return true;
#else
  oc_abort("alloc failed");
#endif
tls_certs_load_err:
  OC_ERR("oc_tls: TLS initialization error");
  return false;
}
#endif /* OC_MFG */

static int
derive_crypto_key_from_password(const unsigned char *passwd, size_t pLen,
                                const uint8_t *salt, size_t saltLen,
                                size_t iterations,
                                size_t keyLen, uint8_t *derivedKey)
{
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t *info_sha;
    int ret = -1;

    if (iterations > UINT_MAX) {
        OC_ERR("Number of iterations over maximum %u", UINT_MAX);
        return ret;
    }

    if (keyLen > UINT32_MAX) {
        OC_ERR("derive_crypto_key_from_password: Key length over maximum %u", UINT32_MAX);
        return ret;
    }

    /* Setup the hash/HMAC function, for the PBKDF2 function. */
    mbedtls_md_init(&sha_ctx);

    info_sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info_sha == NULL) {
        OC_ERR("derive_crypto_key_from_password: failed to get hash information");
        return ret;
    }

    ret = mbedtls_md_setup(&sha_ctx, info_sha, 1);
    if (ret != 0) {
        OC_ERR("derive_crypto_key_from_password: Failed to setup hash function");
        return ret;
    }

    ret = mbedtls_pkcs5_pbkdf2_hmac(&sha_ctx,
                                    passwd, pLen,
                                    salt, saltLen,
                                    (unsigned int)iterations,
                                    (uint32_t)keyLen, derivedKey);
    if (ret != 0) {
        OC_ERR("derive_crypto_key_from_password: Call to mbedtls PBKDF2 function failed");
    }

    mbedtls_md_free(&sha_ctx);
    return ret;
}

void
oc_sec_set_cpubkey_and_token_load(oc_sec_get_cpubkey_and_token cpubkey_and_token_cb)
{
  if(NULL == cpubkey_and_token_cb) {
    OC_ERR("oc_cred: cpubkey_and_token_cb is NULL");
    return;
  }
  g_oc_sec_get_cpubkey_and_token = cpubkey_and_token_cb;
}

void
oc_sec_unset_cpubkey_and_token_load()
{
  g_oc_sec_get_cpubkey_and_token = NULL;
}

void
oc_sec_set_own_key_load(oc_sec_get_own_key own_key_cb)
{
  if(NULL == own_key_cb) {
    OC_ERR("oc_cred: own_key_cb is NULL");
    return;
  }
  g_oc_sec_get_own_key = own_key_cb;
}

void
oc_sec_unset_own_key_load()
{
  g_oc_sec_get_own_key = NULL;
}

static bool
gen_master_key(uint8_t *master, int *master_len)
{
  mbedtls_ecdh_context ecdh_ctx;
  int priv_len = 0, peer_len = 0, token_len = 0, tmp_len = 0;
  uint8_t priv[32] = {0}, peer[32] = {0}, token[32] = {0}, shared[32] = {0}, tmp[32+32] = {0};
  uint8_t peer_rev[32] = {0}, shared_rev[32] = {0}, priv_rev[32] = {0};
  mbedtls_ecdh_init(&ecdh_ctx);
  int i = 0;

  if (!master || !master_len) {
    OC_ERR("NULL params");
    goto master_key_error;
  }
  if (!g_oc_sec_get_own_key || !g_oc_sec_get_cpubkey_and_token) {
    OC_ERR("callbacks not set");
    goto master_key_error;
  }
  g_oc_sec_get_own_key(priv, &priv_len);
  g_oc_sec_get_cpubkey_and_token(peer, &peer_len, token, &token_len);
  for (i = 31; i>=0; i--) {
    peer_rev[31-i] = peer[i];
    priv_rev[31-i] = priv[i];
  }
  if (mbedtls_ecp_group_load(&ecdh_ctx.grp, MBEDTLS_ECP_DP_CURVE25519) != 0) {
    OC_ERR("load CURVE25519");
    goto master_key_error;
  }
  if (mbedtls_mpi_read_binary(&ecdh_ctx.d, priv_rev, priv_len) != 0) {
    OC_ERR("load private key");
    goto master_key_error;
  }
  if (mbedtls_mpi_read_binary(&ecdh_ctx.Qp.X, peer_rev, peer_len) != 0) {
    OC_ERR("set peer's public key X");
    goto master_key_error;
  }
  if (mbedtls_mpi_lset(&ecdh_ctx.Qp.Z, 1) != 0) {
    OC_ERR("set peer's public key Z");
    goto master_key_error;
  }
  if (mbedtls_ecdh_compute_shared(&ecdh_ctx.grp, &ecdh_ctx.z,
      &ecdh_ctx.Qp, &ecdh_ctx.d, mbedtls_ctr_drbg_random, &ctr_drbg_ctx) != 0) {
    OC_ERR("compute shared key");
    goto master_key_error;
  }
  if (mbedtls_mpi_write_binary(&ecdh_ctx.z, shared, 32) != 0) {
    OC_ERR("write shared key");
    goto master_key_error;
  }
  tmp_len = token_len+32;
  for (i = 31; i>=0; i--) {
    shared_rev[31-i] = shared[i];
  }
  memcpy(tmp, shared_rev, 32);
  memcpy(tmp+32, token, token_len);
  if (mbedtls_sha256_ret(tmp, tmp_len, master, 0) != 0) {
    OC_ERR("sha256 hash");
    goto master_key_error;
  }
  *master_len = 32;
  OC_DBG("oc_tls: token:");
  OC_LOGbytes(token, token_len);
  OC_DBG("oc_tls: own private key:");
  OC_LOGbytes(priv_rev, priv_len);
  OC_DBG("oc_tls: cpubkey:");
  OC_LOGbytes(peer_rev, peer_len);
  OC_DBG("oc_tls: shared secret:");
  OC_LOGbytes(shared_rev, 32);
  OC_DBG("oc_tls: master key:");
  OC_LOGbytes(master, *master_len);
  mbedtls_ecdh_free(&ecdh_ctx);
  return true;
master_key_error:
  mbedtls_ecdh_free(&ecdh_ctx);
  return false;
}

bool
oc_sec_get_rpk_psk(int device, unsigned char *psk, int *psk_len)
{
  int ret = 0, master_key_len = 0;
  uint8_t master_key[32];

  if (gen_master_key(master_key, &master_key_len) != true) {
    OC_ERR("gen_master_key failed");
    return false;
  }

  *psk_len = 16;
  ret = derive_crypto_key_from_password((const unsigned char *)master_key, master_key_len,
                                        oc_core_get_device_id(device)->id, 16,
                                        PBKDF_ITERATIONS,
                                        *psk_len, psk);
  if (ret != 0) {
    OC_ERR("derive_crypto_key_from_password failed");
    return false;
  }
  return true;
}

bool
oc_sec_get_rpk_hmac(oc_endpoint_t *endpoint, unsigned char *hmac, int *hmac_len)
{
  if (!endpoint || !hmac || !hmac_len) {
    OC_ERR("%s: NULL params", __func__);
    return false;
  }
  int ret, master_key_len = 0;
  uint8_t master_key[32];
  uint8_t session_master[48];
  mbedtls_md_context_t ctx;
  if (gen_master_key(master_key, &master_key_len) != true) {
    OC_ERR("gen_master_key failed");
    return false;
  }
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (!peer) {
    OC_ERR("%s: unable to get peer", __func__);
    return false;
  }
  memcpy(session_master, peer->ssl_ctx.session->master, 48);
  mbedtls_md_init(&ctx);
  if ((ret = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1)) != 0) {
    OC_ERR("mbedtls_md_setup: %d", ret);
    return false;
  }
  if ((ret = mbedtls_md_hmac_starts(&ctx, session_master, 48)) != 0) {
    OC_ERR("mbedtls_md_hmac_starts: %d", ret);
    return false;
  }
  if ((ret = mbedtls_md_hmac_update(&ctx, (const unsigned char *) master_key, master_key_len)) != 0) {
    OC_ERR("mbedtls_md_hmac_update: %d", ret);
    return false;
  }
  if ((ret = mbedtls_md_hmac_finish(&ctx, hmac)) != 0) {
    OC_ERR("mbedtls_md_hmac_finish: %d", ret);
    return false;
  }
  mbedtls_md_free(&ctx);
  *hmac_len = 32;
  return true;
}

bool
oc_sec_load_ca_cert(const unsigned char *ca_cert_buf, size_t ca_cet_buf_len)
{
  int i = 0, ret = 0;
  if (ca_cet_buf_len == 0 || ca_cert_buf == NULL) {
    OC_ERR("oc_tls: empty ca cert buffer");
    goto tls_load_ca_cert_err;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    if (server_conf[i].ca_chain != NULL) {
      mbedtls_x509_crt_free(server_conf[i].ca_chain);
    }
    mbedtls_x509_crt *ca_crt =
      (mbedtls_x509_crt *)oc_mem_malloc(sizeof(mbedtls_x509_crt));
    if (!ca_crt) {
      goto tls_load_ca_cert_err;
    }
    mbedtls_x509_crt_init(ca_crt);
    ret = mbedtls_x509_crt_parse( ca_crt, ca_cert_buf, ca_cet_buf_len );
    if( ret < 0 ) {
        OC_ERR( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto tls_load_ca_cert_err;
    } else {
      OC_DBG("oc_tls: trust ca cert loaded ");
    }
    mbedtls_ssl_conf_ca_chain(&server_conf[i], ca_crt, NULL);
#ifdef OC_CLIENT
#ifdef OC_TCP
    mbedtls_ssl_conf_ca_chain(&client_conf_tls[0], ca_crt, NULL);
#endif /* OC_TCP */
    mbedtls_ssl_conf_ca_chain(&client_conf[0], ca_crt, NULL);
#endif /* OC_CLIENT */
  }
  return true;
#else
  oc_abort("alloc failed");
#endif
tls_load_ca_cert_err:
  OC_ERR("oc_tls: TLS initialization error");
  return false;
}

int
oc_tls_update_psk_identity(int device)
{
  oc_uuid_t *device_id = oc_core_get_device_id(device);
  if (!device_id) {
    return -1;
  }
  if (mbedtls_ssl_conf_psk(&server_conf[device], device_id->id, 1,
                           device_id->id, 16) != 0) {
    return -1;
  }
#ifdef OC_TCP
  if (mbedtls_ssl_conf_psk(&server_conf_tls[device], device_id->id, 1,
                           device_id->id, 16) != 0) {
    return -1;
  }
#endif /* OC_TCP */
#ifdef OC_CLIENT
  oc_uuid_t *client_device_id = oc_core_get_device_id(0);
  if (mbedtls_ssl_conf_psk(&client_conf[0], client_device_id->id, 1,
                           client_device_id->id, 16) != 0) {
    return -1;
  }
#ifdef OC_TCP
  if (mbedtls_ssl_conf_psk(&client_conf_tls[0], client_device_id->id, 1,
                           client_device_id->id, 16) != 0) {
    return -1;
  }
#endif /* OC_TCP */
#endif /* OC_CLIENT */
  return 0;
}

void
oc_tls_close_connection(oc_endpoint_t *endpoint)
{
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (peer) {
    mbedtls_ssl_close_notify(&peer->ssl_ctx);
    oc_tls_free_peer(peer, false);
  }
}

static int
oc_tls_prf(const uint8_t *secret, size_t secret_len, uint8_t *output,
           size_t output_len, size_t num_message_fragments, ...)
{
#define MBEDTLS_MD(func, ...)                                                  \
  do {                                                                         \
    if (func(__VA_ARGS__) != 0) {                                              \
      gen_output = -1;                                                         \
      goto exit_tls_prf;                                                       \
    }                                                                          \
  } while (0)
  uint8_t A[MBEDTLS_MD_MAX_SIZE], buf[MBEDTLS_MD_MAX_SIZE];
  size_t i;
  int msg_len,
    gen_output = 0, copy_len,
    hash_len =
      mbedtls_md_get_size(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256));
  mbedtls_md_context_t hmacA, hmacA_next;
  va_list msg_list;
  const uint8_t *msg;

  mbedtls_md_init(&hmacA);
  mbedtls_md_init(&hmacA_next);

  MBEDTLS_MD(mbedtls_md_setup, &hmacA,
             mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  MBEDTLS_MD(mbedtls_md_setup, &hmacA_next,
             mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

  MBEDTLS_MD(mbedtls_md_hmac_starts, &hmacA, secret, secret_len);
  va_start(msg_list, num_message_fragments);
  for (i = 0; i < num_message_fragments; i++) {
    msg = va_arg(msg_list, const uint8_t *);
    msg_len = va_arg(msg_list, size_t);
    MBEDTLS_MD(mbedtls_md_hmac_update, &hmacA, msg, msg_len);
  }
  va_end(msg_list);
  MBEDTLS_MD(mbedtls_md_hmac_finish, &hmacA, A);

  while (gen_output < (int)output_len) {
    MBEDTLS_MD(mbedtls_md_hmac_reset, &hmacA);
    MBEDTLS_MD(mbedtls_md_hmac_starts, &hmacA, secret, secret_len);
    MBEDTLS_MD(mbedtls_md_hmac_update, &hmacA, A, hash_len);
    va_start(msg_list, num_message_fragments);
    for (i = 0; i < num_message_fragments; i++) {
      msg = va_arg(msg_list, const uint8_t *);
      msg_len = va_arg(msg_list, size_t);
      MBEDTLS_MD(mbedtls_md_hmac_update, &hmacA, msg, msg_len);
    }
    va_end(msg_list);
    MBEDTLS_MD(mbedtls_md_hmac_finish, &hmacA, buf);

    copy_len = (((int)output_len - gen_output) < hash_len)
                 ? ((int)output_len - gen_output)
                 : hash_len;
    memcpy(output + gen_output, buf, copy_len);
    gen_output += copy_len;

    if (copy_len == hash_len) {
      MBEDTLS_MD(mbedtls_md_hmac_reset, &hmacA_next);
      MBEDTLS_MD(mbedtls_md_hmac_starts, &hmacA_next, secret, secret_len);
      MBEDTLS_MD(mbedtls_md_hmac_update, &hmacA_next, A, hash_len);
      MBEDTLS_MD(mbedtls_md_hmac_finish, &hmacA_next, A);
    }
  }

exit_tls_prf:
#undef MBEDTLS_MD
  va_end(msg_list);
  mbedtls_md_free(&hmacA);
  mbedtls_md_free(&hmacA_next);
  return gen_output;
}

bool oc_sec_derive_owner_psk(oc_endpoint_t *endpoint, const uint8_t *oxm,
                             const size_t oxm_len, const uint8_t *server_uuid,
                             const size_t server_uuid_len,
                             const uint8_t *obt_uuid, const size_t obt_uuid_len,
                             uint8_t *key, const size_t key_len) {
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (!peer) {
    return false;
  }
  size_t j;
  for (j = 0; j < 48; j++) {
    if (peer->master_secret[j] != 0) {
      break;
    }
  }
  if (j == 48) {
    return false;
  }
  for (j = 0; j < 64; j++) {
    if (peer->client_server_random[j] != 0) {
      break;
    }
  }
  if (j == 64) {
    return false;
  }
  uint8_t key_block[96];
  uint8_t label[] = { 0x6b, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70,
                      0x61, 0x6e, 0x73, 0x69, 0x6f, 0x6e };

  // key_block_len set up according to OIC 1.1 Security Specification Section 7.3.2
  int mac_key_len = 0;
  int iv_size = 0;
  int key_size = 0;
  int key_block_len = 0;
  if (MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256 == peer->ssl_ctx.session->ciphersuite ||
      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 == peer->ssl_ctx.session->ciphersuite ||
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 == peer->ssl_ctx.session->ciphersuite ||
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 == peer->ssl_ctx.session->ciphersuite) {
    // 2 * ( 32 + 0 + 16 ) = 96
    mac_key_len = SHA256_MAC_KEY_LENGTH;
    iv_size = CBC_IV_LENGTH;
    key_size = AES128_KEY_LENGTH;
  }
  else if (MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM == peer->ssl_ctx.session->ciphersuite ||
           MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 == peer->ssl_ctx.session->ciphersuite) {
    // 2 * ( 0 + 4 + 16 ) = 40
    mac_key_len = CCM_MAC_KEY_LENGTH;
    iv_size = CCM_IV_LENGTH;
    key_size = AES128_KEY_LENGTH;
  }
  else if (MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 == peer->ssl_ctx.session->ciphersuite) {
    // 2 * ( 32 + 12 + 16 ) = 120
    mac_key_len = SHA256_MAC_KEY_LENGTH;
    iv_size = GCM_IV_LENGTH;
    key_size = AES128_KEY_LENGTH;
  }
  else if (MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256 == peer->ssl_ctx.session->ciphersuite) {
    // 2 * ( 32 + 0 + 32 ) = 128
    mac_key_len = SHA256_MAC_KEY_LENGTH;
    iv_size = CBC_IV_LENGTH;
    key_size = AES256_KEY_LENGTH;
  }
  else if (MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 == peer->ssl_ctx.session->ciphersuite) {
    // 2 * ( 48 + 0 + 32 ) = 160
    mac_key_len = SHA384_MAC_KEY_LENGTH;
    iv_size = CBC_IV_LENGTH;
    key_size = AES256_KEY_LENGTH;
  }
  else if (MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 == peer->ssl_ctx.session->ciphersuite) {
    // 2 * ( 48 + 12 + 32 ) = 184
    mac_key_len = SHA384_MAC_KEY_LENGTH;
    iv_size = GCM_IV_LENGTH;
    key_size = AES256_KEY_LENGTH;
  }
  else if (MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256 == peer->ssl_ctx.session->ciphersuite) {
    // 2 * ( 48 + 12 + 32 ) = 184
    mac_key_len = SHA256_MAC_KEY_LENGTH;
    iv_size = GCM_IV_LENGTH;
    key_size = AES128_KEY_LENGTH;
  }
  key_block_len = 2 * (mac_key_len + key_size + iv_size);

  if (oc_tls_prf(peer->master_secret, 48, key_block, key_block_len, 3, label,
                 sizeof(label), peer->client_server_random + 32, 32,
                 peer->client_server_random, 32) != key_block_len) {
    return false;
  }

  if (oc_tls_prf(key_block, key_block_len, key, key_len, 3, oxm, oxm_len, obt_uuid,
                 obt_uuid_len, server_uuid, server_uuid_len) != (int)key_len) {
    return false;
  }

  OC_DBG("oc_tls: master secret:");
  OC_LOGbytes(peer->master_secret, 48);
  OC_DBG("oc_tls: client_server_random:");
  OC_LOGbytes(peer->client_server_random, 64);
  OC_DBG("oc_tls: key_block");
  OC_LOGbytes(key_block, key_block_len);
  OC_DBG("oc_tls: PSK ");
  OC_LOGbytes(key, key_len);

  return true;
}

int
oc_tls_send_message(oc_message_t *message)
{
  int length = 0;
  oc_tls_peer_t *peer = oc_tls_get_peer(&message->endpoint);
  if (peer) {
    int ret = mbedtls_ssl_write(&peer->ssl_ctx, (unsigned char *)message->data,
                                message->length);
    if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ &&
        ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
#ifdef OC_DEBUG
      char buf[256];
      mbedtls_strerror(ret, buf, 256);
      OC_ERR("oc_tls: mbedtls_error: %s", buf);
#endif /* OC_DEBUG */
      oc_tls_free_peer(peer, false);
    } else {
      length = message->length;
    }
  }
  oc_message_unref(message);
  return length;
}

#ifdef OC_CLIENT
static void
write_application_data(oc_tls_peer_t *peer)
{
  if (!is_peer_active(peer)) {
    OC_DBG("oc_tls: write_application_data: Peer not active");
    return;
  }
  oc_message_t *message = (oc_message_t *)oc_list_pop(peer->send_q);
  while (message != NULL) {
    int ret = mbedtls_ssl_write(&peer->ssl_ctx, (unsigned char *)message->data,
                                message->length);
    oc_message_unref(message);
    if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ &&
        ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
#ifdef OC_DEBUG
      char buf[256];
      mbedtls_strerror(ret, buf, 256);
      OC_ERR("oc_tls: mbedtls_error: %s", buf);
#endif /* OC_DEBUG */
      oc_tls_free_peer(peer, false);
      break;
    }
    message = (oc_message_t *)oc_list_pop(peer->send_q);
  }
}

void
oc_tls_elevate_anon_ciphersuite(void)
{
  mbedtls_ssl_conf_ciphersuites(&client_conf[0], anon_ciphers);
#ifdef OC_TCP
  mbedtls_ssl_conf_ciphersuites(&client_conf_tls[0], anon_ciphers);
#endif /* OC_TCP */
}

void
oc_tls_demote_anon_ciphersuite(void)
{
  mbedtls_ssl_conf_ciphersuites(&client_conf[0], ciphers);
#ifdef OC_TCP
  mbedtls_ssl_conf_ciphersuites(&client_conf_tls[0], ciphers);
#endif /* OC_TCP */
}

static void
oc_tls_init_connection(oc_message_t *message)
{
  oc_tls_peer_t *peer =
    oc_tls_add_peer(&message->endpoint, MBEDTLS_SSL_IS_CLIENT);
  if (peer) {
    oc_message_t *duplicate = oc_list_head(peer->send_q);
    while (duplicate != NULL) {
      if (duplicate == message) {
        break;
      }
      duplicate = duplicate->next;
    }
    if (duplicate == NULL) {
      oc_message_add_ref(message);
      oc_list_add(peer->send_q, message);
    }
    int ret = mbedtls_ssl_handshake(&peer->ssl_ctx);
    if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ &&
        ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
#ifdef OC_DEBUG
      char buf[256];
      mbedtls_strerror(ret, buf, 256);
      OC_ERR("oc_tls: mbedtls_error: %s", buf);
#endif /* OC_DEBUG */
      oc_tls_free_peer(peer, false);
    } else if (ret == 0) {
      oc_tls_handler_schedule_write(peer);
    }
  }
  oc_message_unref(message);
}
#endif /* OC_CLIENT */

oc_uuid_t *
oc_tls_get_peer_uuid(oc_endpoint_t *endpoint)
{
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (peer) {
    return &peer->uuid;
  }
  return NULL;
}

bool
oc_tls_connected(oc_endpoint_t *endpoint)
{
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (peer) {
    return (peer->ssl_ctx.state == MBEDTLS_SSL_HANDSHAKE_OVER);
  }
  return false;
}

#define UUID_PREFIX "uuid:"
#define UUID_DEV_PREFIX "sample ("
#define UUID_STRING_SIZE (37)

static void
read_application_data(oc_tls_peer_t *peer)
{
  OC_DBG("oc_tls: In read_application_data");
  if (!is_peer_active(peer)) {
    OC_DBG("oc_tls: read_application_data: Peer not active");
    return;
  }

  if (peer->ssl_ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    int ret = 0;
    do {
      ret = mbedtls_ssl_handshake_step(&peer->ssl_ctx);
      if (peer->ssl_ctx.state == MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC ||
          peer->ssl_ctx.state == MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC) {
        memcpy(peer->master_secret, peer->ssl_ctx.session_negotiate->master,
               sizeof(peer->master_secret));
        OC_DBG("oc_tls: Got master secret");
        OC_LOGbytes(peer->master_secret, 48);
      }
      if (peer->ssl_ctx.state == MBEDTLS_SSL_CLIENT_KEY_EXCHANGE ||
          peer->ssl_ctx.state == MBEDTLS_SSL_SERVER_KEY_EXCHANGE) {
        memcpy(peer->client_server_random, peer->ssl_ctx.handshake->randbytes,
               sizeof(peer->client_server_random));
        OC_DBG("oc_tls: Got nonce");
        OC_LOGbytes(peer->client_server_random, 64);
      }
      if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
        mbedtls_ssl_session_reset(&peer->ssl_ctx);
        /* For HelloVerifyRequest cookies */
        if (peer->role == MBEDTLS_SSL_IS_SERVER &&
            mbedtls_ssl_set_client_transport_id(
                &peer->ssl_ctx, (const unsigned char *)&peer->endpoint.addr,
                sizeof(peer->endpoint.addr)) != 0) {
          oc_tls_free_peer(peer, false);
          return;
        }
      } else if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ &&
                 ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
#ifdef OC_DEBUG
        char buf[256];
        mbedtls_strerror(ret, buf, 256);
        OC_ERR("oc_tls: mbedtls_error: %s", buf);
#endif /* OC_DEBUG */
        oc_tls_free_peer(peer, false);
        return;
      }
    } while (ret == 0 && peer->ssl_ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER);
    if (peer->ssl_ctx.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
      int cipher = peer->ssl_ctx.session->ciphersuite;
      OC_DBG("oc_tls: (D)TLS Session is connected via ciphersuite [0x%x]", cipher);
      if (MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 != cipher &&
          MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256 != cipher)
      {
        const mbedtls_x509_crt * cert = mbedtls_ssl_get_peer_cert(&peer->ssl_ctx);
        const mbedtls_x509_name * name = NULL;
        if (NULL == cert) {
          OC_DBG("oc_tls: failed to retrieve cert");
        }
        else {
          /* Find the CN component of the subject name. */
          for (name = &cert->subject; NULL != name; name = name->next) {
            if (name->oid.p &&
               (name->oid.len <= MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) &&
               (0 == memcmp(MBEDTLS_OID_AT_CN, name->oid.p, name->oid.len))) {
              if (strstr((const char *)name->val.p, UUID_PREFIX) ||
                strstr((const char *)name->val.p, UUID_DEV_PREFIX)) {
                break;
              }
            }
            else if (name->oid.p &&
               (name->oid.len <= MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_ORG_UNIT)) &&
               (0 == memcmp(MBEDTLS_OID_AT_ORG_UNIT, name->oid.p, name->oid.len))) {
              if (strstr((const char *)name->val.p, UUID_PREFIX) ||
                strstr((const char *)name->val.p, UUID_DEV_PREFIX)) {
                break;
              }
            }
          }
        }
        if (NULL == name) {
          OC_DBG("oc_tls: no CN or OU RDN with uuid found in subject name");
        }
        else {
          const size_t uuid_len = UUID_STRING_SIZE - 1;
          char uuid[UUID_STRING_SIZE] = { 0 };
          const char * uuid_pos = NULL;
          uuid_pos = strstr((const char *)name->val.p, UUID_PREFIX);
          /* If UUID_PREFIX is present, ensure there's enough data for the prefix plus an entire
           * UUID, to make sure we don't read past the end of the buffer.
           */
          if ((NULL != uuid_pos) &&
             (name->val.len >= ((uuid_pos - (const char *)name->val.p) + (sizeof(UUID_PREFIX) - 1) + uuid_len))) {
            memcpy(uuid, uuid_pos + sizeof(UUID_PREFIX) - 1, uuid_len);
            OC_DBG("oc_tls: certificate uuid string: %s", uuid);
            oc_str_to_uuid(uuid, &peer->uuid);
          }
          else {
            uuid_pos = strstr((const char *)name->val.p, UUID_DEV_PREFIX);
            if ((NULL != uuid_pos) &&
             (name->val.len >= ((uuid_pos - (const char *)name->val.p) + (sizeof(UUID_DEV_PREFIX) - 1) + uuid_len))) {
              memcpy(uuid, uuid_pos + sizeof(UUID_DEV_PREFIX) - 1, uuid_len);
              OC_DBG("oc_tls: certificate client uuid string: %s", uuid);
              oc_str_to_uuid(uuid, &peer->uuid);
            }
            else {
              OC_DBG("oc_tls: uuid not found");
            }
          }
        }
      }
      else
      {
        /* No public key information for non-certificate-using ciphersuites. */
      }
      oc_handle_session(&peer->endpoint, OC_SESSION_CONNECTED);
    }
#ifdef OC_CLIENT
    if (ret == 0) {
      oc_tls_handler_schedule_write(peer);
    }
#endif /* OC_CLIENT */
  } else {
    oc_message_t *message = oc_allocate_message();
    if (message) {
      memcpy(&message->endpoint, &peer->endpoint, sizeof(oc_endpoint_t));
      int ret = mbedtls_ssl_read(&peer->ssl_ctx, message->data, OC_PDU_SIZE);
      if (ret <= 0) {
        oc_message_unref(message);
        if (ret == 0 || ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
          OC_DBG("oc_tls: Received WantRead/WantWrite");
          return;
        }
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
          OC_DBG("oc_tls: Close-Notify received");
        } else if (ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
          OC_DBG("oc_tls: Client wants to reconnect");
        } else {
#ifdef OC_DEBUG
          char buf[256];
          mbedtls_strerror(ret, buf, 256);
          OC_ERR("oc_tls: mbedtls_error: %s", buf);
#endif /* OC_DEBUG */
        }
        if (peer->role == MBEDTLS_SSL_IS_SERVER) {
          mbedtls_ssl_close_notify(&peer->ssl_ctx);
        }
        oc_tls_free_peer(peer, false);
        return;
      }
      message->length = (size_t)ret;
      oc_recv_message(message);
      OC_DBG("oc_tls: Decrypted incoming message");
    }
  }
}

static void
oc_tls_recv_message(oc_message_t *message)
{
  oc_tls_peer_t *peer =
    oc_tls_add_peer(&message->endpoint, MBEDTLS_SSL_IS_SERVER);

  if (peer) {
#ifdef OC_DEBUG
    char u[OC_UUID_LEN];
    oc_uuid_to_str(&peer->uuid, u, OC_UUID_LEN);
    OC_DBG("oc_tls: Received message from device %s", u);
#endif /* OC_DEBUG */

    oc_list_add(peer->recv_q, message);
    peer->timestamp = oc_clock_time();
    oc_tls_handler_schedule_read(peer);
  }
}

OC_PROCESS_THREAD(oc_tls_handler, ev, data) {
  OC_PROCESS_BEGIN();

  while (1) {
    OC_PROCESS_YIELD();

    if (ev == oc_events[UDP_TO_TLS_EVENT]) {
      oc_tls_recv_message(data);
    }
#ifdef OC_CLIENT
    else if (ev == oc_events[INIT_TLS_CONN_EVENT]) {
      oc_tls_init_connection(data);
    }
#endif /* OC_CLIENT */
    else if (ev == oc_events[RI_TO_TLS_EVENT]) {
      oc_tls_send_message(data);
    } else if (ev == OC_PROCESS_EVENT_TIMER) {
      check_retr_timers();
    } else if (ev == oc_events[TLS_READ_DECRYPTED_DATA]) {
      read_application_data(data);
    }
#ifdef OC_CLIENT
    else if (ev == oc_events[TLS_WRITE_APPLICATION_DATA]) {
      write_application_data(data);
    }
#endif /* OC_CLIENT */
  }

  OC_PROCESS_END();
}
#endif /* OC_SECURITY */
