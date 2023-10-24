/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_config.h"

#ifdef OC_CLIENT

#include "api/client/oc_client_cb_internal.h"
#include "api/oc_client_api_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_rep_encode_internal.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/options_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_api.h"
#include "oc_message_internal.h"
#include "oc_ri_internal.h"
#include "util/oc_secure_string_internal.h"

#ifdef OC_TCP
#include "messaging/coap/signal_internal.h"
#endif /* OC_TCP */

#ifdef OC_SECURITY
#include "security/oc_tls_internal.h"
#endif /* OC_SECURITY */

#include <assert.h>

typedef struct oc_dispatch_context_t
{
  coap_transaction_t *transaction;
  oc_client_cb_t *client_cb;
} oc_dispatch_context_t;

// TODO returning a handle from oc_init_post / oc_init_put would be cleaner than
// a global variable
static oc_dispatch_context_t g_dispatch = { NULL, NULL };

typedef struct oc_dispatch_request_t
{
  coap_packet_t packet;
#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t *buffer;
#endif /* OC_BLOCK_WISE */
} oc_dispatch_request_t;

static oc_dispatch_request_t g_request;

#ifdef OC_OSCORE
static oc_message_t *g_multicast_update = NULL;
#endif /* OC_OSCORE */

static bool
dispatch_coap_request_set_payload(oc_dispatch_request_t *request,
                                  const oc_dispatch_context_t *dispatch)
{
  int payload_size = oc_rep_get_encoded_payload_size();

  if ((dispatch->client_cb->method == OC_PUT ||
       dispatch->client_cb->method == OC_POST) &&
      payload_size > 0) {

#ifdef OC_BLOCK_WISE
    request->buffer->payload_size = (uint32_t)payload_size;
    uint32_t block_size;
    if (
#ifdef OC_TCP
      (dispatch->transaction->message->endpoint.flags & TCP) == 0 &&
#endif /* OC_TCP */
      (long)payload_size > OC_BLOCK_SIZE) {
      void *payload = oc_blockwise_dispatch_block(
        request->buffer, 0, (uint32_t)OC_BLOCK_SIZE, &block_size);
      if (payload) {
        coap_set_payload(&request->packet, payload, block_size);
        coap_options_set_block1(&request->packet, 0, 1, (uint16_t)block_size,
                                0);
        coap_options_set_size1(&request->packet, (uint32_t)payload_size);
        request->packet.type = COAP_TYPE_CON;
        dispatch->client_cb->qos = HIGH_QOS;
      }
    } else {
      coap_set_payload(&request->packet, request->buffer->buffer,
                       (uint32_t)payload_size);
      request->buffer->ref_count = 0;
    }
#else  /* OC_BLOCK_WISE */
    coap_set_payload(&request->packet,
                     dispatch->transaction->message->data +
                       COAP_MAX_HEADER_SIZE,
                     (uint32_t)payload_size);
#endif /* !OC_BLOCK_WISE */
  }

  if (payload_size > 0) {
    oc_content_format_t cf;
    if (!oc_rep_encoder_get_content_format(&cf)) {
      return false;
    }
#ifdef OC_SPEC_VER_OIC
    if (dispatch->client_cb->endpoint.version == OIC_VER_1_1_0 &&
        cf == APPLICATION_VND_OCF_CBOR) {
      cf = APPLICATION_CBOR;
    }
#endif /* OC_SPEC_VER_OIC */

    coap_options_set_content_format(&request->packet, cf);
  }
  return true;
}

static bool
dispatch_coap_request(void)
{
  bool success = false;
  if (!dispatch_coap_request_set_payload(&g_request, &g_dispatch)) {
    coap_clear_transaction(g_dispatch.transaction);
    oc_client_cb_free(g_dispatch.client_cb);
    goto dispatch_coap_request_exit;
  }

  g_dispatch.transaction->message->length = coap_serialize_message(
    &g_request.packet, g_dispatch.transaction->message->data,
    oc_message_buffer_size());
  if (g_dispatch.transaction->message->length == 0) {
    coap_clear_transaction(g_dispatch.transaction);
    oc_client_cb_free(g_dispatch.client_cb);
    goto dispatch_coap_request_exit;
  }

  coap_send_transaction(g_dispatch.transaction);

  if (g_dispatch.client_cb->observe_seq == OC_COAP_OPTION_OBSERVE_NOT_SET) {
    if (g_dispatch.client_cb->qos == LOW_QOS) {
      oc_set_delayed_callback(g_dispatch.client_cb, &oc_client_cb_remove_async,
                              OC_NON_LIFETIME);
    } else {
      oc_set_delayed_callback(g_dispatch.client_cb, &oc_client_cb_remove_async,
                              OC_EXCHANGE_LIFETIME);
    }
  }

  success = true;

dispatch_coap_request_exit:
#ifdef OC_BLOCK_WISE
  if (g_request.buffer != NULL && g_request.buffer->ref_count == 0) {
    oc_blockwise_free_request_buffer(g_request.buffer);
  }
  g_request.buffer = NULL;
#endif /* OC_BLOCK_WISE */

  g_dispatch.transaction = NULL;
  g_dispatch.client_cb = NULL;

  return success;
}

static bool
prepare_coap_request(oc_client_cb_t *cb, coap_configure_request_fn_t configure,
                     const void *configure_data)
{
  coap_message_type_t type = COAP_TYPE_NON;

  if (cb->qos == HIGH_QOS) {
    type = COAP_TYPE_CON;
  }

  coap_transaction_t *transaction =
    coap_new_transaction(cb->mid, cb->token, cb->token_len, &cb->endpoint);

  if (transaction == NULL) {
    return false;
  }

  g_dispatch.transaction = transaction;
  oc_rep_new_v1(g_dispatch.transaction->message->data + COAP_MAX_HEADER_SIZE,
                OC_BLOCK_SIZE);

#ifdef OC_BLOCK_WISE
  if (cb->method == OC_PUT || cb->method == OC_POST) {
    g_request.buffer = oc_blockwise_alloc_request_buffer(
      oc_string(cb->uri) + 1, oc_string_len(cb->uri) - 1, &cb->endpoint,
      cb->method, OC_BLOCKWISE_CLIENT, (uint32_t)OC_MIN_APP_DATA_SIZE);
    if (!g_request.buffer) {
      OC_ERR("global request_buffer is NULL");
      return false;
    }
#ifdef OC_DYNAMIC_ALLOCATION
#ifdef OC_APP_DATA_BUFFER_POOL
    if (g_request.buffer->block) {
      oc_rep_new_v1(g_request.buffer->buffer, g_request.buffer->buffer_size);
    } else
#endif
    {
      oc_rep_new_realloc_v1(&g_request.buffer->buffer,
                            g_request.buffer->buffer_size,
                            OC_MAX_APP_DATA_SIZE);
    }
#else  /* OC_DYNAMIC_ALLOCATION */
    oc_rep_new_v1(g_request.buffer->buffer, OC_MIN_APP_DATA_SIZE);
#endif /* !OC_DYNAMIC_ALLOCATION */
    g_request.buffer->mid = cb->mid;
    g_request.buffer->client_cb = cb;
  }
#endif /* OC_BLOCK_WISE */

#ifdef OC_TCP
  if (cb->endpoint.flags & TCP) {
    coap_tcp_init_message(&g_request.packet, (uint8_t)cb->method);
  } else
#endif /* OC_TCP */
  {
    coap_udp_init_message(&g_request.packet, type, (uint8_t)cb->method,
                          cb->mid);
  }

  oc_content_format_t cf;
  if (!oc_rep_encoder_get_content_format(&cf)) {
    return false;
  }
#ifdef OC_SPEC_VER_OIC
  if (cb->endpoint.version == OIC_VER_1_1_0 && cf == APPLICATION_VND_OCF_CBOR) {
    cf = APPLICATION_CBOR;
  }
#endif /* OC_SPEC_VER_OIC */

  coap_options_set_accept(&g_request.packet, cf);

  coap_set_token(&g_request.packet, cb->token, cb->token_len);

  coap_options_set_uri_path(&g_request.packet, oc_string(cb->uri),
                            oc_string_len(cb->uri));

  if (cb->observe_seq != OC_COAP_OPTION_OBSERVE_NOT_SET) {
    coap_options_set_observe(&g_request.packet, cb->observe_seq);
  }

  if (oc_string_len(cb->query) > 0) {
    coap_options_set_uri_query(&g_request.packet, oc_string(cb->query),
                               oc_string_len(cb->query));
  }

  if (configure != NULL) {
    configure(&g_request.packet, configure_data);
  }

  g_dispatch.client_cb = cb;

  return true;
}

#ifdef OC_OSCORE

#ifdef OC_IPV4
static void
oc_do_multicast_update_ipv4(void)
{
  oc_message_t *multicast_update4 = oc_message_allocate_outgoing();
  if (multicast_update4) {
    oc_make_ipv4_endpoint(mcast4, IPV4 | MULTICAST | SECURED, 5683, 0xe0, 0x00,
                          0x01, 0xbb);

    memcpy(&multicast_update4->endpoint, &mcast4, sizeof(oc_endpoint_t));

    multicast_update4->length = g_multicast_update->length;
    memcpy(multicast_update4->data, g_multicast_update->data,
           g_multicast_update->length);

    oc_send_message(multicast_update4);
  }
}
#endif /* OC_IPV4 */

bool
oc_do_multicast_update(void)
{
  int payload_size = oc_rep_get_encoded_payload_size();

  if (payload_size <= 0) {
    goto do_multicast_update_error;
  }
  coap_set_payload(&g_request.packet,
                   g_multicast_update->data + COAP_MAX_HEADER_SIZE,
                   (uint32_t)payload_size);

  oc_content_format_t cf;
  if (!oc_rep_encoder_get_content_format(&cf)) {
    goto do_multicast_update_error;
  }
  coap_options_set_content_format(&g_request.packet, cf);

  g_multicast_update->length = coap_serialize_message(
    &g_request.packet, g_multicast_update->data, oc_message_buffer_size());
  if (g_multicast_update->length <= 0) {
    goto do_multicast_update_error;
  }

  oc_send_message(g_multicast_update);

#ifdef OC_IPV4
  oc_do_multicast_update_ipv4();
#endif /* OC_IPV4 */

  g_multicast_update = NULL;
  return true;

do_multicast_update_error:
  oc_message_unref(g_multicast_update);
  g_multicast_update = NULL;
  return false;
}

bool
oc_init_multicast_update(const char *uri, const char *query)
{
  oc_make_ipv6_endpoint(mcast, IPV6 | MULTICAST | SECURED, 5683, 0xff, 0x02, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58);
  mcast.addr.ipv6.scope = 0;

  coap_message_type_t type = COAP_TYPE_NON;

  g_multicast_update = oc_message_allocate_outgoing();

  if (!g_multicast_update) {
    return false;
  }

  memcpy(&g_multicast_update->endpoint, &mcast, sizeof(oc_endpoint_t));

  oc_rep_new_v1(g_multicast_update->data + COAP_MAX_HEADER_SIZE, OC_BLOCK_SIZE);

  coap_udp_init_message(&g_request.packet, type, OC_POST, coap_get_mid());

  coap_options_set_accept(&g_request.packet, APPLICATION_VND_OCF_CBOR);

  g_request.packet.token_len = sizeof(g_request.packet.token);
  oc_random_buffer(g_request.packet.token, g_request.packet.token_len);

  coap_options_set_uri_path(&g_request.packet, uri,
                            oc_strnlen(uri, OC_MAX_STRING_LENGTH));

  if (query) {
    coap_options_set_uri_query(&g_request.packet, query,
                               oc_strnlen(query, OC_MAX_STRING_LENGTH));
  }

  return true;
}
#endif /* OC_OSCORE */

void
oc_free_server_endpoints(oc_endpoint_t *endpoint)
{
  oc_endpoint_t *next;
  while (endpoint != NULL) {
    next = endpoint->next;
    oc_free_endpoint(endpoint);
    endpoint = next;
  }
}

bool
oc_get_response_payload_raw(const oc_client_response_t *response,
                            const uint8_t **payload, size_t *size,
                            oc_content_format_t *content_format)
{
  if (!response || !payload || !size || !content_format) {
    return false;
  }
  if (response->_payload && response->_payload_len > 0) {
    *content_format = response->content_format;
    *payload = response->_payload;
    *size = response->_payload_len;
    return true;
  }
  return false;
}

bool
oc_get_diagnostic_message(const oc_client_response_t *response,
                          const char **msg, size_t *size)
{
  oc_content_format_t cf = 0;
  if (oc_get_response_payload_raw(response, (const uint8_t **)msg, size, &cf)) {
    if (cf != TEXT_PLAIN) {
      return false;
    }
    return true;
  }
  return false;
}

oc_client_cb_t *
oc_do_request(oc_method_t method, const char *uri,
              const oc_endpoint_t *endpoint, const char *query,
              uint16_t timeout_seconds, oc_response_handler_t handler,
              oc_qos_t qos, void *user_data,
              coap_configure_request_fn_t configure_request,
              const void *configure_request_data)
{
  assert(uri != NULL);
  assert(handler != NULL);
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, method, query,
                                             client_handler, qos, user_data);
  if (cb == NULL) {
    return NULL;
  }

  if (!prepare_coap_request(cb, configure_request, configure_request_data)) {
    oc_client_cb_free(cb);
    return NULL;
  }
  if (!dispatch_coap_request()) {
    return NULL;
  }
  if (timeout_seconds > 0) {
    oc_set_delayed_callback(cb, oc_client_cb_remove_with_notify_timeout_async,
                            timeout_seconds);
  }
  return cb;
}

bool
oc_do_delete(const char *uri, const oc_endpoint_t *endpoint, const char *query,
             oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  return oc_do_request(OC_DELETE, uri, endpoint, query, 0, handler, qos,
                       user_data, NULL, NULL) != NULL;
}

bool
oc_do_delete_with_timeout(const char *uri, const oc_endpoint_t *endpoint,
                          const char *query, uint16_t timeout_seconds,
                          oc_response_handler_t handler, oc_qos_t qos,
                          void *user_data)
{
  return oc_do_request(OC_DELETE, uri, endpoint, query, timeout_seconds,
                       handler, qos, user_data, NULL, NULL);
}

bool
oc_do_get(const char *uri, const oc_endpoint_t *endpoint, const char *query,
          oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  return oc_do_request(OC_GET, uri, endpoint, query, 0, handler, qos, user_data,
                       NULL, NULL) != NULL;
}

bool
oc_do_get_with_timeout(const char *uri, const oc_endpoint_t *endpoint,
                       const char *query, uint16_t timeout_seconds,
                       oc_response_handler_t handler, oc_qos_t qos,
                       void *user_data)
{
  return oc_do_request(OC_GET, uri, endpoint, query, timeout_seconds, handler,
                       qos, user_data, NULL, NULL);
}

bool
oc_init_async_request(oc_method_t method, const char *uri,
                      const oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, oc_qos_t qos,
                      void *user_data,
                      coap_configure_request_fn_t configure_request,
                      const void *configure_request_data)
{
  assert(uri != NULL);
  assert(handler != NULL);
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, method, query,
                                             client_handler, qos, user_data);
  if (cb == NULL) {
    return false;
  }

  if (!prepare_coap_request(cb, configure_request, configure_request_data)) {
    oc_client_cb_free(cb);
    return false;
  }
  return true;
}

// execution step for sending coap request using async methods (POST or PUT)
static bool
oc_do_async_request_with_timeout(uint16_t timeout_seconds, oc_method_t method)
{
  oc_client_cb_t *cb = g_dispatch.client_cb;
  if (cb == NULL || cb->method != method) {
    return false;
  }

  if (!dispatch_coap_request()) {
    return false;
  }

  if (timeout_seconds > 0) {
    oc_set_delayed_callback(cb, oc_client_cb_remove_with_notify_timeout_async,
                            timeout_seconds);
  }
  return true;
}

bool
oc_init_put(const char *uri, const oc_endpoint_t *endpoint, const char *query,
            oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  return oc_init_async_request(OC_PUT, uri, endpoint, query, handler, qos,
                               user_data, NULL, NULL);
}

bool
oc_init_post(const char *uri, const oc_endpoint_t *endpoint, const char *query,
             oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  return oc_init_async_request(OC_POST, uri, endpoint, query, handler, qos,
                               user_data, NULL, NULL);
}

bool
oc_do_put(void)
{
  return dispatch_coap_request();
}

bool
oc_do_put_with_timeout(uint16_t timeout_seconds)
{
  return oc_do_async_request_with_timeout(timeout_seconds, OC_PUT);
}

bool
oc_do_post(void)
{
  return dispatch_coap_request();
}

bool
oc_do_post_with_timeout(uint16_t timeout_seconds)
{
  return oc_do_async_request_with_timeout(timeout_seconds, OC_POST);
}

bool
oc_do_observe(const char *uri, const oc_endpoint_t *endpoint, const char *query,
              oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, OC_GET, query,
                                             client_handler, qos, user_data);
  if (cb == NULL) {
    OC_ERR("cannot observe resource: cannot allocate client callback");
    return false;
  }
  cb->observe_seq = OC_COAP_OPTION_OBSERVE_REGISTER;

  if (!prepare_coap_request(cb, NULL, NULL)) {
    OC_ERR("cannot observe resource: failed to prepare coap request");
    oc_client_cb_free(cb);
    return false;
  }
  return dispatch_coap_request();
}

bool
oc_stop_observe(const char *uri, const oc_endpoint_t *endpoint)
{
  // TODO: this might cause an issue if either the client is observing the URI
  // multiple times or if the client is currently waiting for a GET response,
  // oc_ri_get_client_cb will return the first client callback found which might
  // not be the one we want to stop observing
  oc_client_cb_t *cb = oc_ri_get_client_cb(uri, endpoint, OC_GET);
  if (cb == NULL) {
    OC_ERR("cannot stop observation: no client callback found");
    return false;
  }
  cb->mid = coap_get_mid();
  cb->observe_seq = OC_COAP_OPTION_OBSERVE_UNREGISTER;

  if (!prepare_coap_request(cb, NULL, NULL)) {
    OC_ERR("cannot stop observation: failed to prepare coap request");
    return false;
  }
  return dispatch_coap_request();
}

#ifdef OC_IPV4
static oc_client_cb_t *
oc_do_ipv4_discovery(const char *query, oc_client_handler_t handler,
                     void *user_data)
{
  oc_make_ipv4_endpoint(mcast4, IPV4 | DISCOVERY, 5683, 0xe0, 0x00, 0x01, 0xbb);

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(
    OCF_RES_URI, &mcast4, OC_GET, query, handler, LOW_QOS, user_data);

  if (cb == NULL) {
    return NULL;
  }
  if (!prepare_coap_request(cb, NULL, NULL)) {
    oc_client_cb_free(cb);
    return NULL;
  }
  cb->discovery = true;
  if (!dispatch_coap_request()) {
    return NULL;
  }
  return cb;
}

static oc_client_cb_t *
oc_do_ipv4_multicast(const char *uri, const char *query,
                     oc_response_handler_t handler, void *user_data)
{
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_make_ipv4_endpoint(mcast4, IPV4 | DISCOVERY, 5683, 0xe0, 0x00, 0x01, 0xbb);

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(
    uri, &mcast4, OC_GET, query, client_handler, LOW_QOS, user_data);

  if (!cb) {
    return NULL;
  }

  if (!prepare_coap_request(cb, NULL, NULL)) {
    oc_client_cb_free(cb);
    return NULL;
  }
  cb->multicast = true;
  if (!dispatch_coap_request()) {
    return NULL;
  }
  return cb;
}
#endif /* OC_IPV4 */

void
oc_stop_multicast(oc_client_response_t *response)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)response->client_cb;
  cb->stop_multicast_receive = true;
}

static bool
multi_scope_ipv6_multicast(const oc_client_cb_t *cb4, uint8_t scope,
                           const char *uri, const char *query,
                           oc_response_handler_t handler, void *user_data)
{
  if (!uri || !handler) {
    return false;
  }

  oc_make_ipv6_endpoint(mcast, IPV6 | DISCOVERY, 5683, 0xff, scope, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58);
  mcast.addr.ipv6.scope = 0;

  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(
    uri, &mcast, OC_GET, query, client_handler, LOW_QOS, user_data);
  if (cb == NULL) {
    return false;
  }
  if (cb4 != NULL) {
    cb->mid = cb4->mid;
    memcpy(cb->token, cb4->token, cb4->token_len);
  }

  if (!prepare_coap_request(cb, NULL, NULL)) {
    oc_client_cb_free(cb);
    return false;
  }
  cb->multicast = true;
  return dispatch_coap_request();
}

bool
oc_do_realm_local_ipv6_multicast(const char *uri, const char *query,
                                 oc_response_handler_t handler, void *user_data)
{
  if (multi_scope_ipv6_multicast(NULL, 0x03, uri, query, handler, user_data)) {
    return true;
  }
  return false;
}

bool
oc_do_site_local_ipv6_multicast(const char *uri, const char *query,
                                oc_response_handler_t handler, void *user_data)
{
  if (multi_scope_ipv6_multicast(NULL, 0x05, uri, query, handler, user_data)) {
    return true;
  }
  return false;
}

bool
oc_do_ip_multicast(const char *uri, const char *query,
                   oc_response_handler_t handler, void *user_data)
{
  const oc_client_cb_t *cb4 = NULL;
#ifdef OC_IPV4
  cb4 = oc_do_ipv4_multicast(uri, query, handler, user_data);
#endif /* OC_IPV4 */

  return multi_scope_ipv6_multicast(cb4, 0x02, uri, query, handler, user_data);
}

static bool
dispatch_ip_discovery(const oc_client_cb_t *cb4, const char *query,
                      oc_client_handler_t handler,
                      const oc_endpoint_t *endpoint, oc_qos_t qos,
                      void *user_data)
{
  if (!endpoint) {
    OC_ERR("require valid endpoint");
    return false;
  }

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(OCF_RES_URI, endpoint, OC_GET,
                                             query, handler, qos, user_data);
  if (cb == NULL) {
    return false;
  }
  if (cb4 != NULL) {
    cb->mid = cb4->mid;
    memcpy(cb->token, cb4->token, cb4->token_len);
  }

  if (!prepare_coap_request(cb, NULL, NULL)) {
    oc_client_cb_free(cb);
    return false;
  }
  cb->discovery = true;
  return dispatch_coap_request();
}

static bool
multi_scope_ipv6_discovery(const oc_client_cb_t *cb4, uint8_t scope,
                           const char *query, oc_client_handler_t handler,
                           void *user_data)
{
  oc_make_ipv6_endpoint(mcast, IPV6 | DISCOVERY, 5683, 0xff, scope, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58);
  mcast.addr.ipv6.scope = 0;
  return dispatch_ip_discovery(cb4, query, handler, &mcast, LOW_QOS, user_data);
}

bool
oc_do_site_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                    void *user_data)
{
  oc_client_handler_t handlers = {
    .response = NULL,
    .discovery = NULL,
    .discovery_all = handler,
  };
  return multi_scope_ipv6_discovery(NULL, 0x05, NULL, handlers, user_data);
}

bool
oc_do_site_local_ipv6_discovery(const char *rt, oc_discovery_handler_t handler,
                                void *user_data)
{
  oc_client_handler_t handlers = {
    .response = NULL,
    .discovery = handler,
    .discovery_all = NULL,
  };
  oc_string_t uri_query;
  memset(&uri_query, 0, sizeof(oc_string_t));
  if (rt && strlen(rt) > 0) {
    oc_concat_strings(&uri_query, "rt=", rt);
  }
  bool status = multi_scope_ipv6_discovery(NULL, 0x05, oc_string(uri_query),
                                           handlers, user_data);
  oc_free_string(&uri_query);

  return status;
}

bool
oc_do_realm_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                     void *user_data)
{
  oc_client_handler_t handlers = {
    .response = NULL,
    .discovery = NULL,
    .discovery_all = handler,
  };
  return multi_scope_ipv6_discovery(NULL, 0x03, NULL, handlers, user_data);
}

bool
oc_do_realm_local_ipv6_discovery(const char *rt, oc_discovery_handler_t handler,
                                 void *user_data)
{
  oc_client_handler_t handlers = {
    .response = NULL,
    .discovery = handler,
    .discovery_all = NULL,
  };
  oc_string_t uri_query;
  memset(&uri_query, 0, sizeof(oc_string_t));
  if (rt && strlen(rt) > 0) {
    oc_concat_strings(&uri_query, "rt=", rt);
  }
  bool status = multi_scope_ipv6_discovery(NULL, 0x03, oc_string(uri_query),
                                           handlers, user_data);
  oc_free_string(&uri_query);

  return status;
}

bool
oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler,
                   void *user_data)
{
  oc_client_handler_t handlers = {
    .response = NULL,
    .discovery = handler,
    .discovery_all = NULL,
  };
  oc_string_t uri_query;
  memset(&uri_query, 0, sizeof(oc_string_t));
  if (rt && strlen(rt) > 0) {
    oc_concat_strings(&uri_query, "rt=", rt);
  }
  const oc_client_cb_t *cb4 = NULL;
#ifdef OC_IPV4
  cb4 = oc_do_ipv4_discovery(oc_string(uri_query), handlers, user_data);
#endif
  bool status = multi_scope_ipv6_discovery(cb4, 0x02, oc_string(uri_query),
                                           handlers, user_data);
  oc_free_string(&uri_query);

  return status;
}

bool
oc_do_ip_discovery_all(oc_discovery_all_handler_t handler, void *user_data)
{
  oc_client_handler_t handlers = {
    .response = NULL,
    .discovery = NULL,
    .discovery_all = handler,
  };
  const oc_client_cb_t *cb4 = NULL;
#ifdef OC_IPV4
  cb4 = oc_do_ipv4_discovery(NULL, handlers, user_data);
#endif
  return multi_scope_ipv6_discovery(cb4, 0x02, NULL, handlers, user_data);
}

bool
oc_do_ip_discovery_all_at_endpoint(oc_discovery_all_handler_t handler,
                                   const oc_endpoint_t *endpoint,
                                   void *user_data)
{
  oc_client_handler_t handlers = {
    .response = NULL,
    .discovery = NULL,
    .discovery_all = handler,
  };
  return dispatch_ip_discovery(NULL, NULL, handlers, endpoint, HIGH_QOS,
                               user_data);
}

bool
oc_do_ip_discovery_at_endpoint(const char *rt, oc_discovery_handler_t handler,
                               const oc_endpoint_t *endpoint, void *user_data)
{
  oc_client_handler_t handlers = {
    .response = NULL,
    .discovery = handler,
    .discovery_all = NULL,
  };
  oc_string_t uri_query;
  memset(&uri_query, 0, sizeof(oc_string_t));
  if (rt && strlen(rt) > 0) {
    oc_concat_strings(&uri_query, "rt=", rt);
  }
  bool status = dispatch_ip_discovery(NULL, oc_string(uri_query), handlers,
                                      endpoint, HIGH_QOS, user_data);
  oc_free_string(&uri_query);

  return status;
}

void
oc_close_session(const oc_endpoint_t *endpoint)
{
  if (endpoint->flags & SECURED) {
#ifdef OC_SECURITY
    oc_tls_close_connection(endpoint);
#endif /* OC_SECURITY */
  } else if (endpoint->flags & TCP) {
#ifdef OC_TCP
    oc_connectivity_end_session(endpoint);
#endif /* OC_TCP */
  }
}

#endif /* OC_CLIENT */
