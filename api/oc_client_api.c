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

#include "api/oc_helpers_internal.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/transactions.h"
#ifdef OC_TCP
#include "messaging/coap/coap_signal.h"
#endif /* OC_TCP */
#include "oc_api.h"
#include "oc_ri_internal.h"
#ifdef OC_SECURITY
#include "security/oc_tls.h"
#endif /* OC_SECURITY */
#include <assert.h>

#ifdef OC_CLIENT

static coap_transaction_t *g_transaction;
static coap_packet_t g_request[1];
#ifdef OC_BLOCK_WISE
static oc_blockwise_state_t *g_request_buffer = NULL;
#endif /* OC_BLOCK_WISE */
static oc_client_cb_t *g_client_cb;

#ifdef OC_OSCORE
static oc_message_t *g_multicast_update = NULL;
#endif /* OC_OSCORE */

static bool
dispatch_coap_request(void)
{
  int payload_size = oc_rep_get_encoded_payload_size();

  if ((g_client_cb->method == OC_PUT || g_client_cb->method == OC_POST) &&
      payload_size > 0) {

#ifdef OC_BLOCK_WISE
    g_request_buffer->payload_size = (uint32_t)payload_size;
    uint32_t block_size;
#ifdef OC_TCP
    if (!(g_transaction->message->endpoint.flags & TCP) &&
        payload_size > OC_BLOCK_SIZE) {
#else  /* OC_TCP */
    if ((long)payload_size > OC_BLOCK_SIZE) {
#endif /* !OC_TCP */
      const void *payload = oc_blockwise_dispatch_block(
        g_request_buffer, 0, (uint32_t)OC_BLOCK_SIZE, &block_size);
      if (payload) {
        coap_set_payload(g_request, payload, block_size);
        coap_set_header_block1(g_request, 0, 1, (uint16_t)block_size);
        coap_set_header_size1(g_request, (uint32_t)payload_size);
        g_request->type = COAP_TYPE_CON;
        g_client_cb->qos = HIGH_QOS;
      }
    } else {
      coap_set_payload(g_request, g_request_buffer->buffer, payload_size);
      g_request_buffer->ref_count = 0;
    }
#else  /* OC_BLOCK_WISE */
    coap_set_payload(g_request,
                     g_transaction->message->data + COAP_MAX_HEADER_SIZE,
                     payload_size);
#endif /* !OC_BLOCK_WISE */
  }

  if (payload_size > 0) {
#ifdef OC_SPEC_VER_OIC
    if (g_client_cb->endpoint.version == OIC_VER_1_1_0) {
      coap_set_header_content_format(g_request, APPLICATION_CBOR);
    } else
#endif /* OC_SPEC_VER_OIC */
    {
      coap_set_header_content_format(g_request, APPLICATION_VND_OCF_CBOR);
    }
  }

  bool success = false;
  g_transaction->message->length =
    coap_serialize_message(g_request, g_transaction->message->data);
  if (g_transaction->message->length > 0) {
    coap_send_transaction(g_transaction);

    if (g_client_cb->observe_seq == -1) {
      if (g_client_cb->qos == LOW_QOS)
        oc_set_delayed_callback(g_client_cb, &oc_ri_remove_client_cb,
                                OC_NON_LIFETIME);
      else
        oc_set_delayed_callback(g_client_cb, &oc_ri_remove_client_cb,
                                OC_EXCHANGE_LIFETIME);
    }

    success = true;
  } else {
    coap_clear_transaction(g_transaction);
    oc_ri_remove_client_cb(g_client_cb);
  }

#ifdef OC_BLOCK_WISE
  if (g_request_buffer && g_request_buffer->ref_count == 0) {
    oc_blockwise_free_request_buffer(g_request_buffer);
  }
  g_request_buffer = NULL;
#endif /* OC_BLOCK_WISE */

  g_transaction = NULL;
  g_client_cb = NULL;

  return success;
}

static bool
prepare_coap_request(oc_client_cb_t *cb)
{
  coap_message_type_t type = COAP_TYPE_NON;

  if (cb->qos == HIGH_QOS) {
    type = COAP_TYPE_CON;
  }

  g_transaction =
    coap_new_transaction(cb->mid, cb->token, cb->token_len, &cb->endpoint);

  if (!g_transaction) {
    return false;
  }

  oc_rep_new(g_transaction->message->data + COAP_MAX_HEADER_SIZE,
             OC_BLOCK_SIZE);

#ifdef OC_BLOCK_WISE
  if (cb->method == OC_PUT || cb->method == OC_POST) {
    g_request_buffer = oc_blockwise_alloc_request_buffer(
      oc_string(cb->uri) + 1, oc_string_len(cb->uri) - 1, &cb->endpoint,
      cb->method, OC_BLOCKWISE_CLIENT, OC_MIN_APP_DATA_SIZE);
    if (!g_request_buffer) {
      OC_ERR("g_request_buffer is NULL");
      return false;
    }
#ifdef OC_DYNAMIC_ALLOCATION
#ifdef OC_APP_DATA_BUFFER_POOL
    if (g_request_buffer->block) {
      oc_rep_new(g_request_buffer->buffer, g_request_buffer->buffer_size);
    } else
#endif
    {
      oc_rep_new_realloc(&g_request_buffer->buffer,
                         g_request_buffer->buffer_size, OC_MAX_APP_DATA_SIZE);
    }
#else  /* OC_DYNAMIC_ALLOCATION */
    oc_rep_new(g_request_buffer->buffer, OC_MIN_APP_DATA_SIZE);
#endif /* !OC_DYNAMIC_ALLOCATION */
    g_request_buffer->mid = cb->mid;
    g_request_buffer->client_cb = cb;
  }
#endif /* OC_BLOCK_WISE */

#ifdef OC_TCP
  if (cb->endpoint.flags & TCP) {
    coap_tcp_init_message(g_request, cb->method);
  } else
#endif /* OC_TCP */
  {
    coap_udp_init_message(g_request, type, cb->method, cb->mid);
  }

#ifdef OC_SPEC_VER_OIC
  if (cb->endpoint.version == OIC_VER_1_1_0) {
    coap_set_header_accept(g_request, APPLICATION_CBOR);
  } else
#endif /* OC_SPEC_VER_OIC */
  {
    coap_set_header_accept(g_request, APPLICATION_VND_OCF_CBOR);
  }

  coap_set_token(g_request, cb->token, cb->token_len);

  coap_set_header_uri_path(g_request, oc_string(cb->uri),
                           oc_string_len(cb->uri));

  if (cb->observe_seq != -1)
    coap_set_header_observe(g_request, cb->observe_seq);

  if (oc_string_len(cb->query) > 0) {
    coap_set_header_uri_query(g_request, oc_string(cb->query));
  }

  g_client_cb = cb;

  return true;
}

#ifdef OC_OSCORE

#ifdef OC_IPV4
static void
oc_do_multicast_update_ipv4()
{
  oc_message_t *multicast_update4 = oc_internal_allocate_outgoing_message();
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

  if (payload_size > 0) {
    coap_set_payload(g_request, g_multicast_update->data + COAP_MAX_HEADER_SIZE,
                     payload_size);
  } else {
    goto do_multicast_update_error;
  }

  if (payload_size > 0) {
    coap_set_header_content_format(g_request, APPLICATION_VND_OCF_CBOR);
  }

  g_multicast_update->length =
    coap_serialize_message(g_request, g_multicast_update->data);
  if (g_multicast_update->length > 0) {
    oc_send_message(g_multicast_update);
  } else {
    goto do_multicast_update_error;
  }

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

  g_multicast_update = oc_internal_allocate_outgoing_message();

  if (!g_multicast_update) {
    return false;
  }

  memcpy(&g_multicast_update->endpoint, &mcast, sizeof(oc_endpoint_t));

  oc_rep_new(g_multicast_update->data + COAP_MAX_HEADER_SIZE, OC_BLOCK_SIZE);

  coap_udp_init_message(g_request, type, OC_POST, coap_get_mid());

  coap_set_header_accept(g_request, APPLICATION_VND_OCF_CBOR);

  g_request->token_len = sizeof(g_request->token);
  oc_random_buffer(g_request->token, g_request->token_len);

  coap_set_header_uri_path(g_request, uri, strlen(uri));

  if (query) {
    coap_set_header_uri_query(g_request, query);
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
oc_get_diagnostic_message(oc_client_response_t *response, const char **msg,
                          size_t *size)
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

bool
oc_do_delete(const char *uri, oc_endpoint_t *endpoint, const char *query,
             oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  assert(handler != NULL);
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, OC_DELETE, query,
                                             client_handler, qos, user_data);

  if (!cb)
    return false;

  bool status = false;

  status = prepare_coap_request(cb);

  if (status)
    status = dispatch_coap_request();

  return status;
}

static oc_client_cb_t *
oc_do_get_int(const char *uri, oc_endpoint_t *endpoint, const char *query,
              oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, OC_GET, query,
                                             client_handler, qos, user_data);
  if (!cb)
    return NULL;

  bool status = false;

  status = prepare_coap_request(cb);

  if (status)
    status = dispatch_coap_request();
  if (!status) {
    oc_ri_remove_client_cb(cb);
    cb = NULL;
  }
  return cb;
}

bool
oc_do_get(const char *uri, oc_endpoint_t *endpoint, const char *query,
          oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  return oc_do_get_int(uri, endpoint, query, handler, qos, user_data) != NULL;
}

bool
oc_do_get_with_timeout(const char *uri, oc_endpoint_t *endpoint,
                       const char *query, uint16_t timeout_seconds,
                       oc_response_handler_t handler, oc_qos_t qos,
                       void *user_data)
{
  oc_client_cb_t *cb =
    oc_do_get_int(uri, endpoint, query, handler, qos, user_data);
  if (cb == NULL) {
    return false;
  }
  oc_set_delayed_callback(cb, oc_ri_remove_client_cb_with_notify_503,
                          timeout_seconds);
  return true;
}

bool
oc_init_put(const char *uri, oc_endpoint_t *endpoint, const char *query,
            oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, OC_PUT, query,
                                             client_handler, qos, user_data);
  if (!cb)
    return false;

  return prepare_coap_request(cb);
}

bool
oc_init_post(const char *uri, oc_endpoint_t *endpoint, const char *query,
             oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, OC_POST, query,
                                             client_handler, qos, user_data);
  if (!cb) {
    return false;
  }

  return prepare_coap_request(cb);
}

bool
oc_do_put(void)
{
  return dispatch_coap_request();
}

bool
oc_do_post(void)
{
  return dispatch_coap_request();
}

bool
oc_do_observe(const char *uri, oc_endpoint_t *endpoint, const char *query,
              oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, OC_GET, query,
                                             client_handler, qos, user_data);
  if (!cb)
    return false;

  cb->observe_seq = 0;

  bool status = false;

  status = prepare_coap_request(cb);

  if (status)
    status = dispatch_coap_request();

  return status;
}

bool
oc_stop_observe(const char *uri, const oc_endpoint_t *endpoint)
{
  oc_client_cb_t *cb = oc_ri_get_client_cb(uri, endpoint, OC_GET);

  if (!cb)
    return false;

  cb->mid = coap_get_mid();
  cb->observe_seq = 1;

  bool status = false;

  status = prepare_coap_request(cb);

  if (status)
    status = dispatch_coap_request();

  return status;
}

#ifdef OC_TCP
oc_event_callback_retval_t
oc_remove_ping_handler(void *data)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)data;

  oc_client_response_t timeout_response;
  timeout_response.code = OC_PING_TIMEOUT;
  timeout_response.endpoint = &cb->endpoint;
  timeout_response.user_data = cb->user_data;
  cb->handler.response(&timeout_response);

  return oc_ri_remove_client_cb(cb);
}

bool
oc_send_ping(bool custody, oc_endpoint_t *endpoint, uint16_t timeout_seconds,
             oc_response_handler_t handler, void *user_data)
{
  oc_client_handler_t client_handler = {
    .response = handler,
    .discovery = NULL,
    .discovery_all = NULL,
  };

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(
    "/ping", endpoint, 0, NULL, client_handler, LOW_QOS, user_data);
  if (!cb)
    return false;

  if (!coap_send_ping_message(endpoint, custody ? 1 : 0, cb->token,
                              cb->token_len)) {
    oc_ri_remove_client_cb(cb);
    return false;
  }

  oc_set_delayed_callback(cb, oc_remove_ping_handler, timeout_seconds);
  return true;
}
#endif /* OC_TCP */

#ifdef OC_IPV4
static oc_client_cb_t *
oc_do_ipv4_discovery(const char *query, oc_client_handler_t handler,
                     void *user_data)
{
  oc_make_ipv4_endpoint(mcast4, IPV4 | DISCOVERY, 5683, 0xe0, 0x00, 0x01, 0xbb);

  oc_client_cb_t *cb = oc_ri_alloc_client_cb("/oic/res", &mcast4, OC_GET, query,
                                             handler, LOW_QOS, user_data);

  if (cb) {
    cb->discovery = true;
    if (prepare_coap_request(cb)) {
      dispatch_coap_request();
    }
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

  cb->multicast = true;

  bool status = prepare_coap_request(cb);

  if (status) {
    status = dispatch_coap_request();
  }

  if (status) {
    return cb;
  }

  return NULL;
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

  if (cb) {
    if (cb4) {
      cb->mid = cb4->mid;
      memcpy(cb->token, cb4->token, cb4->token_len);
    }
    cb->multicast = true;
    if (prepare_coap_request(cb) && dispatch_coap_request()) {
      return true;
    }

    if (g_transaction) {
      coap_clear_transaction(g_transaction);
      g_transaction = NULL;
    }
    oc_ri_remove_client_cb(cb);
    g_client_cb = NULL;
  }
  return false;
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
  oc_client_cb_t *cb4 = NULL;
#ifdef OC_IPV4
  cb4 = oc_do_ipv4_multicast(uri, query, handler, user_data);
#endif /* OC_IPV4 */

  return multi_scope_ipv6_multicast(cb4, 0x02, uri, query, handler, user_data);
}

static bool
dispatch_ip_discovery(const oc_client_cb_t *cb4, const char *query,
                      oc_client_handler_t handler, oc_endpoint_t *endpoint,
                      oc_qos_t qos, void *user_data)
{
  if (!endpoint) {
    OC_ERR("require valid endpoint");
    return false;
  }

  oc_client_cb_t *cb = oc_ri_alloc_client_cb("/oic/res", endpoint, OC_GET,
                                             query, handler, qos, user_data);

  if (cb) {
    cb->discovery = true;
    if (cb4) {
      cb->mid = cb4->mid;
      memcpy(cb->token, cb4->token, cb4->token_len);
    }

    if (prepare_coap_request(cb) && dispatch_coap_request()) {
      goto exit;
    }

    if (g_transaction) {
      coap_clear_transaction(g_transaction);
      g_transaction = NULL;
      oc_ri_remove_client_cb(cb);
      g_client_cb = cb = NULL;
    }

    return false;
  }

exit:

  return true;
}

static bool
multi_scope_ipv6_discovery(oc_client_cb_t *cb4, uint8_t scope,
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
  oc_client_cb_t *cb4 = NULL;
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
  oc_client_cb_t *cb4 = NULL;
  oc_client_handler_t handlers = {
    .response = NULL,
    .discovery = NULL,
    .discovery_all = handler,
  };
#ifdef OC_IPV4
  cb4 = oc_do_ipv4_discovery(NULL, handlers, user_data);
#endif
  return multi_scope_ipv6_discovery(cb4, 0x02, NULL, handlers, user_data);
}

bool
oc_do_ip_discovery_all_at_endpoint(oc_discovery_all_handler_t handler,
                                   oc_endpoint_t *endpoint, void *user_data)
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
                               oc_endpoint_t *endpoint, void *user_data)
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
oc_close_session(oc_endpoint_t *endpoint)
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
