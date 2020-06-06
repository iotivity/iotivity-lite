/*
// Copyright (c) 2016 Intel Corporation
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

#include "messaging/coap/coap.h"
#include "messaging/coap/transactions.h"
#ifdef OC_TCP
#include "messaging/coap/coap_signal.h"
#endif /* OC_TCP */
#include "oc_api.h"
#ifdef OC_SECURITY
#include "security/oc_tls.h"
#ifdef OC_PKI
#include "security/oc_roles.h"
#endif /* OC_PKI */
#endif /* OC_SECURITY */
#ifdef OC_CLIENT

static coap_transaction_t *transaction;
coap_packet_t request[1];
oc_client_cb_t *client_cb;

#ifdef OC_BLOCK_WISE
static oc_blockwise_state_t *request_buffer = NULL;
#endif /* OC_BLOCK_WISE */

oc_event_callback_retval_t oc_ri_remove_client_cb(void *data);

static bool
dispatch_coap_request(void)
{
  int payload_size = oc_rep_get_encoded_payload_size();

  if ((client_cb->method == OC_PUT || client_cb->method == OC_POST) &&
      payload_size > 0) {

#ifdef OC_BLOCK_WISE
    request_buffer->payload_size = (uint32_t)payload_size;
    uint32_t block_size;
#ifdef OC_TCP
    if (!(transaction->message->endpoint.flags & TCP) &&
        payload_size > OC_BLOCK_SIZE) {
#else  /* OC_TCP */
    if ((long)payload_size > OC_BLOCK_SIZE) {
#endif /* !OC_TCP */
      const void *payload = oc_blockwise_dispatch_block(
        request_buffer, 0, (uint32_t)OC_BLOCK_SIZE, &block_size);
      if (payload) {
        coap_set_payload(request, payload, block_size);
        coap_set_header_block1(request, 0, 1, (uint16_t)block_size);
        coap_set_header_size1(request, (uint32_t)payload_size);
        request->type = COAP_TYPE_CON;
        client_cb->qos = HIGH_QOS;
      }
    } else {
      coap_set_payload(request, request_buffer->buffer, payload_size);
      request_buffer->ref_count = 0;
    }
#else  /* OC_BLOCK_WISE */
    coap_set_payload(request, transaction->message->data + COAP_MAX_HEADER_SIZE,
                     payload_size);
#endif /* !OC_BLOCK_WISE */
  }

  if (payload_size > 0) {
#ifdef OC_SPEC_VER_OIC
    if (client_cb->endpoint.version == OIC_VER_1_1_0) {
      coap_set_header_content_format(request, APPLICATION_CBOR);
    } else
#endif /* OC_SPEC_VER_OIC */
    {
      coap_set_header_content_format(request, APPLICATION_VND_OCF_CBOR);
    }
  }

  bool success = false;
  transaction->message->length =
    coap_serialize_message(request, transaction->message->data);
  if (transaction->message->length > 0) {
    coap_send_transaction(transaction);

    if (client_cb->observe_seq == -1) {
      if (client_cb->qos == LOW_QOS)
        oc_set_delayed_callback(client_cb, &oc_ri_remove_client_cb,
                                OC_NON_LIFETIME);
      else
        oc_set_delayed_callback(client_cb, &oc_ri_remove_client_cb,
                                OC_EXCHANGE_LIFETIME);
    }

    success = true;
  } else {
    coap_clear_transaction(transaction);
    oc_ri_remove_client_cb(client_cb);
  }

#ifdef OC_BLOCK_WISE
  if (request_buffer && request_buffer->ref_count == 0) {
    oc_blockwise_free_request_buffer(request_buffer);
  }
  request_buffer = NULL;
#endif /* OC_BLOCK_WISE */

  transaction = NULL;
  client_cb = NULL;

  return success;
}

static bool
prepare_coap_request(oc_client_cb_t *cb)
{
  coap_message_type_t type = COAP_TYPE_NON;

  if (cb->qos == HIGH_QOS) {
    type = COAP_TYPE_CON;
  }

  transaction = coap_new_transaction(cb->mid, &cb->endpoint);

  if (!transaction) {
    return false;
  }

#ifndef OC_BLOCK_WISE
  oc_rep_new(transaction->message->data + COAP_MAX_HEADER_SIZE, OC_BLOCK_SIZE);
#else  /* !OC_BLOCK_WISE */
  if (cb->method == OC_PUT || cb->method == OC_POST) {
    request_buffer = oc_blockwise_alloc_request_buffer(
      oc_string(cb->uri) + 1, oc_string_len(cb->uri) - 1, &cb->endpoint,
      cb->method, OC_BLOCKWISE_CLIENT);
    if (!request_buffer) {
      OC_ERR("request_buffer is NULL");
      return false;
    }
    oc_rep_new(request_buffer->buffer, OC_MAX_APP_DATA_SIZE);

    request_buffer->mid = cb->mid;
    request_buffer->client_cb = cb;
  }
#endif /* OC_BLOCK_WISE */

#ifdef OC_TCP
  if (cb->endpoint.flags & TCP) {
    coap_tcp_init_message(request, cb->method);
  } else
#endif /* OC_TCP */
  {
    coap_udp_init_message(request, type, cb->method, cb->mid);
  }

#ifdef OC_SPEC_VER_OIC
  if (cb->endpoint.version == OIC_VER_1_1_0) {
    coap_set_header_accept(request, APPLICATION_CBOR);
  } else
#endif /* OC_SPEC_VER_OIC */
  {
    coap_set_header_accept(request, APPLICATION_VND_OCF_CBOR);
  }

  coap_set_token(request, cb->token, cb->token_len);

  coap_set_header_uri_path(request, oc_string(cb->uri), oc_string_len(cb->uri));

  if (cb->observe_seq != -1)
    coap_set_header_observe(request, cb->observe_seq);

  if (oc_string_len(cb->query) > 0) {
    coap_set_header_uri_query(request, oc_string(cb->query));
  }

  client_cb = cb;

  return true;
}

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
oc_get_response_payload_raw(oc_client_response_t *response,
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
  oc_client_handler_t client_handler;
  client_handler.response = handler;

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

bool
oc_do_get(const char *uri, oc_endpoint_t *endpoint, const char *query,
          oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  oc_client_handler_t client_handler;
  client_handler.response = handler;

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, OC_GET, query,
                                             client_handler, qos, user_data);
  if (!cb)
    return false;

  bool status = false;

  status = prepare_coap_request(cb);

  if (status)
    status = dispatch_coap_request();

  return status;
}

bool
oc_init_put(const char *uri, oc_endpoint_t *endpoint, const char *query,
            oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  oc_client_handler_t client_handler;
  client_handler.response = handler;

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
  oc_client_handler_t client_handler;
  client_handler.response = handler;

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
  oc_client_handler_t client_handler;
  client_handler.response = handler;

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
oc_stop_observe(const char *uri, oc_endpoint_t *endpoint)
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
  oc_client_handler_t client_handler;
  client_handler.response = handler;

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
  oc_client_handler_t client_handler;
  client_handler.response = handler;

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
multi_scope_ipv6_multicast(oc_client_cb_t *cb4, uint8_t scope, const char *uri,
                           const char *query, oc_response_handler_t handler,
                           void *user_data)
{
  if (!uri || !handler) {
    return false;
  }

  oc_make_ipv6_endpoint(mcast, IPV6 | DISCOVERY, 5683, 0xff, scope, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58);
  mcast.addr.ipv6.scope = 0;

  oc_client_handler_t client_handler;
  client_handler.response = handler;

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

    if (transaction) {
      coap_clear_transaction(transaction);
      transaction = NULL;
    }
    oc_ri_remove_client_cb(cb);
    client_cb = NULL;
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
dispatch_ip_discovery(oc_client_cb_t *cb4, const char *query,
                      oc_client_handler_t handler, oc_endpoint_t *endpoint,
                      void *user_data)
{
  if (!endpoint) {
    OC_ERR("require valid endpoint");
    return false;
  }

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(
    "/oic/res", endpoint, OC_GET, query, handler, LOW_QOS, user_data);

  if (cb) {
    cb->discovery = true;
    if (cb4) {
      cb->mid = cb4->mid;
      memcpy(cb->token, cb4->token, cb4->token_len);
    }

    if (prepare_coap_request(cb) && dispatch_coap_request()) {
      goto exit;
    }

    if (transaction) {
      coap_clear_transaction(transaction);
      transaction = NULL;
      oc_ri_remove_client_cb(cb);
      client_cb = cb = NULL;
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
  return dispatch_ip_discovery(cb4, query, handler, &mcast, user_data);
}

bool
oc_do_site_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                    void *user_data)
{
  oc_client_handler_t handlers;
  handlers.discovery_all = handler;
  handlers.discovery = NULL;
  return multi_scope_ipv6_discovery(NULL, 0x05, NULL, handlers, user_data);
}

bool
oc_do_site_local_ipv6_discovery(const char *rt, oc_discovery_handler_t handler,
                                void *user_data)
{
  oc_client_handler_t handlers;
  handlers.discovery = handler;
  handlers.discovery_all = NULL;
  oc_string_t uri_query;
  memset(&uri_query, 0, sizeof(oc_string_t));
  if (rt && strlen(rt) > 0) {
    oc_concat_strings(&uri_query, "rt=", rt);
  }
  bool status = multi_scope_ipv6_discovery(NULL, 0x05, oc_string(uri_query),
                                           handlers, user_data);
  if (oc_string_len(uri_query) > 0) {
    oc_free_string(&uri_query);
  }
  return status;
}

bool
oc_do_realm_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                     void *user_data)
{
  oc_client_handler_t handlers;
  handlers.discovery_all = handler;
  handlers.discovery = NULL;
  return multi_scope_ipv6_discovery(NULL, 0x03, NULL, handlers, user_data);
}

bool
oc_do_realm_local_ipv6_discovery(const char *rt, oc_discovery_handler_t handler,
                                 void *user_data)
{
  oc_client_handler_t handlers;
  handlers.discovery = handler;
  handlers.discovery_all = NULL;
  oc_string_t uri_query;
  memset(&uri_query, 0, sizeof(oc_string_t));
  if (rt && strlen(rt) > 0) {
    oc_concat_strings(&uri_query, "rt=", rt);
  }
  bool status = multi_scope_ipv6_discovery(NULL, 0x03, oc_string(uri_query),
                                           handlers, user_data);
  if (oc_string_len(uri_query) > 0) {
    oc_free_string(&uri_query);
  }
  return status;
}

bool
oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler,
                   void *user_data)
{
  oc_client_handler_t handlers;
  handlers.discovery = handler;
  handlers.discovery_all = NULL;
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
  if (oc_string_len(uri_query) > 0) {
    oc_free_string(&uri_query);
  }
  return status;
}

bool
oc_do_ip_discovery_all(oc_discovery_all_handler_t handler, void *user_data)
{
  oc_client_cb_t *cb4 = NULL;
  oc_client_handler_t handlers;
  handlers.discovery_all = handler;
  handlers.discovery = NULL;
#ifdef OC_IPV4
  cb4 = oc_do_ipv4_discovery(NULL, handlers, user_data);
#endif
  return multi_scope_ipv6_discovery(cb4, 0x02, NULL, handlers, user_data);
}

bool
oc_do_ip_discovery_all_at_endpoint(oc_discovery_all_handler_t handler,
                                   oc_endpoint_t *endpoint, void *user_data)
{
  oc_client_handler_t handlers;
  handlers.discovery_all = handler;
  handlers.discovery = NULL;
  return dispatch_ip_discovery(NULL, NULL, handlers, endpoint, user_data);
}

bool
oc_do_ip_discovery_at_endpoint(const char *rt, oc_discovery_handler_t handler,
                               oc_endpoint_t *endpoint, void *user_data)
{
  oc_client_handler_t handlers;
  handlers.discovery = handler;
  handlers.discovery_all = NULL;
  oc_string_t uri_query;
  memset(&uri_query, 0, sizeof(oc_string_t));
  if (rt && strlen(rt) > 0) {
    oc_concat_strings(&uri_query, "rt=", rt);
  }
  bool status = dispatch_ip_discovery(NULL, oc_string(uri_query), handlers,
                                      endpoint, user_data);
  if (oc_string_len(uri_query) > 0) {
    oc_free_string(&uri_query);
  }
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

#if defined(OC_SECURITY) && defined(OC_PKI)
oc_role_t *
oc_get_all_roles(void)
{
  return oc_sec_get_role_creds();
}

static void
serialize_role_credential(CborEncoder *roles_array, oc_sec_cred_t *cr)
{
  oc_rep_begin_object(roles_array, roles);
  /* credtype */
  oc_rep_set_int(roles, credtype, cr->credtype);
  /* roleid */
  if (oc_string_len(cr->role.role) > 0) {
    oc_rep_set_object(roles, roleid);
    oc_rep_set_text_string(roleid, role, oc_string(cr->role.role));
    if (oc_string_len(cr->role.authority) > 0) {
      oc_rep_set_text_string(roleid, authority, oc_string(cr->role.authority));
    }
    oc_rep_close_object(roles, roleid);
  }
  /* credusage */
  oc_rep_set_text_string(roles, credusage, "oic.sec.cred.rolecert");
  /* publicdata */
  if (oc_string_len(cr->publicdata.data) > 0) {
    oc_rep_set_object(roles, publicdata);
    oc_rep_set_text_string(publicdata, data, oc_string(cr->publicdata.data));
    oc_rep_set_text_string(publicdata, encoding, "oic.sec.encoding.pem");
    oc_rep_close_object(roles, publicdata);
  }
  oc_rep_end_object(roles_array, roles);
}

bool
oc_assert_role(const char *role, const char *authority, oc_endpoint_t *endpoint,
               oc_response_handler_t handler, void *user_data)
{
  if (oc_tls_uses_psk_cred(oc_tls_get_peer(endpoint))) {
    return false;
  }
  oc_sec_cred_t *cr = oc_sec_find_role_cred(role, authority);
  if (cr) {
    oc_tls_select_cert_ciphersuite();
    if (oc_init_post("/oic/sec/roles", endpoint, NULL, handler, HIGH_QOS,
                     user_data)) {
      oc_rep_start_root_object();
      oc_rep_set_array(root, roles);
      serialize_role_credential(&roles_array, cr);
      oc_rep_close_array(root, roles);
      oc_rep_end_root_object();
      if (!oc_do_post()) {
        return false;
      }
    }
  }
  return false;
}

void
oc_assert_all_roles(oc_endpoint_t *endpoint, oc_response_handler_t handler,
                    void *user_data)
{
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (oc_tls_uses_psk_cred(peer)) {
    return;
  }
  oc_tls_select_cert_ciphersuite();
  oc_role_t *roles = oc_get_all_roles();
  if (roles) {
    if (oc_init_post("/oic/sec/roles", endpoint, NULL, handler, HIGH_QOS,
                     user_data)) {
      oc_rep_start_root_object();
      oc_rep_set_array(root, roles);

      while (roles) {
        oc_sec_cred_t *cr = oc_sec_find_role_cred(oc_string(roles->role),
                                                  oc_string(roles->authority));
        if (cr) {
          serialize_role_credential(&roles_array, cr);
        }

        roles = roles->next;
      }

      oc_rep_close_array(root, roles);
      oc_rep_end_root_object();
      if (!oc_do_post()) {
        return;
      }
    }
  }
}

#endif /* OC_SECURITY && OC_PKI */

#endif /* OC_CLIENT */
