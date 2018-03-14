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
#include "oc_api.h"

#ifdef OC_CLIENT

static coap_transaction_t *transaction;
coap_packet_t request[1];
oc_client_cb_t *client_cb;

#ifdef OC_BLOCK_WISE
static oc_blockwise_state_t *request_buffer;
#endif /* OC_BLOCK_WISE */

oc_event_callback_retval_t oc_ri_remove_client_cb(void *data);

static bool
dispatch_coap_request(void)
{
  int payload_size = oc_rep_finalize();

  if ((client_cb->method == OC_PUT || client_cb->method == OC_POST) &&
      payload_size > 0) {

#ifdef OC_BLOCK_WISE
    request_buffer->payload_size = payload_size;
    uint16_t block_size;
    if (payload_size > OC_BLOCK_SIZE) {
      const void *payload = oc_blockwise_dispatch_block(
        request_buffer, 0, (uint16_t)OC_BLOCK_SIZE, &block_size);
      if (payload) {
        coap_set_payload(request, payload, block_size);
        coap_set_header_block1(request, 0, 1, block_size);
        coap_set_header_size1(request, payload_size);
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
    coap_set_header_content_format(request, APPLICATION_VND_OCF_CBOR);
  }

  transaction->message->length =
    coap_serialize_message(request, transaction->message->data);

  coap_send_transaction(transaction);

#ifdef OC_BLOCK_WISE
  request_buffer = 0;
#endif /* OC_BLOCK_WISE */

  if (client_cb->observe_seq == -1) {
    if (client_cb->qos == LOW_QOS)
      oc_set_delayed_callback(client_cb, &oc_ri_remove_client_cb,
                              OC_NON_LIFETIME);
    else
      oc_set_delayed_callback(client_cb, &oc_ri_remove_client_cb,
                              OC_EXCHANGE_LIFETIME);
  }

  transaction = 0;
  client_cb = 0;

  return true;
}

static bool
prepare_coap_request(oc_client_cb_t *cb)
{
  coap_message_type_t type = COAP_TYPE_NON;

  if (cb->qos == HIGH_QOS) {
    type = COAP_TYPE_CON;
  }

  transaction = coap_new_transaction(cb->mid, cb->endpoint);

  if (!transaction) {
    return false;
  }

#ifndef OC_BLOCK_WISE
  oc_rep_new(transaction->message->data + COAP_MAX_HEADER_SIZE, OC_BLOCK_SIZE);
#else  /* !OC_BLOCK_WISE */
  if (cb->method == OC_PUT || cb->method == OC_POST) {
    request_buffer = oc_blockwise_alloc_request_buffer(
      oc_string(cb->uri) + 1, oc_string_len(cb->uri) - 1, cb->endpoint,
      cb->method, OC_BLOCKWISE_CLIENT);
    if (!request_buffer) {
      return false;
    }

    oc_rep_new(request_buffer->buffer, OC_MAX_APP_DATA_SIZE);

    request_buffer->mid = cb->mid;
    request_buffer->client_cb = cb;
  }
#endif /* OC_BLOCK_WISE */

  coap_init_message(request, type, cb->method, cb->mid);

  coap_set_header_accept(request, APPLICATION_VND_OCF_CBOR);

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
oc_do_delete(const char *uri, oc_endpoint_t *endpoint,
             oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  oc_client_handler_t client_handler;
  client_handler.response = handler;

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(uri, endpoint, OC_DELETE, NULL,
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

#ifdef OC_IPV4
static bool
oc_do_ipv4_discovery(const oc_client_cb_t *ipv6_cb, const char *query,
                     oc_discovery_handler_t handler, void *user_data)
{
  bool status = false;
  oc_client_handler_t client_handler;
  client_handler.discovery = handler;

  oc_make_ipv4_endpoint(mcast4, IPV4 | DISCOVERY, 5683, 0xe0, 0x00, 0x01, 0xbb);

  oc_client_cb_t *cb = oc_ri_alloc_client_cb(
    "/oic/res", &mcast4, OC_GET, query, client_handler, LOW_QOS, user_data);

  if (!cb)
    return false;

  cb->mid = ipv6_cb->mid;
  memcpy(cb->token, ipv6_cb->token, cb->token_len);

  cb->discovery = true;
  status = prepare_coap_request(cb);

  if (status)
    status = dispatch_coap_request();

  return status;
}
#endif

bool
oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler,
                   void *user_data)
{
  oc_make_ipv6_endpoint(mcast, IPV6 | DISCOVERY, 5683, 0xff, 0x02, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0x01, 0x58);
  mcast.addr.ipv6.scope = 0;

  oc_client_handler_t client_handler;
  client_handler.discovery = handler;

  oc_string_t uri_query;
  memset(&uri_query, 0, sizeof(oc_string_t));
  if (rt && strlen(rt) > 0) {
    oc_concat_strings(&uri_query, "rt=", rt);
  }

  oc_client_cb_t *cb =
    oc_ri_alloc_client_cb("/oic/res", &mcast, OC_GET, oc_string(uri_query),
                          client_handler, LOW_QOS, user_data);

  if (!cb)
    return false;

  cb->discovery = true;

  bool status = false;

  status = prepare_coap_request(cb);

  if (status)
    status = dispatch_coap_request();

#ifdef OC_IPV4
  if (status)
    status = oc_do_ipv4_discovery(cb, oc_string(uri_query), handler, user_data);
#endif

  if (oc_string_len(uri_query) > 0) {
    oc_free_string(&uri_query);
  }

  return status;
}
#endif /* OC_CLIENT */
