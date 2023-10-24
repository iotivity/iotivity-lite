/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "oc_config.h"

#ifdef OC_CLIENT

#include "api/client/oc_client_cb_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_event_callback_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_ping_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/options_internal.h"
#include "oc_client_state.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include "util/oc_macros_internal.h"

#ifdef OC_TCP
#include "messaging/coap/signal_internal.h"
#endif /* OC_TCP */

#ifdef OC_SECURITY
#ifdef OC_OSCORE
#include "messaging/coap/oscore_internal.h"
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */

#include <assert.h>

OC_LIST(g_client_cbs);
OC_MEMB(g_client_cbs_s, oc_client_cb_t, OC_MAX_NUM_CONCURRENT_REQUESTS + 1);

typedef struct client_cb_match_token_t
{
  const uint8_t *data; ///< CoAP token
  uint8_t length;      ///< CoAP token length
} client_cb_match_token_t;

typedef struct client_cb_match_address_t
{
  const char *uri;
  const oc_endpoint_t *endpoint;
  oc_method_t method;
} client_cb_match_address_t;

oc_client_cb_t *
oc_ri_alloc_client_cb(const char *uri, const oc_endpoint_t *endpoint,
                      oc_method_t method, const char *query,
                      oc_client_handler_t handler, oc_qos_t qos,
                      void *user_data)
{
  oc_client_cb_t *cb = oc_memb_alloc(&g_client_cbs_s);
  if (cb == NULL) {
    OC_ERR("insufficient memory to add client callback");
    return NULL;
  }

  cb->mid = coap_get_mid();
  oc_new_string(&cb->uri, uri, strlen(uri));
  cb->method = method;
  cb->qos = qos;
  cb->handler = handler;
  cb->user_data = user_data;
  cb->token_len = sizeof(cb->token);
  oc_random_buffer(cb->token, cb->token_len);
  cb->discovery = false;
  cb->timestamp = oc_clock_time();
  cb->observe_seq = OC_COAP_OPTION_OBSERVE_NOT_SET;
  if (endpoint != NULL) {
    oc_endpoint_copy(&cb->endpoint, endpoint);
  }
  size_t query_len = query != NULL ? strlen(query) : 0;
  if (query_len > 0) {
    oc_new_string(&cb->query, query, query_len);
  }
  oc_list_add(g_client_cbs, cb);
  return cb;
}

oc_client_cb_t *
oc_client_cb_find_by_filter(oc_client_cb_filter_t filter, const void *user_data)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)oc_list_head(g_client_cbs);
  while (cb != NULL) {
    if (filter(cb, user_data)) {
      return cb;
    }
    cb = cb->next;
  }
  return NULL;
}

static bool
client_cb_filter_is_equal(const oc_client_cb_t *client_cb,
                          const void *user_data)
{
  return client_cb == user_data;
}

bool
oc_ri_is_client_cb_valid(const oc_client_cb_t *client_cb)
{
  return oc_client_cb_find_by_filter(client_cb_filter_is_equal, client_cb) !=
         NULL;
}

static bool
client_cb_filter_is_equal_by_token(const oc_client_cb_t *client_cb,
                                   const void *user_data)
{
  const client_cb_match_token_t *match =
    (const client_cb_match_token_t *)user_data;
  return client_cb->token_len == match->length &&
         memcmp(client_cb->token, match->data, match->length) == 0;
}

oc_client_cb_t *
oc_ri_find_client_cb_by_token(const uint8_t *token, uint8_t token_len)
{
  client_cb_match_token_t match = {
    .data = token,
    .length = token_len,
  };
  return oc_client_cb_find_by_filter(client_cb_filter_is_equal_by_token,
                                     &match);
}

static bool
client_cb_filter_is_equal_by_mid(const oc_client_cb_t *client_cb,
                                 const void *user_data)
{
  const uint16_t *mid = (const uint16_t *)user_data;
  return client_cb->mid == *mid;
}

oc_client_cb_t *
oc_ri_find_client_cb_by_mid(uint16_t mid)
{
  return oc_client_cb_find_by_filter(client_cb_filter_is_equal_by_mid, &mid);
}

static bool
client_cb_filter_is_equal_by_address(const oc_client_cb_t *client_cb,
                                     const void *user_data)
{
  const client_cb_match_address_t *match =
    (const client_cb_match_address_t *)user_data;
  return oc_string_is_cstr_equal(&client_cb->uri, match->uri,
                                 strlen(match->uri)) &&
         oc_endpoint_compare(&client_cb->endpoint, match->endpoint) == 0 &&
         client_cb->method == match->method;
}

oc_client_cb_t *
oc_ri_get_client_cb(const char *uri, const oc_endpoint_t *endpoint,
                    oc_method_t method)
{
  client_cb_match_address_t match = {
    .uri = uri,
    .endpoint = endpoint,
    .method = method,
  };
  return oc_client_cb_find_by_filter(client_cb_filter_is_equal_by_address,
                                     &match);
}

static void
client_cb_remove_from_lists(const oc_client_cb_t *cb)
{
  oc_ri_remove_timed_event_callback(cb, &oc_client_cb_remove_async);
  oc_ri_remove_timed_event_callback(
    cb, &oc_client_cb_remove_with_notify_timeout_async);
  oc_list_remove(g_client_cbs, cb);
}

oc_event_callback_retval_t
oc_client_cb_remove_async(void *data)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)data;
  oc_client_cb_free(cb);
  return OC_EVENT_DONE;
}

static void
oc_client_cb_dealloc(oc_client_cb_t *cb)
{
  assert(cb != NULL);
  // assert that we don't leave a dangling pointer
  assert(!oc_ri_is_client_cb_valid(cb));
  assert(oc_timed_event_callback_is_currently_processed(
           cb, oc_client_cb_remove_async) ||
         !oc_ri_has_timed_event_callback(cb, oc_client_cb_remove_async, false));
  assert(oc_timed_event_callback_is_currently_processed(
           cb, oc_client_cb_remove_with_notify_timeout_async) ||
         !oc_ri_has_timed_event_callback(
           cb, oc_client_cb_remove_with_notify_timeout_async, false));
#ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers_for_client_cb(cb);
#endif /* OC_BLOCK_WISE */
  oc_free_string(&cb->uri);
  oc_free_string(&cb->query);
  oc_memb_free(&g_client_cbs_s, cb);
}

void
oc_client_cb_free(oc_client_cb_t *cb)
{
  client_cb_remove_from_lists(cb);
  oc_client_cb_dealloc(cb);
}

#ifdef OC_TCP
static bool
client_cb_is_ping_response(const oc_client_cb_t *cb)
{
  return ((oc_string_len(cb->uri) == OC_CHAR_ARRAY_LEN(OC_PING_URI)) &&
          (memcmp(oc_string(cb->uri), OC_PING_URI,
                  OC_CHAR_ARRAY_LEN(OC_PING_URI)) == 0));
}
#endif /* OC_TCP */

static void
client_cb_notify_with_code(oc_client_cb_t *cb, oc_status_t code)
{
  OC_DBG("client_cb_notify_with_code - calling handler with request timeout "
         "for %d %s",
         cb->method, oc_string(cb->uri));
  client_cb_remove_from_lists(cb);

  oc_client_response_t client_response;
  memset(&client_response, 0, sizeof(oc_client_response_t));
  client_response.client_cb = cb;
  client_response.endpoint = &cb->endpoint;
  client_response.observe_option = OC_COAP_OPTION_OBSERVE_NOT_SET;
  client_response.user_data = cb->user_data;
  client_response.code = code;

  oc_response_handler_t handler = cb->handler.response;
  handler(&client_response);

#ifdef OC_TCP
  if (client_cb_is_ping_response(cb)) {
    oc_ri_remove_timed_event_callback(cb, oc_remove_ping_handler_async);
  }
#endif /* OC_TCP */

  oc_client_cb_dealloc(cb);
}

oc_event_callback_retval_t
oc_client_cb_remove_with_notify_timeout_async(void *data)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)data;
  client_cb_notify_with_code(cb, OC_REQUEST_TIMEOUT);
  return OC_EVENT_DONE;
}

void
oc_ri_free_client_cbs_by_mid_v1(uint16_t mid, oc_status_t code)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)oc_list_head(g_client_cbs);
  while (cb != NULL) {
    oc_client_cb_t *next = cb->next;
    if (!cb->multicast && !cb->discovery && cb->ref_count == 0 &&
        cb->mid == mid) {
      cb->ref_count = 1;
      client_cb_notify_with_code(cb, code);
      cb = (oc_client_cb_t *)oc_list_head(g_client_cbs);
      continue;
    }
    cb = next;
  }
}

void
oc_ri_free_client_cbs_by_mid(uint16_t mid)
{
  oc_ri_free_client_cbs_by_mid_v1(mid, OC_CANCELLED);
}

void
oc_ri_free_client_cbs_by_endpoint_v1(const oc_endpoint_t *endpoint,
                                     oc_status_t code)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)oc_list_head(g_client_cbs);
  while (cb != NULL) {
    oc_client_cb_t *next = cb->next;
    if (!cb->multicast && !cb->discovery && cb->ref_count == 0 &&
        oc_endpoint_compare(&cb->endpoint, endpoint) == 0) {
      cb->ref_count = 1;
      client_cb_notify_with_code(cb, code);
      cb = (oc_client_cb_t *)oc_list_head(g_client_cbs);
      continue;
    }
    cb = next;
  }
}

void
oc_ri_free_client_cbs_by_endpoint(const oc_endpoint_t *endpoint)
{
  oc_ri_free_client_cbs_by_endpoint_v1(endpoint, OC_CANCELLED);
}

static ocf_version_t
ri_get_ocf_version(oc_content_format_t cf)
{
#ifdef OC_SPEC_VER_OIC
  if (cf == APPLICATION_CBOR) {
    return OIC_VER_1_1_0;
  }
#else
  (void)cf;
#endif /* OC_SPEC_VER_OIC */
  return OCF_VER_1_0_0;
}

#ifdef OC_BLOCK_WISE
static oc_client_response_t
ri_prepare_client_response(const coap_packet_t *packet,
                           oc_blockwise_state_t **response_state,
                           oc_client_cb_t *cb, oc_endpoint_t *endpoint,
                           oc_content_format_t cf)
#else  /* !OC_BLOCK_WISE */
static oc_client_response_t
ri_prepare_client_response(const coap_packet_t *packet, oc_client_cb_t *cb,
                           oc_endpoint_t *endpoint, oc_content_format_t cf)
#endif /* OC_BLOCK_WISE */
{
  oc_client_response_t client_response;
  memset(&client_response, 0, sizeof(oc_client_response_t));
  client_response.client_cb = cb;
  client_response.endpoint = endpoint;
  client_response.observe_option = OC_COAP_OPTION_OBSERVE_NOT_SET;
  client_response.content_format = cf;
  client_response.user_data = cb->user_data;

  int status = oc_coap_status_to_status(packet->code);
  if (status != -1) {
    client_response.code = (oc_status_t)status;
  }

#ifdef OC_BLOCK_WISE
  if (response_state != NULL) {
    const oc_blockwise_response_state_t *bwt_response_state =
      (const oc_blockwise_response_state_t *)*response_state;
    if (bwt_response_state != NULL) {
      client_response.observe_option = bwt_response_state->observe_seq;
    }
  }
#else  /* !OC_BLOCK_WISE */
  coap_options_get_observe(packet, &client_response.observe_option);
#endif /* OC_BLOCK_WISE */

#ifdef OC_HAS_FEATURE_ETAG
  const uint8_t *etag;
  uint8_t etag_len = coap_options_get_etag(packet, &etag);
  assert(etag_len <= sizeof(client_response.etag.value));
  if (etag_len > 0) {
    memcpy(client_response.etag.value, etag, etag_len);
    client_response.etag.length = etag_len;
  }
#endif /* OC_HAS_FEATURE_ETAG */

  return client_response;
}

static void
ri_client_cb_set_observe_seq(oc_client_cb_t *cb, int observe_seq,
                             const oc_endpoint_t *endpoint)
{
  cb->observe_seq = observe_seq;

  // Drop old observe callback and keep the last one.
  if (cb->observe_seq == OC_COAP_OPTION_OBSERVE_REGISTER) {
    oc_client_cb_t *dup_cb = (oc_client_cb_t *)oc_list_head(g_client_cbs);
    while (dup_cb != NULL) {
      if (dup_cb != cb &&
          dup_cb->observe_seq != OC_COAP_OPTION_OBSERVE_NOT_SET &&
          dup_cb->token_len == cb->token_len &&
          memcmp(dup_cb->token, cb->token, cb->token_len) == 0 &&
          oc_string_is_equal(&dup_cb->uri, &cb->uri) &&
          oc_endpoint_compare(&dup_cb->endpoint, endpoint) == 0) {
        OC_DBG("Freeing cb %s, token 0x%02X%02X", oc_string(cb->uri),
               dup_cb->token[0], dup_cb->token[1]);
        oc_client_cb_free(dup_cb);
        break;
      }
      dup_cb = dup_cb->next;
    }
  }
}

#ifdef OC_BLOCK_WISE
bool
oc_client_cb_invoke(const coap_packet_t *response,
                    oc_blockwise_state_t **response_state, oc_client_cb_t *cb,
                    oc_endpoint_t *endpoint)
#else  /* !OC_BLOCK_WISE */
bool
oc_client_cb_invoke(const coap_packet_t *response, oc_client_cb_t *cb,
                    oc_endpoint_t *endpoint)
#endif /* OC_BLOCK_WISE */
{
  oc_content_format_t cf = 0;
  coap_options_get_content_format(response, &cf);
  endpoint->version = ri_get_ocf_version(cf);

  cb->ref_count = 1;

#ifdef OC_BLOCK_WISE
  oc_client_response_t client_response =
    ri_prepare_client_response(response, response_state, cb, endpoint, cf);
#else  /* !OC_BLOCK_WISE */
  oc_client_response_t client_response =
    ri_prepare_client_response(response, cb, endpoint, cf);
#endif /* OC_BLOCK_WISE */

#if defined(OC_OSCORE) && defined(OC_SECURITY)
  if (client_response.observe_option >=
      OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE) {
    uint64_t notification_num = 0;
    oscore_read_piv(endpoint->piv, endpoint->piv_len, &notification_num);
    if (notification_num < cb->notification_num) {
      return true;
    }
    cb->notification_num = notification_num;
  }
#endif /* OC_OSCORE && OC_SECURITY */

  const uint8_t *payload = NULL;
  size_t payload_len = 0;
#ifdef OC_BLOCK_WISE
  if (*response_state != NULL) {
    payload = (*response_state)->buffer;
    payload_len = (*response_state)->payload_size;
  }
#else  /* OC_BLOCK_WISE */
  payload_len = coap_get_payload(response, (const uint8_t **)&payload);
#endif /* !OC_BLOCK_WISE */
  client_response._payload = payload;
  client_response._payload_len = payload_len;

  bool separate = false;
  if (payload_len) {
    if (cb->discovery) {
      if (oc_discovery_process_payload(payload, payload_len, cb->handler,
                                       endpoint,
                                       cb->user_data) == OC_STOP_DISCOVERY) {
        uint16_t mid = cb->mid;
        cb->ref_count = 0;
        oc_ri_free_client_cbs_by_mid_v1(mid, OC_CANCELLED);
#ifdef OC_BLOCK_WISE
        *response_state = NULL;
#endif /* OC_BLOCK_WISE */
        return true;
      }
    } else {
      OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
      struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
      int err = 0;
      /* Do not parse an incoming payload when the Content-Format option
       * has not been set to the CBOR encoding.
       */
      if (cf == APPLICATION_CBOR || cf == APPLICATION_VND_OCF_CBOR) {
        err = oc_parse_rep(payload, payload_len, &client_response.payload);
      }
      if (err == 0) {
        oc_response_handler_t handler =
          (oc_response_handler_t)cb->handler.response;
        handler(&client_response);
      } else {
        OC_WRN("Error parsing payload!");
      }
      if (client_response.payload) {
        oc_free_rep(client_response.payload);
      }
      oc_rep_set_pool(prev_rep_objects);
    }
  } else {
    if (response->type == COAP_TYPE_ACK && response->code == 0) {
      separate = true;
      cb->separate = 1;
    } else if (!cb->discovery) {
      oc_response_handler_t handler =
        (oc_response_handler_t)cb->handler.response;
      handler(&client_response);
    }
  }

#ifdef OC_TCP
  if (response->code == PONG_7_03 || client_cb_is_ping_response(cb)) {
    oc_ri_remove_timed_event_callback(cb, oc_remove_ping_handler_async);
  }
#endif /* OC_TCP */

  if (!oc_ri_is_client_cb_valid(cb)) {
    return true;
  }

  cb->ref_count = 0;

  if (client_response.observe_option == OC_COAP_OPTION_OBSERVE_NOT_SET &&
      !separate && !cb->discovery) {
    if (cb->multicast) {
      if (cb->stop_multicast_receive) {
        uint16_t mid = cb->mid;
        oc_ri_free_client_cbs_by_mid_v1(mid, OC_CANCELLED);
      }
    } else {
      oc_client_cb_free(cb);
    }
#ifdef OC_BLOCK_WISE
    *response_state = NULL;
#endif /* OC_BLOCK_WISE */
    return true;
  }
  ri_client_cb_set_observe_seq(cb, client_response.observe_option, endpoint);
  return true;
}

static void
client_cb_free_all(void)
{
  oc_client_cb_t *cb = oc_list_pop(g_client_cbs);
  while (cb != NULL) {
    oc_client_cb_dealloc(cb);
    cb = oc_list_pop(g_client_cbs);
  }
}

void
oc_client_cbs_init(void)
{
  oc_list_init(g_client_cbs);
}

void
oc_client_cbs_shutdown(void)
{
  client_cb_free_all();
}

#endif /* OC_CLIENT */
