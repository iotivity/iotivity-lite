/******************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
 ******************************************************************/
/*
 *
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

#include "oc_config.h"

#ifdef OC_SERVER

#include "api/oc_endpoint_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_message_internal.h"
#include "api/oc_query_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_server_api_internal.h"
#include "messaging/coap/coap_log.h"
#include "messaging/coap/coap_options.h"
#include "messaging/coap/observe.h"
#include "messaging/coap/separate.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_coap.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "util/oc_memb.h"

#ifdef OC_HAS_FEATURE_ETAG
#include "api/oc_etag_internal.h"
#endif /* OC_HAS_FEATURE_ETAG */

#ifdef OC_SECURITY
#include "security/oc_acl_internal.h"
#include "security/oc_pstat_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_BLOCK_WISE
#include "api/oc_blockwise_internal.h"
#endif /* OC_BLOCK_WISE */

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#include "oc_collection.h"
#ifdef OC_COLLECTIONS_IF_CREATE
#include "api/oc_resource_factory_internal.h"
#endif /* OC_COLLECTIONS_IF_CREATE */
#endif /* OC_COLLECTIONS */

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Interval in notifies in which NON notifies are changed to CON notifies to
 * check client. */
enum {
  COAP_OBSERVE_REFRESH_INTERVAL = 5,
};

#ifndef OC_MAX_OBSERVE_SIZE
#define OC_MAX_OBSERVE_SIZE OC_MAX_APP_DATA_SIZE
#endif

#define OC_MIN_OBSERVE_SIZE                                                    \
  (OC_MIN_APP_DATA_SIZE < OC_MAX_OBSERVE_SIZE ? OC_MIN_APP_DATA_SIZE           \
                                              : OC_MAX_OBSERVE_SIZE)

#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)

OC_LIST(g_batch_observers_list);
OC_MEMB(g_batch_observers_memb, coap_batch_observer_t, COAP_MAX_OBSERVERS);

typedef bool cmp_batch_observer_t(const coap_batch_observer_t *o,
                                  const void *ctx);

#if OC_DBG_IS_ENABLED
static const char *
batch_observer_get_resource_uri(coap_batch_observer_t *batch_obs)
{
  if (batch_obs->resource) {
    return oc_string(batch_obs->resource->uri);
  }
  return oc_string(batch_obs->removed_resource_uri);
}
#endif

static bool
cmp_batch_by_observer(const coap_batch_observer_t *o, const void *ctx)
{
  return o->obs == (const coap_observer_t *)ctx;
}

static bool
cmp_batch_by_resource(const coap_batch_observer_t *o, const void *ctx)
{
  return o->resource == (const oc_resource_t *)ctx;
}

static oc_event_callback_retval_t process_batch_observers_async(void *data);

static void
free_batch_observer(coap_batch_observer_t *batch_obs)
{
  if (batch_obs == NULL) {
    return;
  }
  oc_free_string(&batch_obs->removed_resource_uri);
  oc_memb_free(&g_batch_observers_memb, batch_obs);
}

static void
remove_discovery_batch_observers(cmp_batch_observer_t *cmp, const void *ctx)
{
  coap_batch_observer_t *batch_obs =
    (coap_batch_observer_t *)oc_list_head(g_batch_observers_list);
  while (batch_obs != NULL) {
    if (cmp == NULL || cmp(batch_obs, ctx)) {
      coap_batch_observer_t *next = batch_obs->next;
      oc_list_remove(g_batch_observers_list, batch_obs);
      free_batch_observer(batch_obs);
      batch_obs = next;
    } else {
      batch_obs = batch_obs->next;
    }
  }
}

void
coap_free_all_discovery_batch_observers(void)
{
  oc_remove_delayed_callback(NULL, &process_batch_observers_async);
  remove_discovery_batch_observers(NULL, NULL);
}

#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */

static int32_t g_observe_counter = OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE;

static int32_t
observe_increment_observe_counter(int32_t *counter)
{
  int32_t prev = *counter;
  prev == OC_COAP_OPTION_OBSERVE_MAX_VALUE
    ? *counter = OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE
    : ++(*counter);
  return prev;
}

void
coap_observe_counter_reset(void)
{
  g_observe_counter = OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE;
}

OC_LIST(g_observers_list);
OC_MEMB(g_observers_memb, coap_observer_t, COAP_MAX_OBSERVERS);

/*---------------------------------------------------------------------------*/
/*- Internal API ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/

oc_list_t
coap_get_observers(void)
{
  return g_observers_list;
}

static void
coap_remove_observer(coap_observer_t *o)
{
  COAP_DBG("Removing observer for /%s [0x%02X%02X]", oc_string(o->url),
           o->token[0], o->token[1]);

#ifdef OC_BLOCK_WISE
  oc_string_view_t query = oc_query_encode_interface(o->iface_mask);
  oc_blockwise_state_t *response_state = oc_blockwise_find_response_buffer(
    oc_string(o->resource->uri) + 1, oc_string_len(o->resource->uri) - 1,
    &o->endpoint, OC_GET, query.data, query.length, OC_BLOCKWISE_SERVER);
  // If response_state->payload_size == 0 it means, that this blockwise state
  // doesn't belong to the observer. Because the observer always sets
  // payload_size to greater than 0. The payload_size with 0 happens when the
  // client sends a cancelation request to cancel observation.
  if (response_state && response_state->payload_size > 0) {
    response_state->ref_count = 0;
  }
#endif /* OC_BLOCK_WISE */
  o->resource->num_observers--;
  oc_free_string(&o->url);
  oc_list_remove(g_observers_list, o);
#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
  remove_discovery_batch_observers(cmp_batch_by_observer, o);
#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */
  oc_memb_free(&g_observers_memb, o);
}

typedef void (*coap_on_remove_observer_handle_fn_t)(const coap_observer_t *obs);
typedef bool (*coap_on_remove_observer_filter_t)(const coap_observer_t *obs,
                                                 const void *data);

static int
coap_remove_observers_by_filter(coap_on_remove_observer_filter_t filter,
                                const void *filter_data,
                                coap_on_remove_observer_handle_fn_t on_remove,
                                bool match_all)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(g_observers_list);
  while (obs != NULL) {
    coap_observer_t *next = obs->next;
    if (filter(obs, filter_data)) {
      if (on_remove != NULL) {
        on_remove(obs);
      }
      coap_remove_observer(obs);
      ++removed;
      if (!match_all) {
        break;
      }
    }
    obs = next;
  }
  return removed;
}

typedef struct coap_observer_data_t
{
  const oc_endpoint_t *endpoint;
  const char *uri;
  size_t uri_len;
  oc_interface_mask_t iface_mask;
} coap_observer_data_t;

static bool
coap_observer_has_matching_data(const coap_observer_t *obs, const void *data)

{
  const coap_observer_data_t *match = (const coap_observer_data_t *)data;
  return (oc_endpoint_compare(&obs->endpoint, match->endpoint) == 0) &&
         (oc_string_len(obs->url) == match->uri_len &&
          memcmp(oc_string(obs->url), match->uri, match->uri_len) == 0) &&
         obs->iface_mask == match->iface_mask;
}

static int
coap_remove_observer_duplicates(const oc_endpoint_t *endpoint, const char *uri,
                                size_t uri_len, oc_interface_mask_t iface_mask)
{
  coap_observer_data_t od = {
    .endpoint = endpoint,
    .uri = uri,
    .uri_len = uri_len,
    .iface_mask = iface_mask,
  };
  return coap_remove_observers_by_filter(coap_observer_has_matching_data, &od,
                                         NULL, true);
}

coap_observer_t *
coap_add_observer(oc_resource_t *resource, uint16_t block2_size,
                  const oc_endpoint_t *endpoint, const uint8_t *token,
                  size_t token_len, const char *uri, size_t uri_len,
                  oc_interface_mask_t iface_mask)
{
  /* Remove existing observe relationship, if any. */
  int dup = coap_remove_observer_duplicates(endpoint, uri, uri_len, iface_mask);

  coap_observer_t *o = oc_memb_alloc(&g_observers_memb);
  if (o == NULL) {
    COAP_WRN("insufficient memory to add new observer");
    return NULL;
  }
  oc_new_string(&o->url, uri, uri_len);
  memcpy(&o->endpoint, endpoint, sizeof(oc_endpoint_t));
  o->token_len = (uint8_t)token_len;
  memcpy(o->token, token, token_len);
  o->last_mid = 0;
  o->iface_mask = iface_mask;
  o->obs_counter = g_observe_counter;
  o->resource = resource;
#ifdef OC_BLOCK_WISE
  o->block2_size = block2_size;
#else  /* OC_BLOCK_WISE */
  (void)block2_size;
#endif /* OC_BLOCK_WISE */
  resource->num_observers++;
#ifdef OC_DYNAMIC_ALLOCATION
  COAP_DBG("Adding observer (%u) for /%s [0x%02X%02X]",
           oc_list_length(g_observers_list) + 1, oc_string(o->url), o->token[0],
           o->token[1]);
#else  /* OC_DYNAMIC_ALLOCATION */
  COAP_DBG("Adding observer (%u/%u) for /%s [0x%02X%02X]",
           oc_list_length(g_observers_list) + 1, COAP_MAX_OBSERVERS,
           oc_string(o->url), o->token[0], o->token[1]);
#endif /* !OC_DYNAMIC_ALLOCATION */
  COAP_DBG("Removed %d duplicate observer(s)", dup);
  (void)dup;
  oc_list_add(g_observers_list, o);
  return o;
}

void
coap_free_all_observers(void)
{
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(g_observers_list);
  while (obs != NULL) {
    coap_observer_t *next = obs->next;
    coap_remove_observer(obs);
    obs = next;
  }
}

static bool
coap_observer_has_matching_endpoint(const coap_observer_t *obs,
                                    const void *data)
{
  const oc_endpoint_t *endpoint = (const oc_endpoint_t *)data;
  return oc_endpoint_compare(&obs->endpoint, endpoint) == 0;
}

int
coap_remove_observers_by_client(const oc_endpoint_t *endpoint)
{
  COAP_DBG("Unregistering observers for client at: ");
  COAP_LOGipaddr(*endpoint);
  int removed = coap_remove_observers_by_filter(
    coap_observer_has_matching_endpoint, endpoint, NULL, true);
  COAP_DBG("Removed %d observers", removed);
  return removed;
}

typedef struct coap_endpoint_and_token_t
{
  const oc_endpoint_t *endpoint;
  const uint8_t *token;
  size_t token_len;
} coap_endpoint_and_token_t;

static bool
coap_observer_has_matching_endpoint_and_token(const coap_observer_t *obs,
                                              const void *data)
{
  const coap_endpoint_and_token_t *eat =
    (const coap_endpoint_and_token_t *)data;
  return oc_endpoint_compare(&obs->endpoint, eat->endpoint) == 0 &&
         obs->token_len == eat->token_len &&
         memcmp(obs->token, eat->token, eat->token_len) == 0;
}

bool
coap_remove_observer_by_token(const oc_endpoint_t *endpoint,
                              const uint8_t *token, size_t token_len)
{
  COAP_DBG("Unregistering observers for request token 0x%02X%02X", token[0],
           token[1]);
  coap_endpoint_and_token_t eat = { endpoint, token, token_len };
  int removed = coap_remove_observers_by_filter(
    coap_observer_has_matching_endpoint_and_token, &eat, NULL, false);
  COAP_DBG("Removed %d observers", removed);
  return removed > 0;
}

typedef struct coap_endpoint_and_mid_t
{
  const oc_endpoint_t *endpoint;
  uint16_t mid;
} coap_endpoint_and_mid_t;

static bool
coap_observer_has_matching_endpoint_and_mid(const coap_observer_t *obs,
                                            const void *data)
{
  const coap_endpoint_and_mid_t *eam = (const coap_endpoint_and_mid_t *)data;
  return oc_endpoint_compare(&obs->endpoint, eam->endpoint) == 0 &&
         obs->last_mid == eam->mid;
}

bool
coap_remove_observer_by_mid(const oc_endpoint_t *endpoint, uint16_t mid)
{
  COAP_DBG("Unregistering observers for request MID %u", mid);
  coap_endpoint_and_mid_t eam = { endpoint, mid };
  int removed = coap_remove_observers_by_filter(
    coap_observer_has_matching_endpoint_and_mid, &eam, NULL, false);
  COAP_DBG("Removed %d observers", removed);
  return removed > 0;
}

static void
send_cancellation_notification(const coap_observer_t *obs, uint8_t code)
{
  coap_packet_t notification;
#ifdef OC_TCP
  if (obs->endpoint.flags & TCP) {
    coap_tcp_init_message(&notification, code);
  } else
#endif
  {
    coap_udp_init_message(&notification, COAP_TYPE_NON, code, 0);
  }
  coap_set_token(&notification, obs->token, obs->token_len);
  coap_transaction_t *transaction = coap_new_transaction(
    coap_get_mid(), obs->token, obs->token_len, &obs->endpoint);
  if (transaction == NULL) {
    return;
  }
  notification.mid = transaction->mid;
  transaction->message->length = coap_serialize_message(
    &notification, transaction->message->data, oc_message_buffer_size());
  if (transaction->message->length > 0) {
    coap_send_transaction(transaction);
  } else {
    coap_clear_transaction(transaction);
  }
}

static bool
coap_observer_match_resource(const coap_observer_t *obs, const void *data)
{
  const oc_resource_t *rsc = (const oc_resource_t *)data;
  if (obs->resource != rsc) {
    return false;
  }

  const char *rsc_uri = oc_string(rsc->uri);
  size_t rsc_uri_len = oc_string_len(rsc->uri);
  // resources should have a leading slash, but make sure
  if (rsc_uri_len > 0 && rsc_uri[0] == '/') {
    rsc_uri++;
    rsc_uri_len--;
  }

  const char *obs_uri = oc_string(obs->url);
  size_t obs_uri_len = oc_string_len(obs->url);
  // observers are usually without a leading slash, but make sure
  if (obs_uri_len > 0 && obs_uri[0] == '/') {
    obs_uri++;
    obs_uri_len--;
  }

  return (rsc_uri_len == obs_uri_len) &&
         memcmp(rsc_uri, obs_uri, obs_uri_len) == 0;
}

static void
send_not_found_notification(const coap_observer_t *obs)
{
  // https://www.rfc-editor.org/rfc/rfc7641.html#section-4.2
  send_cancellation_notification(obs, NOT_FOUND_4_04);
}

int
coap_remove_observers_by_resource(const oc_resource_t *rsc)
{
  COAP_DBG("Unregistering observers for resource %s", oc_string(rsc->uri));
  int removed = coap_remove_observers_by_filter(
    coap_observer_match_resource, rsc, send_not_found_notification, true);
  COAP_DBG("Removed %d observers", removed);
  return removed;
}

#ifdef OC_SECURITY

typedef struct device_with_dos_change_t
{
  size_t device;
  bool reset;
} device_with_dos_change_t;

static bool
coap_observer_has_matching_device(const coap_observer_t *obs, const void *data)
{
  const device_with_dos_change_t *ddc = (const device_with_dos_change_t *)data;
  return obs->endpoint.device == ddc->device &&
         (ddc->reset ||
          !oc_sec_check_acl(OC_GET, obs->resource, &obs->endpoint));
}

static void
send_service_unavailable_notification(const coap_observer_t *obs)
{
  send_cancellation_notification(obs, SERVICE_UNAVAILABLE_5_03);
}

int
coap_remove_observers_on_dos_change(size_t device, bool reset)
{
  COAP_DBG("Unregistering observers for device %zd (reset=%d)", device,
           (int)reset);
  device_with_dos_change_t ddc = { device, reset };
  int removed = coap_remove_observers_by_filter(
    coap_observer_has_matching_device, &ddc,
    send_service_unavailable_notification, true);
  COAP_DBG("Removed %d observers", removed);
  return removed;
}
#endif /* OC_SECURITY */

/*---------------------------------------------------------------------------*/
/*- Notification ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/

static void
send_notification_separate_response(const coap_observer_t *obs,
                                    oc_response_t *response,
                                    const oc_string_t *uri)
{
  coap_packet_t req;
#ifdef OC_TCP
  if (obs->endpoint.flags & TCP) {
    coap_tcp_init_message(&req, COAP_GET);
  } else
#endif /* OC_TCP */
  {
    coap_udp_init_message(&req, COAP_TYPE_NON, COAP_GET, 0);
  }
  memcpy(&req.token, obs->token, obs->token_len);
  req.token_len = obs->token_len;

  coap_options_set_uri_path(&req, oc_string(*uri), oc_string_len(*uri));

  COAP_DBG("creating separate response for notification");
#ifdef OC_BLOCK_WISE
  uint16_t block2_size = obs->block2_size;
#else  /* !OC_BLOCK_WISE */
  uint16_t block2_size = 0;
#endif /* OC_BLOCK_WISE */
  if (coap_separate_accept(&req, response->separate_response, &obs->endpoint,
                           obs->obs_counter, block2_size)) {
    response->separate_response->active = 1;
  }
}

#ifdef OC_BLOCK_WISE

static int
coap_prepare_notification_blockwise(coap_packet_t *notification,
                                    coap_observer_t *obs,
                                    const oc_response_t *response,
                                    oc_blockwise_finish_cb_t *finish_cb)
{
  assert(oc_string_len(obs->resource->uri) > 0);
  notification->type = COAP_TYPE_CON;
  oc_string_view_t query = oc_query_encode_interface(obs->iface_mask);
  oc_blockwise_state_t *response_state = oc_blockwise_find_response_buffer(
    oc_string(obs->resource->uri) + 1, oc_string_len(obs->resource->uri) - 1,
    &obs->endpoint, OC_GET, query.data, query.length, OC_BLOCKWISE_SERVER);
  if (response_state != NULL) {
    if (response_state->payload_size != response_state->next_block_offset) {
      COAP_DBG("skipping for blockwise transfer running");
      return 0;
    }
    oc_blockwise_free_response_buffer(response_state);
    response_state = NULL;
  }
#ifdef OC_HAS_FEATURE_ETAG
  bool generate_etag = false;
#else  /* OC_HAS_FEATURE_ETAG */
  bool generate_etag = true;
#endif /* OC_HAS_FEATURE_ETAG */
  response_state = oc_blockwise_alloc_response_buffer(
    oc_string(obs->resource->uri) + 1, oc_string_len(obs->resource->uri) - 1,
    &obs->endpoint, OC_GET, OC_BLOCKWISE_SERVER,
    (uint32_t)response->response_buffer->response_length, CONTENT_2_05,
    generate_etag);
  if (response_state == NULL) {
    COAP_ERR("cannot allocate response buffer");
    return -1;
  }
  oc_blockwise_response_state_t *bwt_state =
    (oc_blockwise_response_state_t *)response_state;
  if (query.data != NULL) {
    oc_new_string(&bwt_state->base.uri_query, query.data, query.length);
  }
  if (finish_cb != NULL) {
    bwt_state->base.finish_cb = finish_cb;
  }
  memcpy(bwt_state->base.buffer, response->response_buffer->buffer,
         response->response_buffer->response_length);
  bwt_state->base.payload_size =
    (uint32_t)response->response_buffer->response_length;
  bwt_state->base.content_format = response->response_buffer->content_format;
  uint32_t payload_size = 0;
  void *payload = oc_blockwise_dispatch_block(&bwt_state->base, 0,
                                              obs->block2_size, &payload_size);
  if (payload == NULL) {
    COAP_ERR("cannot dispatch block");
    return -1;
  }

#ifdef OC_HAS_FEATURE_ETAG
  uint8_t etag_len = response->response_buffer->etag.length;
  if (etag_len > 0 && response->response_buffer->response_length > 0) {
    const uint8_t *etag = response->response_buffer->etag.value;
    memcpy(&bwt_state->etag.value[0], &etag[0], etag_len);
    bwt_state->etag.length = etag_len;
  }
#endif /* OC_HAS_FEATURE_ETAG */

  coap_set_payload(notification, payload, payload_size);
  coap_options_set_block2(notification, 0, 1, obs->block2_size, 0);
  coap_options_set_size2(notification, bwt_state->base.payload_size);
  if (bwt_state->etag.length > 0) {
    coap_options_set_etag(notification, bwt_state->etag.value,
                          bwt_state->etag.length);
  }
  return 1;
}

#endif /* OC_BLOCK_WISE */

typedef struct
{
  oc_response_t *response;
  coap_observer_t *obs;
  const oc_string_t *uri;
  bool ignore_is_revert;
#ifdef OC_BLOCK_WISE
  oc_blockwise_finish_cb_t *finish_cb;
#endif /* OC_BLOCK_WISE */
} coap_send_notification_ctx_t;

static int
coap_prepare_notification(coap_packet_t *notification,
                          coap_send_notification_ctx_t ctx)
{
#ifdef OC_BLOCK_WISE
  if (ctx.response->response_buffer->response_length > ctx.obs->block2_size
#ifdef OC_TCP
      && (ctx.obs->endpoint.flags & TCP) == 0
#endif /* OC_TCP */
  ) {
    return coap_prepare_notification_blockwise(notification, ctx.obs,
                                               ctx.response, ctx.finish_cb);
  }
#endif /* OC_BLOCK_WISE */

  if ((ctx.obs->obs_counter % COAP_OBSERVE_REFRESH_INTERVAL) == 0
#ifdef OC_TCP
      && (ctx.obs->endpoint.flags & TCP) == 0
#endif /* OC_TCP */
  ) {
    COAP_DBG("forcing CON notification to check for client liveness");
    notification->type = COAP_TYPE_CON;
  }
  coap_set_payload(notification, ctx.response->response_buffer->buffer,
                   (uint32_t)ctx.response->response_buffer->response_length);
#ifdef OC_HAS_FEATURE_ETAG
  uint8_t etag_len = ctx.response->response_buffer->etag.length;
  if (etag_len > 0 && ctx.response->response_buffer->response_length > 0) {
    const uint8_t *etag = ctx.response->response_buffer->etag.value;
    coap_options_set_etag(notification, etag, etag_len);
  }
#endif /* OC_HAS_FEATURE_ETAG */
  return 1;
}

static int
coap_send_notification_internal(coap_send_notification_ctx_t ctx)
{
  COAP_DBG("send notification for resource %s", oc_string(*ctx.uri));
  if (ctx.response == NULL || ctx.obs == NULL) {
    return 0;
  }
  if (ctx.response->separate_response) {
    send_notification_separate_response(ctx.obs, ctx.response, ctx.uri);
    return 0;
  }

  COAP_DBG("notifying observer");
  coap_transaction_t *transaction = NULL;
  if (ctx.response->response_buffer == NULL) {
    COAP_DBG("response buffer is NULL");
    return 0;
  }
  bool is_revert = false;
  uint8_t status_code = CONTENT_2_05;
  if (ctx.obs->iface_mask == OC_IF_STARTUP_REVERT) {
    COAP_DBG("Setting Valid response for a REVERT notification");
    status_code = VALID_2_03;
    ctx.response->response_buffer->code = VALID_2_03;
    is_revert = true;
  }

  coap_packet_t notification;
#ifdef OC_TCP
  if (ctx.obs->endpoint.flags & TCP) {
    coap_tcp_init_message(&notification, status_code);
  } else
#endif /* OC_TCP */
  {
    coap_udp_init_message(&notification, COAP_TYPE_NON, status_code, 0);
  }

  if (ctx.ignore_is_revert || !is_revert) {
    int ret = coap_prepare_notification(&notification, ctx);
    if (ret <= 0) {
      return ret;
    }
  }

  coap_set_status_code(&notification, ctx.response->response_buffer->code);
  if (notification.code < BAD_REQUEST_4_00 &&
      ctx.obs->resource->num_observers) {
    coap_options_set_observe(
      &notification, observe_increment_observe_counter(&ctx.obs->obs_counter));
    observe_increment_observe_counter(&g_observe_counter);
  } else {
    coap_options_set_observe(&notification, OC_COAP_OPTION_OBSERVE_UNREGISTER);
  }
  if (ctx.response->response_buffer->content_format > 0) {
    coap_options_set_content_format(
      &notification, ctx.response->response_buffer->content_format);
  }
  coap_set_token(&notification, ctx.obs->token, ctx.obs->token_len);
  transaction = coap_new_transaction(coap_get_mid(), ctx.obs->token,
                                     ctx.obs->token_len, &ctx.obs->endpoint);
  if (transaction == NULL) {
    return -1;
  }

  ctx.obs->last_mid = transaction->mid;
  notification.mid = transaction->mid;
  transaction->message->length = coap_serialize_message(
    &notification, transaction->message->data, oc_message_buffer_size());
  if (transaction->message->length > 0) {
    coap_send_transaction(transaction);
  } else {
    coap_clear_transaction(transaction);
  }
  return 1;
}

static int
send_notification(coap_observer_t *obs, oc_response_t *response,
                  const oc_string_t *uri, bool ignore_is_revert)
{
  coap_send_notification_ctx_t ctx = {
    .response = response,
    .obs = obs,
    .uri = uri,
    .ignore_is_revert = ignore_is_revert,
#ifdef OC_BLOCK_WISE
    .finish_cb = NULL,
#endif /* OC_BLOCK_WISE */
  };
  return coap_send_notification_internal(ctx);
}

#ifdef OC_COLLECTIONS
void
coap_notify_collection_observers(const oc_collection_t *collection,
                                 oc_response_buffer_t *response_buf,
                                 oc_interface_mask_t iface_mask)
{
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  response.response_buffer = response_buf;
  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(g_observers_list);
       obs; obs = obs->next) {
    if (obs->resource != (const oc_resource_t *)collection) {
      continue;
    }
    if (obs->iface_mask != iface_mask) {
      // use default interface if obs->iface_mask == 0
      if ((obs->iface_mask | iface_mask) != collection->res.default_interface) {
        continue;
      }
    }
    if (send_notification(obs, &response, &collection->res.uri, true) < 0) {
      break;
    }
  }
}

static int
coap_notify_collection(oc_collection_t *collection,
                       oc_interface_mask_t iface_mask)
{
#ifndef OC_DYNAMIC_ALLOCATION
  uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#else /* !OC_DYNAMIC_ALLOCATION */
  uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
  if (!buffer) {
#if OC_WRN_IS_ENABLED
    oc_string_view_t iface = oc_query_encode_interface(iface_mask);
    COAP_WRN("coap_notify_collection(%s): out of memory allocating buffer",
             iface.data != NULL ? iface.data : "NULL");
#endif /* OC_WRN_IS_ENABLED */
    return -1;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  response_buffer.content_format = APPLICATION_VND_OCF_CBOR;
  response.response_buffer = &response_buffer;
  request.response = &response;
  request.request_payload = NULL;
  request.method = OC_GET;

#ifdef OC_DYNAMIC_ALLOCATION
  oc_rep_new_realloc_v1(&response_buffer.buffer, response_buffer.buffer_size,
                        OC_MAX_OBSERVE_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
  oc_rep_new_v1(response_buffer.buffer, response_buffer.buffer_size);
#endif /* !OC_DYNAMIC_ALLOCATION */

  request.resource = (oc_resource_t *)collection;

  int err = 0;
  if (!oc_handle_collection_request(OC_GET, &request, iface_mask, NULL)) {
#if OC_WRN_IS_ENABLED
    oc_string_view_t iface = oc_query_encode_interface(iface_mask);
    COAP_WRN("coap_notify_collection(%s): failed to handle collection request",
             iface.data != NULL ? iface.data : "NULL");
#endif /* OC_WRN_IS_ENABLED */
    err = -1;
    goto cleanup;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  response_buffer.buffer = oc_rep_shrink_encoder_buf(response_buffer.buffer);
#endif
  coap_notify_collection_observers(collection, &response_buffer, iface_mask);

cleanup:
#ifdef OC_DYNAMIC_ALLOCATION
  buffer = response_buffer.buffer;
  if (buffer)
    free(buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
  return err;
}

int
coap_notify_collection_baseline(oc_collection_t *collection)
{
  return coap_notify_collection(collection, OC_IF_BASELINE);
}

int
coap_notify_collection_batch(oc_collection_t *collection)
{
  return coap_notify_collection(collection, OC_IF_B);
}

int
coap_notify_collection_links_list(oc_collection_t *collection)
{
  return coap_notify_collection(collection, OC_IF_LL);
}

static int
coap_notify_collections(const oc_resource_t *resource)
{
#ifndef OC_DYNAMIC_ALLOCATION
  uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
  if (!buffer) {
    COAP_WRN("out of memory allocating buffer");
    return -1;
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_request_t request;
  memset(&request, 0, sizeof(request));
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  response.response_buffer = &response_buffer;
  response_buffer.content_format = APPLICATION_VND_OCF_CBOR;
  request.response = &response;
  request.request_payload = NULL;
  request.method = OC_GET;

  for (oc_collection_t *collection =
         oc_get_next_collection_with_link(resource, NULL);
       collection != NULL && collection->res.num_observers > 0;
       collection = oc_get_next_collection_with_link(resource, collection)) {
    COAP_DBG("Issue GET request to collection(%s) for resource(%s)",
             oc_string(collection->res.uri), oc_string(resource->uri));

    request.resource = (oc_resource_t *)collection;
#ifdef OC_DYNAMIC_ALLOCATION
    oc_rep_new_realloc_v1(&response_buffer.buffer, response_buffer.buffer_size,
                          OC_MAX_OBSERVE_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
    oc_rep_new_v1(response_buffer.buffer, response_buffer.buffer_size);
#endif /* !OC_DYNAMIC_ALLOCATION */

    if (!oc_handle_collection_request(OC_GET, &request, OC_IF_B, resource)) {
      COAP_WRN("failed to handle collection request");
      continue;
    }
#ifdef OC_DYNAMIC_ALLOCATION
    response_buffer.buffer_size = oc_rep_get_encoder_buffer_size();
#endif
    coap_notify_collection_observers(collection, &response_buffer, OC_IF_B);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  buffer = response_buffer.buffer;
  if (buffer)
    free(buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
  return 0;
}
#endif /* OC_COLLECTIONS */

#ifdef OC_HAS_FEATURE_ETAG

static void
coap_observe_response_buffer_set_etag(oc_response_buffer_t *buffer,
                                      const oc_resource_t *resource,
                                      const oc_endpoint_t *endpoint,
                                      oc_interface_mask_t iface_mask)
{
  uint64_t etag = (iface_mask == OC_IF_B)
                    ? oc_ri_get_batch_etag(resource, endpoint, endpoint->device)
                    : oc_ri_get_etag(resource);
  if (etag != OC_ETAG_UNINITIALIZED) {
    memcpy(&buffer->etag.value[0], &etag, sizeof(etag));
    buffer->etag.length = sizeof(etag);
  }
}

#endif /* OC_HAS_FEATURE_ETAG */

static bool
coap_fill_response(oc_response_t *response, oc_resource_t *resource,
                   const oc_endpoint_t *endpoint,
                   oc_interface_mask_t iface_mask, bool set_etag)
{
  if (!resource || !response) {
    return false;
  }
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.resource = resource;
  request.origin = endpoint;
  request.response = response;
  request.request_payload = NULL;
  request.method = OC_GET;
  if (iface_mask == 0) {
    iface_mask = resource->default_interface;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  oc_rep_new_realloc_v1(&response->response_buffer->buffer,
                        response->response_buffer->buffer_size,
                        OC_MAX_OBSERVE_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
  oc_rep_new_v1(response->response_buffer->buffer,
                response->response_buffer->buffer_size);
#endif /* !OC_DYNAMIC_ALLOCATION */
  if (resource->get_handler.cb) {
    resource->get_handler.cb(&request, iface_mask,
                             resource->get_handler.user_data);
  } else {
    response->response_buffer->code = CLEAR_TRANSACTION;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  response->response_buffer->buffer_size = oc_rep_get_encoded_payload_size();
#endif /* OC_DYNAMIC_ALLOCATION */
  if (response->response_buffer->code == CLEAR_TRANSACTION) {
    COAP_DBG("resource request ignored");
    return false;
  }

#ifdef OC_HAS_FEATURE_ETAG
  if (set_etag) {
    coap_observe_response_buffer_set_etag(response->response_buffer, resource,
                                          endpoint, iface_mask);
  }
#else  /* !OC_HAS_FEATURE_ETAG */
  (void)set_etag;
#endif /* OC_HAS_FEATURE_ETAG */

  return true;
}

static int
coap_iterate_observers(oc_resource_t *resource, oc_response_t *response,
                       const oc_endpoint_t *endpoint, bool prepare_response)
{
  bool resource_is_collection = false;
  oc_interface_mask_t iface_mask = resource->default_interface;
#ifdef OC_COLLECTIONS
  if (oc_check_if_collection(resource)) {
    resource_is_collection = true;
    iface_mask = OC_IF_BASELINE;
  }
#endif /* OC_COLLECTIONS */

  if (prepare_response && endpoint != NULL) {
    COAP_DBG("prepare GET request to resource(%s)", oc_string(resource->uri));
    if (!coap_fill_response(response, resource, endpoint, iface_mask, true)) {
      return 0;
    }
    prepare_response = false;
  }

  int num = 0;
  const oc_resource_t *discover_resource =
    oc_core_get_resource_by_index(OCF_RES, resource->device);
  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(g_observers_list);
       obs; obs = obs->next) {
    if ((obs->resource != resource) ||
        (endpoint != NULL &&
         oc_endpoint_compare(&obs->endpoint, endpoint) != 0)) {
      continue;
    } // obs->resource != resource || endpoint != obs->endpoint
    if (resource_is_collection && obs->iface_mask != OC_IF_BASELINE) {
      continue;
    }
    if (obs->resource == discover_resource && obs->iface_mask == OC_IF_B) {
      continue;
    }
    if (obs->iface_mask == OC_IF_STARTUP) {
      COAP_DBG("Skipping startup established observe");
      continue;
    }
    if (prepare_response) {
#if OC_DBG_IS_ENABLED
      oc_string64_t ep_str;
      const char *ep_cstr = "";
      if (oc_endpoint_to_string64(&obs->endpoint, &ep_str)) {
        ep_cstr = oc_string(ep_str);
      }
      COAP_DBG("prepare GET request to resource(%s) for endpoint %s",
               oc_string(resource->uri), ep_cstr);
#endif /* OC_DBG_IS_ENABLED */
      if (!coap_fill_response(response, resource, &obs->endpoint, iface_mask,
                              true)) {
        continue;
      }
    }
    if (send_notification(obs, response, &resource->uri, false) < 0) {
      return num;
    }
    ++num;
  }

  return num;
}

#ifdef OC_COLLECTIONS
static int
coap_notify_collections_with_links(const oc_resource_t *resource)
{
  int num_links = 0;
  if (resource->num_links > 0) {
    int notify = coap_notify_collections(resource);
    if (notify >= 0) {
      num_links = notify;
    }
  }
  return num_links;
}
#endif /* OC_COLLECTIONS */

static int
coap_notify_observers_internal(oc_resource_t *resource,
                               oc_response_buffer_t *response_buf,
                               const oc_endpoint_t *endpoint)
{
#ifdef OC_SECURITY
  const oc_sec_pstat_t *ps = oc_sec_get_pstat(resource->device);
  if (ps->s != OC_DOS_RFNOP) {
    COAP_WRN("device not in RFNOP, skipping notification");
    return 0;
  }
#endif /* OC_SECURITY */

  int num = 0;
  if (resource->num_observers == 0) {
    COAP_DBG("no observers");
    goto coap_notify_observers_internal_done;
  }

  oc_response_t response;
  memset(&response, 0, sizeof(response));
  if (response_buf != NULL) {
    response.response_buffer = response_buf;
    num = coap_iterate_observers(resource, &response, endpoint, false);
    goto coap_notify_observers_internal_done;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
  if (buffer == NULL) {
    COAP_WRN("out of memory allocating buffer");
    return -1;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  response_buffer.content_format = APPLICATION_VND_OCF_CBOR;
  response.response_buffer = &response_buffer;

  num = coap_iterate_observers(resource, &response, endpoint, true);

#ifdef OC_DYNAMIC_ALLOCATION
  buffer = response_buffer.buffer;
  if (buffer) {
    free(buffer);
  }
#endif /* OC_DYNAMIC_ALLOCATION */

coap_notify_observers_internal_done:
#ifdef OC_COLLECTIONS
  num += coap_notify_collections_with_links(resource);
#endif /* OC_COLLECTIONS */
  return num;
}

void
notify_resource_defaults_observer(oc_resource_t *resource,
                                  oc_interface_mask_t iface_mask)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
  if (buffer == NULL) {
    COAP_WRN("out of memory allocating buffer");
    return;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_response_t response;
  memset(&response, 0, sizeof(response));
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  response_buffer.content_format = APPLICATION_VND_OCF_CBOR;
  response.response_buffer = &response_buffer;
  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(g_observers_list);
       obs; obs = obs->next) {
    if (obs->resource != resource) {
      continue;
    }
    if (obs->iface_mask != iface_mask) {
      continue;
    }
    if (!coap_fill_response(&response, resource, &obs->endpoint, iface_mask,
                            false)) {
      continue;
    }
    if (send_notification(obs, &response, &resource->uri, true) < 0) {
      break;
    }
  }
#ifdef OC_DYNAMIC_ALLOCATION
  buffer = response_buffer.buffer;
  if (buffer) {
    free(buffer);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
void
coap_dispatch_process_batch_observers(void)
{
  oc_reset_delayed_callback(NULL, &process_batch_observers_async, 0);
  _oc_signal_event_loop();
}

static void
create_batch_for_removed_resource(CborEncoder *links,
                                  coap_batch_observer_t *batch_obs)
{
  COAP_DBG("creating batch response for resource(%s)",
           oc_string(batch_obs->removed_resource_uri));
  oc_rep_start_object(links, links_obj);
  char href[OC_MAX_OCF_URI_SIZE];
  memcpy(href, "ocf://", 6);
  oc_uuid_to_str(oc_core_get_device_id(batch_obs->obs->resource->device),
                 href + 6, OC_UUID_LEN);
  memcpy(href + 6 + OC_UUID_LEN - 1, oc_string(batch_obs->removed_resource_uri),
         oc_string_len(batch_obs->removed_resource_uri));
  href[6 + OC_UUID_LEN - 1 + oc_string_len(batch_obs->removed_resource_uri)] =
    '\0';
  oc_rep_set_text_string(links_obj, href, href);
  oc_rep_set_key(oc_rep_object(links_obj), "rep");
  memcpy(oc_rep_get_encoder(), oc_rep_object(links_obj), sizeof(CborEncoder));
  oc_rep_start_root_object();
  oc_rep_end_root_object();
  memcpy(oc_rep_object(links_obj), oc_rep_get_encoder(), sizeof(CborEncoder));
  oc_rep_end_object(links, links_obj);
}

static void
create_batch_for_batch_observer(CborEncoder *links,
                                coap_batch_observer_t *batch_obs,
                                const oc_endpoint_t *endpoint)
{
  if (batch_obs->resource != NULL) {
    COAP_DBG("creating batch response for resource(%s)",
             oc_string(batch_obs->resource->uri));
    oc_discovery_create_batch_for_resource(links, batch_obs->resource,
                                           endpoint);
    return;
  }
  COAP_DBG("creating batch response for removed resource(%s)",
           oc_string(batch_obs->removed_resource_uri));
  create_batch_for_removed_resource(links, batch_obs);
}

static int
notify_batch_observer(coap_observer_t *obs, oc_response_t *response)
{
  coap_send_notification_ctx_t ctx = {
    .response = response,
    .obs = obs,
    .uri = &obs->resource->uri,
    .ignore_is_revert = true,
#ifdef OC_BLOCK_WISE
    .finish_cb = coap_dispatch_process_batch_observers,
#endif /* OC_BLOCK_WISE */
  };
  return coap_send_notification_internal(ctx);
}

static bool
observe_batch_set_response_buffer(coap_batch_observer_t *batch_obs,
                                  oc_response_buffer_t *response_buffer)
{
  const coap_observer_t *obs = batch_obs->obs;
  oc_rep_start_links_array();
  int size_before = oc_rep_get_encoded_payload_size();
  create_batch_for_batch_observer(&links_array, batch_obs, &obs->endpoint);
  coap_batch_observer_t *bnext = batch_obs->next;
  while (bnext != NULL) {
    coap_batch_observer_t *next = bnext->next;
    if (bnext->obs == obs) {
      create_batch_for_batch_observer(&links_array, bnext, &obs->endpoint);
      oc_list_remove(g_batch_observers_list, bnext);
      free_batch_observer(bnext);
    }
    bnext = next;
  }
  int size_after = oc_rep_get_encoded_payload_size();
  if (size_before == size_after) {
    COAP_DBG("drop observations");
    return false;
  }
  oc_rep_end_links_array();
  size_after = oc_rep_get_encoded_payload_size();
  if (size_after < 0) {
    COAP_ERR("invalid size after batch serialization");
    return false;
  }
  COAP_DBG("sending data with size %d", size_after);
  response_buffer->content_format = APPLICATION_VND_OCF_CBOR;
  response_buffer->response_length = size_after;
  response_buffer->code = oc_status_code_unsafe(OC_STATUS_OK);
#ifdef OC_HAS_FEATURE_ETAG
  uint64_t etag =
    oc_ri_get_batch_etag(obs->resource, &obs->endpoint, obs->endpoint.device);
  if (etag != OC_ETAG_UNINITIALIZED) {
    memcpy(&response_buffer->etag.value[0], &etag, sizeof(etag));
    response_buffer->etag.length = sizeof(etag);
  }
#endif /* OC_HAS_FEATURE_ETAG */
  return true;
}

coap_batch_observer_t *
coap_get_discovery_batch_observers(void)
{
  return (coap_batch_observer_t *)oc_list_head(g_batch_observers_list);
}

void
coap_process_discovery_batch_observers(void)
{
  coap_batch_observer_t *batch_obs =
    (coap_batch_observer_t *)oc_list_head(g_batch_observers_list);
  if (batch_obs == NULL) {
    return;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
  if (buffer == NULL) {
    COAP_WRN("out of memory allocating buffer");
    return;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  COAP_DBG("Issue GET request to discovery resource for %s resource",
           batch_observer_get_resource_uri(batch_obs));
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  response_buffer.content_format = APPLICATION_VND_OCF_CBOR;

  while (batch_obs != NULL) {
#ifdef OC_BLOCK_WISE
    coap_observer_t *obs = batch_obs->obs;
    // obs->iface_mask is always OC_IF_B
    oc_string_view_t query = oc_query_encode_interface(obs->iface_mask);
    // obs->resource is always the discovery resource
    const oc_blockwise_state_t *response_state =
      oc_blockwise_find_response_buffer(oc_string(obs->resource->uri) + 1,
                                        oc_string_len(obs->resource->uri) - 1,
                                        &obs->endpoint, OC_GET, query.data,
                                        query.length, OC_BLOCKWISE_SERVER);
    if (response_state != NULL) {
      COAP_DBG(
        "response_state is not NULL, sending of batch response currently "
        "in progress for endpoint, skipping to next observer");
      batch_obs = batch_obs->next;
      continue;
    }
#endif /* OC_BLOCK_WISE */
#ifdef OC_DYNAMIC_ALLOCATION
    oc_rep_new_realloc_v1(&response_buffer.buffer, response_buffer.buffer_size,
                          OC_MAX_OBSERVE_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
    oc_rep_new_v1(response_buffer.buffer, response_buffer.buffer_size);
#endif /* !OC_DYNAMIC_ALLOCATION */
    if (observe_batch_set_response_buffer(batch_obs, &response_buffer)) {
      oc_response_t response;
      memset(&response, 0, sizeof(response));
      response.response_buffer = &response_buffer;
      if (notify_batch_observer(obs, &response) < 0) {
        goto leave_notify_observers;
      }
    }
#ifdef OC_DYNAMIC_ALLOCATION
    response_buffer.buffer_size = oc_rep_get_encoder_buffer_size();
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_list_remove(g_batch_observers_list, batch_obs);
    free_batch_observer(batch_obs);
    batch_obs = (coap_batch_observer_t *)oc_list_head(g_batch_observers_list);
  }
leave_notify_observers:
#ifdef OC_DYNAMIC_ALLOCATION
  buffer = response_buffer.buffer;
  if (buffer != NULL) {
    free(buffer);
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  ;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static oc_event_callback_retval_t
process_batch_observers_async(void *data)
{
  (void)data;
  coap_process_discovery_batch_observers();
  return OC_EVENT_DONE;
}

static bool
cmp_add_batch_observer_resource(const coap_batch_observer_t *batch_obs,
                                const coap_observer_t *obs,
                                const oc_resource_t *resource, bool removed)
{
  if (batch_obs->obs != obs) {
    return false;
  }
  if (batch_obs->resource == resource) {
    return true;
  }
  if (!removed) {
    return false;
  }
  if (oc_string_len(batch_obs->removed_resource_uri) !=
      oc_string_len(resource->uri)) {
    return false;
  }
  return memcmp(oc_string(batch_obs->removed_resource_uri),
                oc_string(resource->uri), oc_string_len(resource->uri)) == 0;
}

void
coap_remove_discovery_batch_observers(const oc_resource_t *resource)
{
  COAP_DBG("remove discovery batch observers for resource(%s)",
           oc_string(resource->uri));
  remove_discovery_batch_observers(cmp_batch_by_resource, resource);
}

bool
coap_add_discovery_batch_observer(oc_resource_t *resource, bool removed,
                                  bool dispatch)
{
  assert(resource != NULL);
  const oc_resource_t *discover_resource =
    oc_core_get_resource_by_index(OCF_RES, resource->device);
  if (discover_resource == resource) {
    return false;
  }

  /* iterate over observers */
  bool added = false;
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(g_observers_list);
       obs; obs = obs->next) {
    if (obs->resource != discover_resource || obs->iface_mask != OC_IF_B) {
      continue;
    }
    if (removed && (oc_string_len(resource->uri) == 0)) {
      COAP_WRN("removed resource has no URI");
      continue;
    }
#ifdef OC_SECURITY
    if (!oc_sec_check_acl(OC_GET, resource, &obs->endpoint)) {
      COAP_DBG("resource %s not authorized for endpoint",
               oc_string(resource->uri));
      continue;
    }
#endif /* OC_SECURITY */
    // deduplicate observations.
    bool found = false;
    for (coap_batch_observer_t *batch_obs =
           (coap_batch_observer_t *)oc_list_head(g_batch_observers_list);
         batch_obs; batch_obs = batch_obs->next) {
      if (cmp_add_batch_observer_resource(batch_obs, obs, resource, removed)) {
        found = true;
        break;
      }
    }
    if (found) {
      COAP_DBG("skipping duplicate batch notification for resource(%s)",
               oc_string(resource->uri));
      continue;
    }
    coap_batch_observer_t *o = oc_memb_alloc(&g_batch_observers_memb);
    if (o == NULL) {
      COAP_ERR("cannot allocate batch notification for resource (%s)",
               oc_string(resource->uri));
      return false;
    }
    o->obs = obs;
    if (removed) {
      COAP_DBG("batch notification for removed resource(%s) added",
               oc_string(resource->uri));
      oc_new_string(&o->removed_resource_uri, oc_string(resource->uri),
                    oc_string_len(resource->uri));
    } else {
      COAP_DBG("batch notification for resource(%s) added",
               oc_string(resource->uri));
      o->resource = resource;
    }
    oc_list_add(g_batch_observers_list, o);
    added = true;
  }

  if (dispatch) {
    coap_dispatch_process_batch_observers();
  }
  return added;
}

#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */

#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
static int
notify_discovery_observers(oc_resource_t *resource)
{
#ifndef OC_DYNAMIC_ALLOCATION
  uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
  if (buffer == NULL) {
    COAP_WRN("out of memory allocating buffer");
    return -1;
  } //! buffer
#endif /* OC_DYNAMIC_ALLOCATION */

  COAP_DBG("Issue GET request to resource %s", oc_string(resource->uri));
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  response_buffer.content_format = APPLICATION_VND_OCF_CBOR;
  response.response_buffer = &response_buffer;

  int num = 0;
  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(g_observers_list);
       obs; obs = obs->next) {
    if (obs->resource != resource) {
      continue;
    }
    oc_interface_mask_t iface_mask = obs->iface_mask;
    if ((iface_mask & OC_IF_B) != 0) {
      continue;
    }
    if (!coap_fill_response(&response, resource, &obs->endpoint,
                            obs->iface_mask, true)) {
      continue;
    }
    if (send_notification(obs, &response, &resource->uri, false) < 0) {
      break;
    }
    ++num;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  buffer = response_buffer.buffer;
  if (buffer) {
    free(buffer);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  return num;
}
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */

int
coap_notify_observers(oc_resource_t *resource,
                      oc_response_buffer_t *response_buf,
                      const oc_endpoint_t *endpoint)
{
#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
#ifdef OC_RES_BATCH_SUPPORT
  coap_add_discovery_batch_observer(resource, /*removed*/ false,
                                    /*dispatch*/ true);
#endif /* OC_RES_BATCH_SUPPORT */
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */
  if ((resource->properties & OC_OBSERVABLE) == 0) {
    return 0;
  }
#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
  oc_resource_t *discover_resource =
    oc_core_get_resource_by_index(OCF_RES, resource->device);
  if (resource == discover_resource) {
    return notify_discovery_observers(discover_resource);
  }
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */
  return coap_notify_observers_internal(resource, response_buf, endpoint);
}

bool
coap_resource_is_observed(const oc_resource_t *resource)
{
#if defined(OC_DISCOVERY_RESOURCE_OBSERVABLE) && defined(OC_RES_BATCH_SUPPORT)
  const oc_resource_t *discover_resource =
    oc_core_get_resource_by_index(OCF_RES, resource->device);
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE && OC_RES_BATCH_SUPPORT */
  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(g_observers_list);
       obs; obs = obs->next) {
    if (obs->resource == resource) {
      return true;
    }
#ifdef OC_RES_BATCH_SUPPORT
#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
    if ((obs->resource == discover_resource) &&
        (obs->iface_mask & OC_IF_B) != 0) {
      return true;
    }
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */
#if defined(OC_COLLECTIONS) && defined(OC_COLLECTIONS_IF_CREATE)
    const oc_rt_created_t *rtc =
      oc_rt_get_factory_create_for_resource(resource);
    if ((rtc != NULL) && (obs->resource == (oc_resource_t *)rtc->collection) &&
        (obs->iface_mask & OC_IF_B)) {
      return true;
    }
#endif /* OC_COLLECTIONS && OC_COLLECTIONS_IF_CREATE */
#endif /* OC_RES_BATCH_SUPPORT */
  }
  return false;
}

#endif /* OC_SERVER */
