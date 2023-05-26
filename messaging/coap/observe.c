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

#include "oc_api.h"
#include "observe.h"
#include "separate.h"
#include "util/oc_memb.h"
#include <stdio.h>
#include <string.h>

#include "oc_buffer.h"
#ifdef OC_SECURITY
#include "security/oc_acl_internal.h"
#include "security/oc_pstat.h"
#endif /* OC_SECURITY */

#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif /* OC_BLOCK_WISE */

#ifdef OC_COLLECTIONS
#include "oc_collection.h"
#endif /* OC_COLLECTIONS */

#if defined(OC_COLLECTIONS) && defined(OC_COLLECTIONS_IF_CREATE)
#include "api/oc_resource_factory.h"
#endif /* OC_COLLECTIONS && OC_COLLECTIONS_IF_CREATE */

#include "oc_coap.h"
#include "oc_endpoint.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_core_res.h"
#include "api/oc_server_api_internal.h"

#ifndef OC_MAX_OBSERVE_SIZE
#define OC_MAX_OBSERVE_SIZE OC_MAX_APP_DATA_SIZE
#endif
#define OC_MIN_OBSERVE_SIZE                                                    \
  (OC_MIN_APP_DATA_SIZE < OC_MAX_OBSERVE_SIZE ? OC_MIN_APP_DATA_SIZE           \
                                              : OC_MAX_OBSERVE_SIZE)

#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
typedef struct batch_observer
{
  struct batch_observer *next; /* for LIST */
  coap_observer_t *obs;
  oc_resource_t *resource;
  oc_string_t removed_resource_uri;
} batch_observer_t;

OC_LIST(batch_observers_list);
OC_MEMB(batch_observers_memb, batch_observer_t, COAP_MAX_OBSERVERS);

typedef bool cmp_batch_observer_t(batch_observer_t *o, void *ctx);

#if OC_DBG_IS_ENABLED
static const char *
batch_observer_get_resource_uri(batch_observer_t *batch_obs)
{
  if (batch_obs->resource) {
    return oc_string(batch_obs->resource->uri);
  }
  return oc_string(batch_obs->removed_resource_uri);
}
#endif

static bool
cmp_batch_by_observer(batch_observer_t *o, void *ctx)
{
  return o->obs == (coap_observer_t *)ctx;
}

static bool
cmp_batch_by_resource(batch_observer_t *o, void *ctx)
{
  return o->resource == (oc_resource_t *)ctx;
}

static oc_event_callback_retval_t process_batch_observers(void *data);

static void
free_batch_observer(batch_observer_t *batch_obs)
{
  if (batch_obs == NULL) {
    return;
  }
  oc_free_string(&batch_obs->removed_resource_uri);
  oc_memb_free(&batch_observers_memb, batch_obs);
}

static void
remove_discovery_batch_observers(cmp_batch_observer_t *cmp, void *ctx)
{
  batch_observer_t *batch_obs =
    (batch_observer_t *)oc_list_head(batch_observers_list);
  while (batch_obs != NULL) {
    if (cmp(batch_obs, ctx)) {
      oc_list_remove(batch_observers_list, batch_obs);
      free_batch_observer(batch_obs);
      batch_obs = (batch_observer_t *)oc_list_head(batch_observers_list);
    } else {
      batch_obs = batch_obs->next;
    }
  }
}

#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */

/*-------------------*/
int32_t observe_counter = 3;
/*---------------------------------------------------------------------------*/
OC_LIST(observers_list);
OC_MEMB(observers_memb, coap_observer_t, COAP_MAX_OBSERVERS);

/*---------------------------------------------------------------------------*/
/*- Internal API ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static int
coap_remove_observer_handle_by_uri(const oc_endpoint_t *endpoint,
                                   const char *uri, int uri_len,
                                   oc_interface_mask_t iface_mask)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list), *next;

  while (obs) {
    next = obs->next;
    if (((oc_endpoint_compare(&obs->endpoint, endpoint) == 0)) &&
        (oc_string_len(obs->url) == (size_t)uri_len &&
         memcmp(oc_string(obs->url), uri, uri_len) == 0) &&
        obs->iface_mask == iface_mask) {
      coap_remove_observer(obs);
      removed++;
      break;
    }
    obs = next;
  }
  return removed;
}
/*---------------------------------------------------------------------------*/
static int
add_observer(oc_resource_t *resource, uint16_t block2_size,
             const oc_endpoint_t *endpoint, const uint8_t *token,
             size_t token_len, const char *uri, size_t uri_len,
             oc_interface_mask_t iface_mask)
{
  /* Remove existing observe relationship, if any. */
  int dup =
    coap_remove_observer_handle_by_uri(endpoint, uri, (int)uri_len, iface_mask);

  coap_observer_t *o = oc_memb_alloc(&observers_memb);

  if (o) {
    oc_new_string(&o->url, uri, uri_len);
    memcpy(&o->endpoint, endpoint, sizeof(oc_endpoint_t));
    o->token_len = (uint8_t)token_len;
    memcpy(o->token, token, token_len);
    o->last_mid = 0;
    o->iface_mask = iface_mask;
    o->obs_counter = observe_counter;
    o->resource = resource;
#ifdef OC_BLOCK_WISE
    o->block2_size = block2_size;
#else  /* OC_BLOCK_WISE */
    (void)block2_size;
#endif /* OC_BLOCK_WISE */
    resource->num_observers++;
#ifdef OC_DYNAMIC_ALLOCATION
    OC_DBG("Adding observer (%u) for /%s [0x%02X%02X]",
           oc_list_length(observers_list) + 1, oc_string(o->url), o->token[0],
           o->token[1]);
#else  /* OC_DYNAMIC_ALLOCATION */
    OC_DBG("Adding observer (%u/%u) for /%s [0x%02X%02X]",
           oc_list_length(observers_list) + 1, COAP_MAX_OBSERVERS,
           oc_string(o->url), o->token[0], o->token[1]);
#endif /* !OC_DYNAMIC_ALLOCATION */
    oc_list_add(observers_list, o);
    return dup;
  }
  OC_WRN("insufficient memory to add new observer");
  return -1;
}
/*---------------------------------------------------------------------------*/
/*- Removal -----------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static const char *
get_iface_query(oc_interface_mask_t iface_mask)
{
  switch (iface_mask) {
  case OC_IF_BASELINE:
    return "if=oic.if.baseline";
  case OC_IF_LL:
    return "if=oic.if.ll";
  case OC_IF_B:
    return "if=oic.if.b";
  case OC_IF_R:
    return "if=oic.if.r";
  case OC_IF_RW:
    return "if=oic.if.rw";
  case OC_IF_A:
    return "if=oic.if.a";
  case OC_IF_S:
    return "if=oic.if.s";
  case OC_IF_CREATE:
    return "if=oic.if.create";
  default:
    break;
  }
  return NULL;
}

void
coap_remove_observer(coap_observer_t *o)
{
  OC_DBG("Removing observer for /%s [0x%02X%02X]", oc_string(o->url),
         o->token[0], o->token[1]);

#ifdef OC_BLOCK_WISE
  const char *query = get_iface_query(o->iface_mask);
  oc_blockwise_state_t *response_state = oc_blockwise_find_response_buffer(
    oc_string(o->resource->uri) + 1, oc_string_len(o->resource->uri) - 1,
    &o->endpoint, OC_GET, query, query != NULL ? strlen(query) : 0,
    OC_BLOCKWISE_SERVER);
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
  oc_list_remove(observers_list, o);
#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
  remove_discovery_batch_observers(cmp_batch_by_observer, o);
#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */
  oc_memb_free(&observers_memb, o);
}
void
coap_free_all_observers(void)
{
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list), *next;

  while (obs) {
    next = obs->next;
    coap_remove_observer(obs);
    obs = next;
  }
#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
  oc_remove_delayed_callback(NULL, &process_batch_observers);
#endif
}
/*---------------------------------------------------------------------------*/
int
coap_remove_observer_by_client(const oc_endpoint_t *endpoint)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list), *next;

  OC_DBG("Unregistering observers for client at: ");
  OC_LOGipaddr(*endpoint);

  while (obs) {
    next = obs->next;
    if (oc_endpoint_compare(&obs->endpoint, endpoint) == 0) {
      coap_remove_observer(obs);
      removed++;
    }
    obs = next;
  }
  OC_DBG("Removed %d observers", removed);
  return removed;
}
/*---------------------------------------------------------------------------*/
int
coap_remove_observer_by_token(const oc_endpoint_t *endpoint,
                              const uint8_t *token, size_t token_len)
{
  int removed = 0;
  OC_DBG("Unregistering observers for request token 0x%02X%02X", token[0],
         token[1]);
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
       obs != NULL; obs = obs->next) {
    if (oc_endpoint_compare(&obs->endpoint, endpoint) == 0 &&
        obs->token_len == token_len &&
        memcmp(obs->token, token, token_len) == 0) {
      coap_remove_observer(obs);
      removed++;
      break;
    }
  }
  OC_DBG("Removed %d observers", removed);
  return removed;
}
/*---------------------------------------------------------------------------*/
int
coap_remove_observer_by_mid(const oc_endpoint_t *endpoint, uint16_t mid)
{
  int removed = 0;
  OC_DBG("Unregistering observers for request MID %u", mid);

  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
       obs != NULL; obs = obs->next) {
    if (oc_endpoint_compare(&obs->endpoint, endpoint) == 0 &&
        obs->last_mid == mid) {
      coap_remove_observer(obs);
      removed++;
      break;
    }
  }
  OC_DBG("Removed %d observers", removed);
  return removed;
}
/*---------------------------------------------------------------------------*/

static void
send_cancellation_notification(coap_observer_t *obs, uint8_t code)
{
  coap_packet_t notification[1];
#ifdef OC_TCP
  if (obs->endpoint.flags & TCP) {
    coap_tcp_init_message(notification, code);
  } else
#endif
  {
    coap_udp_init_message(notification, COAP_TYPE_NON, code, 0);
  }
  coap_set_token(notification, obs->token, obs->token_len);
  coap_transaction_t *transaction = coap_new_transaction(
    coap_get_mid(), obs->token, obs->token_len, &obs->endpoint);
  if (transaction) {
    notification->mid = transaction->mid;
    transaction->message->length =
      coap_serialize_message(notification, transaction->message->data);
    if (transaction->message->length > 0) {
      coap_send_transaction(transaction);
    } else {
      coap_clear_transaction(transaction);
    }
  } // transaction
}

int
coap_remove_observer_by_resource(const oc_resource_t *rsc)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list), *next;

  while (obs) {
    next = obs->next;
    if ((obs->resource == rsc) &&
        (oc_string(rsc->uri) &&
         oc_string_len(obs->url) == (oc_string_len(rsc->uri) - 1) &&
         memcmp(oc_string(obs->url), oc_string(rsc->uri) + 1,
                oc_string_len(rsc->uri) - 1) == 0)) {
      // https://www.rfc-editor.org/rfc/rfc7641.html#section-4.2
      send_cancellation_notification(obs, NOT_FOUND_4_04);
      coap_remove_observer(obs);
      removed++;
    }
    obs = next;
  }
  return removed;
}

/*---------------------------------------------------------------------------*/
/*- Notification ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/

static int
send_notification(coap_observer_t *obs, oc_response_t *response,
                  oc_string_t uri, bool ignore_is_revert,
                  oc_blockwise_finish_cb_t *finish_cb)
{
  OC_DBG("send_notification: send notification for resource %s",
         oc_string(uri));
  if (!response || !obs) {
    return 0;
  }
  if (response->separate_response) {
    coap_packet_t req[1];
#ifdef OC_TCP
    if (obs->endpoint.flags & TCP) {
      coap_tcp_init_message(req, COAP_GET);
    } else
#endif /* OC_TCP */
    {
      coap_udp_init_message(req, COAP_TYPE_NON, COAP_GET, 0);
    }
    memcpy(req->token, obs->token, obs->token_len);
    req->token_len = obs->token_len;

    coap_set_header_uri_path(req, oc_string(uri), oc_string_len(uri));

    OC_DBG("send_notification: creating separate response for "
           "notification");
#ifdef OC_BLOCK_WISE
    uint16_t block2_size = obs->block2_size;
#else  /* !OC_BLOCK_WISE */
    uint16_t block2_size = 0;
#endif /* OC_BLOCK_WISE */
    if (coap_separate_accept(req, response->separate_response, &obs->endpoint,
                             obs->obs_counter, block2_size) == 1) {
      response->separate_response->active = 1;
    }
  } // separate response
  else {
    OC_DBG("send_notification: notifying observer");
    coap_transaction_t *transaction = NULL;
    if (response->response_buffer) {
      coap_packet_t notification[1];
      bool is_revert = false;
      uint8_t status_code = CONTENT_2_05;
      if (obs->iface_mask == OC_IF_STARTUP_REVERT) {
        OC_DBG("send_notification: Setting Valid response for a REVERT "
               "notification");
        status_code = VALID_2_03;
        response->response_buffer->code = VALID_2_03;
        is_revert = !is_revert;
      }
#ifdef OC_TCP
      if (obs->endpoint.flags & TCP) {
        coap_tcp_init_message(notification, status_code);
      } else
#endif /* OC_TCP */
      {
        coap_udp_init_message(notification, COAP_TYPE_NON, status_code, 0);
      }

      if (ignore_is_revert || !is_revert) {
#ifdef OC_BLOCK_WISE
#ifdef OC_TCP
        if (!(obs->endpoint.flags & TCP) &&
            response->response_buffer->response_length > obs->block2_size) {
#else  /* OC_TCP */
        if (response->response_buffer->response_length > obs->block2_size) {
#endif /* !OC_TCP */
          notification->type = COAP_TYPE_CON;
          const char *query = get_iface_query(obs->iface_mask);
          oc_blockwise_state_t *response_state =
            oc_blockwise_find_response_buffer(
              oc_string(obs->resource->uri) + 1,
              oc_string_len(obs->resource->uri) - 1, &obs->endpoint, OC_GET,
              query, query != NULL ? strlen(query) : 0, OC_BLOCKWISE_SERVER);
          if (response_state) {
            if (response_state->payload_size ==
                response_state->next_block_offset) {
              oc_blockwise_free_response_buffer(response_state);
              response_state = NULL;
            } else {
              OC_DBG("send_notification: Skipping for blockwise transfer "
                     "running");
              return 0;
            }
          }
          response_state = oc_blockwise_alloc_response_buffer(
            oc_string(obs->resource->uri) + 1,
            oc_string_len(obs->resource->uri) - 1, &obs->endpoint, OC_GET,
            OC_BLOCKWISE_SERVER, response->response_buffer->response_length);
          if (!response_state) {
            OC_ERR("send_notification: cannot allocate response buffer");
            return -1;
          }
          if (query) {
            oc_new_string(&response_state->uri_query, query, strlen(query));
          }
          if (finish_cb) {
            response_state->finish_cb = finish_cb;
          }
          memcpy(response_state->buffer, response->response_buffer->buffer,
                 response->response_buffer->response_length);
          response_state->payload_size =
            response->response_buffer->response_length;
          uint32_t payload_size = 0;
          const void *payload = oc_blockwise_dispatch_block(
            response_state, 0, obs->block2_size, &payload_size);
          if (payload) {
            coap_set_payload(notification, payload, payload_size);
            coap_set_header_block2(notification, 0, 1, obs->block2_size);
            coap_set_header_size2(notification, response_state->payload_size);
            oc_blockwise_response_state_t *bwt_res_state =
              (oc_blockwise_response_state_t *)response_state;
            coap_set_header_etag(notification, bwt_res_state->etag,
                                 COAP_ETAG_LEN);
          }
        } // blockwise transfer
        else
#endif /* OC_BLOCK_WISE */
        {
#ifdef OC_TCP
          if (!(obs->endpoint.flags & TCP) &&
              obs->obs_counter % COAP_OBSERVE_REFRESH_INTERVAL == 0) {
#else  /* OC_TCP */
          if (obs->obs_counter % COAP_OBSERVE_REFRESH_INTERVAL == 0) {
#endif /* !OC_TCP */
            OC_DBG("send_notification: forcing CON notification to check "
                   "for client liveness");
            notification->type = COAP_TYPE_CON;
          }
          coap_set_payload(
            notification, response->response_buffer->buffer,
            (uint32_t)response->response_buffer->response_length);
        } //! blockwise transfer
      }   // !is_revert

      coap_set_status_code(notification, response->response_buffer->code);
      if (notification->code < BAD_REQUEST_4_00 &&
          obs->resource->num_observers) {
        coap_set_header_observe(notification, (obs->obs_counter)++);
        observe_counter++;
      } else {
        coap_set_header_observe(notification, 1);
      }
      if (response->response_buffer->content_format > 0) {
        coap_set_header_content_format(
          notification, response->response_buffer->content_format);
      }
      coap_set_token(notification, obs->token, obs->token_len);
      transaction = coap_new_transaction(coap_get_mid(), obs->token,
                                         obs->token_len, &obs->endpoint);
      if (transaction) {
        obs->last_mid = transaction->mid;
        notification->mid = transaction->mid;
        transaction->message->length =
          coap_serialize_message(notification, transaction->message->data);
        if (transaction->message->length > 0) {
          coap_send_transaction(transaction);
        } else {
          coap_clear_transaction(transaction);
        }
      } // transaction
    }   // response_buf != NULL
  }     //! separate response
  return 0;
}

#ifdef OC_COLLECTIONS
void
coap_notify_collection_observers(const oc_collection_t *collection,
                                 oc_response_buffer_t *response_buf,
                                 oc_interface_mask_t iface_mask)
{
  oc_response_t response = { 0 };
  response.response_buffer = response_buf;
  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
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
    if (send_notification(obs, &response, collection->res.uri, true, NULL)) {
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
    const char *iface = get_iface_query(iface_mask);
    OC_WRN("coap_notify_collection(%s): out of memory allocating buffer",
           iface != NULL ? iface : "NULL");
#endif /* OC_WRN_IS_ENABLED */
    return -1;
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  oc_response_buffer_t response_buffer;
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
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
    const char *iface = get_iface_query(iface_mask);
    OC_WRN("coap_notify_collection(%s): failed to handle collection request",
           iface != NULL ? iface : "NULL");
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
coap_notify_collections(oc_resource_t *resource)
{
#ifndef OC_DYNAMIC_ALLOCATION
  uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
  if (!buffer) {
    OC_WRN("coap_notify_collections: out of memory allocating buffer");
    return -1;
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_request_t request;
  memset(&request, 0, sizeof(request));
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  oc_response_buffer_t response_buffer;
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  response.response_buffer = &response_buffer;
  request.response = &response;
  request.request_payload = NULL;
  request.method = OC_GET;

  for (oc_collection_t *collection =
         oc_get_next_collection_with_link(resource, NULL);
       collection != NULL && collection->res.num_observers > 0;
       collection = oc_get_next_collection_with_link(resource, collection)) {
    OC_DBG("coap_notify_collections: Issue GET request to collection for "
           "resource");

    request.resource = (oc_resource_t *)collection;
#ifdef OC_DYNAMIC_ALLOCATION
    oc_rep_new_realloc_v1(&response_buffer.buffer, response_buffer.buffer_size,
                          OC_MAX_OBSERVE_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
    oc_rep_new_v1(response_buffer.buffer, response_buffer.buffer_size);
#endif /* !OC_DYNAMIC_ALLOCATION */

    if (!oc_handle_collection_request(OC_GET, &request, OC_IF_B, resource)) {
      OC_WRN("coap_notify_collections: failed to handle collection request");
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

#ifdef OC_SECURITY
int
coap_remove_observers_on_dos_change(size_t device, bool reset)
{
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
  /* iterate over observers */
  while (obs) {
    coap_observer_t *next = obs->next;
    if (obs->endpoint.device == device &&
        (reset || !oc_sec_check_acl(OC_GET, obs->resource, &obs->endpoint))) {
      send_cancellation_notification(obs, SERVICE_UNAVAILABLE_5_03);
      coap_remove_observer(obs);
    }
    obs = next;
  }
  return 0;
}
#endif /* OC_SECURITY */

static bool
fill_response(oc_resource_t *resource, const oc_endpoint_t *endpoint,
              oc_interface_mask_t iface_mask, oc_response_t *response)
{
  if (!resource || !response) {
    return false;
  }
  oc_request_t request = { 0 };
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
    response->response_buffer->code = OC_IGNORE;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  response->response_buffer->buffer_size = oc_rep_get_encoded_payload_size();
#endif /* OC_DYNAMIC_ALLOCATION */
  if (response->response_buffer->code == OC_IGNORE) {
    OC_DBG("fill_response: Resource ignored request");
    return false;
  } // response_buf->code == OC_IGNORE
  return true;
}

static int
coap_notify_observers_internal(oc_resource_t *resource,
                               oc_response_buffer_t *response_buf,
                               const oc_endpoint_t *endpoint)
{
  if (!resource) {
    OC_WRN("coap_notify_observers_internal: no resource passed; returning");
    return 0;
  }

#ifdef OC_SECURITY
  const oc_sec_pstat_t *ps = oc_sec_get_pstat(resource->device);
  if (ps->s != OC_DOS_RFNOP) {
    OC_WRN("coap_notify_observers_internal: device not in RFNOP; skipping "
           "notification");
    return 0;
  }
#endif /* OC_SECURITY */

  bool resource_is_collection = false;
  oc_interface_mask_t iface_mask = resource->default_interface;
#ifdef OC_COLLECTIONS
  if (oc_check_if_collection(resource)) {
    resource_is_collection = true;
    iface_mask = OC_IF_BASELINE;
  }
#endif /* OC_COLLECTIONS */
  if (resource->num_observers > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#else  /* !OC_DYNAMIC_ALLOCATION */
    uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
    if (!buffer) {
      OC_WRN("coap_notify_observers: out of memory allocating buffer");
      return 0;
    } //! buffer
#endif /* OC_DYNAMIC_ALLOCATION */

    oc_response_t response;
    memset(&response, 0, sizeof(response));
    oc_response_buffer_t response_buffer;
    response.response_buffer = response_buf;
    bool has_response = response_buf != NULL;
#ifdef OC_DYNAMIC_ALLOCATION
    bool update_buffer = !has_response;
#endif /* OC_DYNAMIC_ALLOCATION */
    if (!has_response) {
      response_buffer.buffer = buffer;
      response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
      response.response_buffer = &response_buffer;
      if (resource != NULL && endpoint != NULL) {
        OC_DBG("coap_notify_observers_internal: Issue GET request to resource "
               "%s\n\n",
               oc_string(resource->uri));
        if (!fill_response(resource, endpoint, iface_mask, &response)) {
          goto leave_notify_observers;
        }
        has_response = true;
      }
    } //! response_buf && resource

    oc_resource_t *discover_resource =
      oc_core_get_resource_by_index(OCF_RES, resource->device);
    /* iterate over observers */
    for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
         obs; obs = obs->next) {
      if ((obs->resource != resource) ||
          (endpoint && oc_endpoint_compare(&obs->endpoint, endpoint) != 0)) {
        continue;
      } // obs->resource != resource || endpoint != obs->endpoint
      if (resource_is_collection && obs->iface_mask != OC_IF_BASELINE) {
        continue;
      }
      if (obs->resource == discover_resource && obs->iface_mask == OC_IF_B) {
        continue;
      }
      if (obs->iface_mask == OC_IF_STARTUP) {
        OC_DBG("coap_notify_observers_internal: Skipping startup established "
               "observe");
        continue;
      }
      if (!has_response) {
#if OC_DBG_IS_ENABLED
        oc_string_t ep_str;
        memset(&ep_str, 0, sizeof(oc_string_t));
        const char *ep_cstr = "";
        if (oc_endpoint_to_string(&obs->endpoint, &ep_str) == 0) {
          ep_cstr = oc_string(ep_str);
        }
        OC_DBG("coap_notify_observers_internal: Issue GET request to resource "
               "%s for endpoint %s\n\n",
               oc_string(resource->uri), ep_cstr);
        oc_free_string(&ep_str);
#endif /* OC_DBG_IS_ENABLED */
        if (!fill_response(resource, &obs->endpoint, iface_mask, &response)) {
          goto leave_notify_observers;
        }
      }
      if (send_notification(obs, &response, resource->uri, false, NULL)) {
        break;
      }
    } // iterate over observers
  leave_notify_observers:;
#ifdef OC_DYNAMIC_ALLOCATION
    if (update_buffer) {
      buffer = response_buffer.buffer;
    }
    if (buffer) {
      free(buffer);
    }
#endif /* OC_DYNAMIC_ALLOCATION */
  }    // num_observers > 0
  else {
    OC_WRN("coap_notify_observers_internal: no observers");
  }

#ifdef OC_COLLECTIONS
  int num_links = 0;
  if (resource->num_links > 0) {
    int notify = coap_notify_collections(resource);
    if (notify >= 0) {
      num_links = notify;
    }
  }
  return resource->num_observers + num_links;
#else  /* OC_COLLECTIONS */
  return resource->num_observers;
#endif /* !OC_COLLECTIONS */
}

void
notify_resource_defaults_observer(oc_resource_t *resource,
                                  oc_interface_mask_t iface_mask,
                                  oc_response_buffer_t *response_buf)
{
  (void)response_buf;
#ifndef OC_DYNAMIC_ALLOCATION
  uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
  if (!buffer) {
    OC_WRN("coap_notify_observers: out of memory allocating buffer");
    return;
  } //! buffer
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_response_t response;
  memset(&response, 0, sizeof(response));
  oc_response_buffer_t response_buffer;
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  response.response_buffer = &response_buffer;
  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
       obs; obs = obs->next) {
    if (obs->resource != resource) {
      continue;
    } // obs->resource != resource || endpoint != obs->endpoint
    if (obs->iface_mask != iface_mask) {
      continue;
    }
    if (!fill_response(resource, &obs->endpoint, iface_mask, &response)) {
      goto leave_notify_observers;
    }
    if (send_notification(obs, &response, resource->uri, true, NULL)) {
      break;
    }
  }
leave_notify_observers:;
#ifdef OC_DYNAMIC_ALLOCATION
  buffer = response_buffer.buffer;
  if (buffer) {
    free(buffer);
  }
#endif
}

#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
static void
dispatch_process_batch_observers(void)
{
  oc_remove_delayed_callback(NULL, &process_batch_observers);
  oc_set_delayed_callback(NULL, &process_batch_observers, 0);
  _oc_signal_event_loop();
}

static void
create_batch_for_removed_resource(CborEncoder *links_array,
                                  batch_observer_t *batch_obs)
{
  OC_DBG("create_batch_for_removed_resource: resource %s",
         oc_string(batch_obs->removed_resource_uri));
  oc_rep_start_object((links_array), links);
  char href[OC_MAX_OCF_URI_SIZE];
  memcpy(href, "ocf://", 6);
  oc_uuid_to_str(oc_core_get_device_id(batch_obs->obs->resource->device),
                 href + 6, OC_UUID_LEN);
  memcpy(href + 6 + OC_UUID_LEN - 1, oc_string(batch_obs->removed_resource_uri),
         oc_string_len(batch_obs->removed_resource_uri));
  href[6 + OC_UUID_LEN - 1 + oc_string_len(batch_obs->removed_resource_uri)] =
    '\0';
  oc_rep_set_text_string(links, href, href);
  oc_rep_set_key(oc_rep_object(links), "rep");
  memcpy(oc_rep_get_encoder(), &links_map, sizeof(CborEncoder));
  oc_rep_start_root_object();
  oc_rep_end_root_object();
  memcpy(&links_map, oc_rep_get_encoder(), sizeof(CborEncoder));
  oc_rep_end_object((links_array), links);
}

static void
create_batch_for_batch_observer(CborEncoder *links_array,
                                batch_observer_t *batch_obs,
                                oc_endpoint_t *endpoint)
{
  if (batch_obs->resource) {
    oc_discovery_create_batch_for_resource(links_array, batch_obs->resource,
                                           endpoint);
    return;
  }
  create_batch_for_removed_resource(links_array, batch_obs);
}

static oc_event_callback_retval_t
process_batch_observers(void *data)
{
  (void)data;
  batch_observer_t *batch_obs =
    (batch_observer_t *)oc_list_head(batch_observers_list);
  if (batch_obs == NULL) {
    return OC_EVENT_DONE;
  }
#ifndef OC_DYNAMIC_ALLOCATION
  uint8_t buffer[OC_MIN_OBSERVE_SIZE];
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t *buffer = malloc(OC_MIN_OBSERVE_SIZE);
  if (!buffer) {
    OC_WRN("process_batch_observers: out of memory allocating buffer");
    goto leave_notify_observers;
  } //! buffer
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  OC_DBG("process_batch_observers: Issue GET request to "
         "discovery resource for %s resource\n\n",
         batch_observer_get_resource_uri(batch_obs));
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  while (batch_obs != NULL) {
    if (!batch_obs->resource &&
        !oc_string_len(batch_obs->removed_resource_uri)) {
      OC_WRN("process_batch_observers: resource is NULL and "
             "removed_resource_uri is empty");
      oc_list_remove(batch_observers_list, batch_obs);
      free_batch_observer(batch_obs);
      batch_obs = (batch_observer_t *)oc_list_head(batch_observers_list);
      continue;
    }
    coap_observer_t *obs = batch_obs->obs;
#ifdef OC_BLOCK_WISE
    const char *query = get_iface_query(obs->iface_mask);
    oc_blockwise_state_t *response_state = oc_blockwise_find_response_buffer(
      oc_string(obs->resource->uri) + 1, oc_string_len(obs->resource->uri) - 1,
      &obs->endpoint, OC_GET, query, query != NULL ? strlen(query) : 0,
      OC_BLOCKWISE_SERVER);
    if (response_state) {
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
    oc_rep_start_links_array();
    int size_before = oc_rep_get_encoded_payload_size();
    batch_observer_t *o = batch_obs->next;
    create_batch_for_batch_observer(&links_array, batch_obs, &obs->endpoint);
    while (o != NULL) {
      batch_observer_t *next = o->next;
      if (o->obs == obs) {
        create_batch_for_batch_observer(&links_array, o, &obs->endpoint);
        oc_list_remove(batch_observers_list, o);
        free_batch_observer(o);
      }
      o = next;
    }
    int size_after = oc_rep_get_encoded_payload_size();
    if (size_before == size_after) {
      OC_DBG("process_batch_observers: drop observations\n\n");
    } else {
      oc_rep_end_links_array();
      size_after = oc_rep_get_encoded_payload_size();
      if (size_after < 0) {
        OC_ERR("process_batch_observers: invalid size after batch "
               "serialization\n\n");
      } else {
        OC_DBG("process_batch_observers: sending data with size %d\n\n",
               size_after);
        response_buffer.content_format = APPLICATION_VND_OCF_CBOR;
        response_buffer.response_length = size_after;
        response_buffer.code = oc_status_code(OC_STATUS_OK);
        oc_response_t response = { 0 };
        response.response_buffer = &response_buffer;
        if (send_notification(obs, &response, obs->resource->uri, true,
                              dispatch_process_batch_observers)) {
          goto leave_notify_observers;
        }
      }
    }
#ifdef OC_DYNAMIC_ALLOCATION
    response_buffer.buffer_size = oc_rep_get_encoder_buffer_size();
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_list_remove(batch_observers_list, batch_obs);
    free_batch_observer(batch_obs);
    batch_obs = (batch_observer_t *)oc_list_head(batch_observers_list);
  }
leave_notify_observers:
#ifdef OC_DYNAMIC_ALLOCATION
  buffer = response_buffer.buffer;
  if (buffer) {
    free(buffer);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  return OC_EVENT_DONE;
}

static bool
cmp_add_batch_observer_resource(batch_observer_t *batch_obs,
                                coap_observer_t *obs, oc_resource_t *resource,
                                bool removed)
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

static void
add_notification_batch_observers_list(oc_resource_t *resource, bool removed)
{
  if (resource == NULL) {
    return;
  }
  oc_resource_t *discover_resource =
    oc_core_get_resource_by_index(OCF_RES, resource->device);

  if (discover_resource == resource) {
    return;
  }

  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
       obs; obs = obs->next) {
    if (obs->resource != discover_resource || obs->iface_mask != OC_IF_B) {
      continue;
    }
#ifdef OC_SECURITY
    if (!oc_sec_check_acl(OC_GET, resource, &obs->endpoint)) {
      continue;
    }
#endif /* OC_SECURITY */
    // deduplicate observations.
    bool found = false;
    batch_observer_t *batch_obs = NULL;
    for (batch_obs = (batch_observer_t *)oc_list_head(batch_observers_list);
         batch_obs; batch_obs = batch_obs->next) {
      if (cmp_add_batch_observer_resource(batch_obs, obs, resource, removed)) {
        found = true;
        break;
      }
    }
    if (found) {
      continue;
    }
    batch_observer_t *o = oc_memb_alloc(&batch_observers_memb);
    if (o == NULL) {
      OC_ERR("coap_notify_discovery_batch_observers: cannot allocate batch "
             "observer for resource %s",
             oc_string(resource->uri));
      return;
    } else {
      o->obs = obs;
      if (removed) {
        oc_new_string(&o->removed_resource_uri, oc_string(resource->uri),
                      oc_string_len(resource->uri));
      } else {
        o->resource = resource;
      }
      oc_list_add(batch_observers_list, o);
    }
  }
  dispatch_process_batch_observers();
}

void
coap_remove_discovery_batch_observers_by_resource(oc_resource_t *resource)
{
  OC_DBG("coap_remove_discovery_batch_observers_by_resource: resource %s",
         oc_string(resource->uri));
  remove_discovery_batch_observers(cmp_batch_by_resource, resource);
  add_notification_batch_observers_list(resource, true);
}

void
coap_notify_discovery_batch_observers(oc_resource_t *resource)
{
  add_notification_batch_observers_list(resource, false);
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
  if (!buffer) {
    OC_WRN("notify_discovery_observers: out of memory allocating buffer");
    return resource->num_observers;
  } //! buffer
#endif /* OC_DYNAMIC_ALLOCATION */

  OC_DBG("notify_discovery_observers: Issue GET request to resource %s\n\n",
         oc_string(resource->uri));
  oc_response_t response = { 0 };
  oc_response_buffer_t response_buffer = { 0 };
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = OC_MIN_OBSERVE_SIZE;
  response.response_buffer = &response_buffer;

  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
       obs; obs = obs->next) {
    if (obs->resource != resource) {
      continue;
    }
    oc_interface_mask_t iface_mask = obs->iface_mask;
    if (iface_mask & OC_IF_B) {
      continue;
    }
    if (!fill_response(resource, &obs->endpoint, obs->iface_mask, &response)) {
      continue;
    }
    if (send_notification(obs, &response, resource->uri, false, NULL)) {
      break;
    }
  }

#ifdef OC_DYNAMIC_ALLOCATION
  buffer = response_buffer.buffer;
  if (buffer) {
    free(buffer);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  return resource->num_observers;
}
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */

int
coap_notify_observers(oc_resource_t *resource,
                      oc_response_buffer_t *response_buf,
                      const oc_endpoint_t *endpoint)
{
  int num = 0;
#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
#ifdef OC_RES_BATCH_SUPPORT
  coap_notify_discovery_batch_observers(resource);
#endif /* OC_RES_BATCH_SUPPORT */
  oc_resource_t *discover_resource =
    oc_core_get_resource_by_index(OCF_RES, resource->device);
  if (resource == discover_resource) {
    num = notify_discovery_observers(discover_resource);
  } else
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */
  {
    num = coap_notify_observers_internal(resource, response_buf, endpoint);
  }
  return num;
}

/*---------------------------------------------------------------------------*/
int
coap_observe_handler(const coap_packet_t *request,
                     const coap_packet_t *response, oc_resource_t *resource,
                     uint16_t block2_size, const oc_endpoint_t *endpoint,
                     oc_interface_mask_t iface_mask)
{
  if (request->code != COAP_GET || response->code >= 128 ||
      !IS_OPTION(request, COAP_OPTION_OBSERVE)) {
    return -1;
  }
  if (request->observe == 0) {
    return add_observer(resource, block2_size, endpoint, request->token,
                        request->token_len, request->uri_path,
                        request->uri_path_len, iface_mask);
  }
  if (request->observe == 1) {
    return coap_remove_observer_by_token(endpoint, request->token,
                                         request->token_len);
  }
  return -1;
}
/*---------------------------------------------------------------------------*/

bool
coap_want_be_notified(oc_resource_t *resource)
{
#if defined(OC_DISCOVERY_RESOURCE_OBSERVABLE) && defined(OC_RES_BATCH_SUPPORT)
  oc_resource_t *discover_resource =
    oc_core_get_resource_by_index(OCF_RES, resource->device);
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE && OC_RES_BATCH_SUPPORT */
  /* iterate over observers */
  for (coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
       obs; obs = obs->next) {
    if (obs->resource == resource) {
      return true;
    }
#ifdef OC_RES_BATCH_SUPPORT
#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
    if ((obs->resource == discover_resource) && (obs->iface_mask & OC_IF_B)) {
      return true;
    }
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */
#if defined(OC_COLLECTIONS) && defined(OC_COLLECTIONS_IF_CREATE)
    oc_rt_created_t *rtc = oc_rt_get_factory_create_for_resource(resource);
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
