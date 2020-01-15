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

#include "observe.h"
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

#include "oc_coap.h"
#include "oc_endpoint.h"
#include "oc_rep.h"
#include "oc_ri.h"
/*-------------------*/
int32_t observe_counter = 3;
/*---------------------------------------------------------------------------*/
OC_LIST(observers_list);
OC_MEMB(observers_memb, coap_observer_t, COAP_MAX_OBSERVERS);

/*---------------------------------------------------------------------------*/
/*- Internal API ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static int
coap_remove_observer_handle_by_uri(oc_endpoint_t *endpoint, const char *uri,
                                   int uri_len)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list), *next;

  while (obs) {
    next = obs->next;
    if (((oc_endpoint_compare(&obs->endpoint, endpoint) == 0)) &&
        (oc_string_len(obs->url) == (size_t)uri_len &&
         memcmp(oc_string(obs->url), uri, uri_len) == 0)) {
      obs->resource->num_observers--;
      oc_list_remove(observers_list, obs);
      oc_memb_free(&observers_memb, obs);
      removed++;
      break;
    }
    obs = next;
  }
  return removed;
}
/*---------------------------------------------------------------------------*/
static int
#ifdef OC_BLOCK_WISE
add_observer(oc_resource_t *resource, uint16_t block2_size,
             oc_endpoint_t *endpoint, const uint8_t *token, size_t token_len,
             const char *uri, size_t uri_len, oc_interface_mask_t iface_mask)
#else  /* OC_BLOCK_WISE */
add_observer(oc_resource_t *resource, oc_endpoint_t *endpoint,
             const uint8_t *token, size_t token_len, const char *uri,
             size_t uri_len, oc_interface_mask_t iface_mask)
#endif /* !OC_BLOCK_WISE */
{
  /* Remove existing observe relationship, if any. */
  int dup = coap_remove_observer_handle_by_uri(endpoint, uri, (int)uri_len);

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
void
coap_remove_observer(coap_observer_t *o)
{
  OC_DBG("Removing observer for /%s [0x%02X%02X]", oc_string(o->url),
         o->token[0], o->token[1]);

#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t *response_state = oc_blockwise_find_response_buffer(
    oc_string(o->resource->uri) + 1, oc_string_len(o->resource->uri) - 1,
    &o->endpoint, OC_GET, NULL, 0, OC_BLOCKWISE_SERVER);
  if (response_state) {
    response_state->ref_count = 0;
  }
#endif /* OC_BLOCK_WISE */
  o->resource->num_observers--;
  oc_free_string(&o->url);
  oc_list_remove(observers_list, o);
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
}
/*---------------------------------------------------------------------------*/
int
coap_remove_observer_by_client(oc_endpoint_t *endpoint)
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
coap_remove_observer_by_token(oc_endpoint_t *endpoint, uint8_t *token,
                              size_t token_len)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
  OC_DBG("Unregistering observers for request token 0x%02X%02X", token[0],
         token[1]);
  while (obs) {
    if (oc_endpoint_compare(&obs->endpoint, endpoint) == 0 &&
        obs->token_len == token_len &&
        memcmp(obs->token, token, token_len) == 0) {
      coap_remove_observer(obs);
      removed++;
      break;
    }
    obs = obs->next;
  }
  OC_DBG("Removed %d observers", removed);
  return removed;
}
/*---------------------------------------------------------------------------*/
int
coap_remove_observer_by_mid(oc_endpoint_t *endpoint, uint16_t mid)
{
  int removed = 0;
  coap_observer_t *obs = NULL;
  OC_DBG("Unregistering observers for request MID %u", mid);

  for (obs = (coap_observer_t *)oc_list_head(observers_list); obs != NULL;
       obs = obs->next) {
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

#ifdef OC_COLLECTIONS
int
coap_notify_collection_observers(oc_resource_t *resource,
                                 oc_response_buffer_t *response_buf,
                                 oc_interface_mask_t iface_mask)
{
#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t *response_state = NULL;
#endif /* OC_BLOCK_WISE */
  coap_observer_t *obs = NULL;
  /* iterate over observers */
  for (obs = (coap_observer_t *)oc_list_head(observers_list); obs;
       obs = obs->next) {
    if (obs->resource != resource || obs->iface_mask != iface_mask) {
      continue;
    }

    OC_DBG("coap_notify_collections: notifying observer");
    coap_transaction_t *transaction = NULL;
    coap_packet_t notification[1];

#ifdef OC_TCP
    if (obs->endpoint.flags & TCP) {
      coap_tcp_init_message(notification, CONTENT_2_05);
    } else
#endif /* OC_TCP */
    {
      coap_udp_init_message(notification, COAP_TYPE_NON, CONTENT_2_05, 0);
    }

#ifdef OC_BLOCK_WISE
#ifdef OC_TCP
    if (!(obs->endpoint.flags & TCP) &&
        response_buf->response_length > obs->block2_size) {
#else  /* OC_TCP */
    if (response_buf->response_length > obs->block2_size) {
#endif /* !OC_TCP */
      notification->type = COAP_TYPE_CON;
      response_state = oc_blockwise_find_response_buffer(
        oc_string(obs->resource->uri) + 1,
        oc_string_len(obs->resource->uri) - 1, &obs->endpoint, OC_GET, NULL, 0,
        OC_BLOCKWISE_SERVER);
      if (response_state) {
        if (response_state->payload_size == response_state->next_block_offset) {
          oc_blockwise_free_response_buffer(response_state);
          response_state = NULL;
        } else {
          continue;
        }
      }
      response_state = oc_blockwise_alloc_response_buffer(
        oc_string(obs->resource->uri) + 1,
        oc_string_len(obs->resource->uri) - 1, &obs->endpoint, OC_GET,
        OC_BLOCKWISE_SERVER);

      if (!response_state) {
        goto leave_notify_collections;
      }

      memcpy(response_state->buffer, response_buf->buffer,
             response_buf->response_length);
      response_state->payload_size = response_buf->response_length;
      uint32_t payload_size = 0;
      const void *payload = oc_blockwise_dispatch_block(
        response_state, 0, obs->block2_size, &payload_size);
      if (payload) {
        coap_set_payload(notification, payload, payload_size);
        coap_set_header_block2(notification, 0, 1, obs->block2_size);
        coap_set_header_size2(notification, response_state->payload_size);
        oc_blockwise_response_state_t *bwt_res_state =
          (oc_blockwise_response_state_t *)response_state;
        coap_set_header_etag(notification, bwt_res_state->etag, COAP_ETAG_LEN);
      }
    } else
#endif /* OC_BLOCK_WISE */
    {
#ifdef OC_TCP
      if (!(obs->endpoint.flags & TCP) &&
          obs->obs_counter % COAP_OBSERVE_REFRESH_INTERVAL == 0) {
#else  /* OC_TCP */
      if (obs->obs_counter % COAP_OBSERVE_REFRESH_INTERVAL == 0) {
#endif /* !OC_TCP */
        OC_DBG("coap_notify_collections: forcing CON notification to check for "
               "client liveness");
        notification->type = COAP_TYPE_CON;
      }
      coap_set_payload(notification, response_buf->buffer,
                       response_buf->response_length);
    }

    if (notification->code < BAD_REQUEST_4_00 && obs->resource->num_observers) {
      coap_set_header_observe(notification, (obs->obs_counter)++);
      observe_counter++;
    } else {
      coap_set_header_observe(notification, 1);
    }
    coap_set_header_content_format(notification, APPLICATION_VND_OCF_CBOR);
    coap_set_token(notification, obs->token, obs->token_len);
    transaction = coap_new_transaction(coap_get_mid(), &obs->endpoint);
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
    }
  }

#ifdef OC_BLOCK_WISE
leave_notify_collections:
#endif /* OC_BLOCK_WISE */
  return -1;
}

int
coap_notify_links_list(oc_collection_t *collection)
{
#ifndef OC_DYNAMIC_ALLOCATION
  uint8_t buffer[OC_MAX_APP_DATA_SIZE];
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t *buffer = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buffer) {
    OC_WRN("coap_notify_collections: out of memory allocating buffer");
    return -1;
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_request_t request = { 0 };
  oc_response_t response = { 0 };
  response.separate_response = 0;
  oc_response_buffer_t response_buffer;
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = (uint16_t)OC_MAX_APP_DATA_SIZE;
  response.response_buffer = &response_buffer;
  request.response = &response;
  request.request_payload = NULL;
  oc_rep_new(response_buffer.buffer, response_buffer.buffer_size);

  request.resource = (oc_resource_t *)collection;

  oc_handle_collection_request(OC_GET, &request, OC_IF_LL, NULL);

  coap_notify_collection_observers(request.resource, &response_buffer,
                                   OC_IF_LL);

#ifdef OC_DYNAMIC_ALLOCATION
  if (buffer)
    free(buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
  return 0;
}

static int
coap_notify_collections(oc_resource_t *resource)
{
#ifndef OC_DYNAMIC_ALLOCATION
  uint8_t buffer[OC_MAX_APP_DATA_SIZE];
#else  /* !OC_DYNAMIC_ALLOCATION */
  uint8_t *buffer = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buffer) {
    OC_WRN("coap_notify_collections: out of memory allocating buffer");
    return -1;
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  int num_links = 0;

  oc_request_t request = { 0 };
  oc_response_t response = { 0 };
  response.separate_response = 0;
  oc_response_buffer_t response_buffer;
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = (uint16_t)OC_MAX_APP_DATA_SIZE;
  response.response_buffer = &response_buffer;
  request.response = &response;
  request.request_payload = NULL;
  oc_rep_new(response_buffer.buffer, response_buffer.buffer_size);

  oc_collection_t *collection = NULL;

  for (collection = oc_get_next_collection_with_link(resource, NULL);
       collection != NULL && collection->num_observers > 0;
       collection = oc_get_next_collection_with_link(resource, collection)) {
    OC_DBG(
      "coap_notify_collections: Issue GET request to collection for resource");

    request.resource = (oc_resource_t *)collection;

    oc_handle_collection_request(OC_GET, &request, OC_IF_B, resource);

    coap_notify_collection_observers(request.resource, &response_buffer,
                                     OC_IF_B);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  if (buffer)
    free(buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
  return num_links;
}
#endif /* OC_COLLECTIONS */

#ifdef OC_SECURITY
int
coap_remove_observers_on_dos_change(size_t device, bool reset)
{
  /* iterate over observers */
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
  while (obs != NULL) {
    if (obs->endpoint.device == device &&
        (reset || !oc_sec_check_acl(OC_GET, obs->resource, &obs->endpoint))) {
      coap_observer_t *o = obs;
      coap_packet_t notification[1];
#ifdef OC_TCP
      if (obs->endpoint.flags & TCP) {
        coap_tcp_init_message(notification, SERVICE_UNAVAILABLE_5_03);
      } else
#endif
      {
        coap_udp_init_message(notification, COAP_TYPE_NON,
                              SERVICE_UNAVAILABLE_5_03, 0);
      }
      coap_set_token(notification, obs->token, obs->token_len);
      coap_transaction_t *transaction =
        coap_new_transaction(coap_get_mid(), &obs->endpoint);
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
      obs = obs->next;
      coap_remove_observer(o);
      continue;
    }
    obs = obs->next;
  }
  return 0;
}
#endif /* OC_SECURITY */

int
coap_notify_observers(oc_resource_t *resource,
                      oc_response_buffer_t *response_buf,
                      oc_endpoint_t *endpoint)
{
  if (!resource) {
    OC_WRN("coap_notify_observers: no resource passed; returning");
    return 0;
  }

#ifdef OC_SECURITY
  oc_sec_pstat_t *ps = oc_sec_get_pstat(resource->device);
  if (ps->s != OC_DOS_RFNOP) {
    OC_WRN("coap_notify_observers: device not in RFNOP; skipping notification");
    return 0;
  }
#endif /* OC_SECURITY */

  coap_observer_t *obs = NULL;
  if (resource->num_observers > 0) {
#ifdef OC_BLOCK_WISE
    oc_blockwise_state_t *response_state = NULL;
#endif /* OC_BLOCK_WISE */

#ifndef OC_DYNAMIC_ALLOCATION
    uint8_t buffer[OC_MAX_APP_DATA_SIZE];
#else  /* !OC_DYNAMIC_ALLOCATION */
    uint8_t *buffer = malloc(OC_MAX_APP_DATA_SIZE);
    if (!buffer) {
      OC_WRN("coap_notify_observers: out of memory allocating buffer");
      goto leave_notify_observers;
    } //! buffer
#endif /* OC_DYNAMIC_ALLOCATION */

    oc_request_t request = { 0 };
    oc_response_t response = { 0 };
    response.separate_response = 0;
    oc_response_buffer_t response_buffer;
    if (!response_buf && resource) {
      OC_DBG("coap_notify_observers: Issue GET request to resource %s\n\n",
             oc_string(resource->uri));
      response_buffer.buffer = buffer;
      response_buffer.buffer_size = (uint16_t)OC_MAX_APP_DATA_SIZE;
      response.response_buffer = &response_buffer;
      request.resource = resource;
      request.response = &response;
      request.request_payload = NULL;
      oc_rep_new(response_buffer.buffer, response_buffer.buffer_size);
      resource->get_handler.cb(&request, resource->default_interface,
                               resource->get_handler.user_data);
      response_buf = &response_buffer;
      if (response_buf->code == OC_IGNORE) {
        OC_DBG("coap_notify_observers: Resource ignored request");
        goto leave_notify_observers;
      } // response_buf->code == OC_IGNORE
    }   //! response_buf && resource

    /* iterate over observers */
    obs = (coap_observer_t *)oc_list_head(observers_list);
    while (obs != NULL) {
      if ((obs->resource != resource) ||
          (endpoint && oc_endpoint_compare(&obs->endpoint, endpoint) != 0)) {
        obs = obs->next;
        continue;
      } // obs->resource != resource || endpoint != obs->endpoint

      if (response.separate_response != NULL &&
          response_buf->code == oc_status_code(OC_STATUS_OK)) {
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

        coap_set_header_uri_path(req, oc_string(resource->uri),
                                 oc_string_len(resource->uri));

        OC_DBG(
          "coap_notify_observers: Creating separate response for notification");
#ifdef OC_BLOCK_WISE
        if (coap_separate_accept(req, response.separate_response,
                                 &obs->endpoint, 0, obs->block2_size) == 1)
#else  /* OC_BLOCK_WISE */
        if (coap_separate_accept(req, response.separate_response,
                                 &obs->endpoint, 0) == 1)
#endif /* !OC_BLOCK_WISE */
          response.separate_response->active = 1;
      } // separate response
      else {
        OC_DBG("coap_notify_observers: notifying observer");
        coap_transaction_t *transaction = NULL;
        if (response_buf) {
          coap_packet_t notification[1];

#ifdef OC_TCP
          if (obs->endpoint.flags & TCP) {
            coap_tcp_init_message(notification, CONTENT_2_05);
          } else
#endif /* OC_TCP */
          {
            coap_udp_init_message(notification, COAP_TYPE_NON, CONTENT_2_05, 0);
          }

#ifdef OC_BLOCK_WISE
#ifdef OC_TCP
          if (!(obs->endpoint.flags & TCP) &&
              response_buf->response_length > obs->block2_size) {
#else  /* OC_TCP */
          if (response_buf->response_length > obs->block2_size) {
#endif /* !OC_TCP */
            notification->type = COAP_TYPE_CON;
            response_state = oc_blockwise_find_response_buffer(
              oc_string(obs->resource->uri) + 1,
              oc_string_len(obs->resource->uri) - 1, &obs->endpoint, OC_GET,
              NULL, 0, OC_BLOCKWISE_SERVER);
            if (response_state) {
              if (response_state->payload_size ==
                  response_state->next_block_offset) {
                oc_blockwise_free_response_buffer(response_state);
                response_state = NULL;
              } else {
                continue;
              }
            }
            response_state = oc_blockwise_alloc_response_buffer(
              oc_string(obs->resource->uri) + 1,
              oc_string_len(obs->resource->uri) - 1, &obs->endpoint, OC_GET,
              OC_BLOCKWISE_SERVER);

            if (!response_state) {
              goto leave_notify_observers;
            }
            memcpy(response_state->buffer, response_buf->buffer,
                   response_buf->response_length);
            response_state->payload_size = response_buf->response_length;
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
              OC_DBG(
                "coap_observe_notify: forcing CON notification to check for "
                "client liveness");
              notification->type = COAP_TYPE_CON;
            }
            coap_set_payload(notification, response_buf->buffer,
                             response_buf->response_length);
          } //! blockwise transfer

          coap_set_status_code(notification, response_buf->code);
          if (notification->code < BAD_REQUEST_4_00 &&
              obs->resource->num_observers) {
            coap_set_header_observe(notification, (obs->obs_counter)++);
            observe_counter++;
          } else {
            coap_set_header_observe(notification, 1);
          }
#ifdef OC_SPEC_VER_OIC
          if (obs->endpoint.version == OIC_VER_1_1_0) {
            coap_set_header_content_format(notification, APPLICATION_CBOR);
          } else
#endif /* OC_SPEC_VER_OIC */
          {
            coap_set_header_content_format(notification,
                                           APPLICATION_VND_OCF_CBOR);
          }
          coap_set_token(notification, obs->token, obs->token_len);
          transaction = coap_new_transaction(coap_get_mid(), &obs->endpoint);
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
      obs = obs->next;
    } // iterate over observers
  leave_notify_observers:;
#ifdef OC_DYNAMIC_ALLOCATION
    if (buffer) {
      free(buffer);
    }
#endif /* OC_DYNAMIC_ALLOCATION */
  }    // num_observers > 0
  else {
    OC_WRN("coap_notify_observers: no observers");
  }

#ifdef OC_COLLECTIONS
  int num_links = 0;
  if (resource->num_links > 0) {
    num_links = coap_notify_collections(resource);
  }
  return resource->num_observers + num_links;
#else  /* OC_COLLECTIONS */
  return resource->num_observers;
#endif /* !OC_COLLECTIONS */
}
/*---------------------------------------------------------------------------*/
#ifdef OC_BLOCK_WISE
int
coap_observe_handler(void *request, void *response, oc_resource_t *resource,
                     uint16_t block2_size, oc_endpoint_t *endpoint,
                     oc_interface_mask_t iface_mask)
#else  /* OC_BLOCK_WISE */
int
coap_observe_handler(void *request, void *response, oc_resource_t *resource,
                     oc_endpoint_t *endpoint, oc_interface_mask_t iface_mask)
#endif /* !OC_BLOCK_WISE */
{
  (void)iface_mask;
  coap_packet_t *const coap_req = (coap_packet_t *)request;
  coap_packet_t *const coap_res = (coap_packet_t *)response;
  int dup = -1;
  if (coap_req->code == COAP_GET && coap_res->code < 128) {
    if (IS_OPTION(coap_req, COAP_OPTION_OBSERVE)) {
      if (coap_req->observe == 0) {
        dup =
#ifdef OC_BLOCK_WISE
          add_observer(resource, block2_size, endpoint, coap_req->token,
                       coap_req->token_len, coap_req->uri_path,
                       coap_req->uri_path_len, iface_mask);
#else  /* OC_BLOCK_WISE */
          add_observer(resource, endpoint, coap_req->token, coap_req->token_len,
                       coap_req->uri_path, coap_req->uri_path_len, iface_mask);
#endif /* !OC_BLOCK_WISE */
      } else if (coap_req->observe == 1) {
        dup = coap_remove_observer_by_token(endpoint, coap_req->token,
                                            coap_req->token_len);
      }
    }
  }
  return dup;
}
/*---------------------------------------------------------------------------*/

#endif /* OC_SERVER */
