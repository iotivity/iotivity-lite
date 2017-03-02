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

#include "config.h"

#ifdef OC_SERVER

#include "observe.h"
#include "util/oc_memb.h"
#include <stdio.h>
#include <string.h>

#ifdef OC_BLOCK_WISE_SET_MTU
#include "oc_blockwise.h"
#endif /* OC_BLOCK_WISE_SET_MTU */

#ifdef OC_COLLECTIONS
#include "oc_collection.h"
#endif /* OC_COLLECTIONS */

#include "oc_coap.h"
#include "oc_rep.h"
#include "oc_ri.h"
/*-------------------*/
uint64_t observe_counter = 3;
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
    if (((memcmp(&obs->endpoint, endpoint, sizeof(oc_endpoint_t)) == 0)) &&
        (obs->url == uri || memcmp(obs->url, uri, uri_len) == 0)) {
      obs->resource->num_observers--;
      oc_memb_free(&observers_memb, obs);
      oc_list_remove(observers_list, obs);
      removed++;
      break;
    }
    obs = next;
  }
  return removed;
}
/*---------------------------------------------------------------------------*/
static int
#ifdef OC_BLOCK_WISE_SET_MTU
add_observer(oc_resource_t *resource, uint16_t block2_size,
             oc_endpoint_t *endpoint, const uint8_t *token, size_t token_len,
             const char *uri, int uri_len)
#else  /* OC_BLOCK_WISE_SET_MTU */
add_observer(oc_resource_t *resource, oc_endpoint_t *endpoint,
             const uint8_t *token, size_t token_len, const char *uri,
             int uri_len)
#endif /* !OC_BLOCK_WISE_SET_MTU */
{
  /* Remove existing observe relationship, if any. */
  int dup = coap_remove_observer_handle_by_uri(endpoint, uri, uri_len);

  coap_observer_t *o = oc_memb_alloc(&observers_memb);

  if (o) {
    int max = sizeof(o->url) - 1;
    if (max > uri_len) {
      max = uri_len;
    }
    memcpy(o->url, uri, max);
    o->url[max] = 0;
    memcpy(&o->endpoint, endpoint, sizeof(oc_endpoint_t));
    o->token_len = token_len;
    memcpy(o->token, token, token_len);
    o->last_mid = 0;
    o->obs_counter = observe_counter;
    o->resource = resource;
#ifdef OC_BLOCK_WISE_SET_MTU
    o->block2_size = block2_size;
#endif /* OC_BLOCK_WISE_SET_MTU */
    resource->num_observers++;
    OC_DBG("Adding observer (%u/%u) for /%s [0x%02X%02X]\n",
           oc_list_length(observers_list) + 1, COAP_MAX_OBSERVERS, o->url,
           o->token[0], o->token[1]);
    oc_list_add(observers_list, o);
    return dup;
  }
  return -1;
}
/*---------------------------------------------------------------------------*/
/*- Removal -----------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
void
coap_remove_observer(coap_observer_t *o)
{
  OC_DBG("Removing observer for /%s [0x%02X%02X]\n", o->url, o->token[0],
         o->token[1]);

#ifdef OC_BLOCK_WISE_SET_MTU
  oc_blockwise_state_t *response_state = oc_blockwise_find_response_buffer(
    oc_string(o->resource->uri) + 1, oc_string_len(o->resource->uri) - 1,
    &o->endpoint, OC_GET);
  if (response_state) {
    oc_blockwise_free_response_buffer(response_state);
  }
#endif /* OC_BLOCK_WISE_SET_MTU */

  oc_memb_free(&observers_memb, o);
  oc_list_remove(observers_list, o);
}
/*---------------------------------------------------------------------------*/
int
coap_remove_observer_by_client(oc_endpoint_t *endpoint)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list), *next;

  OC_DBG("Unregistering observers for client at: ");
  LOGipaddr(*endpoint);

  while (obs) {
    next = obs->next;
    if (memcmp(&obs->endpoint, endpoint, sizeof(oc_endpoint_t)) == 0) {
      obs->resource->num_observers--;
      coap_remove_observer(obs);
      removed++;
    }
    obs = next;
  }
  OC_DBG("Removed %d observers\n", removed);
  return removed;
}
/*---------------------------------------------------------------------------*/
int
coap_remove_observer_by_token(oc_endpoint_t *endpoint, uint8_t *token,
                              size_t token_len)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t *)oc_list_head(observers_list);
  OC_DBG("Unregistering observers for request token 0x%02X%02X\n", token[0],
         token[1]);
  while (obs) {
    if (memcmp(&obs->endpoint, endpoint, sizeof(oc_endpoint_t)) == 0 &&
        obs->token_len == token_len &&
        memcmp(obs->token, token, token_len) == 0) {
      obs->resource->num_observers--;
      coap_remove_observer(obs);
      removed++;
      break;
    }
    obs = obs->next;
  }
  OC_DBG("Removed %d observers\n", removed);
  return removed;
}
/*---------------------------------------------------------------------------*/
int
coap_remove_observer_by_mid(oc_endpoint_t *endpoint, uint16_t mid)
{
  int removed = 0;
  coap_observer_t *obs = NULL;
  OC_DBG("Unregistering observers for request MID %u\n", mid);

  for (obs = (coap_observer_t *)oc_list_head(observers_list); obs != NULL;
       obs = obs->next) {
    if (memcmp(&obs->endpoint, endpoint, sizeof(*endpoint)) == 0 &&
        obs->last_mid == mid) {
      obs->resource->num_observers--;
      coap_remove_observer(obs);
      removed++;
      break;
    }
  }
  OC_DBG("Removed %d observers\n", removed);
  return removed;
}

/*---------------------------------------------------------------------------*/
/*- Notification ------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
int
coap_notify_observers(oc_resource_t *resource,
                      oc_response_buffer_t *response_buf,
                      oc_endpoint_t *endpoint)
{
  int num_observers = 0;
  if (resource) {
    if (!resource->num_observers) {
      OC_DBG("coap_notify_observers: no observers; returning\n");
      return 0;
    }
    num_observers = resource->num_observers;
  }

#ifdef OC_BLOCK_WISE_SET_MTU
  uint8_t buffer[OC_BLOCK_WISE_BUFFER_SIZE];
  oc_blockwise_state_t *response_state;
#else  /* OC_BLOCK_WISE_SET_MTU */
  uint8_t buffer[OC_BLOCK_SIZE];
#endif /* OC_BLOCK_WISE_SET_MTU */

  oc_request_t request = { 0 };
  oc_response_t response = { 0 };
  response.separate_response = 0;
  oc_response_buffer_t response_buffer;
  if (!response_buf && resource) {
    OC_DBG("coap_notify_observers: Issue GET request to resource\n");
    response_buffer.buffer = buffer;

#ifdef OC_BLOCK_WISE_SET_MTU
    response_buffer.buffer_size = OC_BLOCK_WISE_BUFFER_SIZE;
#else /* OC_BLOCK_WISE_SET_MTU */
    response_buffer.buffer_size = OC_BLOCK_SIZE;
#endif /* !OC_BLOCK_WISE_SET_MTU */

    response.response_buffer = &response_buffer;
    request.resource = resource;
    request.response = &response;
    request.request_payload = NULL;
    oc_rep_new(response_buffer.buffer, response_buffer.buffer_size);
#ifdef OC_COLLECTIONS
    if (oc_check_if_collection(resource))
      oc_handle_collection_request(OC_GET, &request,
                                   resource->default_interface);
    else
#endif /* OC_COLLECTIONS */
      resource->get_handler.cb(&request, resource->default_interface,
                               resource->get_handler.user_data);
    response_buf = &response_buffer;
    if (response_buf->code == OC_IGNORE) {
      OC_DBG("coap_notify_observers: Resource ignored request\n");
      return num_observers;
    }
  }

  coap_observer_t *obs = NULL;
  /* iterate over observers */
  for (obs = (coap_observer_t *)oc_list_head(observers_list);
       obs && ((resource && obs->resource == resource) ||
               (endpoint &&
                memcmp(&obs->endpoint, endpoint, sizeof(oc_endpoint_t)) == 0));
       obs = obs->next) {
    num_observers = obs->resource->num_observers;

    if (response.separate_response != NULL &&
        response_buf->code == oc_status_code(OC_STATUS_OK)) {
      coap_packet_t req[1];
      coap_init_message(req, COAP_TYPE_NON, COAP_GET, 0);
      memcpy(req->token, obs->token, obs->token_len);
      req->token_len = obs->token_len;

#ifdef OC_BLOCK_WISE_SET_MTU
      coap_set_header_uri_path(req, oc_string(resource->uri),
                               oc_string_len(resource->uri));
#endif /* OC_BLOCK_WISE_SET_MTU */

      OC_DBG("Resource is SLOW; creating separate response\n");
#ifdef OC_BLOCK_WISE_SET_MTU
      if (coap_separate_accept(req, response.separate_response, &obs->endpoint,
                               0, obs->block2_size) == 1)
#else  /* OC_BLOCK_WISE_SET_MTU */
      if (coap_separate_accept(req, response.separate_response, &obs->endpoint,
                               0) == 1)
#endif /* !OC_BLOCK_WISE_SET_MTU */
        response.separate_response->active = 1;
    } else {
      OC_DBG("coap_notify_observers: notifying observer\n");
      coap_transaction_t *transaction = NULL;
      if (response_buf) {
        coap_packet_t notification[1];
        coap_init_message(notification, COAP_TYPE_NON, CONTENT_2_05, 0);

#ifdef OC_BLOCK_WISE_SET_MTU
        if (response_buf->response_length > obs->block2_size) {
          notification->type = COAP_TYPE_CON;
          response_state = oc_blockwise_find_response_buffer(
            oc_string(obs->resource->uri) + 1,
            oc_string_len(obs->resource->uri) - 1, &obs->endpoint, OC_GET);
          if (response_state) {
            continue;
          }
          response_state = oc_blockwise_alloc_response_buffer(
            oc_string(obs->resource->uri) + 1,
            oc_string_len(obs->resource->uri) - 1, &obs->endpoint, OC_GET);
          if (!response_state) {
            return num_observers;
          }
          memcpy(response_state->buffer, response_buf->buffer,
                 response_buf->response_length);
          response_state->payload_size = response_buf->response_length;
          uint16_t payload_size = 0;
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
        } else
#endif /* OC_BLOCK_WISE_SET_MTU */
        {
          if (obs->obs_counter % COAP_OBSERVE_REFRESH_INTERVAL == 0) {
            OC_DBG("coap_observe_notify: forcing CON notification to check for "
                   "client liveness\n");
            notification->type = COAP_TYPE_CON;
          }
          coap_set_payload(notification, response_buf->buffer,
                           response_buf->response_length);
        }

        coap_set_status_code(notification, response_buf->code);
        if (notification->code < BAD_REQUEST_4_00 &&
            obs->resource->num_observers) {
          coap_set_header_observe(notification, (obs->obs_counter)++);
          observe_counter++;
        } else {
          coap_set_header_observe(notification, 1);
        }
        coap_set_header_content_format(notification, APPLICATION_CBOR);
        coap_set_token(notification, obs->token, obs->token_len);
        transaction = coap_new_transaction(coap_get_mid(), &obs->endpoint);
        if (transaction) {
          obs->last_mid = transaction->mid;
          notification->mid = transaction->mid;

          transaction->message->length =
            coap_serialize_message(notification, transaction->message->data);

          coap_send_transaction(transaction);
        }
      }
    }
  }
  return num_observers;
}
/*---------------------------------------------------------------------------*/
#ifdef OC_BLOCK_WISE_SET_MTU
int
coap_observe_handler(void *request, void *response, oc_resource_t *resource,
                     uint16_t block2_size, oc_endpoint_t *endpoint)
#else  /* OC_BLOCK_WISE_SET_MTU */
int
coap_observe_handler(void *request, void *response, oc_resource_t *resource,
                     oc_endpoint_t *endpoint)
#endif /* !OC_BLOCK_WISE_SET_MTU */
{
  coap_packet_t *const coap_req = (coap_packet_t *)request;
  coap_packet_t *const coap_res = (coap_packet_t *)response;
  int dup = -1;
  if (coap_req->code == COAP_GET && coap_res->code < 128) {
    if (IS_OPTION(coap_req, COAP_OPTION_OBSERVE)) {
      if (coap_req->observe == 0) {
        dup =
#ifdef OC_BLOCK_WISE_SET_MTU
          add_observer(resource, block2_size, endpoint, coap_req->token,
                       coap_req->token_len, coap_req->uri_path,
                       coap_req->uri_path_len);
#else  /* OC_BLOCK_WISE_SET_MTU */
          add_observer(resource, endpoint, coap_req->token, coap_req->token_len,
                       coap_req->uri_path, coap_req->uri_path_len);
#endif /* !OC_BLOCK_WISE_SET_MTU */
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
