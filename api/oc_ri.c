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

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "util/oc_etimer.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include "util/oc_process.h"

#include "messaging/coap/constants.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/oc_coap.h"
#ifdef OC_TCP
#include "messaging/coap/coap_signal.h"
#endif /* OC_TCP */

#include "port/oc_random.h"

#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_discovery.h"
#include "oc_events.h"
#include "oc_network_events.h"
#ifdef OC_TCP
#include "oc_session_events.h"
#endif /* OC_TCP */
#include "oc_api.h"
#include "oc_ri.h"
#include "oc_uuid.h"

#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif /* OC_BLOCK_WISE */

#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
#include "oc_collection.h"
#endif /* OC_COLLECTIONS && OC_SERVER */

#ifdef OC_SECURITY
#include "security/oc_acl_internal.h"
#include "security/oc_pstat.h"
#include "security/oc_roles.h"
#include "security/oc_tls.h"
#include "security/oc_audit.h"
#endif /* OC_SECURITY */

#ifdef OC_SERVER
OC_LIST(app_resources);
OC_LIST(observe_callbacks);
OC_MEMB(app_resources_s, oc_resource_t, OC_MAX_APP_RESOURCES);
#endif /* OC_SERVER */

#ifdef OC_CLIENT
#include "oc_client_state.h"
OC_LIST(client_cbs);
OC_MEMB(client_cbs_s, oc_client_cb_t, OC_MAX_NUM_CONCURRENT_REQUESTS + 1);
#endif /* OC_CLIENT */

OC_LIST(timed_callbacks);
OC_MEMB(event_callbacks_s, oc_event_callback_t,
        1 + OCF_D * OC_MAX_NUM_DEVICES + OC_MAX_APP_RESOURCES +
          OC_MAX_NUM_CONCURRENT_REQUESTS * 2);

OC_PROCESS(timed_callback_events, "OC timed callbacks");

#ifdef OC_TCP
oc_event_callback_retval_t oc_remove_ping_handler(void *data);
#endif /* OC_TCP */

extern int strncasecmp(const char *s1, const char *s2, size_t n);

static unsigned int oc_coap_status_codes[__NUM_OC_STATUS_CODES__];

oc_process_event_t oc_events[__NUM_OC_EVENT_TYPES__];

static void
set_mpro_status_codes(void)
{
  /* OK_200 */
  oc_coap_status_codes[OC_STATUS_OK] = CONTENT_2_05;
  /* CREATED_201 */
  oc_coap_status_codes[OC_STATUS_CREATED] = CREATED_2_01;
  /* NO_CONTENT_204 */
  oc_coap_status_codes[OC_STATUS_CHANGED] = CHANGED_2_04;
  /* NO_CONTENT_204 */
  oc_coap_status_codes[OC_STATUS_DELETED] = DELETED_2_02;
  /* NOT_MODIFIED_304 */
  oc_coap_status_codes[OC_STATUS_NOT_MODIFIED] = VALID_2_03;
  /* BAD_REQUEST_400 */
  oc_coap_status_codes[OC_STATUS_BAD_REQUEST] = BAD_REQUEST_4_00;
  /* UNAUTHORIZED_401 */
  oc_coap_status_codes[OC_STATUS_UNAUTHORIZED] = UNAUTHORIZED_4_01;
  /* BAD_REQUEST_400 */
  oc_coap_status_codes[OC_STATUS_BAD_OPTION] = BAD_OPTION_4_02;
  /* FORBIDDEN_403 */
  oc_coap_status_codes[OC_STATUS_FORBIDDEN] = FORBIDDEN_4_03;
  /* NOT_FOUND_404 */
  oc_coap_status_codes[OC_STATUS_NOT_FOUND] = NOT_FOUND_4_04;
  /* METHOD_NOT_ALLOWED_405 */
  oc_coap_status_codes[OC_STATUS_METHOD_NOT_ALLOWED] = METHOD_NOT_ALLOWED_4_05;
  /* NOT_ACCEPTABLE_406 */
  oc_coap_status_codes[OC_STATUS_NOT_ACCEPTABLE] = NOT_ACCEPTABLE_4_06;
  /* REQUEST_ENTITY_TOO_LARGE_413 */
  oc_coap_status_codes[OC_STATUS_REQUEST_ENTITY_TOO_LARGE] =
    REQUEST_ENTITY_TOO_LARGE_4_13;
  /* UNSUPPORTED_MEDIA_TYPE_415 */
  oc_coap_status_codes[OC_STATUS_UNSUPPORTED_MEDIA_TYPE] =
    UNSUPPORTED_MEDIA_TYPE_4_15;
  /* INTERNAL_SERVER_ERROR_500 */
  oc_coap_status_codes[OC_STATUS_INTERNAL_SERVER_ERROR] =
    INTERNAL_SERVER_ERROR_5_00;
  /* NOT_IMPLEMENTED_501 */
  oc_coap_status_codes[OC_STATUS_NOT_IMPLEMENTED] = NOT_IMPLEMENTED_5_01;
  /* BAD_GATEWAY_502 */
  oc_coap_status_codes[OC_STATUS_BAD_GATEWAY] = BAD_GATEWAY_5_02;
  /* SERVICE_UNAVAILABLE_503 */
  oc_coap_status_codes[OC_STATUS_SERVICE_UNAVAILABLE] =
    SERVICE_UNAVAILABLE_5_03;
  /* GATEWAY_TIMEOUT_504 */
  oc_coap_status_codes[OC_STATUS_GATEWAY_TIMEOUT] = GATEWAY_TIMEOUT_5_04;
  /* INTERNAL_SERVER_ERROR_500 */
  oc_coap_status_codes[OC_STATUS_PROXYING_NOT_SUPPORTED] =
    PROXYING_NOT_SUPPORTED_5_05;
}

#ifdef OC_SERVER
oc_resource_t *
oc_ri_get_app_resources(void)
{
  return oc_list_head(app_resources);
}

bool
oc_ri_is_app_resource_valid(oc_resource_t *resource)
{
  oc_resource_t *res = oc_ri_get_app_resources();
  while (res) {
    if (res == resource) {
      return true;
    }
    res = res->next;
  }
  return false;
}
#endif

int
oc_status_code(oc_status_t key)
{
  return oc_coap_status_codes[key];
}

int
oc_ri_get_query_nth_key_value(const char *query, size_t query_len, char **key,
                              size_t *key_len, char **value, size_t *value_len,
                              size_t n)
{
  int next_pos = -1;
  size_t i = 0;
  char *start = (char *)query, *current, *end = (char *)query + query_len;
  current = start;

  while (i < (n - 1) && current != NULL) {
    current = memchr(start, '&', end - start);
    if (current == NULL) {
      return -1;
    }
    i++;
    start = current + 1;
  }

  current = memchr(start, '=', end - start);
  if (current != NULL) {
    *key_len = (current - start);
    *key = start;
    *value = current + 1;
    current = memchr(*value, '&', end - *value);
    if (current == NULL) {
      *value_len = (end - *value);
    } else {
      *value_len = (current - *value);
    }
    next_pos = (int)(*value + *value_len - query + 1);
  }
  return next_pos;
}

int
oc_ri_get_query_value(const char *query, size_t query_len, const char *key,
                      char **value)
{
  int next_pos = 0, found = -1;
  size_t kl, vl, pos = 0;
  char *k;

  while (pos < query_len) {
    next_pos = oc_ri_get_query_nth_key_value(query + pos, query_len - pos, &k,
                                             &kl, value, &vl, 1u);
    if (next_pos == -1)
      return -1;

    if (kl == strlen(key) && strncasecmp(key, k, kl) == 0) {
      found = (int)vl;
      break;
    }

    pos += next_pos;
  }
  return found;
}

static void
allocate_events(void)
{
  int i = 0;
  for (i = 0; i < __NUM_OC_EVENT_TYPES__; i++) {
    oc_events[i] = oc_process_alloc_event();
  }
}

static void
start_processes(void)
{
  allocate_events();
  oc_process_start(&oc_etimer_process, NULL);
  oc_process_start(&timed_callback_events, NULL);
  oc_process_start(&coap_engine, NULL);
  oc_process_start(&message_buffer_handler, NULL);

#ifdef OC_SECURITY
  oc_process_start(&oc_tls_handler, NULL);
#endif /* OC_SECURITY */

  oc_process_start(&oc_network_events, NULL);
#ifdef OC_TCP
  oc_process_start(&oc_session_events, NULL);
#endif /* OC_TCP */
}

static void
stop_processes(void)
{
#ifdef OC_TCP
  oc_process_exit(&oc_session_events);
#endif /* OC_TCP */
  oc_process_exit(&oc_network_events);
  oc_process_exit(&oc_etimer_process);
  oc_process_exit(&timed_callback_events);
  oc_process_exit(&coap_engine);

#ifdef OC_SECURITY
  oc_process_exit(&oc_tls_handler);
#endif /* OC_SECURITY */

  oc_process_exit(&message_buffer_handler);
}

#ifdef OC_SERVER
oc_resource_t *
oc_ri_get_app_resource_by_uri(const char *uri, size_t uri_len, size_t device)
{
  if (!uri || uri_len == 0)
    return NULL;
  int skip = 0;
  if (uri[0] != '/')
    skip = 1;
  oc_resource_t *res = oc_ri_get_app_resources();
  while (res != NULL) {
    if (oc_string_len(res->uri) == (uri_len + skip) &&
        strncmp(uri, oc_string(res->uri) + skip, uri_len) == 0 &&
        res->device == device)
      return res;
    res = res->next;
  }

#ifdef OC_COLLECTIONS
  if (!res) {
    res = (oc_resource_t *)oc_get_collection_by_uri(uri, uri_len, device);
  }
#endif /* OC_COLLECTIONS */

  return res;
}

static void
oc_ri_delete_all_app_resources(void)
{
  oc_resource_t *res = oc_ri_get_app_resources();
  while (res) {
    oc_ri_delete_resource(res);
    res = oc_ri_get_app_resources();
  }
}
#endif /* OC_SERVER */

void
oc_ri_init(void)
{
  oc_random_init();
  oc_clock_init();
  set_mpro_status_codes();

#ifdef OC_SERVER
  oc_list_init(app_resources);
  oc_list_init(observe_callbacks);
#endif

#ifdef OC_CLIENT
  oc_list_init(client_cbs);
#endif

  oc_list_init(timed_callbacks);

  oc_process_init();
  start_processes();
}

#ifdef OC_SERVER
oc_resource_t *
oc_ri_alloc_resource(void)
{
  return oc_memb_alloc(&app_resources_s);
}

bool
oc_ri_delete_resource(oc_resource_t *resource)
{
  if (!resource)
    return false;

  if (resource->num_observers > 0) {
    coap_remove_observer_by_resource(resource);
  }
  oc_list_remove(app_resources, resource);
  oc_ri_free_resource_properties(resource);
  oc_memb_free(&app_resources_s, resource);
  return true;
}

bool
oc_ri_add_resource(oc_resource_t *resource)
{
  if (!resource)
    return false;

  bool valid = true;

  if (!resource->get_handler.cb && !resource->put_handler.cb &&
      !resource->post_handler.cb && !resource->delete_handler.cb)
    valid = false;

  if ((resource->properties & OC_PERIODIC) &&
      resource->observe_period_seconds == 0)
    valid = false;

  if (valid) {
    oc_list_add(app_resources, resource);
  }

  return valid;
}
#endif /* OC_SERVER */

void
oc_ri_free_resource_properties(oc_resource_t *resource)
{
  if (resource) {
    if (oc_string_len(resource->name) > 0) {
      oc_free_string(&(resource->name));
    }
    if (oc_string_len(resource->uri) > 0) {
      oc_free_string(&(resource->uri));
    }
    if (oc_string_array_get_allocated_size(resource->types) > 0) {
      oc_free_string_array(&(resource->types));
    }
  }
}

void
oc_ri_remove_timed_event_callback(void *cb_data, oc_trigger_t event_callback)
{
  oc_event_callback_t *event_cb =
    (oc_event_callback_t *)oc_list_head(timed_callbacks);

  while (event_cb != NULL) {
    if (event_cb->data == cb_data && event_cb->callback == event_callback) {
      OC_PROCESS_CONTEXT_BEGIN(&timed_callback_events);
      oc_etimer_stop(&event_cb->timer);
      OC_PROCESS_CONTEXT_END(&timed_callback_events);
      oc_list_remove(timed_callbacks, event_cb);
      oc_memb_free(&event_callbacks_s, event_cb);
      break;
    }
    event_cb = event_cb->next;
  }
}

void
oc_ri_add_timed_event_callback_ticks(void *cb_data, oc_trigger_t event_callback,
                                     oc_clock_time_t ticks)
{
  oc_event_callback_t *event_cb =
    (oc_event_callback_t *)oc_memb_alloc(&event_callbacks_s);

  if (event_cb) {
    event_cb->data = cb_data;
    event_cb->callback = event_callback;
    OC_PROCESS_CONTEXT_BEGIN(&timed_callback_events);
    oc_etimer_set(&event_cb->timer, ticks);
    OC_PROCESS_CONTEXT_END(&timed_callback_events);
    oc_list_add(timed_callbacks, event_cb);
  } else {
    OC_WRN("insufficient memory to add timed event callback");
  }
}

static void
poll_event_callback_timers(oc_list_t list, struct oc_memb *cb_pool)
{
  oc_event_callback_t *event_cb = (oc_event_callback_t *)oc_list_head(list),
                      *next;

  while (event_cb != NULL) {
    next = event_cb->next;

    if (oc_etimer_expired(&event_cb->timer)) {
      if (event_cb->callback(event_cb->data) == OC_EVENT_DONE) {
        oc_list_remove(list, event_cb);
        oc_memb_free(cb_pool, event_cb);
        event_cb = oc_list_head(list);
        continue;
      } else {
        OC_PROCESS_CONTEXT_BEGIN(&timed_callback_events);
        oc_etimer_restart(&event_cb->timer);
        OC_PROCESS_CONTEXT_END(&timed_callback_events);
        event_cb = oc_list_head(list);
        continue;
      }
    }

    event_cb = next;
  }
}

static void
check_event_callbacks(void)
{
#ifdef OC_SERVER
  poll_event_callback_timers(observe_callbacks, &event_callbacks_s);
#endif /* OC_SERVER */
  poll_event_callback_timers(timed_callbacks, &event_callbacks_s);
}

#ifdef OC_SERVER
static oc_event_callback_retval_t
oc_observe_notification_delayed(void *data)
{
  (void)data;
  coap_notify_observers((oc_resource_t *)data, NULL, NULL);
  return OC_EVENT_DONE;
}
#endif

#ifdef OC_SERVER
static oc_event_callback_retval_t
periodic_observe_handler(void *data)
{
  oc_resource_t *resource = (oc_resource_t *)data;

  if (coap_notify_observers(resource, NULL, NULL)) {
    return OC_EVENT_CONTINUE;
  }

  return OC_EVENT_DONE;
}

static oc_event_callback_t *
get_periodic_observe_callback(oc_resource_t *resource)
{
  oc_event_callback_t *event_cb;
  bool found = false;

  for (event_cb = (oc_event_callback_t *)oc_list_head(observe_callbacks);
       event_cb; event_cb = event_cb->next) {
    if (resource == event_cb->data) {
      found = true;
      break;
    }
  }

  if (found) {
    return event_cb;
  }

  return NULL;
}

static void
remove_periodic_observe_callback(oc_resource_t *resource)
{
  oc_event_callback_t *event_cb = get_periodic_observe_callback(resource);

  if (event_cb) {
    oc_etimer_stop(&event_cb->timer);
    oc_list_remove(observe_callbacks, event_cb);
    oc_memb_free(&event_callbacks_s, event_cb);
  }
}

static bool
add_periodic_observe_callback(oc_resource_t *resource)
{
  oc_event_callback_t *event_cb = get_periodic_observe_callback(resource);

  if (!event_cb) {
    event_cb = (oc_event_callback_t *)oc_memb_alloc(&event_callbacks_s);

    if (!event_cb) {
      OC_WRN("insufficient memory to add periodic observe callback");
      return false;
    }

    event_cb->data = resource;
    event_cb->callback = periodic_observe_handler;
    OC_PROCESS_CONTEXT_BEGIN(&timed_callback_events);
    oc_etimer_set(&event_cb->timer,
                  resource->observe_period_seconds * OC_CLOCK_SECOND);
    OC_PROCESS_CONTEXT_END(&timed_callback_events);
    oc_list_add(observe_callbacks, event_cb);
  }

  return true;
}
#endif

static void
free_all_event_timers(void)
{
#ifdef OC_SERVER
  oc_event_callback_t *obs_cb =
    (oc_event_callback_t *)oc_list_pop(observe_callbacks);
  while (obs_cb != NULL) {
    oc_etimer_stop(&obs_cb->timer);
    oc_list_remove(observe_callbacks, obs_cb);
    oc_memb_free(&event_callbacks_s, obs_cb);
    obs_cb = oc_list_pop(observe_callbacks);
  }
#endif /* OC_SERVER */
  oc_event_callback_t *event_cb =
    (oc_event_callback_t *)oc_list_pop(timed_callbacks);
  while (event_cb != NULL) {
    oc_etimer_stop(&event_cb->timer);
    oc_list_remove(timed_callbacks, event_cb);
    oc_memb_free(&event_callbacks_s, event_cb);
    event_cb = oc_list_pop(timed_callbacks);
  }
}

oc_interface_mask_t
oc_ri_get_interface_mask(char *iface, size_t if_len)
{
  oc_interface_mask_t iface_mask = 0;
  if (15 == if_len && strncmp(iface, "oic.if.baseline", if_len) == 0)
    iface_mask |= OC_IF_BASELINE;
  if (9 == if_len && strncmp(iface, "oic.if.ll", if_len) == 0)
    iface_mask |= OC_IF_LL;
  if (8 == if_len && strncmp(iface, "oic.if.b", if_len) == 0)
    iface_mask |= OC_IF_B;
  if (8 == if_len && strncmp(iface, "oic.if.r", if_len) == 0)
    iface_mask |= OC_IF_R;
  if (9 == if_len && strncmp(iface, "oic.if.rw", if_len) == 0)
    iface_mask |= OC_IF_RW;
  if (8 == if_len && strncmp(iface, "oic.if.a", if_len) == 0)
    iface_mask |= OC_IF_A;
  if (8 == if_len && strncmp(iface, "oic.if.s", if_len) == 0)
    iface_mask |= OC_IF_S;
  if (13 == if_len && strncmp(iface, "oic.if.create", if_len) == 0)
    iface_mask |= OC_IF_CREATE;
  return iface_mask;
}

static bool
does_interface_support_method(oc_interface_mask_t iface_mask,
                              oc_method_t method)
{
  bool supported = true;
  switch (iface_mask) {
  /* Per section 7.5.3 of the OCF Core spec, the following three interfaces
   * are RETRIEVE-only.
   */
  case OC_IF_LL:
  case OC_IF_S:
  case OC_IF_R:
    if (method != OC_GET)
      supported = false;
    break;
  /* Per section 7.5.3 of the OCF Core spec, the following three interfaces
   * support RETRIEVE, UPDATE.
   * TODO: Refine logic below after adding logic that identifies
   * and handles CREATE requests using PUT/POST.
   */
  case OC_IF_RW:
  case OC_IF_B:
  case OC_IF_BASELINE:
  case OC_IF_CREATE:
  /* Per section 7.5.3 of the OCF Core spec, the following interface
   * supports CREATE, RETRIEVE and UPDATE.
   */
  case OC_IF_A:
    break;
  }
  return supported;
}

#ifdef OC_SECURITY
static void
oc_ri_audit_log(oc_method_t method, oc_resource_t *resource,
                oc_endpoint_t *endpoint)
{
#define LINE_WIDTH 80
  char aux_arr[6][LINE_WIDTH];
  memset(aux_arr, 0, sizeof(aux_arr));
  char *aux[] = { aux_arr[0], aux_arr[1], aux_arr[2],
                  aux_arr[3], aux_arr[4], aux_arr[5] };
  size_t idx = 1;
  SNPRINTFipaddr(aux[0], LINE_WIDTH, *endpoint);
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (peer) {
    oc_uuid_to_str(&peer->uuid, aux[idx++], LINE_WIDTH);
  }
  memcpy(aux[idx++], oc_string(resource->uri), oc_string_len(resource->uri));
  static const char *method_str_val[] = { "UNKNOWN", "RETRIEVE", "UPDATE",
                                          "UPDATE", "DELETE" };
  snprintf(aux[idx++], LINE_WIDTH, "attempt to %s the resource",
           method_str_val[method]);
  static const char *state_str_val[] = { "RESET", "RFOTM", "RFPRO", "RFNOP",
                                         "SRESET" };
  int state = oc_sec_get_pstat(endpoint->device)->s;
  snprintf(aux[idx++], LINE_WIDTH, "device is in %s", state_str_val[state]);
  snprintf(aux[idx++], LINE_WIDTH, "No roles asserted");
#ifdef OC_PKI
  if (peer) {
    size_t pos = 0;
    for (oc_sec_cred_t *rc = oc_sec_get_roles(peer); rc && pos < LINE_WIDTH;
         rc = rc->next) {
      pos += snprintf(aux[idx - 1] + pos, LINE_WIDTH - pos - 1, "%s ",
                      oc_string(rc->role.role));
    }
  }
#endif /* OC_PKI */
  oc_audit_log(endpoint->device, "AC-1", "Access Denied", 0x01, 2,
               (const char **)aux, idx);
}
#endif /* OC_SECURITY */

#ifdef OC_BLOCK_WISE
bool
oc_ri_invoke_coap_entity_handler(void *request, void *response,
                                 oc_blockwise_state_t **request_state,
                                 oc_blockwise_state_t **response_state,
                                 uint16_t block2_size, oc_endpoint_t *endpoint)
#else  /* OC_BLOCK_WISE */
bool
oc_ri_invoke_coap_entity_handler(void *request, void *response, uint8_t *buffer,
                                 oc_endpoint_t *endpoint)
#endif /* !OC_BLOCK_WISE */
{
  /* Flags that capture status along various stages of processing
   *  the request.
   */
  bool method_impl = true, bad_request = false, success = false,
       forbidden = false, entity_too_large = false;

  endpoint->version = OCF_VER_1_0_0;
#ifdef OC_SPEC_VER_OIC
  unsigned int accept = 0;
  if (coap_get_header_accept(request, &accept) == 1) {
    if (accept == APPLICATION_CBOR) {
      endpoint->version = OIC_VER_1_1_0;
    }
  }
#endif /* OC_SPEC_VER_OIC */

#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
  bool resource_is_collection = false;
#endif /* OC_COLLECTIONS && OC_SERVER */

#ifdef OC_SECURITY
  bool authorized = true;
#endif /* OC_SECURITY */

  /* Parsed CoAP PDU structure. */
  coap_packet_t *const packet = (coap_packet_t *)request;

  /* This function is a server-side entry point solely for requests.
   *  Hence, "code" contains the CoAP method code.
   */
  oc_method_t method = packet->code;

  /* Initialize request/response objects to be sent up to the app layer. */
  oc_request_t request_obj;
  oc_response_buffer_t response_buffer;
  oc_response_t response_obj;

#ifdef OC_BLOCK_WISE
#ifndef OC_SERVER
  (void)block2_size;
#endif /* !OC_SERVER */
#endif /* OC_BLOCK_WISE */

  /* Postpone allocating response_state right after calling
   * oc_parse_rep()
   *  in order to reducing peak memory in OC_BLOCK_WISE & OC_DYNAMIC_ALLOCATION
   */
  response_buffer.code = 0;
  response_buffer.response_length = 0;
  response_buffer.content_format = 0;

  response_obj.separate_response = NULL;
  response_obj.response_buffer = &response_buffer;

  request_obj.response = &response_obj;
  request_obj.request_payload = NULL;
  request_obj.query = NULL;
  request_obj.query_len = 0;
  request_obj.resource = NULL;
  request_obj.origin = endpoint;
  request_obj._payload = NULL;
  request_obj._payload_len = 0;

  /* Initialize OCF interface selector. */
  oc_interface_mask_t iface_query = 0, iface_mask = 0;

  /* Obtain request uri from the CoAP packet. */
  const char *uri_path = NULL;
  size_t uri_path_len = coap_get_header_uri_path(request, &uri_path);

  /* Obtain query string from CoAP packet. */
  const char *uri_query = 0;
  size_t uri_query_len = coap_get_header_uri_query(request, &uri_query);

  /* Read the Content-Format CoAP option in the request */
  oc_content_format_t cf = 0;
  coap_get_header_content_format(request, &cf);

  if (uri_query_len) {
    request_obj.query = uri_query;
    request_obj.query_len = (int)uri_query_len;

    /* Check if query string includes interface selection. */
    char *iface;
    int if_len =
      oc_ri_get_query_value(uri_query, (int)uri_query_len, "if", &iface);
    if (if_len != -1) {
      iface_query |= oc_ri_get_interface_mask(iface, (size_t)if_len);
    }
  }

  /* Obtain handle to buffer containing the serialized payload */
  const uint8_t *payload = NULL;
  int payload_len = 0;
#ifdef OC_BLOCK_WISE
  if (*request_state) {
    payload = (*request_state)->buffer;
    payload_len = (*request_state)->payload_size;
  }
#else  /* OC_BLOCK_WISE */
  payload_len = coap_get_payload(request, &payload);
#endif /* !OC_BLOCK_WISE */
  request_obj._payload = payload;
  request_obj._payload_len = (size_t)payload_len;
  request_obj.content_format = cf;
#ifndef OC_DYNAMIC_ALLOCATION
  char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
  memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
  memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                 rep_objects_alloc, (void *)rep_objects_pool,
                                 0 };
#else  /* !OC_DYNAMIC_ALLOCATION */
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_rep_set_pool(&rep_objects);

  if (payload_len > 0 &&
      (cf == APPLICATION_CBOR || cf == APPLICATION_VND_OCF_CBOR)) {
    /* Attempt to parse request payload using tinyCBOR via oc_rep helper
     * functions. The result of this parse is a tree of oc_rep_t structures
     * which will reflect the schema of the payload.
     * Any failures while parsing the payload is viewed as an erroneous
     * request and results in a 4.00 response being sent.
     */
    int parse_error =
      oc_parse_rep(payload, payload_len, &request_obj.request_payload);
    if (parse_error != 0) {
      OC_WRN("ocri: error parsing request payload; tinyCBOR error code:  %d",
             parse_error);
      if (parse_error == CborErrorUnexpectedEOF)
        entity_too_large = true;
      bad_request = true;
    }

#if defined(OC_BLOCK_WISE)
    /* Free request_state cause it isn't used any more
     */
    oc_blockwise_free_request_buffer(*request_state);
    *request_state = NULL;
#endif
  }

  oc_resource_t *resource, *cur_resource = NULL;

  /* If there were no errors thus far, attempt to locate the specific
   * resource object that will handle the request using the request uri.
   */
  /* Check against list of declared core resources.
   */
  if (!bad_request) {
    int i;
    for (i = 0; i < OC_NUM_CORE_RESOURCES_PER_DEVICE; i++) {
      resource = oc_core_get_resource_by_index(i, endpoint->device);
      if (oc_string_len(resource->uri) == (uri_path_len + 1) &&
          strncmp((const char *)oc_string(resource->uri) + 1, uri_path,
                  uri_path_len) == 0) {
        request_obj.resource = cur_resource = resource;
        break;
      }
    }
  }

#ifdef OC_SERVER
  /* Check against list of declared application resources.
   */
  if (!cur_resource && !bad_request) {
    request_obj.resource = cur_resource =
      oc_ri_get_app_resource_by_uri(uri_path, uri_path_len, endpoint->device);

#if defined(OC_COLLECTIONS)
    if (cur_resource && oc_check_if_collection(cur_resource)) {
      resource_is_collection = true;
    }
#endif /* OC_COLLECTIONS */
  }
#endif /* OC_SERVER */

  if (cur_resource) {
    /* If there was no interface selection, pick the "default interface". */
    iface_mask = iface_query;
    if (iface_mask == 0)
      iface_mask = cur_resource->default_interface;

    /* Found the matching resource object. Now verify that:
     * 1) the selected interface is one that is supported by
     *    the resource, and,
     * 2) the selected interface supports the request method.
     *
     * If not, return a 4.00 response.
     */
    if (((iface_mask & ~cur_resource->interfaces) != 0) ||
        !does_interface_support_method(iface_mask, method)) {
      forbidden = true;
      bad_request = true;
#ifdef OC_SECURITY
      oc_audit_log(endpoint->device, "COMM-1", "Operation not supported", 0x40,
                   2, NULL, 0);
#endif
    }
  }

/* Alloc response_state. It also affects request_obj.response.
 */
#ifdef OC_BLOCK_WISE
  if (cur_resource && !bad_request) {
    if (!(*response_state)) {
      OC_DBG("creating new block-wise response state");
      *response_state = oc_blockwise_alloc_response_buffer(
        uri_path, uri_path_len, endpoint, method, OC_BLOCKWISE_SERVER);
      if (!(*response_state)) {
        OC_ERR("failure to alloc response state");
        bad_request = true;
      } else {
        if (uri_query_len > 0) {
          oc_new_string(&(*response_state)->uri_query, uri_query,
                        uri_query_len);
        }
        response_buffer.buffer = (*response_state)->buffer;
        response_buffer.buffer_size = (uint16_t)OC_MAX_APP_DATA_SIZE;
      }
    }
  }
#else  /* OC_BLOCK_WISE */
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = (uint16_t)OC_BLOCK_SIZE;
#endif /* !OC_BLOCK_WISE */

  if (cur_resource && !bad_request) {
    /* Process a request against a valid resource, request payload, and
     * interface.
     */
    /* Initialize oc_rep with a buffer to hold the response payload. "buffer"
     * points to memory allocated in the messaging layer for the "CoAP
     * Transaction" to service this request.
     */
    oc_rep_new(response_buffer.buffer, response_buffer.buffer_size);

#ifdef OC_SECURITY
    /* If cur_resource is a coaps:// resource, then query ACL to check if
     * the requestor (the subject) is authorized to issue this request to
     * the resource.
     */
    if (!oc_sec_check_acl(method, cur_resource, endpoint)) {
      authorized = false;
      oc_ri_audit_log(method, cur_resource, endpoint);
    } else
#endif /* OC_SECURITY */
    {
/* If cur_resource is a collection resource, invoke the framework's
 * internal handler for collections.
 */
#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
      if (resource_is_collection) {
        oc_handle_collection_request(method, &request_obj, iface_mask, NULL);
      } else
#endif /* OC_COLLECTIONS && OC_SERVER */
        /* If cur_resource is a non-collection resource, invoke
         * its handler for the requested method. If it has not
         * implemented that method, then return a 4.05 response.
         */
        if (method == OC_GET && cur_resource->get_handler.cb) {
        cur_resource->get_handler.cb(&request_obj, iface_mask,
                                     cur_resource->get_handler.user_data);
      } else if (method == OC_POST && cur_resource->post_handler.cb) {
        cur_resource->post_handler.cb(&request_obj, iface_mask,
                                      cur_resource->post_handler.user_data);
      } else if (method == OC_PUT && cur_resource->put_handler.cb) {
        cur_resource->put_handler.cb(&request_obj, iface_mask,
                                     cur_resource->put_handler.user_data);
      } else if (method == OC_DELETE && cur_resource->delete_handler.cb) {
        cur_resource->delete_handler.cb(&request_obj, iface_mask,
                                        cur_resource->delete_handler.user_data);
      } else {
        method_impl = false;
      }
    }
  }

  if (request_obj.request_payload) {
    /* To the extent that the request payload was parsed, free the
     * payload structure (and return its memory to the pool).
     */
    oc_free_rep(request_obj.request_payload);
  }

  if (forbidden) {
    OC_WRN("ocri: Forbidden request");
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_FORBIDDEN);
  } else if (entity_too_large) {
    OC_WRN("ocri: Request payload too large (hence incomplete)");
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_REQUEST_ENTITY_TOO_LARGE);
  } else if (bad_request) {
    OC_WRN("ocri: Bad request");
    /* Return a 4.00 response */
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_BAD_REQUEST);
  } else if (!cur_resource) {
    OC_WRN("ocri: Could not find resource");
    /* Return a 4.04 response if the requested resource was not found */
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_NOT_FOUND);
  } else if (!method_impl) {
    OC_WRN("ocri: Could not find method");
    /* Return a 4.05 response if the resource does not implement the
     * request method.
     */
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_METHOD_NOT_ALLOWED);
  }
#ifdef OC_SECURITY
  else if (!authorized) {
    OC_WRN("ocri: Subject not authorized");
    /* If the requestor (subject) does not have access granted via an
     * access control entry in the ACL, then it is not authorized to
     * access the resource. A 4.01 response is sent.
     */
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_UNAUTHORIZED);
  }
#endif /* OC_SECURITY */
  else {
    success = true;
  }

#ifdef OC_SERVER
  /* If a GET request was successfully processed, then check its
   *  observe option.
   */
  uint32_t observe = 2;
  if (success && response_buffer.code < oc_status_code(OC_STATUS_BAD_REQUEST) &&
      coap_get_header_observe(request, &observe)) {
    /* Check if the resource is OBSERVABLE */
    if (cur_resource->properties & OC_OBSERVABLE) {
      bool set_observe_option = true;
      /* If the observe option is set to 0, make an attempt to add the
       * requesting client as an observer.
       */
      if (observe == 0) {
#ifdef OC_BLOCK_WISE
        if (coap_observe_handler(request, response, cur_resource, block2_size,
                                 endpoint, iface_query) >= 0) {
#else  /* OC_BLOCK_WISE */
        if (coap_observe_handler(request, response, cur_resource, endpoint,
                                 iface_query) >= 0) {
#endif /* !OC_BLOCK_WISE */
          /* If the resource is marked as periodic observable it means
           * it must be polled internally for updates (which would lead to
           * notifications being sent). If so, add the resource to a list of
           * periodic GET callbacks to utilize the framework's internal
           * polling mechanism.
           */
          if (cur_resource->properties & OC_PERIODIC) {
            if (!add_periodic_observe_callback(cur_resource)) {
              set_observe_option = false;
            }
          }
        }
#if defined(OC_COLLECTIONS)
        if (resource_is_collection) {
          oc_collection_t *collection = (oc_collection_t *)cur_resource;
          oc_link_t *links = (oc_link_t *)oc_list_head(collection->links);
#ifdef OC_SECURITY
          while (links) {
            if (links->resource &&
                (links->resource->properties & OC_OBSERVABLE)) {
              if (!oc_sec_check_acl(OC_GET, links->resource, endpoint)) {
                set_observe_option = false;
                break;
              }
            }
            links = links->next;
          }
#endif /* OC_SECURITY */
          if (set_observe_option) {
            if (iface_query == OC_IF_B) {
              links = (oc_link_t *)oc_list_head(collection->links);
              while (links) {
                if (links->resource &&
                    (links->resource->properties & OC_PERIODIC)) {
                  add_periodic_observe_callback(links->resource);
                }
                links = links->next;
              }
            }
          }
        }
#endif /* OC_COLLECTIONS */
        if (set_observe_option) {
          coap_set_header_observe(response, 0);
        } else {
          coap_remove_observer_by_token(endpoint, packet->token,
                                        packet->token_len);
        }
      }
      /* If the observe option is set to 1, make an attempt to remove
       * the requesting client from the list of observers. In addition,
       * remove the resource from the list periodic GET callbacks if it
       * is periodic observable.
       */
      else if (observe == 1) {
#ifdef OC_BLOCK_WISE
        if (coap_observe_handler(request, response, cur_resource, block2_size,
                                 endpoint, iface_query) > 0) {
#else  /* OC_BLOCK_WISE */
        if (coap_observe_handler(request, response, cur_resource, endpoint,
                                 iface_query) > 0) {
#endif /* !OC_BLOCK_WISE */
          if (cur_resource->properties & OC_PERIODIC) {
            remove_periodic_observe_callback(cur_resource);
          }
#if defined(OC_COLLECTIONS)
          if (resource_is_collection) {
            oc_collection_t *collection = (oc_collection_t *)cur_resource;
            oc_link_t *links = (oc_link_t *)oc_list_head(collection->links);
            while (links) {
              if (links->resource &&
                  (links->resource->properties & OC_PERIODIC)) {
                remove_periodic_observe_callback(links->resource);
              }
              links = links->next;
            }
          }
#endif /* OC_COLLECTIONS */
        }
      }
    }
  }
#endif /* OC_SERVER */

  if (request_obj.origin && (request_obj.origin->flags & MULTICAST) &&
      response_buffer.code >= oc_status_code(OC_STATUS_BAD_REQUEST)) {
    response_buffer.code = OC_IGNORE;
  }

#ifdef OC_SERVER
  /* The presence of a separate response handle here indicates a
   * successful handling of the request by a slow resource.
   */
  if (response_obj.separate_response != NULL) {
/* Attempt to register a client request to the separate response tracker
 * and pass in the observe option (if present) or the value 2 as
 * determined by the code block above. Values 0 and 1 result in their
 * expected behaviors whereas 2 indicates an absence of an observe
 * option and hence a one-off request.
 * Following a successful registration, the separate response tracker
 * is flagged as "active". In this way, the function that later executes
 * out-of-band upon availability of the resource state knows it must
 * send out a response with it.
 */
#ifdef OC_BLOCK_WISE
    if (coap_separate_accept(request, response_obj.separate_response, endpoint,
                             observe, block2_size) == 1)
#else  /* OC_BLOCK_WISE */
    if (coap_separate_accept(request, response_obj.separate_response, endpoint,
                             observe) == 1)
#endif /* !OC_BLOCK_WISE */
      response_obj.separate_response->active = 1;
  } else
#endif /* OC_SERVER */
    if (response_buffer.code == OC_IGNORE) {
    /* If the server-side logic chooses to reject a request, it sends
     * below a response code of IGNORE, which results in the messaging
     * layer freeing the CoAP transaction associated with the request.
     */
    coap_status_code = CLEAR_TRANSACTION;
  } else {
#ifdef OC_SERVER
    /* If the recently handled request was a PUT/POST, it conceivably
     * altered the resource state, so attempt to notify all observers
     * of that resource with the change.
     */
    if (
#ifdef OC_COLLECTIONS
      !resource_is_collection &&
#endif /* OC_COLLECTIONS */
      cur_resource && (method == OC_PUT || method == OC_POST) &&
      response_buffer.code < oc_status_code(OC_STATUS_BAD_REQUEST))
      oc_ri_add_timed_event_callback_ticks(cur_resource,
                                           &oc_observe_notification_delayed, 0);

#endif /* OC_SERVER */
    if (response_buffer.response_length > 0) {
#ifdef OC_BLOCK_WISE
      (*response_state)->payload_size = response_buffer.response_length;
#else  /* OC_BLOCK_WISE */
      coap_set_payload(response, response_buffer.buffer,
                       response_buffer.response_length);
#endif /* !OC_BLOCK_WISE */
      if (response_buffer.content_format > 0) {
        coap_set_header_content_format(response,
                                       response_buffer.content_format);
      }
    }

    if (response_buffer.code ==
        oc_status_code(OC_STATUS_REQUEST_ENTITY_TOO_LARGE)) {
      coap_set_header_size1(response, OC_BLOCK_SIZE);
    }

    /* response_buffer.code at this point contains a valid CoAP status
     *  code.
     */
    coap_set_status_code(response, response_buffer.code);
  }
  return success;
}

#ifdef OC_CLIENT
static void
free_client_cb(oc_client_cb_t *cb)
{
  oc_list_remove(client_cbs, cb);
#ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers_for_client_cb(cb);
#endif /* OC_BLOCK_WISE */
  oc_free_string(&cb->uri);
  if (oc_string_len(cb->query)) {
    oc_free_string(&cb->query);
  }
  oc_memb_free(&client_cbs_s, cb);
}

oc_event_callback_retval_t
oc_ri_remove_client_cb(void *data)
{
  free_client_cb(data);
  return OC_EVENT_DONE;
}

static void
notify_client_cb_503(oc_client_cb_t *cb)
{
  oc_ri_remove_timed_event_callback(cb, &oc_ri_remove_client_cb);

  oc_client_response_t client_response;
  memset(&client_response, 0, sizeof(oc_client_response_t));
  client_response.client_cb = cb;
  client_response.endpoint = &cb->endpoint;
  client_response.observe_option = -1;
  client_response.user_data = cb->user_data;
  client_response.code = OC_STATUS_SERVICE_UNAVAILABLE;

  oc_response_handler_t handler = (oc_response_handler_t)cb->handler.response;
  handler(&client_response);

#ifdef OC_TCP
  if ((oc_string_len(cb->uri) == 5 &&
       memcmp((const char *)oc_string(cb->uri), "/ping", 5) == 0)) {
    oc_ri_remove_timed_event_callback(cb, oc_remove_ping_handler);
  }
#endif /* OC_TCP */

  free_client_cb(cb);
}

void
oc_ri_free_client_cbs_by_mid(uint16_t mid)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)oc_list_head(client_cbs), *next;
  while (cb != NULL) {
    next = cb->next;
    if (!cb->multicast && !cb->discovery && cb->ref_count == 0 &&
        cb->mid == mid) {
      cb->ref_count = 1;
      notify_client_cb_503(cb);
      cb = (oc_client_cb_t *)oc_list_head(client_cbs);
      continue;
    }
    cb = next;
  }
}

void
oc_ri_free_client_cbs_by_endpoint(oc_endpoint_t *endpoint)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)oc_list_head(client_cbs), *next;
  while (cb != NULL) {
    next = cb->next;
    if (!cb->multicast && !cb->discovery && cb->ref_count == 0 &&
        oc_endpoint_compare(&cb->endpoint, endpoint) == 0) {
      cb->ref_count = 1;
      notify_client_cb_503(cb);
      cb = (oc_client_cb_t *)oc_list_head(client_cbs);
      continue;
    }
    cb = next;
  }
}

oc_client_cb_t *
oc_ri_find_client_cb_by_mid(uint16_t mid)
{
  oc_client_cb_t *cb = oc_list_head(client_cbs);
  while (cb) {
    if (cb->mid == mid)
      break;
    cb = cb->next;
  }
  return cb;
}

oc_client_cb_t *
oc_ri_find_client_cb_by_token(uint8_t *token, uint8_t token_len)
{
  oc_client_cb_t *cb = oc_list_head(client_cbs);
  while (cb != NULL) {
    if (cb->token_len == token_len && memcmp(cb->token, token, token_len) == 0)
      break;
    cb = cb->next;
  }
  return cb;
}

bool
oc_ri_is_client_cb_valid(oc_client_cb_t *client_cb)
{
  oc_client_cb_t *cb = oc_list_head(client_cbs);
  while (cb != NULL) {
    if (cb == client_cb) {
      return true;
    }
    cb = cb->next;
  }
  return false;
}

#ifdef OC_BLOCK_WISE
bool
oc_ri_invoke_client_cb(void *response, oc_blockwise_state_t **response_state,
                       oc_client_cb_t *cb, oc_endpoint_t *endpoint)
#else  /* OC_BLOCK_WISE */
bool
oc_ri_invoke_client_cb(void *response, oc_client_cb_t *cb,
                       oc_endpoint_t *endpoint)
#endif /* OC_BLOCK_WISE */
{
  endpoint->version = OCF_VER_1_0_0;
  oc_content_format_t cf = 0;
  coap_get_header_content_format(response, &cf);
#ifdef OC_SPEC_VER_OIC
  if (cf == APPLICATION_CBOR) {
    endpoint->version = OIC_VER_1_1_0;
  }
#endif /* OC_SPEC_VER_OIC */

  cb->ref_count = 1;

  uint8_t *payload = NULL;
  int payload_len = 0;
  coap_packet_t *const pkt = (coap_packet_t *)response;
  int i;

  oc_client_response_t client_response;
  memset(&client_response, 0, sizeof(oc_client_response_t));
  client_response.client_cb = cb;
  client_response.endpoint = endpoint;
  client_response.observe_option = -1;
  client_response.payload = 0;
  client_response._payload = 0;
  client_response._payload_len = 0;
  client_response.content_format = cf;
  client_response.user_data = cb->user_data;
  for (i = 0; i < __NUM_OC_STATUS_CODES__; i++) {
    if (oc_coap_status_codes[i] == pkt->code) {
      client_response.code = i;
      break;
    }
  }

#ifdef OC_BLOCK_WISE
  if (response_state) {
    oc_blockwise_response_state_t *bwt_response_state =
      (oc_blockwise_response_state_t *)*response_state;
    client_response.observe_option = bwt_response_state->observe_seq;
  }
#else  /* OC_BLOCK_WISE */
  coap_get_header_observe(pkt, (uint32_t *)&client_response.observe_option);
#endif /* !OC_BLOCK_WISE */

  bool separate = false;

#ifdef OC_BLOCK_WISE
  if (response_state) {
    payload = (*response_state)->buffer;
    payload_len = (*response_state)->payload_size;
  }
#else  /* OC_BLOCK_WISE */
  payload_len = coap_get_payload(response, (const uint8_t **)&payload);
#endif /* !OC_BLOCK_WISE */
  client_response._payload = payload;
  client_response._payload_len = (size_t)payload_len;
#ifndef OC_DYNAMIC_ALLOCATION
  char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
  memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
  memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                 rep_objects_alloc, (void *)rep_objects_pool,
                                 0 };
#else  /* !OC_DYNAMIC_ALLOCATION */
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_rep_set_pool(&rep_objects);
  if (payload_len) {
    if (cb->discovery) {
      if (oc_ri_process_discovery_payload(payload, payload_len, cb->handler,
                                          endpoint,
                                          cb->user_data) == OC_STOP_DISCOVERY) {
        uint16_t mid = cb->mid;
        cb->ref_count = 0;
        oc_ri_free_client_cbs_by_mid(mid);
#ifdef OC_BLOCK_WISE
        *response_state = NULL;
#endif /* OC_BLOCK_WISE */
        return true;
      }
    } else {
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
    }
  } else {
    if (pkt->type == COAP_TYPE_ACK && pkt->code == 0) {
      separate = true;
      cb->separate = 1;
    } else if (!cb->discovery) {
      oc_response_handler_t handler =
        (oc_response_handler_t)cb->handler.response;
      handler(&client_response);
    }
  }

#ifdef OC_TCP
  if (pkt->code == PONG_7_03 ||
      (oc_string_len(cb->uri) == 5 &&
       memcmp((const char *)oc_string(cb->uri), "/ping", 5) == 0)) {
    oc_ri_remove_timed_event_callback(cb, oc_remove_ping_handler);
  }
#endif /* OC_TCP */

  if (!oc_ri_is_client_cb_valid(cb)) {
    return true;
  }

  cb->ref_count = 0;

  if (client_response.observe_option == -1 && !separate && !cb->discovery) {
    if (cb->multicast) {
      if (cb->stop_multicast_receive) {
        uint16_t mid = cb->mid;
        oc_ri_free_client_cbs_by_mid(mid);
      }
    } else {
      oc_ri_remove_timed_event_callback(cb, &oc_ri_remove_client_cb);
      free_client_cb(cb);
    }
#ifdef OC_BLOCK_WISE
    *response_state = NULL;
#endif /* OC_BLOCK_WISE */
  } else {
    cb->observe_seq = client_response.observe_option;

    // Drop old observe callback and keep the last one.
    if (cb->observe_seq == 0) {
      oc_client_cb_t *dup_cb = (oc_client_cb_t *)oc_list_head(client_cbs);
      size_t uri_len = oc_string_len(cb->uri);

      while (dup_cb != NULL) {
        if (dup_cb != cb && dup_cb->observe_seq != -1 &&
            dup_cb->token_len == cb->token_len &&
            memcmp(dup_cb->token, cb->token, cb->token_len) == 0 &&
            oc_string_len(dup_cb->uri) == uri_len &&
            strncmp(oc_string(dup_cb->uri), oc_string(cb->uri), uri_len) == 0 &&
            oc_endpoint_compare(&dup_cb->endpoint, endpoint) == 0) {
          OC_DBG("Freeing cb %s, token 0x%02X%02X", oc_string(dup_cb->uri),
                 dup_cb->token[0], dup_cb->token[1]);
          oc_ri_remove_timed_event_callback(dup_cb, &oc_ri_remove_client_cb);
          free_client_cb(dup_cb);
          break;
        }
        dup_cb = dup_cb->next;
      }
    }
  }
  return true;
}

oc_client_cb_t *
oc_ri_get_client_cb(const char *uri, oc_endpoint_t *endpoint,
                    oc_method_t method)
{
  oc_client_cb_t *cb = (oc_client_cb_t *)oc_list_head(client_cbs);

  while (cb != NULL) {
    if (oc_string_len(cb->uri) == strlen(uri) &&
        strncmp(oc_string(cb->uri), uri, strlen(uri)) == 0 &&
        oc_endpoint_compare(&cb->endpoint, endpoint) == 0 &&
        cb->method == method)
      return cb;

    cb = cb->next;
  }

  return cb;
}

static void
free_all_client_cbs(void)
{
  oc_client_cb_t *cb = oc_list_pop(client_cbs);
  while (cb != NULL) {
    free_client_cb(cb);
    cb = oc_list_pop(client_cbs);
  }
}

oc_client_cb_t *
oc_ri_alloc_client_cb(const char *uri, oc_endpoint_t *endpoint,
                      oc_method_t method, const char *query,
                      oc_client_handler_t handler, oc_qos_t qos,
                      void *user_data)
{
  oc_client_cb_t *cb = oc_memb_alloc(&client_cbs_s);
  if (!cb) {
    OC_WRN("insufficient memory to add client callback");
    return cb;
  }

  cb->mid = coap_get_mid();
  oc_new_string(&cb->uri, uri, strlen(uri));
  cb->method = method;
  cb->qos = qos;
  cb->handler = handler;
  cb->user_data = user_data;
  cb->token_len = 8;
  int i = 0;
  uint32_t r;
  while (i < cb->token_len) {
    r = oc_random_value();
    memcpy(cb->token + i, &r, sizeof(r));
    i += sizeof(r);
  }
  cb->discovery = false;
  cb->timestamp = oc_clock_time();
  cb->observe_seq = -1;
  oc_endpoint_copy(&cb->endpoint, endpoint);
  if (query && strlen(query) > 0) {
    oc_new_string(&cb->query, query, strlen(query));
  }
  oc_list_add(client_cbs, cb);
  return cb;
}
#endif /* OC_CLIENT */

void
oc_ri_shutdown(void)
{
#ifdef OC_SERVER
  coap_free_all_observers();
#endif /* OC_SERVER */
  coap_free_all_transactions();
  free_all_event_timers();
#ifdef OC_CLIENT
  free_all_client_cbs();
#endif /* OC_CLIENT */
#ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers(true);
#endif /* OC_BLOCK_WISE */

  while (oc_main_poll() != 0)
    ;

  stop_processes();

  oc_process_shutdown();

#ifdef OC_SERVER
#ifdef OC_COLLECTIONS
  oc_collection_t *collection = oc_collection_get_all(), *next;
  while (collection != NULL) {
    next = collection->next;
    oc_collection_free(collection);
    collection = next;
  }
#endif /* OC_COLLECTIONS */

  oc_ri_delete_all_app_resources();
#endif /* OC_SERVER */

  oc_random_destroy();
}

OC_PROCESS_THREAD(timed_callback_events, ev, data)
{
  (void)data;
  OC_PROCESS_BEGIN();
  while (1) {
    OC_PROCESS_YIELD();
    if (ev == OC_PROCESS_EVENT_TIMER) {
      check_event_callbacks();
    }
  }
  OC_PROCESS_END();
}
