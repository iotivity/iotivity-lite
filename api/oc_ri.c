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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "api/oc_event_callback_internal.h"
#include "api/oc_events_internal.h"
#include "api/oc_message_buffer_internal.h"
#include "api/oc_network_events_internal.h"
#include "api/oc_rep_encode_internal.h"
#include "api/oc_rep_decode_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/options_internal.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/engine_internal.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_events_internal.h"
#include "oc_network_events_internal.h"
#include "oc_uuid.h"
#include "port/oc_assert.h"
#include "port/oc_random.h"
#include "util/oc_etimer_internal.h"
#include "util/oc_features.h"
#include "util/oc_list.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"
#include "util/oc_process_internal.h"

#ifdef OC_BLOCK_WISE
#include "api/oc_blockwise_internal.h"
#endif /* OC_BLOCK_WISE */

#ifdef OC_CLIENT
#include "api/client/oc_client_cb_internal.h"
#endif /* OC_CLIENT */

#ifdef OC_SERVER
#include "api/oc_ri_server_internal.h"
#include "api/oc_server_api_internal.h"
#include "messaging/coap/observe_internal.h"
#include "messaging/coap/separate_internal.h"
#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#include "api/oc_link_internal.h"
#include "oc_collection.h"
#ifdef OC_COLLECTIONS_IF_CREATE
#include "oc_resource_factory_internal.h"
#endif /* OC_COLLECTIONS_IF_CREATE */
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */

#ifdef OC_HAS_FEATURE_ETAG
#include "api/oc_discovery_internal.h"
#include "api/oc_etag_internal.h"
#endif /* OC_HAS_FEATURE_ETAG */

#ifdef OC_HAS_FEATURE_PUSH
#include "oc_push_internal.h"
#endif /*OC_HAS_FEATURE_PUSH  */

#ifdef OC_SECURITY
#include "security/oc_acl_internal.h"
#include "security/oc_audit_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_roles_internal.h"
#include "security/oc_tls_internal.h"
#ifdef OC_OSCORE
#include "security/oc_oscore_internal.h"
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */

#ifdef OC_TCP
#include "api/oc_session_events_internal.h"
#include "messaging/coap/signal_internal.h"
#endif /* OC_TCP */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#else /* !WIN32 */
#include <strings.h>
#endif /* WIN32 */

#ifdef OC_HAS_FEATURE_PUSH
OC_PROCESS_NAME(oc_push_process);
#endif /* OC_HAS_FEATURE_PUSH */

#ifdef OC_SERVER

typedef struct oc_resource_defaults_data_t
{
  oc_resource_t *resource;
  oc_interface_mask_t iface_mask;
} oc_resource_defaults_data_t;

OC_LIST(g_app_resources);
OC_LIST(g_app_resources_to_be_deleted);
OC_MEMB(g_app_resources_s, oc_resource_t, OC_MAX_APP_RESOURCES);
OC_MEMB(g_resource_default_s, oc_resource_defaults_data_t,
        OC_MAX_APP_RESOURCES);
#endif /* OC_SERVER */

static coap_status_t oc_coap_status_codes[__NUM_OC_STATUS_CODES__] = { 0 };

static const char *oc_status_strs[] = {
  "OC_STATUS_OK",                       /* 0 */
  "OC_STATUS_CREATED",                  /* 1 */
  "OC_STATUS_CHANGED",                  /* 2 */
  "OC_STATUS_DELETED",                  /* 3 */
  "OC_STATUS_NOT_MODIFIED",             /* 4 */
  "OC_STATUS_BAD_REQUEST",              /* 5 */
  "OC_STATUS_UNAUTHORIZED",             /* 6 */
  "OC_STATUS_BAD_OPTION",               /* 7 */
  "OC_STATUS_FORBIDDEN",                /* 8 */
  "OC_STATUS_NOT_FOUND",                /* 9 */
  "OC_STATUS_METHOD_NOT_ALLOWED",       /* 10 */
  "OC_STATUS_NOT_ACCEPTABLE",           /* 11 */
  "OC_STATUS_REQUEST_ENTITY_TOO_LARGE", /* 12 */
  "OC_STATUS_UNSUPPORTED_MEDIA_TYPE",   /* 13 */
  "OC_STATUS_INTERNAL_SERVER_ERROR",    /* 14 */
  "OC_STATUS_NOT_IMPLEMENTED",          /* 15 */
  "OC_STATUS_BAD_GATEWAY",              /* 16 */
  "OC_STATUS_SERVICE_UNAVAILABLE",      /* 17 */
  "OC_STATUS_GATEWAY_TIMEOUT",          /* 18 */
  "OC_STATUS_PROXYING_NOT_SUPPORTED"    /* 19 */
};

static void
ri_set_status_codes(void)
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
  return oc_list_head(g_app_resources);
}

static bool
ri_app_resource_is_in_list(oc_list_t list, const oc_resource_t *resource)
{
  const oc_resource_t *res = oc_list_head(list);
  for (; res != NULL; res = res->next) {
    if (res == resource) {
      return true;
    }
  }
  return false;
}

bool
oc_ri_is_app_resource_valid(const oc_resource_t *resource)
{
  return ri_app_resource_is_in_list(g_app_resources, resource);
}

bool
oc_ri_is_app_resource_to_be_deleted(const oc_resource_t *resource)
{
  return ri_app_resource_is_in_list(g_app_resources_to_be_deleted, resource);
}

static bool
ri_uri_is_in_list(oc_list_t list, const char *uri, size_t uri_len,
                  size_t device)
{
  while (uri[0] == '/') {
    uri++;
    uri_len--;
  }

  const oc_resource_t *res = oc_list_head(list);
  for (; res != NULL; res = res->next) {
    if (res->device == device && oc_string_len(res->uri) == (uri_len + 1) &&
        strncmp(oc_string(res->uri) + 1, uri, uri_len) == 0) {
      return true;
    }
  }
  return false;
}

bool
oc_ri_URI_is_in_use(size_t device, const char *uri, size_t uri_len)
{
  // check core resources
  if (oc_core_get_resource_by_uri_v1(uri, uri_len, device) != NULL) {
    return true;
  }
  // dynamic resources / dynamic resources scheduled to be deleted
  if (ri_uri_is_in_list(g_app_resources, uri, uri_len, device) ||
      ri_uri_is_in_list(g_app_resources_to_be_deleted, uri, uri_len, device)) {
    return true;
  }

#ifdef OC_COLLECTIONS
  // collections
  if (oc_get_collection_by_uri(uri, uri_len, device) != NULL) {
    return true;
  }
#endif /* OC_COLLECTIONS */
  return false;
}

static void
ri_app_resource_to_be_deleted(oc_resource_t *resource)
{
  oc_list_remove2(g_app_resources, resource);
  if (!oc_ri_is_app_resource_to_be_deleted(resource)) {
    oc_list_add(g_app_resources_to_be_deleted, resource);
  }
}

static oc_event_callback_retval_t
oc_delayed_delete_resource_cb(void *data)
{
  oc_resource_t *resource = (oc_resource_t *)data;
  OC_DBG("delayed delete resource(%p)", (void *)resource);
  oc_ri_on_delete_resource_invoke(resource);
  oc_delete_resource(resource);
  return OC_EVENT_DONE;
}

void
oc_delayed_delete_resource(oc_resource_t *resource)
{
  if (resource == NULL) {
    return;
  }
  OC_DBG("(re)scheduling delayed delete resource(%p)", (void *)resource);
  ri_app_resource_to_be_deleted(resource);
  oc_reset_delayed_callback(resource, oc_delayed_delete_resource_cb, 0);
}

#endif /* OC_SERVER */

coap_status_t
oc_status_code_unsafe(oc_status_t key)
{
  return oc_coap_status_codes[key];
}

bool
oc_status_is_internal_code(oc_status_t code)
{
  return code >= __NUM_OC_STATUS_CODES__;
}

int
oc_status_code(oc_status_t key)
{
  if (!oc_status_is_internal_code(key)) {
    return oc_status_code_unsafe(key);
  }

  if (OC_IGNORE == key) {
    return CLEAR_TRANSACTION;
  }
  OC_WRN("oc_status_code: invalid status code %d", (int)key);
  return -1;
}

int
oc_coap_status_to_status(coap_status_t status)
{
  for (int i = 0; i < __NUM_OC_STATUS_CODES__; ++i) {
    if (oc_coap_status_codes[i] == status) {
      return i;
    }
  }
#ifdef OC_TCP
  if ((uint8_t)status == PONG_7_03) {
    return OC_STATUS_OK;
  }
#endif /* OC_TCP */
  OC_WRN("oc_coap_status_to_status: invalid coap status code %d", (int)status);
  return -1;
}

const char *
oc_status_to_str(oc_status_t key)
{
  if (key < 0 || key >= OC_ARRAY_SIZE(oc_status_strs)) {
    return "";
  }
  return oc_status_strs[key];
}

/*
 * Filter requests by device id in the query string
 * @param device the device index
 * @param query the query string
 * @param query_len the length of the query string
 * @return true if the query string contains a di=<deviceID> or doesn't contains
 * di key, otherwise it returns false
 */
static bool
oc_ri_filter_request_by_device_id(size_t device, const char *query,
                                  size_t query_len)
{
  const oc_uuid_t *device_id = oc_core_get_device_id(device);
  assert(device_id != NULL);
  if (query == NULL || query_len == 0) {
    return true;
  }
  char di[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(device_id, di, OC_UUID_LEN);
  for (size_t pos = 0; pos < query_len;) {
    const char *value = NULL;
    int value_len = oc_ri_get_query_value_v1(query + pos, query_len - pos, "di",
                                             OC_CHAR_ARRAY_LEN("di"), &value);
    if (value_len == -1) {
      // pos == 0 key not found, otherwise device id not match the device.
      return pos == 0;
    }
    if (OC_UUID_LEN == value_len + 1 && strncmp(di, value, value_len) == 0) {
      return true;
    }
    pos = (value - query) + value_len;
  }
  return false;
}

static void
start_processes(void)
{
  oc_event_assign_oc_process_events();
  oc_process_start(&oc_etimer_process, NULL);
  oc_event_callbacks_process_start();
  oc_process_start(&g_coap_engine, NULL);
  oc_message_buffer_handler_start();

#ifdef OC_SECURITY
  oc_process_start(&oc_tls_handler, NULL);
#ifdef OC_OSCORE
  oc_process_start(&oc_oscore_handler, NULL);
#endif /* OC_OSCORE */
#endif /* OC_SECURITY */

  oc_process_start(&oc_network_events, NULL);
#ifdef OC_TCP
  oc_process_start(&oc_session_events, NULL);
#endif /* OC_TCP */

#ifdef OC_HAS_FEATURE_PUSH
  oc_process_start(&oc_push_process, NULL);
#endif
}

static void
stop_processes(void)
{
#ifdef OC_HAS_FEATURE_PUSH
  oc_process_exit(&oc_push_process);
#endif
#ifdef OC_TCP
  oc_process_exit(&oc_session_events);
#endif /* OC_TCP */
  oc_process_exit(&oc_network_events);
  oc_process_exit(&oc_etimer_process);
  oc_event_callbacks_process_exit();
  oc_process_exit(&g_coap_engine);

#ifdef OC_SECURITY
#ifdef OC_OSCORE
  oc_process_exit(&oc_oscore_handler);
#endif /* OC_OSCORE */
  oc_process_exit(&oc_tls_handler);
#endif /* OC_SECURITY */

  oc_message_buffer_handler_stop();
}

#ifdef OC_SERVER
oc_resource_t *
oc_ri_get_app_resource_by_uri(const char *uri, size_t uri_len, size_t device)
{
  if (!uri || uri_len == 0) {
    return NULL;
  }

  int skip = 0;
  if (uri[0] != '/') {
    skip = 1;
  }
  oc_resource_t *res = oc_ri_get_app_resources();
  while (res != NULL) {
    if (oc_string_len(res->uri) == (uri_len + skip) &&
        strncmp(uri, oc_string(res->uri) + skip, uri_len) == 0 &&
        res->device == device) {
      return res;
    }
    res = res->next;
  }

#ifdef OC_COLLECTIONS
  oc_collection_t *col = oc_get_collection_by_uri(uri, uri_len, device);
  if (col != NULL) {
    return &col->res;
  }
#endif /* OC_COLLECTIONS */
  return NULL;
}
#endif /* OC_SERVER */

void
oc_ri_init(void)
{
  ri_set_status_codes();

#ifdef OC_SERVER
  oc_list_init(g_app_resources);
  oc_list_init(g_app_resources_to_be_deleted);
#endif /* OC_SERVER */

#ifdef OC_CLIENT
  oc_client_cbs_init();
#endif /* OC_CLIENT */

  oc_event_callbacks_init();

#ifdef OC_HAS_FEATURE_PUSH
  oc_push_init();
#endif /* OC_HAS_FEATURE_PUSH */

  oc_process_init();
  start_processes();
}

static const char *method_strs[] = {
  "",       /* 0 */
  "GET",    /* OC_GET */
  "POST",   /* OC_POST */
  "PUT",    /* OC_PUT */
  "DELETE", /* OC_DELETE */
  "FETCH",  /*OC_FETCH */
};

const char *
oc_method_to_str(oc_method_t method)
{
  if (method <= 0 || method >= OC_ARRAY_SIZE(method_strs)) {
    return method_strs[0];
  }
  return method_strs[method];
}

#ifdef OC_SERVER

oc_resource_t *
oc_ri_alloc_resource(void)
{
  return oc_memb_alloc(&g_app_resources_s);
}

void
oc_ri_dealloc_resource(oc_resource_t *resource)
{
  oc_memb_free(&g_app_resources_s, resource);
}

static oc_resource_defaults_data_t *
oc_ri_alloc_resource_defaults(void)
{
  return oc_memb_alloc(&g_resource_default_s);
}

static void
oc_ri_dealloc_resource_defaults(oc_resource_defaults_data_t *data)
{
  oc_memb_free(&g_resource_default_s, data);
}

static void
ri_delete_resource(oc_resource_t *resource, bool notify)
{
  OC_DBG("delete resource(%p)", (void *)resource);

#ifdef OC_COLLECTIONS
#ifdef OC_COLLECTIONS_IF_CREATE
  oc_rt_created_t *rtc = oc_rt_get_factory_create_for_resource(resource);
  if (rtc != NULL) {
    /* For dynamically created resources invoke the created instance destructor
     * and return. The destructor invokes at the end oc_delete_resource again,
     * but the resource will no longer be in the list of created resources so
     * this if-branch will be skipped and normal resource deallocation will be
     * executed. */
    oc_rt_factory_free_created_resource(rtc, rtc->rf);
    return;
  }
#endif /* OC_COLLECTIONS_IF_CREATE */

#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
  bool needsBatchDispatch = false;
#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */
  // remove the resource from the collections
  oc_collection_t *collection =
    oc_get_next_collection_with_link(resource, NULL);
  while (collection != NULL) {
    oc_link_t *link = oc_get_link_by_uri(collection, oc_string(resource->uri),
                                         oc_string_len(resource->uri));
    if (link != NULL) {
      if (oc_collection_remove_link_and_notify(&collection->res, link, notify,
                                               /*batchDispatch*/ false)) {
#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
        needsBatchDispatch = true;
#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */
      }
      oc_delete_link(link);
    }
    collection = oc_get_next_collection_with_link(resource, collection);
  }
#endif /* OC_COLLECTIONS */

  bool removed = oc_list_remove2(g_app_resources, resource) != NULL;
  removed =
    oc_list_remove2(g_app_resources_to_be_deleted, resource) != NULL || removed;

  oc_remove_delayed_callback(resource, oc_delayed_delete_resource_cb);
  oc_notify_clear(resource);

  if (resource->num_observers > 0) {
    int removed_num = coap_remove_observers_by_resource(resource);
    OC_DBG("removing resource observers: removed(%d) vs expected(%d)",
           removed_num, resource->num_observers);
#if !OC_DBG_IS_ENABLED
    (void)removed_num;
#endif /* !OC_DBG_IS_ENABLED */
  }

  if (notify) {
    if (removed) {
      oc_notify_resource_removed(resource);
    } else {
#if defined(OC_COLLECTIONS) && defined(OC_RES_BATCH_SUPPORT) &&                \
  defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
      // if oc_notify_resource_removed is not called, then we need to dispatch
      // manually if it is requested
      if (needsBatchDispatch) {
        coap_dispatch_process_batch_observers();
      }
#endif /* OC_COLLECTIONS && OC_RES_BATCH_SUPPORT &&                            \
          OC_DISCOVERY_RESOURCE_OBSERVABLE */
    }
  }

  oc_ri_free_resource_properties(resource);
  oc_ri_dealloc_resource(resource);
}

bool
oc_ri_delete_resource(oc_resource_t *resource)
{
  if (resource == NULL) {
    return false;
  }
  ri_delete_resource(resource, true);
  return true;
}

bool
oc_ri_add_resource(oc_resource_t *resource)
{
  if (resource == NULL) {
    return false;
  }

  if (!resource->get_handler.cb && !resource->put_handler.cb &&
      !resource->post_handler.cb && !resource->delete_handler.cb) {
    OC_ERR("resource(%s) has no handlers", oc_string(resource->uri));
    return false;
  }

  if ((resource->properties & OC_PERIODIC) != 0 &&
      resource->observe_period_seconds == 0) {
    OC_ERR("resource(%s) has invalid observe period", oc_string(resource->uri));
    return false;
  }

  if (oc_ri_is_app_resource_valid(resource)) {
    OC_ERR("resource(%s) already exists in IoTivity stack",
           oc_string(resource->uri));
    return false;
  }
  if (oc_ri_is_app_resource_to_be_deleted(resource)) {
    OC_ERR("resource(%s) is scheduled to be deleted", oc_string(resource->uri));
    return false;
  }
  if (oc_ri_URI_is_in_use(resource->device, oc_string(resource->uri),
                          oc_string_len(resource->uri))) {
    OC_ERR("resource(%s) URI is already in use", oc_string(resource->uri));
    return false;
  }

  oc_list_add(g_app_resources, resource);
  oc_notify_resource_added(resource);
  return true;
}

static void
ri_delete_all_app_resources(void)
{
  oc_resource_t *res = oc_ri_get_app_resources();
  while (res) {
    ri_delete_resource(res, false);
    res = oc_ri_get_app_resources();
  }

  res = oc_list_head(g_app_resources_to_be_deleted);
  while (res) {
    ri_delete_resource(res, false);
    res = oc_list_head(g_app_resources_to_be_deleted);
  }
}

#endif /* OC_SERVER */

void
oc_ri_free_resource_properties(oc_resource_t *resource)
{
  oc_free_string(&(resource->name));
  oc_free_string(&(resource->uri));
  if (oc_string_array_get_allocated_size(resource->types) > 0) {
    oc_free_string_array(&(resource->types));
  }
}

oc_interface_mask_t
oc_ri_get_interface_mask(const char *iface, size_t iface_len)
{
  struct
  {
    oc_interface_mask_t mask;
    oc_string_view_t str;
  } iface_to_strs[] = {
    { OC_IF_BASELINE, OC_STRING_VIEW(OC_IF_BASELINE_STR) },
    { OC_IF_LL, OC_STRING_VIEW(OC_IF_LL_STR) },
    { OC_IF_B, OC_STRING_VIEW(OC_IF_B_STR) },
    { OC_IF_R, OC_STRING_VIEW(OC_IF_R_STR) },
    { OC_IF_RW, OC_STRING_VIEW(OC_IF_RW_STR) },
    { OC_IF_A, OC_STRING_VIEW(OC_IF_A_STR) },
    { OC_IF_S, OC_STRING_VIEW(OC_IF_S_STR) },
    { OC_IF_CREATE, OC_STRING_VIEW(OC_IF_CREATE_STR) },
    { OC_IF_W, OC_STRING_VIEW(OC_IF_W_STR) },
    { OC_IF_STARTUP, OC_STRING_VIEW(OC_IF_STARTUP_STR) },
    { OC_IF_STARTUP_REVERT, OC_STRING_VIEW(OC_IF_STARTUP_REVERT_STR) },
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
    { PLGD_IF_ETAG, OC_STRING_VIEW(PLGD_IF_ETAG_STR) },
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
  };

  for (size_t i = 0; i < OC_ARRAY_SIZE(iface_to_strs); ++i) {
    if (iface_len == iface_to_strs[i].str.length &&
        strncmp(iface, iface_to_strs[i].str.data, iface_len) == 0) {
      return iface_to_strs[i].mask;
    }
  }
  return 0;
}

bool
oc_ri_interface_supports_method(oc_interface_mask_t iface, oc_method_t method)
{
  /* Supported operations are defined in section 7.5.3 of the OCF Core spec */
  switch (iface) {
  /* The following interfaces are RETRIEVE-only: */
  case OC_IF_LL:
  case OC_IF_S:
  case OC_IF_R:
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
  case PLGD_IF_ETAG:
#endif
    return method == OC_GET;
  /* The following interafaces are UPDATE(WRITE)-only: */
  case OC_IF_W:
    return method == OC_PUT || method == OC_POST || method == OC_DELETE;
  /* The CREATE interface supports GET/PUT/POST: */
  case OC_IF_CREATE:
    return method == OC_GET || method == OC_PUT || method == OC_POST;
  /* The following interfaces support RETRIEVE and UPDATE: */
  case OC_IF_RW:
  case OC_IF_B:
  case OC_IF_BASELINE:
  case OC_IF_A:
  case OC_IF_STARTUP:
  case OC_IF_STARTUP_REVERT:
    return true;
  }
  return false;
}

#ifdef OC_SECURITY
static void
oc_ri_audit_log(oc_method_t method, const oc_resource_t *resource,
                const oc_endpoint_t *endpoint)
{
#define LINE_WIDTH 80
  char aux_arr[6][LINE_WIDTH];
  memset(aux_arr, 0, sizeof(aux_arr));
  char *aux[] = { aux_arr[0], aux_arr[1], aux_arr[2],
                  aux_arr[3], aux_arr[4], aux_arr[5] };
  size_t idx = 1;
  OC_SNPRINTFipaddr(aux[0], LINE_WIDTH, *endpoint);
  const oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
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
  if (peer != NULL) {
    size_t pos = 0;
    for (oc_sec_cred_t *rc = oc_sec_roles_get(peer); rc && pos < LINE_WIDTH;
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

static oc_status_t
ri_invoke_request_handler(oc_resource_t *resource, oc_method_t method,
                          oc_request_t *request, oc_interface_mask_t iface_mask,
                          bool is_collection)
{
  /* If resource is a collection resource, invoke the framework's internal
   * handler for collections.
   */
#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
  if (is_collection) {
    if (!oc_handle_collection_request(method, request, iface_mask, NULL)) {
      OC_WRN("ocri: failed to handle collection request");
      return OC_STATUS_BAD_REQUEST;
    }
    return OC_STATUS_OK;
  }
#else  /* !OC_COLLECTIONS || !OC_SERVER */
  (void)is_collection;
#endif /* OC_COLLECTIONS && OC_SERVER */
  /* If cur_resource is a non-collection resource, invoke
   * its handler for the requested method. If it has not
   * implemented that method, then return a 4.05 response.
   */
  if (method == OC_GET && resource->get_handler.cb) {
    resource->get_handler.cb(request, iface_mask,
                             resource->get_handler.user_data);
    return OC_STATUS_OK;
  }
  if (method == OC_POST && resource->post_handler.cb) {
    resource->post_handler.cb(request, iface_mask,
                              resource->post_handler.user_data);
    return OC_STATUS_OK;
  }
  if (method == OC_PUT && resource->put_handler.cb) {
    resource->put_handler.cb(request, iface_mask,
                             resource->put_handler.user_data);
    return OC_STATUS_OK;
  }
  if (method == OC_DELETE && resource->delete_handler.cb) {
    resource->delete_handler.cb(request, iface_mask,
                                resource->delete_handler.user_data);
    return OC_STATUS_OK;
  }
  return OC_STATUS_METHOD_NOT_ALLOWED;
}

static ocf_version_t
ri_get_ocf_version_from_header(const coap_packet_t *request)
{
#ifdef OC_SPEC_VER_OIC
  oc_content_format_t accept = APPLICATION_NOT_DEFINED;
  if (coap_options_get_accept(request, &accept)) {
    if (accept == APPLICATION_CBOR) {
      return OIC_VER_1_1_0;
    }
  }
#else  /* !OC_SPEC_VER_OIC */
  (void)request;
#endif /* OC_SPEC_VER_OIC */
  return OCF_VER_1_0_0;
}

#ifdef OC_SERVER

#ifdef OC_COLLECTIONS
static bool
ri_add_collection_observation(oc_collection_t *collection,
                              const oc_endpoint_t *endpoint, bool is_batch)
{
  oc_link_t *links = (oc_link_t *)oc_list_head(collection->links);
#ifdef OC_SECURITY
  for (; links != NULL; links = links->next) {
    if (links->resource == NULL ||
        (links->resource->properties & OC_OBSERVABLE) == 0 ||
        oc_sec_check_acl(OC_GET, links->resource, endpoint)) {
      continue;
    }
    return false;
  }
#else  /* !OC_SECURITY */
  (void)endpoint;
#endif /* OC_SECURITY */
  if (is_batch) {
    links = (oc_link_t *)oc_list_head(collection->links);
    for (; links != NULL; links = links->next) {
      if (links->resource == NULL ||
          (links->resource->properties & OC_PERIODIC) == 0) {
        continue;
      }
      if (!oc_periodic_observe_callback_add(links->resource)) {
        // TODO: shouldn't we remove the periodic observe of links added by this
        // call?
        return false;
      }
    }
  }
  return true;
}

#endif /* OC_COLLECTIONS */

static int
ri_observe_handler(const coap_packet_t *request, const coap_packet_t *response,
                   oc_resource_t *resource, uint16_t block2_size,
                   const oc_endpoint_t *endpoint,
                   oc_interface_mask_t iface_mask)
{
  if (request->code != COAP_GET || response->code >= 128 ||
      !IS_OPTION(request, COAP_OPTION_OBSERVE)) {
    return -1;
  }
  if (request->observe == OC_COAP_OPTION_OBSERVE_REGISTER) {
    if (NULL == coap_add_observer(resource, block2_size, endpoint,
                                  request->token, request->token_len,
                                  request->uri_path, request->uri_path_len,
                                  iface_mask)) {
      OC_ERR("failed to add observer");
      return -1;
    }
    return 0;
  }
  if (request->observe == OC_COAP_OPTION_OBSERVE_UNREGISTER) {
    if (!coap_remove_observer_by_token(endpoint, request->token,
                                       request->token_len)) {
      return 0;
    }
    return 1;
  }
  return -1;
}

static bool
ri_add_observation(const coap_packet_t *request, const coap_packet_t *response,
                   oc_resource_t *resource, bool resource_is_collection,
                   uint16_t block2_size, const oc_endpoint_t *endpoint,
                   oc_interface_mask_t iface_query)
{
  if (ri_observe_handler(request, response, resource, block2_size, endpoint,
                         iface_query) >= 0) {
    /* If the resource is marked as periodic observable it means it must be
     * polled internally for updates (which would lead to notifications being
     * sent). If so, add the resource to a list of periodic GET callbacks to
     * utilize the framework's internal polling mechanism.
     */
    if ((resource->properties & OC_PERIODIC) != 0 &&
        !oc_periodic_observe_callback_add(resource)) {
      return false;
    }
  }
#ifdef OC_COLLECTIONS
  if (resource_is_collection) {
    oc_collection_t *collection = (oc_collection_t *)resource;
    if (!ri_add_collection_observation(collection, endpoint,
                                       iface_query == OC_IF_B)) {
      // TODO: shouldn't we remove the periodic observe callback here?
      return false;
    }
  }
#else  /* !OC_COLLECTIONS */
  (void)resource_is_collection;
#endif /* OC_COLLECTIONS */
  return true;
}

static void
ri_remove_observation(const coap_packet_t *request,
                      const coap_packet_t *response, oc_resource_t *resource,
                      bool resource_is_collection, uint16_t block2_size,
                      const oc_endpoint_t *endpoint,
                      oc_interface_mask_t iface_query)
{
  if (ri_observe_handler(request, response, resource, block2_size, endpoint,
                         iface_query) <= 0) {
    return;
  }
  if ((resource->properties & OC_PERIODIC) != 0) {
    oc_periodic_observe_callback_remove(resource);
  }
#if defined(OC_COLLECTIONS)
  if (resource_is_collection) {
    oc_collection_t *collection = (oc_collection_t *)resource;
    oc_link_t *links = (oc_link_t *)oc_list_head(collection->links);
    for (; links != NULL; links = links->next) {
      if (links->resource != NULL &&
          (links->resource->properties & OC_PERIODIC) != 0) {
        oc_periodic_observe_callback_remove(links->resource);
      }
    }
  }
#else  /* !OC_COLLECTIONS */
  (void)resource_is_collection;
#endif /* OC_COLLECTIONS */
}

static int
ri_handle_observation(const coap_packet_t *request, coap_packet_t *response,
                      oc_resource_t *resource, bool resource_is_collection,
                      uint16_t block2_size, const oc_endpoint_t *endpoint,
                      oc_interface_mask_t iface_query)
{

  /* If a GET request was successfully processed, then check if the resource is
   * OBSERVABLE and check its observe option.
   */
  int32_t observe = OC_COAP_OPTION_OBSERVE_NOT_SET;
  if ((resource->properties & OC_OBSERVABLE) == 0 ||
      !coap_options_get_observe(request, &observe)) {
    return OC_COAP_OPTION_OBSERVE_NOT_SET;
  }

  /* If the observe option is set to 0, make an attempt to add the requesting
   * client as an observer.
   */
  if (observe == OC_COAP_OPTION_OBSERVE_REGISTER) {
    if (!ri_add_observation(request, response, resource, resource_is_collection,
                            block2_size, endpoint, iface_query)) {
      coap_remove_observer_by_token(endpoint, request->token,
                                    request->token_len);
      return OC_COAP_OPTION_OBSERVE_NOT_SET;
    }
    coap_options_set_observe(response, OC_COAP_OPTION_OBSERVE_REGISTER);
    return OC_COAP_OPTION_OBSERVE_REGISTER;
  }

  /* If the observe option is set to 1, make an attempt to remove  the
   * requesting client from the list of observers. In addition, remove the
   * resource from the list periodic GET callbacks if it is periodic observable.
   */
  if (observe == OC_COAP_OPTION_OBSERVE_UNREGISTER) {
    ri_remove_observation(request, response, resource, resource_is_collection,
                          block2_size, endpoint, iface_query);
    return OC_COAP_OPTION_OBSERVE_UNREGISTER;
  }

  // if the observe option is >= 2 then we a have a notification
  return observe;
}

static oc_event_callback_retval_t
ri_observe_notification_resource_defaults_delayed(void *data)
{
  oc_resource_defaults_data_t *resource_defaults_data =
    (oc_resource_defaults_data_t *)data;
  notify_resource_defaults_observer(resource_defaults_data->resource,
                                    resource_defaults_data->iface_mask);
  oc_ri_dealloc_resource_defaults(resource_defaults_data);
  return OC_EVENT_DONE;
}

#ifdef OC_HAS_FEATURE_ETAG

uint64_t
oc_ri_get_etag(const oc_resource_t *resource)
{
  return resource->etag;
}

uint64_t
oc_ri_get_batch_etag(const oc_resource_t *resource,
                     const oc_endpoint_t *endpoint, size_t device)
{
#ifdef OC_RES_BATCH_SUPPORT
  if (oc_core_get_resource_by_index(OCF_RES, device) == resource) {
    return oc_discovery_get_batch_etag(endpoint, device);
  }
#endif /* OC_RES_BATCH_SUPPORT */
#ifdef OC_COLLECTIONS
  if (oc_check_if_collection(resource)) {
    return oc_collection_get_batch_etag((const oc_collection_t *)resource);
  }
#endif /* OC_COLLECTIONS */
  (void)resource;
  (void)endpoint;
  (void)device;
  OC_DBG("custom batch etag");
  return OC_ETAG_UNINITIALIZED;
}

#endif /* OC_HAS_FEATURE_ETAG */
#endif /* OC_SERVER */

typedef struct
{
  oc_response_t *response_obj;
#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t **response_state;
#endif /* OC_BLOCK_WISE */
#ifdef OC_SERVER
  const coap_packet_t *request;
  const oc_endpoint_t *endpoint;
  oc_method_t method;
  oc_interface_mask_t iface_mask;
  int32_t observe;
  uint16_t block2_size;
  oc_resource_t *resource;
#ifdef OC_COLLECTIONS
  bool resource_is_collection;
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */
} ri_invoke_coap_entity_set_response_ctx_t;

#ifdef OC_HAS_FEATURE_ETAG

static void
ri_invoke_coap_entity_set_response_etag(
  coap_packet_t *response, const ri_invoke_coap_entity_set_response_ctx_t *ctx)
{
  if (ctx->response_obj->response_buffer->etag.length == 0) {
    return;
  }

  const uint8_t *etag = ctx->response_obj->response_buffer->etag.value;
  uint8_t etag_len = ctx->response_obj->response_buffer->etag.length;
#ifdef OC_BLOCK_WISE
  if (ctx->response_obj->response_buffer->response_length > 0) {
    assert(*ctx->response_state != NULL);
    oc_blockwise_response_state_t *bw_response_buffer =
      (oc_blockwise_response_state_t *)*ctx->response_state;
    memcpy(&bw_response_buffer->etag.value[0], &etag[0], etag_len);
    bw_response_buffer->etag.length = etag_len;
    return;
  }
#endif /* OC_BLOCK_WISE */
  coap_options_set_etag(response, &etag[0], etag_len);
}

#endif /* OC_HAS_FEATURE_ETAG */

static void
ri_invoke_coap_entity_set_response(coap_packet_t *response,
                                   ri_invoke_coap_entity_set_response_ctx_t ctx)
{
#ifdef OC_SERVER
  oc_response_t *response_obj = ctx.response_obj;

  /* The presence of a separate response handle here indicates a
   * successful handling of the request by a slow resource.
   */
  if (response_obj->separate_response != NULL) {
    /* Attempt to register a client request to the separate response tracker
     * and pass in the observe option (if present) or the value -1 as
     * determined by the code block above. Values 0 and 1 result in their
     * expected behaviors whereas -1 indicates an absence of an observe
     * option and hence a one-off request.
     * Following a successful registration, the separate response tracker
     * is flagged as "active". In this way, the function that later executes
     * out-of-band upon availability of the resource state knows it must
     * send out a response with it.
     */
    if (coap_separate_accept(ctx.request, response_obj->separate_response,
                             ctx.endpoint, ctx.observe, ctx.block2_size)) {
      response_obj->separate_response->active = 1;
    }
    return;
  }
#endif /* OC_SERVER */

  const oc_response_buffer_t *response_buffer =
    ctx.response_obj->response_buffer;
  if (response_buffer->code == CLEAR_TRANSACTION) {
    /* If the server-side logic chooses to reject a request, it sends
     * below a response code of CLEAR_TRANSACTION, which results in the
     * messaging layer freeing the CoAP transaction associated with the request.
     */
    coap_set_global_status_code(CLEAR_TRANSACTION);
    return;
  }

#ifdef OC_SERVER
  if (ctx.resource != NULL) {
#ifdef OC_HAS_FEATURE_ETAG
    if (ctx.method == OC_GET &&
        (response_buffer->code == oc_status_code_unsafe(OC_STATUS_OK) ||
         response_buffer->code ==
           oc_status_code_unsafe(OC_STATUS_NOT_MODIFIED))) {
      ri_invoke_coap_entity_set_response_etag(response, &ctx);
    }
#endif /* OC_HAS_FEATURE_ETAG */

    /* If the recently handled request was a PUT/POST, it conceivably
     * altered the resource state, so attempt to notify all observers
     * of that resource with the change.
     */
    if (
#ifdef OC_COLLECTIONS
      !ctx.resource_is_collection &&
#endif /* OC_COLLECTIONS */
      (ctx.method == OC_PUT || ctx.method == OC_POST) &&
      response_buffer->code < oc_status_code_unsafe(OC_STATUS_BAD_REQUEST)) {
      if ((ctx.iface_mask == OC_IF_STARTUP) ||
          (ctx.iface_mask == OC_IF_STARTUP_REVERT)) {
        oc_resource_defaults_data_t *resource_defaults_data =
          oc_ri_alloc_resource_defaults();
        resource_defaults_data->resource = ctx.resource;
        resource_defaults_data->iface_mask = ctx.iface_mask;
        oc_ri_add_timed_event_callback_ticks(
          resource_defaults_data,
          &ri_observe_notification_resource_defaults_delayed, 0);
      } else {
        oc_notify_resource_changed_delayed_ms(ctx.resource, 0);
      }
    }
  }

#endif /* OC_SERVER */
  if (response_buffer->response_length > 0) {
#ifdef OC_BLOCK_WISE
    assert(*ctx.response_state != NULL);
    oc_blockwise_response_state_t *bw_response_buffer =
      (oc_blockwise_response_state_t *)*ctx.response_state;
    bw_response_buffer->base.payload_size =
      (uint32_t)response_buffer->response_length;
    bw_response_buffer->code = response_buffer->code;
#else  /* OC_BLOCK_WISE */
    coap_set_payload(response, response_buffer->buffer,
                     response_buffer->response_length);
#endif /* !OC_BLOCK_WISE */
    if (response_buffer->content_format > 0) {
      coap_options_set_content_format(response,
                                      response_buffer->content_format);
    }
  }

  if (response_buffer->code ==
      oc_status_code_unsafe(OC_STATUS_REQUEST_ENTITY_TOO_LARGE)) {
    coap_options_set_size1(response, (uint32_t)OC_BLOCK_SIZE);
  }

  /* response_buffer->code at this point contains a valid CoAP status
   *  code.
   */
  coap_set_status_code(response, response_buffer->code);
}

bool
oc_ri_invoke_coap_entity_handler(coap_make_response_ctx_t *ctx,
                                 oc_endpoint_t *endpoint, void *user_data)
{
  (void)user_data;
  endpoint->version = ri_get_ocf_version_from_header(ctx->request);

  /* This function is a server-side entry point solely for requests.
   *  Hence, "code" contains the CoAP method code.
   */
  oc_method_t method = ctx->request->code;

  /* Initialize request/response objects to be sent up to the app layer. */
  /* Postpone allocating response_state right after calling oc_parse_rep()
   * in order to reduce peak memory in OC_BLOCK_WISE & OC_DYNAMIC_ALLOCATION
   */
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.content_format = APPLICATION_NOT_DEFINED;

  oc_response_t response_obj;
  memset(&response_obj, 0, sizeof(response_obj));
  response_obj.response_buffer = &response_buffer;

  oc_request_t request_obj;
  memset(&request_obj, 0, sizeof(request_obj));
  request_obj.response = &response_obj;
  request_obj.origin = endpoint;
  request_obj.method = method;

  /* Obtain request uri from the CoAP request. */
  const char *uri_path = NULL;
  size_t uri_path_len = coap_options_get_uri_path(ctx->request, &uri_path);

  /* Obtain query string from CoAP request. */
  const char *uri_query = NULL;
  size_t uri_query_len = coap_options_get_uri_query(ctx->request, &uri_query);

  /* Read the Content-Format CoAP option in the request */
  oc_content_format_t cf = 0;
  coap_options_get_content_format(ctx->request, &cf);

  /* Read the accept CoAP option in the request */
  oc_content_format_t accept = APPLICATION_NOT_DEFINED;
  coap_options_get_accept(ctx->request, &accept);

  /* Initialize OCF interface selector. */
  oc_interface_mask_t iface_query = 0;
  if (uri_query_len) {
    // Check if the request is a multicast request and if the device id in
    // query matches the device id
    if (request_obj.origin && (request_obj.origin->flags & MULTICAST) &&
        !oc_ri_filter_request_by_device_id(endpoint->device, uri_query,
                                           uri_query_len)) {
      coap_set_global_status_code(CLEAR_TRANSACTION);
      coap_set_status_code(ctx->response, CLEAR_TRANSACTION);
      return false;
    }

    request_obj.query = uri_query;
    request_obj.query_len = uri_query_len;
    /* Check if query string includes interface selection. */
    const char *iface = NULL;
    int iface_len = oc_ri_get_query_value_v1(uri_query, uri_query_len, "if",
                                             OC_CHAR_ARRAY_LEN("if"), &iface);
    if (iface_len != -1 && iface != NULL) {
      iface_query |= oc_ri_get_interface_mask(iface, (size_t)iface_len);
    }
  }

  /* Obtain handle to buffer containing the serialized payload */
  const uint8_t *payload = NULL;
  size_t payload_len = 0;
#ifdef OC_BLOCK_WISE
  if (*ctx->request_state) {
    payload = (*ctx->request_state)->buffer;
    payload_len = (*ctx->request_state)->payload_size;
  }
#else  /* OC_BLOCK_WISE */
  payload_len = coap_get_payload(ctx->request, &payload);
#endif /* !OC_BLOCK_WISE */
  request_obj._payload = payload;
  request_obj._payload_len = payload_len;
  request_obj.content_format = cf;
  request_obj.accept = accept;
#ifdef OC_HAS_FEATURE_ETAG
  request_obj.etag = NULL;
  request_obj.etag_len = coap_options_get_etag(ctx->request, &request_obj.etag);
#endif /* OC_HAS_FEATURE_ETAG */

  OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
  struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);

  bool bad_request = false;
  bool entity_too_large = false;
  if (payload_len > 0) {
    if (!oc_rep_decoder_set_by_content_format(cf)) {
      OC_WRN("ocri: unsupported content format (%d)", (int)cf);
      bad_request = true;
    }

    if (!bad_request) {
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
        if (parse_error == CborErrorUnexpectedEOF) {
          entity_too_large = true;
        }
        bad_request = true;
      }
    }
  }

  oc_resource_t *cur_resource = NULL;

  /* If there were no errors thus far, attempt to locate the specific
   * resource object that will handle the request using the request uri.
   */
  /* Check against list of declared core resources.
   */
  if (!bad_request) {
    for (int i = 0; i < OC_NUM_CORE_RESOURCES_PER_DEVICE; ++i) {
      oc_resource_t *resource =
        oc_core_get_resource_by_index(i, endpoint->device);
      if (resource != NULL &&
          oc_string_len(resource->uri) == (uri_path_len + 1) &&
          strncmp(oc_string(resource->uri) + 1, uri_path, uri_path_len) == 0) {
        request_obj.resource = cur_resource = resource;
        break;
      }
    }
  }

  bool resource_is_collection = false;
#ifdef OC_SERVER
  /* Check against list of declared application resources.
   */
  if (!cur_resource && !bad_request) {
    cur_resource =
      oc_ri_get_app_resource_by_uri(uri_path, uri_path_len, endpoint->device);
    request_obj.resource = cur_resource;

#if defined(OC_COLLECTIONS)
    if (cur_resource && oc_check_if_collection(cur_resource)) {
      resource_is_collection = true;
    }
#endif /* OC_COLLECTIONS */
  }
#endif /* OC_SERVER */

  bool forbidden = false;
  oc_interface_mask_t iface_mask = 0;
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
        !oc_ri_interface_supports_method(iface_mask, method)) {
      forbidden = true;
      bad_request = true;
#ifdef OC_SECURITY
      oc_audit_log(endpoint->device, "COMM-1", "Operation not supported", 0x40,
                   2, NULL, 0);
#endif
    }
  }

  bool not_authorized = false;
#ifdef OC_SECURITY
  if (cur_resource && !bad_request) {
    /* If resource is a coaps:// resource, then query ACL to check if
     * the requestor (the subject) is authorized to issue this request to
     * the resource.
     */
    not_authorized = !oc_sec_check_acl(method, cur_resource, endpoint);
    if (not_authorized) {
      oc_ri_audit_log(method, cur_resource, endpoint);
    }
  }
#endif /* OC_SECURITY */

  bool not_modified = false;
#ifdef OC_HAS_FEATURE_ETAG
  if (cur_resource != NULL && !bad_request && !not_authorized &&
      method == OC_GET &&
      (resource_is_collection || cur_resource->get_handler.cb != NULL)) {
    /* If the request is a GET request, check if the client has provided a valid
     * ETag in the header. If so, and if the ETag matches the ETag of the
     * resource, then the response will be a 2.03 response with an empty
     * payload.
     */
    const uint8_t *req_etag_buf = NULL;
    uint8_t req_etag_buf_len =
      coap_options_get_etag(ctx->request, &req_etag_buf);
    uint64_t etag =
      (iface_mask == OC_IF_B)
        ? oc_ri_get_batch_etag(cur_resource, endpoint, endpoint->device)
        : oc_ri_get_etag(cur_resource);
    if (etag != OC_ETAG_UNINITIALIZED) {
      if (req_etag_buf_len == sizeof(etag)) {
        uint64_t req_etag;
        memcpy(&req_etag, &req_etag_buf[0], sizeof(etag));
        not_modified = req_etag == etag;
      }

      // Store ETag to the response buffer before the method handler is invoked.
      // A resource with a custom method handler may want to override the ETag
      // value with oc_set_send_response_etag().
      memcpy(&response_buffer.etag.value[0], &etag, sizeof(etag));
      response_buffer.etag.length = sizeof(etag);
    }
  }
#endif /* OC_HAS_FEATURE_ETAG */

/* Alloc response_state. It also affects request_obj.response.
 */
#ifdef OC_BLOCK_WISE
#ifdef OC_DYNAMIC_ALLOCATION
  bool response_state_allocated = false;
  bool enable_realloc_rep = false;
#endif /* OC_DYNAMIC_ALLOCATION */
  if (cur_resource != NULL && !bad_request && !not_authorized &&
      !not_modified) {
    if (*ctx->response_state == NULL) {
#ifdef OC_HAS_FEATURE_ETAG
      bool generate_etag = false;
#else  /* OC_HAS_FEATURE_ETAG */
      bool generate_etag = true;
#endif /* OC_HAS_FEATURE_ETAG */
      OC_DBG("creating new block-wise response state");
      *ctx->response_state = oc_blockwise_alloc_response_buffer(
        uri_path, uri_path_len, endpoint, method, OC_BLOCKWISE_SERVER,
        (uint32_t)OC_MIN_APP_DATA_SIZE, CONTENT_2_05, generate_etag);
      if (*ctx->response_state == NULL) {
        OC_ERR("failure to alloc response state");
        bad_request = true;
      } else {
#ifdef OC_DYNAMIC_ALLOCATION
#ifdef OC_APP_DATA_BUFFER_POOL
        if (!(*ctx->response_state)->block)
#endif /* OC_APP_DATA_BUFFER_POOL */
        {
          response_state_allocated = true;
        }
#endif /* OC_DYNAMIC_ALLOCATION */
        if (uri_query_len > 0) {
          oc_new_string(&(*ctx->response_state)->uri_query, uri_query,
                        uri_query_len);
        }
        response_buffer.buffer = (*ctx->response_state)->buffer;
#ifdef OC_DYNAMIC_ALLOCATION
        response_buffer.buffer_size = (*ctx->response_state)->buffer_size;
#else  /* !OC_DYNAMIC_ALLOCATION */
        response_buffer.buffer_size = sizeof((*ctx->response_state)->buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
      }
    } else {
      OC_DBG("using existing block-wise response state");
      response_buffer.buffer = (*ctx->response_state)->buffer;
#ifdef OC_DYNAMIC_ALLOCATION
      response_buffer.buffer_size = (*ctx->response_state)->buffer_size;
#else  /* !OC_DYNAMIC_ALLOCATION */
      response_buffer.buffer_size = sizeof((*ctx->response_state)->buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
    }
  }
#else  /* OC_BLOCK_WISE */
  response_buffer.buffer = ctx->buffer;
  response_buffer.buffer_size = OC_BLOCK_SIZE;
#endif /* !OC_BLOCK_WISE */

  bool method_not_allowed = false;
  if (cur_resource && !bad_request && !not_authorized && !not_modified) {
    /* Process a request against a valid resource, request payload, and
     * interface.
     */
    /* Initialize oc_rep with a buffer to hold the response payload. "buffer"
     * points to memory allocated in the messaging layer for the "CoAP
     * Transaction" to service this request.
     */
#if defined(OC_BLOCK_WISE) && defined(OC_DYNAMIC_ALLOCATION)
    if (response_state_allocated) {
      oc_rep_new_realloc_v1(&response_buffer.buffer,
                            response_buffer.buffer_size, OC_MAX_APP_DATA_SIZE);
      enable_realloc_rep = true;
    } else {
      oc_rep_new_v1(response_buffer.buffer, response_buffer.buffer_size);
    }
#else  /* OC_DYNAMIC_ALLOCATION */
    oc_rep_new_v1(response_buffer.buffer, response_buffer.buffer_size);
#endif /* !OC_DYNAMIC_ALLOCATION */
    oc_rep_encoder_set_type_by_accept(accept);

    oc_status_t ret = ri_invoke_request_handler(
      cur_resource, method, &request_obj, iface_mask, resource_is_collection);
    switch (ret) {
    case OC_STATUS_OK:
      break;
    case OC_STATUS_METHOD_NOT_ALLOWED:
      method_not_allowed = true;
      break;
    default:
      bad_request = true;
      break;
    }
  }

#ifdef OC_BLOCK_WISE
  oc_blockwise_free_request_buffer(*ctx->request_state);
  *ctx->request_state = NULL;
#ifdef OC_DYNAMIC_ALLOCATION
  // for realloc we need reassign memory again.
  if (enable_realloc_rep) {
    response_buffer.buffer = oc_rep_shrink_encoder_buf(response_buffer.buffer);
    if ((*ctx->response_state) != NULL) {
      (*ctx->response_state)->buffer = response_buffer.buffer;
    }
  }
#endif /* OC_DYNAMIC_ALLOCATION */
#endif /* OC_BLOCK_WISE */

  if (request_obj.request_payload != NULL) {
    /* To the extent that the request payload was parsed, free the payload
     * structure (and return its memory to the pool).
     */
    oc_free_rep(request_obj.request_payload);
  }
  oc_rep_set_pool(prev_rep_objects);

  bool success = false;
  if (forbidden) {
    OC_WRN("ocri: Forbidden request");
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code_unsafe(OC_STATUS_FORBIDDEN);
  } else if (entity_too_large) {
    OC_WRN("ocri: Request payload too large (hence incomplete)");
    response_buffer.response_length = 0;
    response_buffer.code =
      oc_status_code_unsafe(OC_STATUS_REQUEST_ENTITY_TOO_LARGE);
  } else if (bad_request) {
    OC_WRN("ocri: Bad request");
    /* Return a 4.00 response */
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code_unsafe(OC_STATUS_BAD_REQUEST);
  } else if (!cur_resource) {
    OC_WRN("ocri: Could not find resource");
    /* Return a 4.04 response if the requested resource was not found */
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code_unsafe(OC_STATUS_NOT_FOUND);
  } else if (method_not_allowed) {
    OC_WRN("ocri: Could not find method");
    /* Return a 4.05 response if the resource does not implement the
     * request method.
     */
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code_unsafe(OC_STATUS_METHOD_NOT_ALLOWED);
  }
#ifdef OC_SECURITY
  else if (not_authorized) {
    OC_WRN("ocri: Subject not authorized");
    /* If the requestor (subject) does not have access granted via an
     * access control entry in the ACL, then it is not authorized to
     * access the resource. A 4.01 response is sent.
     */
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code_unsafe(OC_STATUS_UNAUTHORIZED);
  }
#endif /* OC_SECURITY */
  else {
    if (not_modified) {
      response_buffer.response_length = 0;
      response_buffer.code = oc_status_code_unsafe(OC_STATUS_NOT_MODIFIED);
    }
    success = true;
  }

#ifdef OC_SERVER
  int32_t observe = OC_COAP_OPTION_OBSERVE_NOT_SET;
#ifdef OC_BLOCK_WISE
  uint16_t block2_size = ctx->block2_size;
#else  /* !OC_BLOCK_WISE */
  uint16_t block2_size = 0;
#endif /* OC_BLOCK_WISE */
  if (success && method == OC_GET &&
      response_buffer.code < oc_status_code_unsafe(OC_STATUS_BAD_REQUEST)) {
    observe = ri_handle_observation(ctx->request, ctx->response, cur_resource,
                                    resource_is_collection, block2_size,
                                    endpoint, iface_query);
  }
#endif /* OC_SERVER */

  if (request_obj.origin != NULL &&
      (request_obj.origin->flags & MULTICAST) != 0 &&
      response_buffer.code >= oc_status_code_unsafe(OC_STATUS_BAD_REQUEST)) {
    response_buffer.code = CLEAR_TRANSACTION;
  }

  ri_invoke_coap_entity_set_response_ctx_t resp_ctx = {
    .response_obj = &response_obj,
#ifdef OC_BLOCK_WISE
    .response_state = ctx->response_state,
#endif /* OC_BLOCK_WISE */
#ifdef OC_SERVER
    .request = ctx->request,
    .endpoint = endpoint,
    .method = method,
    .iface_mask = iface_mask,
    .observe = observe,
    .block2_size = block2_size,
    .resource = cur_resource,
#ifdef OC_COLLECTIONS
    .resource_is_collection = resource_is_collection,
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */
  };
  ri_invoke_coap_entity_set_response(ctx->response, resp_ctx);
  return success;
}

void
oc_ri_shutdown(void)
{
#ifdef OC_SERVER
#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
  coap_free_all_discovery_batch_observers();
#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */
  coap_free_all_observers();
#endif /* OC_SERVER */
  coap_free_all_transactions();
  oc_event_callbacks_shutdown();
#ifdef OC_CLIENT
  oc_client_cbs_shutdown();
#endif /* OC_CLIENT */
#ifdef OC_BLOCK_WISE
  oc_blockwise_free_all_buffers(true);
#endif /* OC_BLOCK_WISE */

  while (oc_main_poll_v1() != 0) {
    // no-op
  }

  stop_processes();

  oc_process_shutdown();

#ifdef OC_SERVER
  oc_ri_on_delete_resource_remove_all();

#ifdef OC_COLLECTIONS
  oc_collections_free_all();
#endif /* OC_COLLECTIONS */

  ri_delete_all_app_resources();
#endif /* OC_SERVER */
}
