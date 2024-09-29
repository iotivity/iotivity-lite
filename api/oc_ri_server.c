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

#include "util/oc_features.h"

#ifdef OC_SERVER

#include "api/oc_discovery_internal.h"
#include "api/oc_event_callback_internal.h"
#include "api/oc_server_api_internal.h"
#include "messaging/coap/options_internal.h"
#include "messaging/coap/observe_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_ri_server_internal.h"
#include "port/oc_log_internal.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#include "api/oc_link_internal.h"
#ifdef OC_COLLECTIONS_IF_CREATE
#include "oc_resource_factory_internal.h"
#endif /* OC_COLLECTIONS_IF_CREATE */
#endif /* OC_COLLECTIONS */

#ifdef OC_SECURITY
#include "security/oc_acl_util_internal.h"
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_ETAG
#include "api/oc_etag_internal.h"
#endif /* OC_HAS_FEATURE_ETAG */

typedef struct oc_resource_defaults_data_t
{
  oc_resource_t *resource;
  oc_interface_mask_t iface_mask;
} oc_resource_defaults_data_t;

OC_LIST(g_app_resources);
OC_LIST(g_app_resources_to_be_deleted);
OC_MEMB(g_resource_default_s, oc_resource_defaults_data_t,
        OC_MAX_APP_RESOURCES);

OC_MEMB(g_app_resources_s, oc_resource_t, OC_MAX_APP_RESOURCES);

OC_LIST(g_on_delete_resource_cb_list);
OC_MEMB(g_on_delete_resource_cb_s, oc_ri_on_delete_resource_t,
        OC_MAX_ON_DELETE_RESOURCE_CBS);

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

oc_resource_t *
oc_ri_get_app_resources(void)
{
  return oc_list_head(g_app_resources);
}

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

bool
oc_ri_on_delete_resource_add_callback(oc_ri_delete_resource_cb_t cb)
{
  if (oc_ri_on_delete_resource_find_callback(cb) != NULL) {
    OC_ERR("delete resource callback already exists");
    return false;
  }
  oc_ri_on_delete_resource_t *item = oc_memb_alloc(&g_on_delete_resource_cb_s);
  if (item == NULL) {
    OC_ERR("delete resource callback item alloc failed");
    return false;
  }
  item->cb = cb;
  oc_list_add(g_on_delete_resource_cb_list, item);
  return true;
}

oc_ri_on_delete_resource_t *
oc_ri_on_delete_resource_find_callback(oc_ri_delete_resource_cb_t cb)
{
  oc_ri_on_delete_resource_t *item = oc_list_head(g_on_delete_resource_cb_list);
  for (; item != NULL; item = item->next) {
    if (cb == item->cb) {
      return item;
    }
    continue;
  }
  return NULL;
}

bool
oc_ri_on_delete_resource_remove_callback(oc_ri_delete_resource_cb_t cb)
{
  oc_ri_on_delete_resource_t *on_delete =
    oc_ri_on_delete_resource_find_callback(cb);
  if (on_delete == NULL) {
    return false;
  }
  oc_list_remove(g_on_delete_resource_cb_list, on_delete);
  oc_memb_free(&g_on_delete_resource_cb_s, on_delete);
  return true;
}

void
oc_ri_on_delete_resource_remove_all(void)
{
  oc_ri_on_delete_resource_t *on_delete =
    oc_list_pop(g_on_delete_resource_cb_list);
  while (on_delete != NULL) {
    oc_list_remove(g_on_delete_resource_cb_list, on_delete);
    oc_memb_free(&g_on_delete_resource_cb_s, on_delete);

    on_delete = oc_list_pop(g_on_delete_resource_cb_list);
  }
}

void
oc_ri_on_delete_resource_invoke(oc_resource_t *resource)
{
  for (oc_ri_on_delete_resource_t *on_delete =
         oc_list_head(g_on_delete_resource_cb_list);
       on_delete != NULL; on_delete = on_delete->next) {
    on_delete->cb(resource);
  }
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
      if (oc_collection_remove_link_and_notify(
            &collection->res, link, notify,
            /*discoveryBatchDispatch*/ false)) {
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

void
oc_ri_notify_resource_observers(oc_resource_t *resource,
                                oc_interface_mask_t iface_mask)
{
  if ((iface_mask == OC_IF_STARTUP) || (iface_mask == OC_IF_STARTUP_REVERT)) {
    oc_resource_defaults_data_t *resource_defaults_data =
      oc_ri_alloc_resource_defaults();
    resource_defaults_data->resource = resource;
    resource_defaults_data->iface_mask = iface_mask;
    oc_ri_add_timed_event_callback_ticks(
      resource_defaults_data,
      &ri_observe_notification_resource_defaults_delayed, 0);
  } else {
    oc_notify_resource_changed_delayed_ms(resource, 0);
  }
}

void
oc_ri_server_init(void)
{

  oc_list_init(g_app_resources);
  oc_list_init(g_app_resources_to_be_deleted);
}

void
oc_ri_server_reset(void)
{
#if defined(OC_RES_BATCH_SUPPORT) && defined(OC_DISCOVERY_RESOURCE_OBSERVABLE)
  coap_free_all_discovery_batch_observers();
#endif /* OC_RES_BATCH_SUPPORT && OC_DISCOVERY_RESOURCE_OBSERVABLE */
  coap_free_all_observers();
}

void
oc_ri_server_shutdown(void)
{
  oc_ri_on_delete_resource_remove_all();

#ifdef OC_COLLECTIONS
  oc_collections_free_all();
#endif /* OC_COLLECTIONS */

  ri_delete_all_app_resources();
}

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
                         iface_query) >= 0 &&
      /* If the resource is marked as periodic observable it means it must be
       * polled internally for updates (which would lead to notifications being
       * sent). If so, add the resource to a list of periodic GET callbacks to
       * utilize the framework's internal polling mechanism.
       */
      ((resource->properties & OC_PERIODIC) != 0 &&
       !oc_periodic_observe_callback_add(resource))) {
    return false;
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

int
oc_ri_handle_observation(const coap_packet_t *request, coap_packet_t *response,
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
