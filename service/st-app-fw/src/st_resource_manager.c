/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "st_resource_manager.h"
#include "oc_api.h"
#include "oc_ri.h"
#include "samsung/sc_easysetup.h"
#include "st_data_manager.h"
#include "st_port.h"
#include "st_process.h"

static st_resource_handler g_resource_get_handler = NULL;
static st_resource_handler g_resource_set_handler = NULL;

static int device_index = 0;

typedef enum {
  ST_RSC_READABLE = (1 << 0),
  ST_RSC_WRITABLE = (1 << 1)
} st_permission_t;

static void
st_resource_get_handler(oc_request_t *request, oc_interface_mask_t interface,
                        void *user_data)
{
  (void)user_data;
  st_print_log("[ST_RM] st_resource_get_handler: %s\n",
               oc_string(request->resource->uri));

  if (!g_resource_get_handler) {
    st_print_log("[ST_RM] please initialize valid handler first\n");
    oc_send_response(request, OC_STATUS_NOT_IMPLEMENTED);
    return;
  }

  st_request_t req = {.uri = oc_string(request->resource->uri),
                      .uri_len = oc_string_len(request->resource->uri),
                      .query = request->query,
                      .query_len = request->query_len,
                      .request_payload = request->request_payload };

  oc_rep_start_root_object();
  if (interface & OC_IF_BASELINE) {
    oc_process_baseline_interface(request->resource);
  }
  if (!g_resource_get_handler(&req)) {
    oc_rep_reset();
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
st_resource_post_handler(oc_request_t *request, oc_interface_mask_t interface,
                         void *user_data)
{
  (void)interface;
  (void)user_data;
  st_print_log("[ST_RM] st_resource_post_handler: %s\n",
               oc_string(request->resource->uri));

  if (!g_resource_set_handler) {
    st_print_log("[ST_RM] please initialize valid handler first\n");
    oc_send_response(request, OC_STATUS_NOT_IMPLEMENTED);
    return;
  }

  st_request_t req = {.uri = oc_string(request->resource->uri),
                      .uri_len = oc_string_len(request->resource->uri),
                      .query = request->query,
                      .query_len = request->query_len,
                      .request_payload = request->request_payload };

  oc_rep_start_root_object();
  if (interface & OC_IF_BASELINE) {
    oc_process_baseline_interface(request->resource);
  }
  if (!g_resource_set_handler(&req)) {
    oc_rep_reset();
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_CHANGED);
}

static int
st_register_resource(st_resource_info_t *resource_info)
{
  st_print_log("[ST_RM] st_register_resource IN\n");
  st_print_log("[ST_RM] uri : %s\n", oc_string(resource_info->uri));
  oc_resource_t *resource =
    oc_new_resource(NULL, oc_string(resource_info->uri),
                    oc_string_array_get_allocated_size(resource_info->types),
                    resource_info->device_idx);
  if (!resource)
    return -1;

  int i;
  int rw = 0;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(resource_info->types);
       i++) {
    char *value = oc_string_array_get_item(resource_info->types, i);
    oc_resource_bind_resource_type(resource, value);
    st_print_log("[ST_RM] rt : %s\n", value);
    if (rw < (ST_RSC_READABLE | ST_RSC_WRITABLE)) {
      st_resource_type_t *rt_info = st_data_mgr_get_rsc_type_info(value);
      st_property_t *prop = oc_list_head(rt_info->properties);
      while (prop) {
        if (rw < prop->rw)
          rw = prop->rw;
        prop = prop->next;
      }
    }
  }

  st_print_log("[ST_RM] interface : %d\n", resource_info->interfaces);
  oc_resource_bind_resource_interface(resource, resource_info->interfaces);
  st_print_log("[ST_RM] default_interface : %d\n",
               resource_info->default_interface);
  oc_resource_set_default_interface(resource, resource_info->default_interface);

  st_print_log("[ST_RM] policy : %d\n", resource_info->policy);
  oc_resource_set_discoverable(
    resource, resource_info->policy & OC_DISCOVERABLE ? true : false);
  oc_resource_set_observable(
    resource, resource_info->policy & OC_OBSERVABLE ? true : false);

  st_print_log("[ST_RM] read : %s, write %s\n",
               rw & ST_RSC_READABLE ? "true" : "false",
               rw & ST_RSC_WRITABLE ? "true" : "false");
  if (rw & ST_RSC_READABLE) {
    oc_resource_set_request_handler(resource, OC_GET, st_resource_get_handler,
                                    NULL);
  }
  if (rw & ST_RSC_WRITABLE) {
    oc_resource_set_request_handler(resource, OC_POST, st_resource_post_handler,
                                    NULL);
  }

  st_print_log("[ST_RM] st_register_resource OUT\n");
  return oc_add_resource(resource) ? 0 : -1;
}

int
st_register_resources(int device)
{
  st_resource_info_t *resources = st_data_mgr_get_resource_info();
  if (!resources) {
    st_print_log("[ST_RM] resource list not exist\n");
    return -1;
  }

  while (resources) {
    if (st_register_resource(resources) != 0) {
      st_print_log("[ST_RM] st_register_resource failed\n");
      return -1;
    }
    resources = resources->next;
  }

  es_result_e ret = init_provisioning_info_resource(NULL);

  device_index = device;
  return (ret == ES_OK) ? 0 : -1;
}

st_error_t
st_register_resource_handler(st_resource_handler get_handler,
                             st_resource_handler set_handler)
{
  if (!get_handler || !set_handler) {
    st_print_log("[ST_RM] invalid parameter.\n");
    return ST_ERROR_INVALID_PARAMETER;
  }

  g_resource_get_handler = get_handler;
  g_resource_set_handler = set_handler;
  return ST_ERROR_NONE;
}

st_error_t
st_notify_back(const char *uri)
{
  int ret = 0;
  if (!uri) {
    st_print_log("[ST_RM] invalid parameter.\n");
    return ST_ERROR_INVALID_PARAMETER;
  }

  st_process_app_sync_lock();
  oc_resource_t *resource =
    oc_ri_get_app_resource_by_uri(uri, strlen(uri), device_index);
  if (!resource) {
    st_print_log("[ST_RM] %s is not registered resource.\n", uri);
    st_process_app_sync_unlock();
    return ST_ERROR_OPERATION_FAILED;
  }

  ret = oc_notify_observers(resource);
  st_process_app_sync_unlock();
  _oc_signal_event_loop();

  return (ret >= 0) ? ST_ERROR_NONE : ST_ERROR_OPERATION_FAILED;
}
