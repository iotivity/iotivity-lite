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

#include "st_queue.h"

#define MAX_NOTIFY_COUNT 5

typedef struct st_notify_item
{
  struct st_notify_item *next;
  char *uri;
} st_notify_item_t;

static st_queue_t *g_notify_queue = NULL;
OC_MEMB(st_notify_item_s, st_notify_item_t, MAX_NOTIFY_COUNT);

static st_resource_handler g_resource_get_handler = NULL;
static st_resource_handler g_resource_set_handler = NULL;

static size_t device_index = 0;

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
st_register_resources(size_t device)
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
  if (g_resource_get_handler || g_resource_set_handler) {
    st_print_log("[ST_RM] already registered handler.\n");
    return ST_ERROR_OPERATION_FAILED;
  }

  g_resource_get_handler = get_handler;
  g_resource_set_handler = set_handler;
  return ST_ERROR_NONE;
}

void
st_unregister_resource_handler(void)
{
  g_resource_get_handler = NULL;
  g_resource_set_handler = NULL;
}

oc_define_interrupt_handler(st_notify)
{
  st_notify_item_t *item = NULL;
  while ((item = (st_notify_item_t *)st_queue_pop(g_notify_queue))) {
    oc_resource_t *resource =
      oc_ri_get_app_resource_by_uri(item->uri, strlen(item->uri), device_index);
    if (!resource) {
      st_print_log("[ST_RM] %s is not registered resource.\n", item->uri);
    } else {
      oc_notify_observers(resource);
    }

    st_queue_free_item(g_notify_queue, item);
  }
}

st_error_t
st_notify_back(const char *uri)
{
  if (!uri) {
    st_print_log("[ST_RM] invalid parameter.\n");
    return ST_ERROR_INVALID_PARAMETER;
  }

  if (st_queue_push(g_notify_queue, (void *)uri) != 0) {
    st_print_log("[ST_RM] st_queue_push failed\n");
    return ST_ERROR_OPERATION_FAILED;
  }
  oc_signal_interrupt_handler(st_notify);
  return ST_ERROR_NONE;
}

static void *
notify_add_handler(void *value)
{
  if (!value) {
    return NULL;
  }

  char *uri = (char *)value;
  st_notify_item_t *notify_item = oc_memb_alloc(&st_notify_item_s);
  if (!notify_item) {
    st_print_log("[ST_MGR] oc_memb_alloc failed!\n");
    return NULL;
  }

  int len = strlen(uri);
  notify_item->uri = (char *)malloc(sizeof(char) * (len + 1));
  strncpy(notify_item->uri, uri, len);
  notify_item->uri[len] = '\0';

  return notify_item;
}

static void
notify_free_handler(void *item)
{
  if (!item)
    return;

  st_notify_item_t *notify_item = (st_notify_item_t *)item;
  free(notify_item->uri);
  oc_memb_free(&st_notify_item_s, item);
}

int
st_notify_initialize(void)
{
  if (g_notify_queue) {
    st_print_log("[ST_RM] notify queue is already initialized\n");
    return -1;
  }

  g_notify_queue = st_queue_initialize(notify_add_handler, notify_free_handler);

  if (!g_notify_queue) {
    st_print_log("[ST_RM] st_queue_initialize failed\n");
    return -1;
  }

  return 0;
}

void
st_notify_activate(void)
{
  oc_activate_interrupt_handler(st_notify);
  st_print_log("[ST_RM] notify_queue activated.\n");
}

void
st_notify_deinitialize(void)
{
  if (!g_notify_queue) {
    st_print_log("[ST_RM] notify queue is not initialized\n");
    return;
  }

  st_queue_deinitialize(g_notify_queue);
  g_notify_queue = NULL;
}