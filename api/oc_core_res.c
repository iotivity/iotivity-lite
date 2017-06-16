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

#include "oc_core_res.h"
#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_rep.h"

#ifdef OC_SECURITY
#include "security/oc_pstat.h"
#endif /* OC_SECURITY */

#include <stdarg.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
#include <stdlib.h>
static oc_resource_t *core_resources;
static oc_device_info_t *oc_device_info;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_resource_t core_resources[NUM_OC_CORE_RESOURCES];
static oc_device_info_t oc_device_info[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

static int device_count;
static oc_uuid_t *next_di;
static oc_string_t oc_platform_payload;
static oc_resource_t con_app_resource;

#ifdef OC_DYNAMIC_ALLOCATION
void
oc_core_init(void)
{
  core_resources =
    (oc_resource_t *)calloc(NUM_OC_CORE_RESOURCES, sizeof(oc_resource_t));
  if (!core_resources) {
    oc_abort("Insufficient memory");
  }
}
#endif /* OC_DYNAMIC_ALLOCATION */

void
oc_core_encode_interfaces_mask(CborEncoder *parent,
                               oc_interface_mask_t interface)
{
  oc_rep_set_key((*parent), "if");
  oc_rep_start_array((*parent), if);
  if (interface & OC_IF_LL) {
    oc_rep_add_text_string(if, "oic.if.ll");
  }
  if (interface & OC_IF_B) {
    oc_rep_add_text_string(if, "oic.if.b");
  }
  if (interface & OC_IF_R) {
    oc_rep_add_text_string(if, "oic.if.r");
  }
  if (interface & OC_IF_RW) {
    oc_rep_add_text_string(if, "oic.if.rw");
  }
  if (interface & OC_IF_A) {
    oc_rep_add_text_string(if, "oic.if.a");
  }
  if (interface & OC_IF_S) {
    oc_rep_add_text_string(if, "oic.if.s");
  }
  oc_rep_add_text_string(if, "oic.if.baseline");
  oc_rep_end_array((*parent), if);
}

static void
oc_core_device_handler(oc_request_t *request, oc_interface_mask_t interface,
                       void *data)
{
  (void)data;
  int device = request->resource->device;
  oc_rep_start_root_object();

  char uuid[37];
  oc_uuid_to_str(&oc_device_info[device].uuid, uuid, 37);

  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  case OC_IF_R: {
    oc_rep_set_text_string(root, di, uuid);
    oc_rep_set_text_string(root, n, oc_string(oc_device_info[device].name));
    oc_rep_set_text_string(root, icv, oc_string(oc_device_info[device].icv));
    oc_rep_set_text_string(root, dmv, oc_string(oc_device_info[device].dmv));
    if (oc_device_info[device].add_device_cb)
      oc_device_info[device].add_device_cb(NULL);
  } break;
  default:
    break;
  }

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
oc_core_con_handler_get(oc_request_t *request, oc_interface_mask_t interface,
                        void *data)
{
  (void)data;
  (void)interface;

  int device = request->resource->device;
  oc_rep_start_root_object();

  oc_process_baseline_interface(request->resource);
  /* oic.wk.d attribute n shall always be the same value as
     oic.wk.con attribute n. */
  oc_rep_set_text_string(root, n, oc_string(oc_device_info[device].name));

  if (con_app_resource.get_handler.cb) {
    con_app_resource.get_handler.cb(request,
                                    interface,
                                    con_app_resource.get_handler.user_data);
  }

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
oc_core_con_handler_post(oc_request_t *request, oc_interface_mask_t interface,
                         void *data)
{

  if (interface != OC_IF_RW) {
    oc_send_response(request, OC_STATUS_FORBIDDEN);
    return;
  }

  bool handled = false;
  oc_rep_t *rep = request->request_payload;

  oc_rep_start_root_object();

  while (rep != NULL) {
    if (strcmp(oc_string(rep->name), "n") == 0) {
      if (rep->type != STRING || oc_string_len(rep->value.string) == 0) {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }

      int device = request->resource->device;
      oc_free_string(&oc_device_info[device].name);
      oc_new_string(&oc_device_info[device].name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      oc_rep_set_text_string(root, n, oc_string(oc_device_info[device].name));
      handled = true;
      break;
    }
    rep = rep->next;
  }

  if (con_app_resource.post_handler.cb) {
    /* cannot know what the handler does, so assume it knows
       how to treat the request*/
    handled = true;
    con_app_resource.post_handler.cb(request,
                                     interface,
                                     con_app_resource.post_handler.user_data);
  }

  oc_rep_end_root_object();

  if (handled) {
    oc_send_response(request, OC_STATUS_CHANGED);
    /* notify_observers is automatically triggered in
       oc_ri_invoke_coap_entity_handler() */
    return;
  }

  oc_send_response(request, OC_STATUS_BAD_REQUEST);
}

int
oc_core_get_num_devices(void)
{
  return device_count;
}

int
oc_core_get_num_resources(void)
{
    return NUM_OC_CORE_RESOURCES - 1 + device_count;
}

oc_resource_t *
oc_core_get_con_app_resource(void)
{
  return &con_app_resource;
}

static int
finalize_payload(uint8_t *buffer, oc_string_t *payload)
{
  oc_rep_end_root_object();
  int size = oc_rep_finalize();
  if (size != -1) {
    oc_alloc_string(payload, size);
    memcpy(oc_cast(*payload, uint8_t), buffer, size);
#ifdef OC_DYNAMIC_ALLOCATION
    free(buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
    return 1;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  free(buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
  return -1;
}

void
oc_core_set_device_id(oc_uuid_t *uuid)
{
  next_di = uuid;
}

oc_device_info_t *
oc_core_add_new_device(const char *uri, const char *rt, const char *name,
                       const char *spec_version, const char *data_model_version,
                       oc_core_add_device_cb_t add_device_cb, void *data)
{
#ifndef OC_DYNAMIC_ALLOCATION
  if (device_count == OC_MAX_NUM_DEVICES) {
    OC_ERR("device limit reached\n");
    return NULL;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  core_resources = (oc_resource_t *)realloc(
    core_resources,
    (NUM_OC_CORE_RESOURCES + device_count) * sizeof(oc_resource_t));
  if (!core_resources) {
    oc_abort("Insufficient memory");
  }

  oc_device_info = (oc_device_info_t *)realloc(
    oc_device_info, (device_count + 1) * sizeof(oc_device_info_t));
  if (!oc_device_info) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  int ocf_d = oc_core_get_num_resources();

/* Once provisioned, UUID is retrieved from the credential store.
   If not yet provisioned, a default is generated in the security
   layer.
*/
#ifdef OC_SECURITY /*fix if add new devices after provisioning, need to reset  \
                      or it will generate non-standard uuid */
  /* where are secondary device ids persisted? */
  if (!oc_sec_provisioned() && device_count > 0)
    if (next_di == NULL)
      oc_gen_uuid(&oc_device_info[device_count].uuid);
    else
      oc_device_info[device_count].uuid = *next_di;
#else
  if (next_di == NULL)
    oc_gen_uuid(&oc_device_info[device_count].uuid);
  else
    oc_device_info[device_count].uuid = *next_di;
#endif
next_di = NULL;

  /* Construct device resource */
  if (strlen(rt) == 8 && strncmp(rt, "oic.wk.d", 8) == 0) {
    oc_core_populate_resource(
      ocf_d, device_count, uri, OC_IF_R | OC_IF_BASELINE, OC_IF_R,
      OC_DISCOVERABLE, oc_core_device_handler, 0, 0, 0, 1, rt);
  } else {
    oc_core_populate_resource(
      ocf_d, device_count, uri, OC_IF_R | OC_IF_BASELINE, OC_IF_R,
      OC_DISCOVERABLE, oc_core_device_handler, 0, 0, 0, 2, rt, "oic.wk.d");
  }

  oc_new_string(&oc_device_info[device_count].name, name, strlen(name));
  oc_new_string(&oc_device_info[device_count].icv, spec_version,
                strlen(spec_version));
  oc_new_string(&oc_device_info[device_count].dmv, data_model_version,
                strlen(data_model_version));
  oc_device_info[device_count].add_device_cb = add_device_cb;

  /* Construct oic.wk.con resource for this device */
  oc_core_populate_resource(
    OCF_CON, device_count, "/oic/con", OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
    OC_DISCOVERABLE | OC_OBSERVABLE, 
    oc_core_con_handler_get, oc_core_con_handler_post, oc_core_con_handler_post,
    0, 1, "oic.wk.con");

  return &oc_device_info[device_count++];
}

void
oc_core_platform_handler(oc_request_t *request, oc_interface_mask_t interface,
                         void *data)
{
  (void)data;
  uint8_t *buffer = request->response->response_buffer->buffer;
  uint16_t buffer_size = request->response->response_buffer->buffer_size;
  int payload_size = oc_platform_payload.size;

  if (buffer_size < payload_size) {
    request->response->response_buffer->response_length = 0;
    request->response->response_buffer->code =
      oc_status_code(OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }

  switch (interface) {
  case OC_IF_R:
  case OC_IF_BASELINE:
    memcpy(buffer, oc_cast(oc_platform_payload, uint8_t), payload_size);
    request->response->response_buffer->response_length = payload_size;
    request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
    break;
  default:
    break;
  }
}

oc_string_t *
oc_core_init_platform(const char *mfg_name, oc_core_init_platform_cb_t init_cb,
                      void *data)
{
  if (oc_platform_payload.size > 0)
    return NULL;

  /* Populating resource obuject */
  oc_core_populate_resource(OCF_P, 0, "oic/p", OC_IF_R | OC_IF_BASELINE,
                            OC_IF_BASELINE, OC_DISCOVERABLE,
                            oc_core_platform_handler, 0, 0, 0, 1, "oic.wk.p");

/* Encoding platform resource payload */
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buffer) {
    oc_abort("Insufficient memory");
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_rep_new(buffer, OC_MAX_APP_DATA_SIZE);
  oc_rep_start_root_object();
  oc_rep_set_string_array(root, rt, core_resources[OCF_P].types);

  oc_core_encode_interfaces_mask(oc_rep_object(root),
                                 core_resources[OCF_P].interfaces);

  oc_uuid_t uuid;
  oc_gen_uuid(&uuid);
  char uuid_str[37];

  oc_uuid_to_str(&uuid, uuid_str, 37);
  oc_rep_set_text_string(root, pi, uuid_str);
  oc_rep_set_text_string(root, mnmn, mfg_name);

  if (init_cb)
    init_cb(data);

  if (!finalize_payload(buffer, &oc_platform_payload))
    return NULL;

  return &oc_platform_payload;
}

void
oc_store_uri(const char *s_uri, oc_string_t *d_uri)
{
  if (s_uri[0] != '/') {
    size_t s_len = strlen(s_uri);
    oc_alloc_string(d_uri, s_len + 2);
    memcpy((char *)oc_string(*d_uri) + 1, s_uri, s_len);
    ((char *)oc_string(*d_uri))[0] = '/';
    ((char *)oc_string(*d_uri))[s_len + 1] = '\0';
  } else
    oc_new_string(d_uri, s_uri, strlen(s_uri));
}

void
oc_core_populate_resource(int core_resource, int device_index, const char *uri,
                          oc_interface_mask_t interfaces,
                          oc_interface_mask_t default_interface,
                          oc_resource_properties_t properties,
                          oc_request_callback_t get, oc_request_callback_t put,
                          oc_request_callback_t post,
                          oc_request_callback_t delete, int num_resource_types,
                          ...)
{
  oc_resource_t *r = &core_resources[core_resource];
  r->device = device_index;
  oc_store_uri(uri, &r->uri);
  r->properties = properties;
  va_list rt_list;
  int i;
  va_start(rt_list, num_resource_types);
  oc_new_string_array(&r->types, num_resource_types);
  for (i = 0; i < num_resource_types; i++) {
    oc_string_array_add_item(r->types, va_arg(rt_list, const char *));
  }
  va_end(rt_list);
  r->interfaces = interfaces;
  r->default_interface = default_interface;
  r->get_handler.cb = get;
  r->put_handler.cb = put;
  r->post_handler.cb = post;
  r->delete_handler.cb = delete;
}

oc_uuid_t *
oc_core_get_device_id(int device)
{
  return &oc_device_info[device].uuid;
}

oc_resource_t *
oc_core_get_resource_by_index(int type)
{
  return &core_resources[type];
}

oc_resource_t *
oc_core_get_resource_by_uri(const char *uri)
{
  int i, num_core_resources = oc_core_get_num_resources();
  for (i = 0; i < num_core_resources; i++) {
    if (oc_string_len(core_resources[i].uri) == strlen(uri) &&
        strncmp(uri, oc_string(core_resources[i].uri), strlen(uri)) == 0)
      return &core_resources[i];
  }
  return NULL;
}
