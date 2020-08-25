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

#include "messaging/coap/engine.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/separate.h"
#include "oc_api.h"

#ifdef OC_SECURITY
#include "security/oc_store.h"
#endif /* OC_SECURITY */

#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
#include "oc_collection.h"
#endif /* OC_COLLECTIONS && OC_SERVER */

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#include "oc_core_res.h"

static size_t query_iterator;

int
oc_add_device(const char *uri, const char *rt, const char *name,
              const char *spec_version, const char *data_model_version,
              oc_add_device_cb_t add_device_cb, void *data)
{
  if (!oc_core_add_new_device(uri, rt, name, spec_version, data_model_version,
                              add_device_cb, data))
    return -1;
  return 0;
}

int
oc_init_platform(const char *mfg_name, oc_init_platform_cb_t init_platform_cb,
                 void *data)
{
  if (!oc_core_init_platform(mfg_name, init_platform_cb, data))
    return -1;
  return 0;
}

int
oc_get_query_value(oc_request_t *request, const char *key, char **value)
{
  if (!request)
    return -1;
  return oc_ri_get_query_value(request->query, request->query_len, key, value);
}

static int
response_length(void)
{
  int size = oc_rep_get_encoded_payload_size();
  return (size <= 2) ? 0 : size;
}

void
oc_send_response(oc_request_t *request, oc_status_t response_code)
{
#ifdef OC_SPEC_VER_OIC
  if (request->origin && request->origin->version == OIC_VER_1_1_0) {
    request->response->response_buffer->content_format = APPLICATION_CBOR;
  } else
#endif /* OC_SPEC_VER_OIC */
  {
    request->response->response_buffer->content_format =
      APPLICATION_VND_OCF_CBOR;
  }
  request->response->response_buffer->response_length =
    (uint16_t)response_length();
  request->response->response_buffer->code = oc_status_code(response_code);
}

void
oc_ignore_request(oc_request_t *request)
{
  request->response->response_buffer->code = OC_IGNORE;
}

void
oc_set_immutable_device_identifier(size_t device, oc_uuid_t *piid)
{
  if (piid && device < oc_core_get_num_devices()) {
    oc_device_info_t *info = oc_core_get_device_info(device);
    if (info) {
#ifdef OC_SECURITY
      oc_sec_load_unique_ids(device);
#endif /* OC_SECURITY */
      memcpy(info->piid.id, piid->id, sizeof(oc_uuid_t));
#ifdef OC_SECURITY
      oc_sec_dump_unique_ids(device);
#endif /* OC_SECURITY */
    }
  }
}

void
oc_set_delayed_callback(void *cb_data, oc_trigger_t callback, uint16_t seconds)
{
  oc_ri_add_timed_event_callback_seconds(cb_data, callback, seconds);
}

void
oc_remove_delayed_callback(void *cb_data, oc_trigger_t callback)
{
  oc_ri_remove_timed_event_callback(cb_data, callback);
}

void
oc_resource_tag_pos_desc(oc_resource_t *resource, oc_pos_description_t pos)
{
  resource->tag_pos_desc = pos;
}

void
oc_resource_tag_pos_rel(oc_resource_t *resource, double x, double y, double z)
{
  resource->tag_pos_rel[0] = x;
  resource->tag_pos_rel[1] = y;
  resource->tag_pos_rel[2] = z;
}

void
oc_resource_tag_func_desc(oc_resource_t *resource, oc_enum_t func)
{
  resource->tag_func_desc = func;
}

void
oc_process_baseline_interface(oc_resource_t *resource)
{
  if (oc_string_len(resource->name) > 0) {
    oc_rep_set_text_string(root, n, oc_string(resource->name));
  }
  oc_rep_set_string_array(root, rt, resource->types);
  oc_core_encode_interfaces_mask(oc_rep_object(root), resource->interfaces);
  if (resource->tag_pos_desc > 0) {
    const char *desc = oc_enum_pos_desc_to_str(resource->tag_pos_desc);
    if (desc) {
      oc_rep_set_text_string(root, tag-pos-desc, desc);
    }
  }
  if (resource->tag_func_desc > 0) {
    const char *func = oc_enum_to_str(resource->tag_func_desc);
    if (func) {
      oc_rep_set_text_string(root, tag-func-desc, func);
    }
  }
  double *pos = resource->tag_pos_rel;
  if (pos[0] != 0 || pos[1] != 0 || pos[2] != 0) {
    oc_rep_set_key(oc_rep_object(root), "tag-pos-rel");
    oc_rep_start_array(oc_rep_object(root), tag_pos_rel);
    oc_rep_add_double(tag_pos_rel, pos[0]);
    oc_rep_add_double(tag_pos_rel, pos[1]);
    oc_rep_add_double(tag_pos_rel, pos[2]);
    oc_rep_end_array(oc_rep_object(root), tag_pos_rel);
  }
}

void
oc_init_query_iterator(void)
{
  query_iterator = 0;
}

int
oc_iterate_query(oc_request_t *request, char **key, size_t *key_len,
                 char **value, size_t *value_len)
{
  query_iterator++;
  return oc_ri_get_query_nth_key_value(request->query, request->query_len, key,
                                       key_len, value, value_len,
                                       query_iterator);
}

bool
oc_iterate_query_get_values(oc_request_t *request, const char *key,
                            char **value, int *value_len)
{
  char *current_key = 0;
  size_t key_len = 0, v_len;
  int pos = 0;

  do {
    pos = oc_iterate_query(request, &current_key, &key_len, value, &v_len);
    *value_len = (int)v_len;
    if (pos != -1 && strlen(key) == key_len &&
        memcmp(key, current_key, key_len) == 0) {
      goto more_or_done;
    }
  } while (pos != -1);

  *value_len = -1;

more_or_done:
  if (pos == -1 || (size_t)pos >= request->query_len) {
    return false;
  }
  return true;
}

#ifdef OC_SERVER

bool
oc_get_request_payload_raw(oc_request_t *request, const uint8_t **payload,
                           size_t *size, oc_content_format_t *content_format)
{
  if (!request || !payload || !size || !content_format) {
    return false;
  }
  if (request->_payload && request->_payload_len > 0) {
    *content_format = request->content_format;
    *payload = request->_payload;
    *size = request->_payload_len;
    return true;
  }
  return false;
}

void
oc_send_response_raw(oc_request_t *request, const uint8_t *payload, size_t size,
                     oc_content_format_t content_format,
                     oc_status_t response_code)
{
  request->response->response_buffer->content_format = content_format;
  memcpy(request->response->response_buffer->buffer, payload, size);
  request->response->response_buffer->response_length = (uint16_t)size;
  request->response->response_buffer->code = oc_status_code(response_code);
}

void
oc_send_diagnostic_message(oc_request_t *request, const char *msg,
                           size_t msg_len, oc_status_t response_code)
{
  oc_send_response_raw(request, (const uint8_t *)msg, msg_len, TEXT_PLAIN,
                       response_code);
}

static void
oc_populate_resource_object(oc_resource_t *resource, const char *name,
                            const char *uri, uint8_t num_resource_types,
                            size_t device)
{
  if (name) {
    oc_new_string(&resource->name, name, strlen(name));
  } else {
    memset(&resource->name, 0, sizeof(oc_string_t));
  }
  oc_store_uri(uri, &resource->uri);
  oc_new_string_array(&resource->types, num_resource_types);
  resource->properties = 0;
  resource->device = device;

#ifdef OC_SECURITY
  resource->properties |= OC_SECURE;
#endif /* OC_SECURITY */
}

oc_resource_t *
oc_new_resource(const char *name, const char *uri, uint8_t num_resource_types,
                size_t device)
{
  oc_resource_t *resource = oc_ri_alloc_resource();
  if (resource) {
    resource->interfaces = OC_IF_BASELINE;
    resource->default_interface = OC_IF_BASELINE;
    resource->observe_period_seconds = 0;
    resource->num_observers = 0;
    oc_populate_resource_object(resource, name, uri, num_resource_types,
                                device);
  }
  return resource;
}

#if defined(OC_COLLECTIONS)
oc_resource_t *
oc_new_collection(const char *name, const char *uri, uint8_t num_resource_types,
                  size_t device)
{
  oc_collection_t *collection = oc_collection_alloc();
  if (collection) {
    collection->interfaces = OC_IF_BASELINE | OC_IF_LL | OC_IF_B;
    collection->default_interface = OC_IF_LL;
    oc_populate_resource_object((oc_resource_t *)collection, name, uri,
                                num_resource_types, device);
  }
  return (oc_resource_t *)collection;
}

void
oc_delete_collection(oc_resource_t *collection)
{
  oc_collection_free((oc_collection_t *)collection);
}

void
oc_add_collection(oc_resource_t *collection)
{
  oc_resource_set_observable(collection, true);
  oc_collection_add((oc_collection_t *)collection);
}

oc_resource_t *
oc_collection_get_collections(void)
{
  return (oc_resource_t *)oc_collection_get_all();
}
#endif /* OC_COLLECTIONS */

void
oc_resource_bind_resource_interface(oc_resource_t *resource,
                                    oc_interface_mask_t iface_mask)
{
  resource->interfaces |= iface_mask;
}

void
oc_resource_set_default_interface(oc_resource_t *resource,
                                  oc_interface_mask_t iface_mask)
{
  resource->default_interface = iface_mask;
}

void
oc_resource_bind_resource_type(oc_resource_t *resource, const char *type)
{
  oc_string_array_add_item(resource->types, (char *)type);
}

#ifdef OC_SECURITY
void
oc_resource_make_public(oc_resource_t *resource)
{
  resource->properties &= ~OC_SECURE;
}
#endif /* OC_SECURITY */

void
oc_resource_set_discoverable(oc_resource_t *resource, bool state)
{
  if (state)
    resource->properties |= OC_DISCOVERABLE;
  else
    resource->properties &= ~OC_DISCOVERABLE;
}

void
oc_resource_set_observable(oc_resource_t *resource, bool state)
{
  if (state)
    resource->properties |= OC_OBSERVABLE;
  else
    resource->properties &= ~(OC_OBSERVABLE | OC_PERIODIC);
}

void
oc_resource_set_periodic_observable(oc_resource_t *resource, uint16_t seconds)
{
  resource->properties |= OC_OBSERVABLE | OC_PERIODIC;
  resource->observe_period_seconds = seconds;
}

void
oc_resource_set_properties_cbs(oc_resource_t *resource,
                               oc_get_properties_cb_t get_properties,
                               void *get_props_user_data,
                               oc_set_properties_cb_t set_properties,
                               void *set_props_user_data)
{
  resource->get_properties.cb.get_props = get_properties;
  resource->get_properties.user_data = get_props_user_data;
  resource->set_properties.cb.set_props = set_properties;
  resource->set_properties.user_data = set_props_user_data;
}

void
oc_resource_set_request_handler(oc_resource_t *resource, oc_method_t method,
                                oc_request_callback_t callback, void *user_data)
{
  oc_request_handler_t *handler = NULL;
  switch (method) {
  case OC_GET:
    handler = &resource->get_handler;
    break;
  case OC_POST:
    handler = &resource->post_handler;
    break;
  case OC_PUT:
    handler = &resource->put_handler;
    break;
  case OC_DELETE:
    handler = &resource->delete_handler;
    break;
  default:
    break;
  }

  if (handler) {
    handler->cb = callback;
    handler->user_data = user_data;
  }
}

void
oc_set_con_write_cb(oc_con_write_cb_t callback)
{
  size_t i;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    oc_resource_t *res = oc_core_get_resource_by_index(OCF_CON, i);
    if (res) {
      res->post_handler.user_data = *(void **)(&callback);
    }
  }
}

bool
oc_add_resource(oc_resource_t *resource)
{
  return oc_ri_add_resource(resource);
}

bool
oc_delete_resource(oc_resource_t *resource)
{
  return oc_ri_delete_resource(resource);
}

void
oc_indicate_separate_response(oc_request_t *request,
                              oc_separate_response_t *response)
{
  request->response->separate_response = response;
  oc_send_response(request, OC_STATUS_OK);
}

void
oc_set_separate_response_buffer(oc_separate_response_t *handle)
{
#ifdef OC_BLOCK_WISE
  oc_rep_new(handle->buffer, OC_MAX_APP_DATA_SIZE);
#else  /* OC_BLOCK_WISE */
  oc_rep_new(handle->buffer, OC_BLOCK_SIZE);
#endif /* !OC_BLOCK_WISE */
}

void
oc_send_separate_response(oc_separate_response_t *handle,
                          oc_status_t response_code)
{
  oc_response_buffer_t response_buffer;
  response_buffer.buffer = handle->buffer;
  response_buffer.response_length = (uint16_t)response_length();
  response_buffer.code = oc_status_code(response_code);
  response_buffer.content_format = APPLICATION_VND_OCF_CBOR;

  coap_separate_t *cur = oc_list_head(handle->requests), *next = NULL;
  coap_packet_t response[1];

  while (cur != NULL) {
    next = cur->next;
    if (cur->observe < 3) {
      coap_transaction_t *t =
        coap_new_transaction(coap_get_mid(), &cur->endpoint);
      if (t) {
        coap_separate_resume(response, cur,
                             (uint8_t)oc_status_code(response_code), t->mid);
        coap_set_header_content_format(response,
                                       response_buffer.content_format);

#ifdef OC_BLOCK_WISE
        oc_blockwise_state_t *response_state = NULL;
#ifdef OC_TCP
        if (!(cur->endpoint.flags & TCP) &&
            response_buffer.response_length > cur->block2_size) {
#else  /* OC_TCP */
        if (response_buffer.response_length > cur->block2_size) {
#endif /* !OC_TCP */
          response_state = oc_blockwise_find_response_buffer(
            oc_string(cur->uri), oc_string_len(cur->uri), &cur->endpoint,
            cur->method, NULL, 0, OC_BLOCKWISE_SERVER);
          if (response_state) {
            if (response_state->payload_size ==
                response_state->next_block_offset) {
              oc_blockwise_free_response_buffer(response_state);
              response_state = NULL;
            } else {
              goto next_separate_request;
            }
          }
          response_state = oc_blockwise_alloc_response_buffer(
            oc_string(cur->uri), oc_string_len(cur->uri), &cur->endpoint,
            cur->method, OC_BLOCKWISE_SERVER);
          if (!response_state) {
            goto next_separate_request;
          }

          memcpy(response_state->buffer, response_buffer.buffer,
                 response_buffer.response_length);
          response_state->payload_size = response_buffer.response_length;

          uint32_t payload_size = 0;
          const void *payload = oc_blockwise_dispatch_block(
            response_state, 0, cur->block2_size, &payload_size);
          if (payload) {
            coap_set_payload(response, payload, payload_size);
            coap_set_header_block2(response, 0, 1, cur->block2_size);
            coap_set_header_size2(response, response_state->payload_size);
            oc_blockwise_response_state_t *bwt_res_state =
              (oc_blockwise_response_state_t *)response_state;
            coap_set_header_etag(response, bwt_res_state->etag, COAP_ETAG_LEN);
          }
        } else
#endif /* OC_BLOCK_WISE */
          if (response_buffer.response_length > 0) {
          coap_set_payload(response, handle->buffer,
                           response_buffer.response_length);
        }
        coap_set_status_code(response, response_buffer.code);
        t->message->length = coap_serialize_message(response, t->message->data);
        if (t->message->length > 0) {
          coap_send_transaction(t);
        } else {
          coap_clear_transaction(t);
        }
      }
    } else {
      oc_resource_t *resource = oc_ri_get_app_resource_by_uri(
        oc_string(cur->uri), oc_string_len(cur->uri), cur->endpoint.device);
      if (resource) {
        coap_notify_observers(resource, &response_buffer, &cur->endpoint);
      }
    }
#ifdef OC_BLOCK_WISE
  next_separate_request:
#endif /* OC_BLOCK_WISE */
    coap_separate_clear(handle, cur);
    cur = next;
  }
  handle->active = 0;
#ifdef OC_DYNAMIC_ALLOCATION
  free(handle->buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
}

int
oc_notify_observers(oc_resource_t *resource)
{
  return coap_notify_observers(resource, NULL, NULL);
}
#endif /* OC_SERVER */
