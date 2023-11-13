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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "api/oc_core_res_internal.h"
#include "api/oc_main_internal.h"
#include "api/oc_message_internal.h"
#include "api/oc_platform_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_server_api_internal.h"
#include "messaging/coap/options_internal.h"
#include "messaging/coap/engine_internal.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/observe_internal.h"
#include "messaging/coap/separate_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "port/oc_log_internal.h"
#include "util/oc_features.h"
#include "util/oc_macros_internal.h"

#ifdef OC_SERVER
#include "api/oc_ri_server_internal.h"
#endif /* OC_SERVER */

#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
#include "api/oc_collection_internal.h"
#endif /* OC_COLLECTIONS && OC_SERVER */

#ifdef OC_HAS_FEATURE_ETAG
#include "api/oc_etag_internal.h"
#endif /* OC_HAS_FEATURE_ETAG */

#ifdef OC_SECURITY
#include "oc_store.h"
#endif /* OC_SECURITY */

#include <assert.h>
#include <errno.h>
#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

static oc_send_response_cb_t g_oc_send_response_cb;

int
oc_add_device(const char *uri, const char *rt, const char *name,
              const char *spec_version, const char *data_model_version,
              oc_add_device_cb_t add_device_cb, void *data)
{
  oc_add_new_device_t cfg = {
    .uri = uri,
    .rt = rt,
    .name = name,
    .spec_version = spec_version,
    .data_model_version = data_model_version,
    .add_device_cb = add_device_cb,
    .add_device_cb_data = data,
  };
  memset(&cfg.ports, 0, sizeof(cfg.ports));
  return oc_add_device_v1(cfg);
}

int
oc_add_device_v1(oc_add_new_device_t cfg)
{
  return oc_core_add_new_device(cfg) == NULL ? -1 : 0;
}

int
oc_init_platform(const char *mfg_name, oc_init_platform_cb_t init_platform_cb,
                 void *data)
{
  return oc_platform_init(mfg_name, init_platform_cb, data) == NULL ? -1 : 0;
}

static int
response_length(void)
{
  int size = oc_rep_get_encoded_payload_size();
  return (size <= 2) ? 0 : size;
}

void
oc_set_send_response_callback(oc_send_response_cb_t cb)
{
  g_oc_send_response_cb = cb;
}

#ifdef OC_HAS_FEATURE_ETAG

int
oc_set_send_response_etag(oc_request_t *request, const uint8_t *etag,
                          uint8_t etag_len)
{
  assert(etag != NULL);
  if (request->method != OC_GET || etag_len > COAP_ETAG_LEN) {
    OC_ERR("invalid input parameters");
    return -EINVAL;
  }
  memcpy(&request->response->response_buffer->etag.value[0], &etag[0],
         etag_len);
  request->response->response_buffer->etag.length = etag_len;
  return 0;
}

#endif /* OC_HAS_FEATURE_ETAG */

static void
oc_trigger_send_response_callback(oc_request_t *request,
                                  oc_status_t response_code)
{
  if (g_oc_send_response_cb == NULL) {
    return;
  }
  g_oc_send_response_cb(request, response_code);
}

/** CoAP codes properly handled by the messaging layer */
static bool
is_valid_coap_status_code(coap_status_t code)
{
  return (code >= COAP_NO_ERROR && code < MEMORY_ALLOCATION_ERROR) ||
         code == CLEAR_TRANSACTION;
}

bool
oc_send_response_internal(oc_request_t *request, oc_status_t response_code,
                          oc_content_format_t content_format,
                          size_t response_length, bool trigger_cb)
{
  int status_code = oc_status_code(response_code);
  if (status_code < 0) {
    request->response->response_buffer->code = CLEAR_TRANSACTION;
    return false;
  }
  request->response->response_buffer->content_format = content_format;
  request->response->response_buffer->response_length = response_length;
  request->response->response_buffer->code = (coap_status_t)status_code;
  if (trigger_cb) {
    oc_trigger_send_response_callback(request, response_code);
    if (!is_valid_coap_status_code(request->response->response_buffer->code)) {
      OC_ERR(
        "could not send response: invalid response code(%d) set by external "
        "callback",
        (int)request->response->response_buffer->code);
      request->response->response_buffer->code = CLEAR_TRANSACTION;
      return false;
    }
  }
  return true;
}

void
oc_send_response_with_callback(oc_request_t *request, oc_status_t response_code,
                               bool trigger_cb)
{
  if (!request) {
    return;
  }

  // if no accept header is present, use APPLICATION_VND_OCF_CBOR
  oc_content_format_t content_format = APPLICATION_VND_OCF_CBOR;
  if (request->response->response_buffer->content_format ==
        APPLICATION_NOT_DEFINED &&
      request->accept != APPLICATION_NOT_DEFINED) {
    content_format = request->accept;
  }
#ifdef OC_SPEC_VER_OIC
  if (request->origin && request->origin->version == OIC_VER_1_1_0) {
    content_format = APPLICATION_CBOR;
  }
#endif /* OC_SPEC_VER_OIC */
  if (!oc_send_response_internal(request, response_code, content_format,
                                 response_length(), trigger_cb)) {
    OC_ERR("could not send response: invalid response code");
  }
}

void
oc_send_response(oc_request_t *request, oc_status_t response_code)
{
  oc_send_response_with_callback(request, response_code, false);
}

void
oc_ignore_request(oc_request_t *request)
{
  // oc_status_code(OC_IGNORE) = CLEAR_TRANSACTION
  request->response->response_buffer->code = CLEAR_TRANSACTION;
}

void
oc_set_immutable_device_identifier(size_t device, const oc_uuid_t *piid)
{
  if (piid == NULL) {
    OC_ERR("cannot set immutable device identifier: invalid piid");
    return;
  }
  oc_device_info_t *info = oc_core_get_device_info(device);
  if (info == NULL) {
    OC_ERR("cannot set immutable device identifier: invalid device");
    return;
  }
#ifdef OC_SECURITY
  oc_sec_load_unique_ids(device);
#endif /* OC_SECURITY */
  memcpy(info->piid.id, piid->id, sizeof(oc_uuid_t));
#ifdef OC_SECURITY
  oc_sec_dump_unique_ids(device);
#endif /* OC_SECURITY */
}

void
oc_set_delayed_callback(void *cb_data, oc_trigger_t callback, uint16_t seconds)
{
  oc_ri_add_timed_event_callback_seconds(cb_data, callback, seconds);
}

void
oc_set_delayed_callback_ms(void *cb_data, oc_trigger_t callback,
                           uint16_t milliseconds)
{
  oc_set_delayed_callback_ms_v1(cb_data, callback, (uint64_t)milliseconds);
}

void
oc_set_delayed_callback_ms_v1(void *cb_data, oc_trigger_t callback,
                              uint64_t milliseconds)
{
  oc_clock_time_t ticks = milliseconds * OC_CLOCK_SECOND / 1000;
  oc_ri_add_timed_event_callback_ticks(cb_data, callback, ticks);
}

void
oc_reset_delayed_callback(void *cb_data, oc_trigger_t callback,
                          uint16_t seconds)
{
  oc_reset_delayed_callback_ms(cb_data, callback, seconds * 1000UL);
}

void
oc_reset_delayed_callback_ms(void *cb_data, oc_trigger_t callback,
                             uint64_t milliseconds)
{
  oc_remove_delayed_callback(cb_data, callback);
  oc_set_delayed_callback_ms_v1(cb_data, callback, milliseconds);
}

bool
oc_has_delayed_callback(const void *cb_data, oc_trigger_t callback,
                        bool ignore_cb_data)
{
  return oc_ri_has_timed_event_callback(cb_data, callback, ignore_cb_data);
}

void
oc_remove_delayed_callback_by_filter(oc_trigger_t cb,
                                     oc_ri_timed_event_filter_t filter,
                                     const void *filter_data, bool match_all,
                                     oc_ri_timed_event_on_delete_t on_delete)
{
  oc_ri_remove_timed_event_callback_by_filter(cb, filter, filter_data,
                                              match_all, on_delete);
}

void
oc_remove_delayed_callback(const void *cb_data, oc_trigger_t callback)
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
oc_resource_tag_locn(oc_resource_t *resource, oc_locn_t locn)
{
  resource->tag_locn = locn;
}

static void
resource_encode_name(CborEncoder *object, const char *name, size_t name_len)
{
  if (name != NULL) {
    g_err |= oc_rep_object_set_text_string(
      object, OC_BASELINE_PROP_NAME, OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_NAME),
      name, name_len);
  }
}

static void
resource_encode_tag_pos_desc(CborEncoder *object,
                             oc_pos_description_t tag_pos_desc)
{
  if (tag_pos_desc == 0) {
    return;
  }
  const char *desc = oc_enum_pos_desc_to_str(tag_pos_desc);
  if (desc == NULL) {
    return;
  }
  /* tag-pos-desc will be handled as a string */
  g_err |= oc_rep_object_set_text_string(
    object, OC_BASELINE_PROP_TAG_POS_DESC,
    OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_TAG_POS_DESC), desc, strlen(desc));
}

static void
resource_encode_tag_func_desc(CborEncoder *object, oc_enum_t tag_func_desc)
{
  if (tag_func_desc == 0) {
    return;
  }
  const char *func = oc_enum_to_str(tag_func_desc);
  if (func == NULL) {
    return;
  }
  /* tag-func-desc will be handled as a string */
  g_err |= oc_rep_object_set_text_string(
    object, OC_BASELINE_PROP_FUNC_DESC,
    OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_FUNC_DESC), func, strlen(func));
}

static void
resource_encode_tag_locn(CborEncoder *object, oc_locn_t tag_locn)
{
  if (tag_locn == 0) {
    return;
  }
  const char *locn = oc_enum_locn_to_str(tag_locn);
  if (locn == NULL) {
    return;
  }
  /* tag-locn will be handled as a string */
  g_err |= oc_rep_object_set_text_string(
    object, OC_BASELINE_PROP_TAG_LOCN,
    OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_TAG_LOCN), locn, strlen(locn));
}

static void
resource_encode_tag_pos_rel(CborEncoder *object, const double pos[3])
{
  if (pos[0] != 0 || pos[1] != 0 || pos[2] != 0) {
    oc_rep_set_key(object, "tag-pos-rel");
    oc_rep_start_array(object, tag_pos_rel);
    oc_rep_add_double(tag_pos_rel, pos[0]);
    oc_rep_add_double(tag_pos_rel, pos[1]);
    oc_rep_add_double(tag_pos_rel, pos[2]);
    oc_rep_end_array(object, tag_pos_rel);
  }
}

void
oc_process_baseline_interface_with_filter(
  CborEncoder *object, const oc_resource_t *resource,
  oc_process_baseline_interface_filter_fn_t filter, void *filter_data)
{
  if (filter == NULL || filter(OC_BASELINE_PROP_NAME, filter_data)) {
    resource_encode_name(object, oc_string(resource->name),
                         oc_string_len(resource->name));
  }
  if (filter == NULL || filter(OC_BASELINE_PROP_RT, filter_data)) {
    g_err |= oc_rep_object_set_string_array(
      object, OC_BASELINE_PROP_RT, OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_RT),
      &resource->types);
  }
  if (filter == NULL || filter(OC_BASELINE_PROP_IF, filter_data)) {
    oc_core_encode_interfaces_mask(object, resource->interfaces, false);
  }
  if (filter == NULL || filter(OC_BASELINE_PROP_TAG_LOCN, filter_data)) {
    resource_encode_tag_locn(object, resource->tag_locn);
  }
  if (filter == NULL || filter(OC_BASELINE_PROP_TAG_POS_REL, filter_data)) {
    resource_encode_tag_pos_rel(object, resource->tag_pos_rel);
  }
  if (filter == NULL || filter(OC_BASELINE_PROP_TAG_POS_DESC, filter_data)) {
    resource_encode_tag_pos_desc(object, resource->tag_pos_desc);
  }
  if (filter == NULL || filter(OC_BASELINE_PROP_FUNC_DESC, filter_data)) {
    resource_encode_tag_func_desc(object, resource->tag_func_desc);
  }
}

void
oc_process_baseline_interface(const oc_resource_t *resource)
{
  oc_process_baseline_interface_with_filter(oc_rep_object(root), resource, NULL,
                                            NULL);
}

#ifdef OC_SERVER

bool
oc_get_request_payload_raw(const oc_request_t *request, const uint8_t **payload,
                           size_t *size, oc_content_format_t *content_format)
{
  if (!request || !payload || !size || !content_format) {
    OC_ERR("invalid input parameters");
    return false;
  }
  if (request->_payload != NULL && request->_payload_len > 0) {
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
  int status_code = oc_status_code(response_code);
  if (status_code < 0) {
    OC_ERR("invalid response code(%d)", (int)response_code);
    return;
  }
  request->response->response_buffer->content_format = content_format;
  memcpy(request->response->response_buffer->buffer, payload, size);
  request->response->response_buffer->response_length = size;
  request->response->response_buffer->code = (coap_status_t)status_code;
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
  if (num_resource_types > 0) {
    oc_new_string_array(&resource->types, num_resource_types);
  } else {
    memset(&resource->types, 0, sizeof(oc_string_array_t));
  }
  resource->properties = 0;
  resource->device = device;

#ifdef OC_SECURITY
  resource->properties |= OC_SECURE;
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_ETAG
  resource->etag = oc_etag_get();
#endif /* OC_HAS_FEATURE_ETAG */
}

oc_resource_t *
oc_new_resource(const char *name, const char *uri, uint8_t num_resource_types,
                size_t device)
{
  oc_resource_t *resource = oc_ri_alloc_resource();
  if (resource == NULL) {
    OC_ERR("cannot allocate new resource");
    return NULL;
  }
  resource->interfaces = OC_IF_BASELINE;
  resource->default_interface = OC_IF_BASELINE;
  resource->observe_period_seconds = 0;
  resource->num_observers = 0;
  oc_populate_resource_object(resource, name, uri, num_resource_types, device);
  return resource;
}

#if defined(OC_COLLECTIONS)
oc_resource_t *
oc_new_collection(const char *name, const char *uri, uint8_t num_resource_types,
                  size_t device)
{
  assert(uri != NULL);
  oc_resource_t *collection = (oc_resource_t *)oc_collection_alloc();
  if (collection == NULL) {
    return NULL;
  }
  collection->interfaces = OC_IF_BASELINE | OC_IF_LL | OC_IF_B;
  collection->default_interface = OC_IF_LL;
  oc_populate_resource_object(collection, name, uri, num_resource_types,
                              device);

  return collection;
}

void
oc_delete_collection(oc_resource_t *collection)
{
  oc_collection_free((oc_collection_t *)collection);
}

bool
oc_add_collection_v1(oc_resource_t *collection)
{
  if (!oc_collection_add((oc_collection_t *)collection)) {
    return false;
  }
  oc_resource_set_observable(collection, true);
  oc_notify_resource_added(collection);
  return true;
}

void
oc_add_collection(oc_resource_t *collection)
{
  if (!oc_add_collection_v1(collection)) {
    OC_ERR("failed to add collection");
  }
}

oc_resource_t *
oc_collection_get_collections(void)
{
  return (oc_resource_t *)oc_collection_get_all();
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
  oc_string_array_add_item(resource->types, type);
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

#ifdef OC_HAS_FEATURE_PUSH
void
oc_resource_set_pushable(oc_resource_t *resource, bool state)
{
  if (state)
    resource->properties |= OC_PUSHABLE;
  else
    resource->properties &= ~OC_PUSHABLE;
}
#endif /* OC_HAS_FEATURE_PUSH */

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

static oc_request_handler_t *
resource_get_request_handler(oc_resource_t *resource, oc_method_t method)
{
  if (method == OC_GET) {
    return &resource->get_handler;
  }
  if (method == OC_POST) {
    return &resource->post_handler;
  }
  if (method == OC_PUT) {
    return &resource->put_handler;
  }
  if (method == OC_DELETE) {
    return &resource->delete_handler;
  }
  return NULL;
}

void
oc_resource_set_request_handler(oc_resource_t *resource, oc_method_t method,
                                oc_request_callback_t callback, void *user_data)
{
  oc_request_handler_t *handler =
    resource_get_request_handler(resource, method);
  if (handler != NULL) {
    handler->cb = callback;
    handler->user_data = user_data;
  }
}

#ifdef OC_OSCORE
void
oc_resource_set_secure_mcast(oc_resource_t *resource, bool supported)
{
  if (resource) {
    if (supported) {
      resource->properties |= OC_SECURE_MCAST;
    } else {
      resource->properties &= ~OC_SECURE_MCAST;
    }
  }
}
#endif /* OC_OSCORE */

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
  oc_send_response_with_callback(request, OC_STATUS_OK, false);
}

void
oc_set_separate_response_buffer(oc_separate_response_t *handle)
{
#ifdef OC_BLOCK_WISE
  oc_rep_new_v1(handle->buffer, OC_MAX_APP_DATA_SIZE);
#else  /* OC_BLOCK_WISE */
  oc_rep_new_v1(handle->buffer, OC_BLOCK_SIZE);
#endif /* !OC_BLOCK_WISE */
}

static void
handle_separate_response_transaction(coap_transaction_t *t,
                                     coap_packet_t *response,
                                     uint8_t response_code)
{
  coap_set_status_code(response, response_code);
  t->message->length = coap_serialize_message(response, t->message->data,
                                              oc_message_buffer_size());
  if (t->message->length <= 0) {
    coap_clear_transaction(t);
    return;
  }
  coap_send_transaction(t);
}

static void
handle_separate_response_request(coap_separate_t *request,
                                 const oc_response_buffer_t *response_buffer)
{
  coap_packet_t response;
  coap_transaction_t *t = coap_new_transaction(
    coap_get_mid(), request->token, request->token_len, &request->endpoint);
  if (t == NULL) {
    return;
  }
  assert(response_buffer->code <= (int)UINT8_MAX);
  coap_separate_resume(&response, request, (uint8_t)response_buffer->code,
                       t->mid);
  coap_options_set_content_format(&response, response_buffer->content_format);

#ifdef OC_BLOCK_WISE
  oc_blockwise_state_t *response_state = NULL;
#ifdef OC_TCP
  bool blockwise = (request->endpoint.flags & TCP) == 0 &&
                   response_buffer->response_length > request->block2_size;
#else  /* !OC_TCP */
  bool blockwise = response_buffer->response_length > request->block2_size;
#endif /* OC_TCP */
  if (blockwise) {
    response_state = oc_blockwise_find_response_buffer(
      oc_string(request->uri), oc_string_len(request->uri), &request->endpoint,
      request->method, NULL, 0, OC_BLOCKWISE_SERVER);
    if (response_state != NULL) {
      if (response_state->payload_size != response_state->next_block_offset) {
        return;
      }
      oc_blockwise_free_response_buffer(response_state);
      response_state = NULL;
    }
    response_state = oc_blockwise_alloc_response_buffer(
      oc_string(request->uri), oc_string_len(request->uri), &request->endpoint,
      request->method, OC_BLOCKWISE_SERVER,
      (uint32_t)response_buffer->response_length, CONTENT_2_05, false);
    if (response_state == NULL) {
      return;
    }

    memcpy(response_state->buffer, response_buffer->buffer,
           response_buffer->response_length);
    response_state->payload_size = (uint32_t)response_buffer->response_length;

    uint32_t payload_size = 0;
    void *payload = oc_blockwise_dispatch_block(
      response_state, 0, request->block2_size, &payload_size);
    if (payload != NULL) {
      coap_set_payload(&response, payload, payload_size);
      coap_options_set_block2(&response, 0, 1, request->block2_size, 0);
      coap_options_set_size2(&response, response_state->payload_size);
      const oc_blockwise_response_state_t *bwt_res_state =
        (oc_blockwise_response_state_t *)response_state;
      if (bwt_res_state->etag.length > 0) {
        coap_options_set_etag(&response, bwt_res_state->etag.value,
                              bwt_res_state->etag.length);
      }
    }
    handle_separate_response_transaction(t, &response,
                                         (uint8_t)response_buffer->code);
    return;
  }
#endif /* OC_BLOCK_WISE */
  if (response_buffer->response_length > 0) {
    coap_set_payload(&response, response_buffer->buffer,
                     (uint32_t)response_buffer->response_length);
  }
  handle_separate_response_transaction(t, &response,
                                       (uint8_t)response_buffer->code);
}

static void
separate_response_clear(oc_separate_response_t *handle)
{
#ifdef OC_DYNAMIC_ALLOCATION
  free(handle->buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
  coap_separate_t *cur = oc_list_head(handle->requests);
  while (cur != NULL) {
    coap_separate_t *next = cur->next;
    coap_separate_clear(handle, cur);
    cur = next;
  }
}

void
oc_send_separate_response(oc_separate_response_t *handle,
                          oc_status_t response_code)
{
  int code = oc_status_code(response_code);
  if (code < 0) {
    OC_ERR("cannot send separate response: invalid response code(%d)",
           (int)response_code);
    separate_response_clear(handle);
    return;
  }
  oc_response_buffer_t response_buffer;
  response_buffer.buffer = handle->buffer;
  if (handle->len != 0) {
    response_buffer.response_length = handle->len;
  } else {
    response_buffer.response_length = response_length();
  }

  response_buffer.code = (coap_status_t)code;
  response_buffer.content_format = APPLICATION_VND_OCF_CBOR;

  coap_separate_t *cur = oc_list_head(handle->requests);
  while (cur != NULL) {
    coap_separate_t *next = cur->next;
    if (cur->observe < OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE) {
      handle_separate_response_request(cur, &response_buffer);
    } else {
      oc_resource_t *resource = oc_ri_get_app_resource_by_uri(
        oc_string(cur->uri), oc_string_len(cur->uri), cur->endpoint.device);
      if (resource != NULL) {
        coap_notify_observers(resource, &response_buffer, &cur->endpoint);
      }
    }
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
  assert(resource != NULL);
  if (!oc_main_initialized()) {
    return 0;
  }
  return coap_notify_observers(resource, NULL, NULL);
}

static oc_event_callback_retval_t
notify_observers_async(void *data)
{
  coap_notify_observers((oc_resource_t *)data, NULL, NULL);
  return OC_EVENT_DONE;
}

static void
oc_notify_observers_delayed_ticks(oc_resource_t *resource,
                                  oc_clock_time_t ticks)
{
  assert(resource != NULL);
  if (!coap_resource_is_observed(resource)) {
    return;
  }
  oc_remove_delayed_callback(resource, &notify_observers_async);
  oc_ri_add_timed_event_callback_ticks(resource, &notify_observers_async,
                                       ticks);
}

void
oc_notify_observers_delayed(oc_resource_t *resource, uint16_t seconds)
{
  oc_clock_time_t ticks = (oc_clock_time_t)seconds * OC_CLOCK_SECOND;
  oc_notify_observers_delayed_ticks(resource, ticks);
}

void
oc_notify_observers_delayed_ms(oc_resource_t *resource, uint16_t milliseconds)
{
  oc_clock_time_t ticks =
    (oc_clock_time_t)milliseconds * OC_CLOCK_SECOND / 1000;
  oc_notify_observers_delayed_ticks(resource, ticks);
}

static void
notify_resource_changed(oc_resource_t *resource)
{
#ifdef OC_HAS_FEATURE_ETAG
  oc_resource_update_etag(resource);
#endif /* OC_HAS_FEATURE_ETAG */
  oc_notify_observers(resource);
}

void
oc_notify_resource_changed(oc_resource_t *resource)
{
  assert(resource != NULL);
  if (!oc_main_initialized()) {
    return;
  }
  notify_resource_changed(resource);
}

static oc_event_callback_retval_t
notify_resource_changed_async(void *data)
{
  notify_resource_changed((oc_resource_t *)data);
  return OC_EVENT_DONE;
}

static void
notify_resource_changed_delayed_ms(oc_resource_t *resource,
                                   uint64_t milliseconds)
{
  oc_reset_delayed_callback_ms(resource, &notify_resource_changed_async,
                               milliseconds);
}

void
oc_notify_resource_changed_delayed_ms(oc_resource_t *resource,
                                      uint64_t milliseconds)
{
  assert(resource != NULL);
  if (!oc_main_initialized()) {
    return;
  }
  notify_resource_changed_delayed_ms(resource, milliseconds);
}

#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE

static oc_event_callback_retval_t
notify_resource_added_or_deleted_dispatch_async(void *data)
{
  size_t device = (size_t)data;
  oc_resource_t *discovery = oc_core_get_resource_by_index(OCF_RES, device);
  if (discovery != NULL) {
    // NOTE: order is important, notify_resource_changed must be executed before
    // coap_process_discovery_batch_observers because it will update the ETag of
    // the discovery resource; if the functions execute in the wrong order then
    // the batch response will contain an out-of-date ETag
    notify_resource_changed(discovery);
  }
#ifdef OC_RES_BATCH_SUPPORT
  coap_process_discovery_batch_observers();
#endif /* OC_RES_BATCH_SUPPORT */
  return OC_EVENT_DONE;
}

#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */

void
oc_notify_resource_added(oc_resource_t *resource)
{
#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
  if (!oc_main_initialized()) {
    return;
  }

  // dispatch must be delayed to avoid corrupting memory in case
  // oc_notify_resource_added is invoked from a request handler
#ifdef OC_RES_BATCH_SUPPORT
  coap_add_discovery_batch_observer(resource, /*removed*/ false,
                                    /*dispatch*/ false);
#endif /* OC_RES_BATCH_SUPPORT */
  oc_reset_delayed_callback((void *)resource->device,
                            notify_resource_added_or_deleted_dispatch_async, 0);
#else  /* !OC_DISCOVERY_RESOURCE_OBSERVABLE */
  (void)resource;
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */
}

void
oc_notify_resource_removed(oc_resource_t *resource)
{
#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
  if (!oc_main_initialized()) {
    return;
  }

  // dispatch must be delayed to avoid corrupting memory in case
  // oc_notify_resource_removed is invoked from a request handler
#ifdef OC_RES_BATCH_SUPPORT
  coap_remove_discovery_batch_observers(resource);
  coap_add_discovery_batch_observer(resource, /*removed*/ true,
                                    /*dispatch*/ false);
#endif /* OC_RES_BATCH_SUPPORT */
  oc_reset_delayed_callback((void *)resource->device,
                            notify_resource_added_or_deleted_dispatch_async, 0);

#else  /* !OC_DISCOVERY_RESOURCE_OBSERVABLE */
  (void)resource;
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */
}

void
oc_notify_clear(const oc_resource_t *resource)
{
  assert(resource != NULL);
  oc_remove_delayed_callback(resource, &notify_resource_changed_async);
  oc_remove_delayed_callback(resource, &notify_observers_async);
}

#endif /* OC_SERVER */
