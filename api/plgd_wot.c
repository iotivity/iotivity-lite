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

#include "oc_core_res.h"
#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_core_res_internal.h"
#include "oc_discovery.h"
#include "oc_introspection_internal.h"
#include "oc_rep.h"
#include "oc_ri_internal.h"
#include "oc_main.h"
#include "port/oc_assert.h"
#include "util/oc_atomic.h"
#include "util/oc_compiler.h"
#include "util/oc_features.h"
#include "oc_discovery_internal.h"
#include "plgd_wot.h"
#include "plgd_wot_internal.h"
#include "oc_json_to_cbor_internal.h"

#ifdef OC_HAS_FEATURE_PLGD_WOT

#ifdef OC_CLOUD
#include "api/cloud/oc_cloud_resource_internal.h"
#endif /* OC_CLOUD */

#ifdef OC_MNT
#include "api/oc_mnt_internal.h"
#endif /* OC_MNT */

#ifdef OC_SECURITY
#include "security/oc_doxm.h"
#include "security/oc_pstat.h"
#include "security/oc_tls.h"
#endif /* OC_SECURITY */

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include "oc_endpoint.h"
#include <stdlib.h>

static void
process_wot_response_set_link(CborEncoder *links_array, oc_resource_t *resource,
                              const char *scheme_host, void* user_data)
{
  (void) user_data;
  if ((resource->interfaces & PLGD_IF_WOT_TD) == 0) {
    return;
  }
  oc_rep_start_object((links_array), links);
  oc_rep_set_text_string(links, rel, "item");
  oc_rep_set_text_string(links, type, "application/json");

  char href[512];
  memset(href, 0, sizeof(href));
  memcpy(href, scheme_host, strlen(scheme_host));
  memcpy(href + strlen(href), oc_string(resource->uri),
         oc_string_len(resource->uri));
  memcpy(href + strlen(href), "?if=" PLGD_IF_WOT_TD_STR, strlen("?if=" PLGD_IF_WOT_TD_STR));
  oc_rep_set_text_string(links, href, href);
  oc_rep_end_object((links_array), links);
}

typedef enum oc_wot_operation_t {
  readProperty = 1 << 0,
  writeProperty = 1 << 1,
  observeProperty = 1 << 2,
  readAllProperties = 1 << 3,
  writeMultipleProperties = 1 << 4,
  observeAllProperties = 1 << 5,
} oc_wot_operation_t;


static void
process_wot_response_set_form(CborEncoder *forms_array, oc_resource_t *resource,
                              const char *scheme_host, oc_wot_operation_t op_flags)
{
  char href[512];
  memset(href, 0, sizeof(href));
  memcpy(href, scheme_host, strlen(scheme_host));
  memcpy(href + strlen(href), oc_string(resource->uri),
         oc_string_len(resource->uri));

  struct form_s {
    oc_wot_operation_t op_flag;
    const char **op;
    size_t op_len;
    const char *cov_method;
    const char *subprotocol;
  } forms [] = {
    {
      .op_flag = readProperty,
      .op = (const char *[]){ "readproperty"},
      .op_len = 1,
      .cov_method = "GET",
    },
    {
      .op_flag = writeProperty,
      .op = (const char *[]){ "writeproperty"},
      .op_len = 1,
      .cov_method = "POST",
    },
    {
      .op_flag = observeProperty,
      .op = (const char *[]){ "observeproperty", "unobserveproperty"},
      .op_len = 2,
      .cov_method = "GET",
      .subprotocol = "cov:observe",
    },
    {
      .op_flag = readAllProperties,
      .op = (const char *[]){ "readallproperties"},
      .op_len = 1,
      .cov_method = "GET",
    },
    {
      .op_flag = writeMultipleProperties,
      .op = (const char *[]){ "writemultipleproperties"},
      .op_len = 1,
      .cov_method = "POST",
    },
    {
      .op_flag = observeAllProperties,
      .op = (const char *[]){ "observeallproperties", "unobserveallproperties"},
      .op_len = 2,
      .cov_method = "GET",
      .subprotocol = "cov:observe",
    },
  };
  while (op_flags != 0) {
    oc_rep_start_object((forms_array), forms);
    oc_rep_set_text_string(forms, type, "application/vnd.ocf+cbor");
    oc_rep_set_text_string(forms, href, href);
    for (size_t i = 0; i < (sizeof(forms) / sizeof(forms[0])); ++i) {
      if (op_flags & forms[i].op_flag) {
        oc_string_array_t op;
        oc_new_string_array(&op, forms[i].op_len);
        for (size_t j = 0; j < forms[i].op_len; ++j) {
          oc_string_array_add_item(op, forms[i].op[j]);
        }
        oc_rep_set_string_array(forms, op, op);
        oc_free_string_array(&op);
        oc_rep_set_text_string(forms, cov:method, forms[i].cov_method);
        if (forms[i].subprotocol) {
          oc_rep_set_text_string(forms, subprotocol, forms[i].subprotocol);
        }
        op_flags &= ~forms[i].op_flag;
        break;
      }
    }
    oc_rep_end_object((forms_array), forms);
  }
}

static void
process_wot_response_set_form_all(CborEncoder *forms_array, oc_resource_t *resource,
                              const char *scheme_host, void *user_data)
{
  (void)user_data;
  oc_wot_operation_t op_flags = 0;
  if (resource->properties & OC_OBSERVABLE) {
    op_flags |= observeAllProperties;
  }
  if (resource->get_handler.cb) {
    op_flags |= readAllProperties;
  }
  if (resource->put_handler.cb || resource->post_handler.cb) {
    op_flags |= writeMultipleProperties;
  }
  process_wot_response_set_form(forms_array, resource, scheme_host, op_flags);
}

typedef void (*set_endpoint_cbk_t)(CborEncoder *links_array,
                                   oc_resource_t *resource,
                                   const char *scheme_host,
                                   void *user_data);

  static void process_wot_response_set_endpoint_cbk(CborEncoder *links_array,
                                                    oc_resource_t *resource,
                                                    oc_endpoint_t *endpoint,
                                                    set_endpoint_cbk_t cbk,
                                                    void *user_data)
{
  size_t device_index = resource->device;
  oc_endpoint_t *eps = oc_connectivity_get_endpoints(device_index);

#ifdef OC_SECURITY
  bool owned_for_SVRs =
    (oc_core_is_SVR(resource, device_index) &&
     (((oc_sec_get_pstat(device_index))->s != OC_DOS_RFOTM) ||
      oc_tls_num_peers(device_index) != 0));
#else  /* OC_SECURITY */
  bool owned_for_SVRs = false;
#endif /* OC_SECURITY */

  for (; eps != NULL; eps = eps->next) {
    if (oc_filter_out_ep_for_resource(eps, resource, endpoint, device_index,
                                      owned_for_SVRs)) {
      continue;
    }
    oc_string_t ep;
    if (oc_endpoint_to_string(eps, &ep) == 0) {
      cbk(links_array, resource, oc_string(ep), user_data);
      oc_free_string(&ep);
    }
  }
#ifdef OC_OSCORE
  if (resource->properties & OC_SECURE_MCAST) {
#ifdef OC_IPV4
    cbk(links_array, resource, "coap://224.0.1.187:5683", user_data);
#endif /* OC_IPV4 */
    cbk(links_array, resource, "coap://[ff02::158]:5683", user_data);
  }
#endif /* OC_OSCORE */
}

typedef struct
{
  CborEncoder *array;
  oc_endpoint_t *endpoint;
  set_endpoint_cbk_t endpoint_cbk;
  void *user_data;
} iterate_over_all_resources_cbk_data_t;

static bool
iterate_over_all_resources_cbk(oc_resource_t *resource, void *data)
{
  iterate_over_all_resources_cbk_data_t *cbk_data =
    (iterate_over_all_resources_cbk_data_t *)data;
  process_wot_response_set_endpoint_cbk(
    cbk_data->array, resource, cbk_data->endpoint, cbk_data->endpoint_cbk, cbk_data->user_data);
  return true;
}

static void
process_wot_request(CborEncoder *links_array, oc_endpoint_t *endpoint,
                    size_t device_index)
{
  iterate_over_all_resources_cbk_data_t data = {
    .array = links_array,
    .endpoint = endpoint,
    .endpoint_cbk = process_wot_response_set_link,
    .user_data = NULL,
  };

  oc_ri_iterate_over_all_resources(device_index, iterate_over_all_resources_cbk,
                                   &data);
}

static
void set_security(CborEncoder *obj_map)
{
  oc_rep_set_object(*obj, securityDefinitions);
  oc_rep_set_object(securityDefinitions, nosec_sc);
  oc_rep_set_text_string(nosec_sc, scheme, "nosec");
  oc_rep_close_object(securityDefinitions, nosec_sc);
  oc_rep_close_object(*obj, securityDefinitions);
  oc_rep_set_text_string(*obj, security, "nosec_sc");
}

static void
wot_root_get(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;
  size_t device_index = request->origin->device;
  oc_rep_encoder_set_encoder_type(OC_REP_JSON_ENCODER);
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, @context, "https://www.w3.org/2022/wot/td/v1.1");
  oc_rep_set_text_string(root, @type, "Thing");
  oc_rep_set_text_string(
    root, title, oc_string(oc_core_get_device_info(device_index)->name));
  set_security(&root_map);

  CborEncoder encoder;
  oc_rep_set_array(root, links);
  memcpy(&encoder, oc_rep_get_encoder(), sizeof(CborEncoder));
  process_wot_request(&links_array, request->origin, device_index);
  memcpy(oc_rep_get_encoder(), &encoder, sizeof(CborEncoder));
  oc_rep_close_array(root, links);

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
  request->response->response_buffer->content_format = APPLICATION_JSON;
}

void
plgd_wot_get_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
                void *data)
{
  (void)iface_mask;
  (void)data;
  oc_rep_encoder_set_encoder_type(OC_REP_JSON_ENCODER);
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, @context, "https://www.w3.org/2022/wot/td/v1.1");
  oc_rep_set_text_string(root, @type, "Thing");
  char title[64];
  memset(title, 0, 64);
  if (oc_string_len(request->resource->name) > 0) {
    snprintf(title, 64, "%s", oc_string(request->resource->name));
  } else {
    snprintf(title, 64, "%s", oc_string(request->resource->uri));
  }
  oc_rep_set_text_string(root, title, title);
  set_security(&root_map);

  // forms
  oc_rep_set_array(root, forms);
  process_wot_response_set_endpoint_cbk(&forms_array, request->resource, request->origin,
                                        process_wot_response_set_form_all, NULL);
  oc_rep_close_array(root, forms);

  if (request->resource->wot_extend_thing_description_handler.cb) {
    request->resource->wot_extend_thing_description_handler.cb(&root_map, request, request->resource->wot_extend_thing_description_handler.user_data);
  }

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
  request->response->response_buffer->content_format = APPLICATION_JSON;
}

typedef struct default_td_s {
  oc_core_resource_t id ;
  size_t properties_size;
  const plgd_wot_property_t *properties;
} default_td_t;

static plgd_wot_property_t default_device_properties[] = {
      {
        .name = "di",
        .type = PLGD_WOT_PROPERTY_TYPE_STRING,
        .description = "Device Identifier",
        .read_only = true,
      },
      { 
        .name = "piid",
        .type = PLGD_WOT_PROPERTY_TYPE_STRING,
        .read_only = true,
        .description = "Platform Instance Identifier"
      },
      {
        .name = "n",
        .type = PLGD_WOT_PROPERTY_TYPE_STRING,
        .read_only = true,
        .observable = true,
        .description = "Device Name"
      },
      { 
        .name = "icv",
        .type = PLGD_WOT_PROPERTY_TYPE_STRING,
        .read_only = true,
        .description = "Interoperability Specification Version"
      },
      {
        .name = "dmv",
        .type = PLGD_WOT_PROPERTY_TYPE_STRING,
        .read_only = true,
        .description = "Data Model Version"
      },
};

static plgd_wot_property_t default_platform_properties[] = {
    {
      .name = "pi",
      .type = PLGD_WOT_PROPERTY_TYPE_STRING,
      .read_only = true, 
      .description = "Unique identifier for the physical platform.",
    },
    {
      .name = "mnmn",
      .type = PLGD_WOT_PROPERTY_TYPE_STRING,
      .read_only = true, 
      .description = "Name of manufacturer."
    },
};

static plgd_wot_property_t default_device_configuration_properties[] = {
      {
        .name = "n",
        .type = PLGD_WOT_PROPERTY_TYPE_STRING,
        .observable = true,
        .description = "Device Name"
      },
};

static default_td_t default_td[] = {
  {
    .id = OCF_D,
    .properties = default_device_properties,
    .properties_size = sizeof(default_device_properties) / sizeof(plgd_wot_property_t),
  },
  {
    .id = OCF_P,
    .properties = default_platform_properties,
    .properties_size = sizeof(default_platform_properties) / sizeof(plgd_wot_property_t),
  },
  {
    .id = OCF_CON,
    .properties = default_device_configuration_properties,
    .properties_size = sizeof(default_device_configuration_properties) / sizeof(plgd_wot_property_t),
  }
};

static void set_properties_for_ocf_resources(CborEncoder* parent_map, const oc_request_t *request, void *data) {
  default_td_t *td = (default_td_t*)data;
  plgd_wot_resource_set_td_properties_num(parent_map, request, td->properties, td->properties_size);
}

void
plgd_wot_resource_set_td_properties(CborEncoder* parent_map, const oc_request_t *request, const plgd_wot_property_t *properties)
{
  size_t properties_size = 0;
  for (const plgd_wot_property_t* p = properties; p->name != NULL; p++  ) {
    ++properties_size;
  }
  plgd_wot_resource_set_td_properties_num(parent_map, request, properties, properties_size);
}

static void
wot_init(size_t device)
{
  oc_resource_t *root_wot =
    oc_new_resource("Root WoT", "/.well-known/wot", 1, device);
  oc_resource_bind_resource_type(root_wot, PLGD_WOT_THING_DESCRIPTION_RT);
  oc_resource_bind_resource_interface(root_wot, PLGD_IF_WOT_TD);
  oc_resource_set_default_interface(root_wot, OC_IF_BASELINE);
  oc_resource_set_discoverable(root_wot, true);
  oc_resource_set_request_handler(root_wot, OC_GET, wot_root_get, NULL);
  oc_add_resource(root_wot);

  for (size_t i = 0; i < sizeof(default_td) / sizeof(default_td_t); ++i) {
    size_t d = device;
    if (default_td[i].id == OCF_P) {
      d = 0;
    }
    oc_resource_t *resource = oc_core_get_resource_by_index(default_td[i].id, d);
    if (resource) {
      plgd_wot_resource_set_thing_description(resource, set_properties_for_ocf_resources, &default_td[i]);
    }
  }
}

void
plgd_wot_init()
{
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    wot_init(device);
  }
}

void plgd_wot_resource_set_thing_description(oc_resource_t* resource,  plgd_wot_extend_thing_description_cb_t cb, void* data)
{
  if (resource == NULL) {
    return;
  }
  bool add_rt = true;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(resource->types); i++) {
    if (oc_string_array_get_item_size(resource->types, i) == strlen(PLGD_WOT_THING_DESCRIPTION_RT) &&
        memcmp(oc_string_array_get_item(resource->types, i), PLGD_WOT_THING_DESCRIPTION_RT, strlen(PLGD_WOT_THING_DESCRIPTION_RT)) == 0) {
      add_rt = false;
      break;
    }
  }
  if (add_rt) {
      oc_string_array_t types;
      memcpy(&types, &resource->types, sizeof(oc_string_array_t));
      size_t num_types = oc_string_array_get_allocated_size(types);
      ++num_types;
      memset(&resource->types, 0, sizeof(oc_string_array_t));
      oc_new_string_array(&resource->types, num_types);
      for (size_t i = 0; i < num_types; i++) {
        if (i == 0) {
          oc_string_array_add_item(resource->types, PLGD_WOT_THING_DESCRIPTION_RT);
          continue;
        }
        oc_string_array_add_item(resource->types,
                                oc_string_array_get_item(types, (i - 1)));
      }
      oc_free_string_array(&types);
  }
  resource->wot_extend_thing_description_handler.cb = cb;
  resource->wot_extend_thing_description_handler.user_data = data;
  resource->interfaces |= PLGD_IF_WOT_TD;
  resource->wot_get_handler.cb = plgd_wot_get_handler;
}

const char* plgd_wot_property_str(plgd_wot_property_type_t p) {
  switch (p) {
    case PLGD_WOT_PROPERTY_TYPE_BOOLEAN:
      return "boolean";
    case PLGD_WOT_PROPERTY_TYPE_INTEGER:
      return "integer";
    case PLGD_WOT_PROPERTY_TYPE_NUMBER:
      return "double";
    case PLGD_WOT_PROPERTY_TYPE_STRING:
      return "string";
    case PLGD_WOT_PROPERTY_TYPE_OBJECT:
      return "object";
    case PLGD_WOT_PROPERTY_TYPE_ARRAY:
      return "array";
    case PLGD_WOT_PROPERTY_TYPE_NULL:
      return "null";
    default:
      return "unknown";
  }
}

static void
process_wot_response_set_form_property(CborEncoder *forms_array, oc_resource_t *resource,
                              const char *scheme_host, void *user_data)
{
  plgd_wot_property_t* property = (plgd_wot_property_t*)user_data;
  oc_wot_operation_t op_flags = 0;
  if (resource->properties & OC_OBSERVABLE && property->observable && resource->get_handler.cb && !property->write_only) {
    op_flags |= observeProperty;
  }
  if (resource->get_handler.cb && !property->write_only) {
    op_flags |= readProperty;
  }
  if ((resource->post_handler.cb || resource->put_handler.cb) && !property->read_only) {
    op_flags |= writeProperty;
  }
  process_wot_response_set_form(forms_array, resource, scheme_host, op_flags);
}

void plgd_wot_resource_set_td_properties_num(CborEncoder* parent_map, const oc_request_t *request, const plgd_wot_property_t* props, size_t props_count)
{
  if (props == NULL || props_count == 0) {
    return;
  }
  g_err |= oc_rep_encode_text_string(parent_map, "properties", strlen("properties"));
  oc_rep_begin_object(parent_map, properties);
  for (size_t i = 0; i < props_count; ++i) {
    g_err |= oc_rep_encode_text_string(&properties_map, props[i].name, strlen(props[i].name));
    oc_rep_begin_object(&properties_map, property);
    oc_rep_set_text_string(property, type, plgd_wot_property_str(PLGD_WOT_PROPERTY_TYPE_OBJECT));
    
    // ocf:property
    g_err |= oc_rep_encode_text_string(&property_map, "properties", strlen("properties"));
    oc_rep_begin_object(&property_map, property_properties);
    g_err |= oc_rep_encode_text_string(&property_properties_map, props[i].name, strlen(props[i].name));
    oc_rep_begin_object(&property_properties_map, property_properties_property);
    oc_rep_set_text_string(property_properties_property, type, plgd_wot_property_str(props[i].type));
    oc_rep_end_object(&property_properties_map, property_properties_property);
    oc_rep_end_object(&property_map, property_properties);
   
    if (props[i].description) {
      oc_rep_set_text_string(property, description, props[i].description);
    }
    if (props[i].observable && (request->resource->properties & OC_OBSERVABLE)) {
      oc_rep_set_boolean(property, observable, props[i].observable);
    }
    if (props[i].read_only) {
      oc_rep_set_boolean(property, readOnly, props[i].read_only);
    }
    if (props[i].write_only) {
      oc_rep_set_boolean(property, writeOnly, props[i].write_only);
    }
    oc_rep_set_array(property, forms);
    process_wot_response_set_endpoint_cbk(&forms_array, request->resource, request->origin,
                                        process_wot_response_set_form_property, (void*)&props[i]);
    oc_rep_close_array(property, forms);
    oc_rep_close_object(properties, property);
  }
  oc_rep_end_object(parent_map, properties);
}

#endif /* OC_HAS_FEATURE_PLGD_WOT */