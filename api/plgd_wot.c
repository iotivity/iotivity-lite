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
#include "plgd_wot_internal.h"

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
                              const char *scheme_host)
{
  oc_rep_start_object((links_array), links);
  oc_rep_set_text_string(links, rel, "item");
  oc_rep_set_text_string(links, type, "application/vnd.ocf+cbor");

  char href[512];
  memset(href, 0, sizeof(href));
  memcpy(href, scheme_host, strlen(scheme_host));
  memcpy(href + strlen(href), oc_string(resource->uri),
         oc_string_len(resource->uri));
  oc_rep_set_text_string(links, href, href);
  oc_rep_set_text_string(links, query, "if=" PLGD_IF_WOT_TD_STR);
  oc_rep_end_object((links_array), links);
}

typedef enum oc_wot_operation_t {
  readAllProperties = 1 << 1,
  writeMultipleProperties = 1 << 2,
  observeAllProperties = 1 << 3,
} oc_wot_operation_t;

static void
process_wot_response_set_form(CborEncoder *forms_array, oc_resource_t *resource,
                              const char *scheme_host)
{
  oc_rep_start_object((forms_array), forms);
  oc_rep_set_text_string(forms, rel, "item");
  oc_rep_set_text_string(forms, type, "application/vnd.ocf+cbor");

  char href[512];
  memset(href, 0, sizeof(href));
  memcpy(href, scheme_host, strlen(scheme_host));
  memcpy(href + strlen(href), oc_string(resource->uri),
         oc_string_len(resource->uri));

  size_t op_size = 0;
  oc_wot_operation_t op_flags = 0;
  if (resource->properties & OC_OBSERVABLE) {
    op_size += 2;
    op_flags |= observeAllProperties;
  }
  if (resource->get_handler.cb) {
    op_size += 1;
    op_flags |= readAllProperties;
  }
  if (resource->put_handler.cb || resource->post_handler.cb) {
    op_size += 1;
    op_flags |= writeMultipleProperties;
  }
  oc_string_array_t op;
  oc_new_string_array(&op, op_size);
  if (op_flags & readAllProperties) {
    oc_string_array_add_item(op, "readallproperties");
  }
  if (op_flags & writeMultipleProperties) {
    oc_string_array_add_item(op, "writemultipleproperties");
  }
  if (op_flags & observeAllProperties) {
    oc_string_array_add_item(op, "observeallproperties");
    oc_string_array_add_item(op, "unobserveallproperties");
  }
  oc_rep_set_string_array(forms, op, op);
  oc_free_string_array(&op);
  oc_rep_set_text_string(forms, href, href);
  oc_rep_end_object((forms_array), forms);
}

typedef void (*set_endpoint_cbk_t)(CborEncoder *links_array,
                                   oc_resource_t *resource,
                                   const char *scheme_host);

  static void process_wot_response_set_endpoint_cbk(CborEncoder *links_array,
                                                    oc_resource_t *resource,
                                                    oc_endpoint_t *endpoint,
                                                    set_endpoint_cbk_t cbk)
{
  char scheme_host[256];
  memset(scheme_host, 0, sizeof(scheme_host));
  memcpy(scheme_host, "ocf://", 6);
  oc_uuid_to_str(oc_core_get_device_id(resource->device), scheme_host + 6,
                 OC_UUID_LEN);
  cbk(links_array, resource, scheme_host);
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
      cbk(links_array, resource, oc_string(ep));
      oc_free_string(&ep);
    }
  }
#ifdef OC_OSCORE
  if (resource->properties & OC_SECURE_MCAST) {
#ifdef OC_IPV4
    cbk(links_array, resource, "coap://224.0.1.187:5683");
#endif /* OC_IPV4 */
    cbk(links_array, resource, "coap://[ff02::158]:5683");
  }
#endif /* OC_OSCORE */
}

typedef struct
{
  CborEncoder *array;
  oc_endpoint_t *endpoint;
  set_endpoint_cbk_t endpoint_cbk;
} iterate_over_all_resources_cbk_data_t;

static bool
iterate_over_all_resources_cbk(oc_resource_t *resource, void *data)
{
  iterate_over_all_resources_cbk_data_t *cbk_data =
    (iterate_over_all_resources_cbk_data_t *)data;
  process_wot_response_set_endpoint_cbk(
    cbk_data->array, resource, cbk_data->endpoint, cbk_data->endpoint_cbk);
  return true;
}

static void
process_wot_request(CborEncoder *links_array, oc_endpoint_t *endpoint,
                    size_t device_index)
{
  iterate_over_all_resources_cbk_data_t data = {
    .array = links_array,
    .endpoint = endpoint,
    .endpoint_cbk = process_wot_response_set_link
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
}

void
plgd_wot_get_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
                void *data)
{
  (void)iface_mask;
  (void)data;
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
  CborEncoder encoder;
  oc_rep_set_array(root, forms);
  memcpy(&encoder, oc_rep_get_encoder(), sizeof(CborEncoder));
  process_wot_response_set_endpoint_cbk(&forms_array, request->resource, request->origin,
                                        process_wot_response_set_form);
  memcpy(oc_rep_get_encoder(), &encoder, sizeof(CborEncoder));
  oc_rep_close_array(root, forms);
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
wot_init(size_t device)
{
  oc_resource_t *root_wot =
    oc_new_resource("Root WoT", "/.well-known/wot", 1, device);
  oc_resource_bind_resource_type(root_wot, "wot.thing");
  oc_resource_bind_resource_interface(root_wot, PLGD_IF_WOT_TD);
  oc_resource_set_default_interface(root_wot, OC_IF_BASELINE);
  oc_resource_set_discoverable(root_wot, true);
  oc_resource_set_request_handler(root_wot, OC_GET, wot_root_get, NULL);
  oc_add_resource(root_wot);
}

void
plgd_wot_init()
{
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    wot_init(device);
  }
}

#endif /* OC_HAS_FEATURE_PLGD_WOT */