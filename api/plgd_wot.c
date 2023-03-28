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

  char href[32 + 6 + 256];
  memset(href, 0, sizeof(href));
  size_t len = strlen(scheme_host);
  memcpy(href, scheme_host, strlen(scheme_host));
  memcpy(href + len, oc_string(resource->uri), oc_string_len(resource->uri));
  oc_rep_set_text_string(links, href, href);
  oc_rep_end_object((links_array), links);
}

static void
process_wot_response(CborEncoder *links_array, oc_resource_t *resource,
                     oc_endpoint_t *endpoint)
{
  (void)endpoint;
  if (!(resource->properties & OC_DISCOVERABLE)) {
    return;
  }

  char scheme_host[256];
  memset(scheme_host, 0, sizeof(scheme_host));
  memcpy(scheme_host, "ocf://", 6);
  oc_uuid_to_str(oc_core_get_device_id(resource->device), scheme_host + 6,
                 OC_UUID_LEN);
  process_wot_response_set_link(links_array, resource, scheme_host);
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
      process_wot_response_set_link(links_array, resource, oc_string(ep));
      oc_free_string(&ep);
    }
  }
#ifdef OC_OSCORE
  if (resource->properties & OC_SECURE_MCAST) {
#ifdef OC_IPV4
    process_wot_response_set_link(links_array, resource,
                                  "coap://224.0.1.187:5683");
#endif /* OC_IPV4 */
    process_wot_response_set_link(links_array, resource,
                                  "coap://[ff02::158]:5683");
  }
#endif /* OC_OSCORE */
}

static void
process_wot_request(CborEncoder *links_array, oc_endpoint_t *endpoint,
                    size_t device_index)
{
  process_wot_response(links_array, oc_core_get_resource_by_index(OCF_P, 0),
                       endpoint);
  process_wot_response(
    links_array, oc_core_get_resource_by_index(OCF_D, device_index), endpoint);

  process_wot_response(
    links_array,
    oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, device_index),
    endpoint);

  if (oc_get_con_res_announced()) {
    process_wot_response(links_array,
                         oc_core_get_resource_by_index(OCF_CON, device_index),
                         endpoint);
  }

#ifdef OC_MNT
  process_wot_response(links_array,
                       oc_core_get_resource_by_index(OCF_MNT, device_index),
                       endpoint);
#endif /* OC_MNT */

#ifdef OC_SOFTWARE_UPDATE
  process_wot_response(
    links_array, oc_core_get_resource_by_index(OCF_SW_UPDATE, device_index),
    endpoint);
#endif /* OC_SOFTWARE_UPDATE */

#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  process_wot_response(
    links_array, oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, device_index),
    endpoint);
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */

#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {
    if (resource->device != device_index)
      continue;
    process_wot_response(links_array, resource, endpoint);
  }

#endif /* OC_SERVER */
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
  oc_rep_set_text_string(root, title,
                         oc_string(oc_core_get_device_info(device_index)->name));
  CborEncoder encoder;
  oc_rep_set_array(root, links);
  memcpy(&encoder, oc_rep_get_encoder(), sizeof(CborEncoder));
  process_wot_request(&links_array, request->origin, device_index);
  memcpy(oc_rep_get_encoder(), &encoder, sizeof(CborEncoder));
  oc_rep_close_array(root, links);

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static
void wot_init(size_t device) {
  oc_resource_t *root_wot =
    oc_new_resource("Root WoT", "/.well-known/wot", 1, device);
  oc_resource_bind_resource_type(root_wot, "wot.thing");
  oc_resource_bind_resource_interface(root_wot, OC_IF_R | OC_IF_LL);
  oc_resource_set_default_interface(root_wot, OC_IF_LL);
  oc_resource_set_discoverable(root_wot, true);
  oc_resource_set_request_handler(root_wot, OC_GET, wot_root_get, NULL);
  oc_add_resource(root_wot);
}

void plgd_wot_init() {
  for (size_t device = 0; device < oc_core_get_num_devices(); ++device) {
    wot_init(device);
  }
}

#endif /* OC_HAS_FEATURE_PLGD_WOT */