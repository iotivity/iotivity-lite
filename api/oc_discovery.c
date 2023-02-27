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

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif /* OC_CLIENT */

#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_discovery.h"
#include "oc_discovery_internal.h"
#include "oc_enums.h"

#ifdef OC_RES_BATCH_SUPPORT
#include "oc_server_api_internal.h"
#ifdef OC_SECURITY
#include "security/oc_acl_internal.h"
#endif /* OC_SECURITY */
#endif /* OC_RES_BATCH_SUPPORT */

#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
#include "oc_collection.h"
#endif /* OC_COLLECTIONS  && OC_SERVER */

#include "oc_core_res.h"
#include "oc_endpoint.h"

#ifdef OC_SECURITY
#include "security/oc_pstat.h"
#include "security/oc_sdi.h"
#include "security/oc_tls.h"
#endif

#ifdef WIN32
#include <windows.h>
#else /* !WIN32 */
#include <strings.h>
#endif /* WIN32 */

#ifdef OC_WKCORE
static size_t
clf_add_str_to_buffer(const char *str, size_t len)
{
  oc_rep_encode_raw((const uint8_t *)str, len);
  return len;
}

static size_t
clf_add_line_to_buffer(const char *line)
{
  size_t len = strlen(line);
  return clf_add_str_to_buffer(line, len);
}

#endif /* OC_WKCORE */

bool
oc_filter_out_ep_for_resource(const oc_endpoint_t *ep,
                              const oc_resource_t *resource,
                              const oc_endpoint_t *request_origin,
                              size_t device_index, bool owned_for_SVRs)
{
#ifndef OC_SECURITY
  (void)owned_for_SVRs;
#endif
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  if (((oc_sec_get_pstat(device_index))->s == OC_DOS_RFOTM) &&
      (resource->properties & OC_ACCESS_IN_RFOTM)) {
    return false;
  }
#else  /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  (void)device_index;
#endif /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  /*  If this resource has been explicitly tagged as SECURE on the
   *  application layer, skip all coap:// endpoints, and only include
   *  coaps:// endpoints.
   *  Also, exclude all endpoints that are not associated with the interface
   *  through which this request arrived. This is achieved by checking if the
   *  interface index matches.
   */
  if (((resource->properties & OC_SECURE
#ifdef OC_SECURITY
        || owned_for_SVRs
#endif /* OC_SECURITY */
        ) &&
       !(ep->flags & SECURED)) ||
      (request_origin && request_origin->interface_index != -1 &&
       request_origin->interface_index != ep->interface_index)) {
    return true;
  }
  if (request_origin &&
      (((request_origin->flags & IPV4) && (ep->flags & IPV6)) ||
       ((request_origin->flags & IPV6) && (ep->flags & IPV4)))) {
    return true;
  }
  return false;
}

static bool
filter_resource(const oc_resource_t *resource, const oc_request_t *request,
                const char *anchor, CborEncoder *links, size_t device_index)
{
  if (!oc_filter_resource_by_rt(resource, request)) {
    return false;
  }

  if (!(resource->properties & OC_DISCOVERABLE)) {
    return false;
  }

  oc_rep_start_object(links, link);

  // rel
  if (oc_core_get_resource_by_index(OCF_RES, resource->device) == resource) {
    oc_rep_set_array(link, rel);
    oc_rep_add_text_string(rel, "self");
    oc_rep_close_array(link, rel);
  }

  // anchor
  oc_rep_set_text_string(link, anchor, anchor);

  // uri
  oc_rep_set_text_string(link, href, oc_string(resource->uri));

  // rt
  oc_rep_set_array(link, rt);
  int i;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(resource->types);
       i++) {
    size_t size = oc_string_array_get_item_size(resource->types, i);
    const char *t = (const char *)oc_string_array_get_item(resource->types, i);
    if (size > 0)
      oc_rep_add_text_string(rt, t);
  }
  oc_rep_close_array(link, rt);

  // if
  oc_core_encode_interfaces_mask(oc_rep_object(link), resource->interfaces);

  // p
  oc_rep_set_object(link, p);
  oc_rep_set_uint(p, bm,
                  (uint8_t)(resource->properties & ~(OC_PERIODIC | OC_SECURE)));
  oc_rep_close_object(link, p);

  // eps
  oc_rep_set_array(link, eps);
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
    if (oc_filter_out_ep_for_resource(eps, resource, request->origin,
                                      device_index, owned_for_SVRs)) {
      continue;
    }
    oc_rep_object_array_start_item(eps);
    oc_string_t ep;
    if (oc_endpoint_to_string(eps, &ep) == 0) {
      oc_rep_set_text_string(eps, ep, oc_string(ep));
      oc_free_string(&ep);
    }
    if (oc_core_get_latency() > 0)
      oc_rep_set_uint(eps, lat, oc_core_get_latency());
    oc_rep_object_array_end_item(eps);
  }
#ifdef OC_OSCORE
  if (resource->properties & OC_SECURE_MCAST) {
    oc_rep_object_array_start_item(eps);
#ifdef OC_IPV4
    oc_rep_set_text_string(eps, ep, "coap://224.0.1.187:5683");
#endif /* OC_IPV4 */
    oc_rep_set_text_string(eps, ep, "coap://[ff02::158]:5683");
    oc_rep_object_array_end_item(eps);
  }
#endif /* OC_OSCORE */
  oc_rep_close_array(link, eps);

  // tag-pos-desc
  if (resource->tag_pos_desc > 0) {
    const char *desc = oc_enum_pos_desc_to_str(resource->tag_pos_desc);
    if (desc) {
      // clang-format off
      oc_rep_set_text_string(link, tag-pos-desc, desc);
      // clang-format on
    }
  }

  // tag-func-desc
  if (resource->tag_func_desc > 0) {
    const char *func = oc_enum_to_str(resource->tag_func_desc);
    if (func) {
      // clang-format off
      oc_rep_set_text_string(link, tag-func-desc, func);
      // clang-format on
    }
  }

  // tag-locn
  if (resource->tag_locn > 0) {
    const char *locn = oc_enum_locn_to_str(resource->tag_locn);
    if (locn) {
      // clang-format off
      oc_rep_set_text_string(link, tag-locn, locn);
      // clang-format on
    }
  }

  // tag-pos-rel
  const double *pos = resource->tag_pos_rel;
  if (pos[0] != 0 || pos[1] != 0 || pos[2] != 0) {
    oc_rep_set_key(oc_rep_object(link), "tag-pos-rel");
    oc_rep_start_array(oc_rep_object(link), tag_pos_rel);
    oc_rep_add_double(tag_pos_rel, pos[0]);
    oc_rep_add_double(tag_pos_rel, pos[1]);
    oc_rep_add_double(tag_pos_rel, pos[2]);
    oc_rep_end_array(oc_rep_object(link), tag_pos_rel);
  }

  oc_rep_end_object(links, link);

  return true;
}

static int
process_device_resources(CborEncoder *links, const oc_request_t *request,
                         size_t device_index)
{
  int matches = 0;
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, OC_UUID_LEN);
  oc_string_t anchor;
  oc_concat_strings(&anchor, "ocf://", uuid);

  if (filter_resource(oc_core_get_resource_by_index(OCF_P, 0), request,
                      oc_string(anchor), links, device_index))
    matches++;

  if (filter_resource(oc_core_get_resource_by_index(OCF_RES, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;

  if (filter_resource(oc_core_get_resource_by_index(OCF_D, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;

  if (filter_resource(
        oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, device_index),
        request, oc_string(anchor), links, device_index))
    matches++;

  if (oc_get_con_res_announced() &&
      filter_resource(oc_core_get_resource_by_index(OCF_CON, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;
#ifdef OC_MNT
  if (filter_resource(oc_core_get_resource_by_index(OCF_MNT, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;
#endif /* OC_MNT */
#ifdef OC_SOFTWARE_UPDATE
  if (filter_resource(
        oc_core_get_resource_by_index(OCF_SW_UPDATE, device_index), request,
        oc_string(anchor), links, device_index))
    matches++;
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_SECURITY
  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_DOXM, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;

  if (filter_resource(
        oc_core_get_resource_by_index(OCF_SEC_PSTAT, device_index), request,
        oc_string(anchor), links, device_index))
    matches++;

  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_ACL, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;

  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_AEL, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;

  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_CRED, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;

  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_SP, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;

#ifdef OC_PKI
  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_CSR, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;

  if (filter_resource(
        oc_core_get_resource_by_index(OCF_SEC_ROLES, device_index), request,
        oc_string(anchor), links, device_index))
    matches++;
#endif /* OC_PKI */

  if (filter_resource(oc_core_get_resource_by_index(OCF_SEC_SDI, device_index),
                      request, oc_string(anchor), links, device_index))
    matches++;

#endif /* OC_SECURITY */

#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  if (filter_resource(
        oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, device_index), request,
        oc_string(anchor), links, device_index))
    matches++;
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */

#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {
    if (resource->device != device_index ||
        !(resource->properties & OC_DISCOVERABLE))
      continue;

    if (filter_resource(resource, request, oc_string(anchor), links,
                        device_index))
      matches++;
  }

#if defined(OC_COLLECTIONS)
  oc_resource_t *collection = (oc_resource_t *)oc_collection_get_all();
  for (; collection; collection = collection->next) {
    if (collection->device != device_index ||
        !(collection->properties & OC_DISCOVERABLE))
      continue;

    if (filter_resource(collection, request, oc_string(anchor), links,
                        device_index))
      matches++;
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */

  oc_free_string(&anchor);

  return matches;
}

#ifdef OC_SPEC_VER_OIC
static bool
filter_oic_1_1_resource(oc_resource_t *resource, oc_request_t *request,
                        CborEncoder *links)
{
  if (!oc_filter_resource_by_rt(resource, request)) {
    return false;
  }

  if (!(resource->properties & OC_DISCOVERABLE)) {
    return false;
  }

  oc_rep_start_object(links, res);

  // uri
  oc_rep_set_text_string(res, href, oc_string(resource->uri));

  // rt
  oc_rep_set_array(res, rt);
  int i;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(resource->types);
       i++) {
    size_t size = oc_string_array_get_item_size(resource->types, i);
    const char *t = (const char *)oc_string_array_get_item(resource->types, i);
    if (size > 0)
      oc_rep_add_text_string(rt, t);
  }
  oc_rep_close_array(res, rt);

  // if
  oc_core_encode_interfaces_mask(oc_rep_object(res), resource->interfaces);

  // p
  oc_rep_set_object(res, p);
  oc_rep_set_uint(p, bm,
                  (uint8_t)(resource->properties & ~(OC_PERIODIC | OC_SECURE)));

#ifdef OC_SECURITY
  /** Tag all resources with sec=true for OIC 1.1 to pass the CTT script. */
  oc_rep_set_boolean(p, sec, true);
#endif /* OC_SECURITY */

  // port, x.org.iotivity.tcp and x.org.iotivity.tls
  oc_endpoint_t *eps = oc_connectivity_get_endpoints(resource->device);
  size_t device_index = resource->device;
#ifdef OC_SECURITY
  bool owned_for_SVRs =
    (oc_core_is_SVR(resource, device_index) &&
     (((oc_sec_get_pstat(device_index))->s != OC_DOS_RFOTM) ||
      oc_tls_num_peers(device_index) != 0));
#else  /* OC_SECURITY */
  bool owned_for_SVRs = false;
#endif /* OC_SECURITY */

  for (; eps != NULL; eps = eps->next) {
    if (oc_filter_out_ep_for_resource(eps, resource, request->origin,
                                      device_index, owned_for_SVRs)) {
      continue;
    }

#ifdef OC_TCP
    if (eps->flags & TCP) {
      if (eps->flags & SECURED) {
        if (request->origin->flags & IPV6 && eps->flags & IPV6) {
          oc_rep_set_uint(p, x.org.iotivity.tls, eps->addr.ipv6.port);
        }
#ifdef OC_IPV4
        else if (request->origin->flags & IPV4 && eps->flags & IPV4) {
          oc_rep_set_uint(p, x.org.iotivity.tls, eps->addr.ipv4.port);
        }
#endif /* OC_IPV4 */
      } else {
        if (request->origin->flags & IPV6 && eps->flags & IPV6) {
          oc_rep_set_uint(p, x.org.iotivity.tcp, eps->addr.ipv6.port);
        }
#ifdef OC_IPV4
        else if (request->origin->flags & IPV4 && eps->flags & IPV4) {
          oc_rep_set_uint(p, x.org.iotivity.tcp, eps->addr.ipv4.port);
        }
#endif /* OC_IPV4 */
      }
    } else
#endif /* OC_TCP */
      if (eps->flags & SECURED) {
        if (request->origin->flags & IPV6 && eps->flags & IPV6) {
          oc_rep_set_uint(p, port, eps->addr.ipv6.port);
        }
#ifdef OC_IPV4
        else if (request->origin->flags & IPV4 && eps->flags & IPV4) {
          oc_rep_set_uint(p, port, eps->addr.ipv4.port);
        }
#endif /* OC_IPV4 */
      }
  }

  oc_rep_close_object(res, p);

  oc_rep_end_object(links, res);
  return true;
}

static int
process_oic_1_1_device_object(CborEncoder *device, oc_request_t *request,
                              size_t device_num, bool baseline)
{
  int matches = 0;
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(device_num), uuid, OC_UUID_LEN);

  oc_rep_start_object(device, links);
  oc_rep_set_text_string(links, di, uuid);

  if (baseline) {
    oc_resource_t *ocf_res = oc_core_get_resource_by_index(OCF_RES, device_num);
    oc_rep_set_string_array(links, rt, ocf_res->types);
    oc_core_encode_interfaces_mask(oc_rep_object(links), ocf_res->interfaces);
  }

  oc_rep_set_array(links, links);

  if (filter_oic_1_1_resource(oc_core_get_resource_by_index(OCF_P, device_num),
                              request, oc_rep_array(links)))
    matches++;

  if (filter_oic_1_1_resource(oc_core_get_resource_by_index(OCF_D, device_num),
                              request, oc_rep_array(links)))
    matches++;

  /* oic.wk.con */
  if (oc_get_con_res_announced() &&
      filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_CON, device_num), request,
        oc_rep_array(links)))
    matches++;

#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {

    if (resource->device != device_num ||
        !(resource->properties & OC_DISCOVERABLE))
      continue;

    if (filter_oic_1_1_resource(resource, request, oc_rep_array(links)))
      matches++;
  }

#if defined(OC_COLLECTIONS)
  oc_resource_t *collection = (oc_resource_t *)oc_collection_get_all();
  for (; collection; collection = collection->next) {
    if (collection->device != device_num ||
        !(collection->properties & OC_DISCOVERABLE))
      continue;

    if (filter_oic_1_1_resource(collection, request, oc_rep_array(links)))
      matches++;
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */

#ifdef OC_SECURITY
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_DOXM, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_PSTAT, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_CRED, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_ACL, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_AEL, device_num), request,
        oc_rep_array(links)))
    matches++;

  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_SP, device_num), request,
        oc_rep_array(links)))
    matches++;
#ifdef OC_PKI
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_CSR, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_ROLES, device_num), request,
        oc_rep_array(links)))
    matches++;
#endif /* OC_PKI */
#endif

  if (filter_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, device_num),
        request, oc_rep_array(links)))
    matches++;

  oc_rep_close_array(links, links);
  oc_rep_end_object(device, links);

  return matches;
}

static void
oc_core_1_1_discovery_handler(oc_request_t *request,
                              oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  int matches = 0;
  size_t device;

  switch (iface_mask) {
  case OC_IF_LL: {
    oc_rep_start_links_array();
    for (device = 0; device < oc_core_get_num_devices(); device++) {
      matches += process_oic_1_1_device_object(oc_rep_array(links), request,
                                               device, false);
    }
    oc_rep_end_links_array();
  } break;
  case OC_IF_BASELINE: {
    oc_rep_start_links_array();
    for (device = 0; device < oc_core_get_num_devices(); device++) {
      matches += process_oic_1_1_device_object(oc_rep_array(links), request,
                                               device, true);
    }
    oc_rep_end_links_array();
  } break;
  default:
    break;
  }

  int response_length = oc_rep_get_encoded_payload_size();
  request->response->response_buffer->content_format = APPLICATION_CBOR;
  if (matches && response_length) {
    request->response->response_buffer->response_length = response_length;
    request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  } else if (request->origin && (request->origin->flags & MULTICAST) == 0) {
    request->response->response_buffer->code =
      oc_status_code(OC_STATUS_BAD_REQUEST);
  } else {
    request->response->response_buffer->code = OC_IGNORE;
  }
}
#endif /* OC_SPEC_VER_OIC */

#ifdef OC_RES_BATCH_SUPPORT
static void
process_batch_response(CborEncoder *links_array, oc_resource_t *resource,
                       oc_endpoint_t *endpoint)
{
  if (!(resource->properties & OC_DISCOVERABLE)) {
    return;
  }

  oc_request_t rest_request = { 0 };
  oc_response_t response = { 0 };
  oc_response_buffer_t response_buffer;
  response.response_buffer = &response_buffer;
  rest_request.response = &response;
  rest_request.origin = endpoint;
  rest_request.query = 0;
  rest_request.query_len = 0;
#ifdef OC_SECURITY
  if (oc_sec_check_acl(OC_GET, resource, endpoint)) {
#endif /* OC_SECURITY */
    oc_rep_start_object((links_array), links);

    char href[OC_MAX_OCF_URI_SIZE];
    memcpy(href, "ocf://", 6);
    oc_uuid_to_str(oc_core_get_device_id(resource->device), href + 6,
                   OC_UUID_LEN);
    memcpy(href + 6 + OC_UUID_LEN - 1, oc_string(resource->uri),
           oc_string_len(resource->uri));
    href[6 + OC_UUID_LEN - 1 + oc_string_len(resource->uri)] = '\0';

    oc_rep_set_text_string(links, href, href);
    oc_rep_set_key(oc_rep_object(links), "rep");
    memcpy(oc_rep_get_encoder(), &links_map, sizeof(CborEncoder));

    int size_before = oc_rep_get_encoded_payload_size();
    rest_request.resource = resource;
    response_buffer.code = 0;
    response_buffer.response_length = 0;

#if defined(OC_SERVER) && defined(OC_COLLECTIONS)
    if (oc_check_if_collection(resource)) {
      if (!oc_handle_collection_request(OC_GET, &rest_request,
                                        resource->default_interface, NULL)) {
        OC_WRN("failed to process batch response: failed to handle collection "
               "request");
      }
    } else
#endif /* OC_SERVER && OC_COLLECTIONS */
    {
      resource->get_handler.cb(&rest_request, resource->default_interface,
                               resource->get_handler.user_data);
    }

    int size_after = oc_rep_get_encoded_payload_size();
    if (size_before == size_after) {
      oc_rep_start_root_object();
      oc_rep_end_root_object();
    }
    memcpy(&links_map, oc_rep_get_encoder(), sizeof(CborEncoder));
    oc_rep_end_object((links_array), links);
#ifdef OC_SECURITY
  }
#endif /* OC_SECURITY */
}

void
oc_discovery_create_batch_for_resource(CborEncoder *links_array,
                                       oc_resource_t *resource,
                                       oc_endpoint_t *endpoint)
{
  process_batch_response(links_array, resource, endpoint);
}

static void
process_batch_request(CborEncoder *links_array, oc_endpoint_t *endpoint,
                      size_t device_index)
{
  process_batch_response(links_array, oc_core_get_resource_by_index(OCF_P, 0),
                         endpoint);
  process_batch_response(
    links_array, oc_core_get_resource_by_index(OCF_D, device_index), endpoint);

  process_batch_response(
    links_array,
    oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, device_index),
    endpoint);

  if (oc_get_con_res_announced()) {
    process_batch_response(links_array,
                           oc_core_get_resource_by_index(OCF_CON, device_index),
                           endpoint);
  }

#ifdef OC_MNT
  process_batch_response(links_array,
                         oc_core_get_resource_by_index(OCF_MNT, device_index),
                         endpoint);
#endif /* OC_MNT */

#ifdef OC_SOFTWARE_UPDATE
  process_batch_response(
    links_array, oc_core_get_resource_by_index(OCF_SW_UPDATE, device_index),
    endpoint);
#endif /* OC_SOFTWARE_UPDATE */

#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  process_batch_response(
    links_array, oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, device_index),
    endpoint);
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */

#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {
    if (resource->device != device_index)
      continue;
    process_batch_response(links_array, resource, endpoint);
  }

#if defined(OC_COLLECTIONS)
  oc_resource_t *collection = (oc_resource_t *)oc_collection_get_all();
  for (; collection; collection = collection->next) {
    if (collection->device != device_index)
      continue;

    process_batch_response(links_array, collection, endpoint);
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */
}
#endif /* OC_RES_BATCH_SUPPORT */

static void
oc_core_discovery_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
                          void *data)
{
  (void)data;

#ifdef OC_SPEC_VER_OIC
  if (request->origin && request->origin->version == OIC_VER_1_1_0) {
    oc_core_1_1_discovery_handler(request, iface_mask, data);
    return;
  }
#endif /* OC_SPEC_VER_OIC */

  int matches = 0;
  size_t device = request->resource->device;

  // for dev without SVRs, ignore queries for backward compatibility
#ifdef OC_SECURITY
  const char *q;
  int ql = oc_get_query_value(request, "sduuid", &q);
  if (ql > 0) {
    const oc_sec_sdi_t *s = oc_sec_get_sdi(device);
    if (s->priv) {
      oc_ignore_request(request);
      OC_DBG("private sdi");
      return;
    } else {
      char uuid[OC_UUID_LEN];
      oc_uuid_to_str(&s->uuid, uuid, OC_UUID_LEN);
      if (ql != (OC_UUID_LEN - 1)) {
        oc_ignore_request(request);
        OC_DBG("uuid mismatch: ql %d", ql);
        return;
      }
      if (strncasecmp(q, uuid, OC_UUID_LEN - 1) != 0) {
        oc_ignore_request(request);
        OC_DBG("uuid mismatch: %s", uuid);
        return;
      }
    }
  }
#endif

  switch (iface_mask) {
  case OC_IF_LL: {
    oc_rep_start_links_array();
    matches += process_device_resources(oc_rep_array(links), request, device);
    oc_rep_end_links_array();
  } break;
#ifdef OC_RES_BATCH_SUPPORT
  case OC_IF_B: {
    if (request->origin
#ifdef OC_SECURITY
        && request->origin->flags & SECURED
#endif /* OC_SECURITY */
    ) {
      CborEncoder encoder;
      oc_rep_start_links_array();
      memcpy(&encoder, oc_rep_get_encoder(), sizeof(CborEncoder));
      process_batch_request(&links_array, request->origin, device);
      memcpy(oc_rep_get_encoder(), &encoder, sizeof(CborEncoder));
      oc_rep_end_links_array();
      matches++;
    }
  } break;
#endif /* #ifdef OC_RES_BATCH_SUPPORT */
  case OC_IF_BASELINE: {
    oc_rep_start_links_array();
    oc_rep_start_object(oc_rep_array(links), props);
    memcpy(&root_map, &props_map, sizeof(CborEncoder));
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_RES, device));
#ifdef OC_SECURITY
    oc_sec_sdi_t *s = oc_sec_get_sdi(device);
    if (!s->priv) {
      char uuid[OC_UUID_LEN];
      oc_uuid_to_str(&s->uuid, uuid, OC_UUID_LEN);
      oc_rep_set_text_string(root, sduuid, uuid);
      oc_rep_set_text_string(root, sdname, oc_string(s->name));
    }
#endif
    oc_rep_set_array(root, links);
    matches += process_device_resources(oc_rep_array(links), request, device);
    oc_rep_close_array(root, links);
    memcpy(&props_map, &root_map, sizeof(CborEncoder));
    oc_rep_end_object(oc_rep_array(links), props);
    oc_rep_end_links_array();
  } break;
  default:
    break;
  }
  int response_length = oc_rep_get_encoded_payload_size();
  request->response->response_buffer->content_format = APPLICATION_VND_OCF_CBOR;
  if (matches && response_length > 0) {
    request->response->response_buffer->response_length = response_length;
    request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  } else if (request->origin && (request->origin->flags & MULTICAST) == 0) {
    request->response->response_buffer->code =
      oc_status_code(OC_STATUS_BAD_REQUEST);
  } else {
    request->response->response_buffer->code = OC_IGNORE;
  }
}

#ifdef OC_WKCORE
static void
oc_wkcore_discovery_handler(oc_request_t *request,
                            oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  (void)iface_mask;
  size_t response_length = 0;
  int matches = 0;

  /* check if the accept header is link-format */
  if (request->accept != APPLICATION_LINK_FORMAT) {
    request->response->response_buffer->code =
      oc_status_code(OC_STATUS_BAD_REQUEST);
    return;
  }

  const char *value = NULL;
  size_t value_len;
  const char *key;
  const char *rt_request = 0;
  int rt_len = 0;
  const char *rt_device = 0;
  int rt_devlen = 0;
  size_t key_len;

  oc_init_query_iterator();
  while (oc_iterate_query(request, &key, &key_len, &value, &value_len) > 0) {
    if (strncmp(key, "rt", key_len) == 0) {
      rt_request = value;
      rt_len = (int)value_len;
    }
  }

  if (rt_request != 0 && strncmp(rt_request, "oic.wk.res", rt_len) == 0) {
    /* request for all devices */
    matches = 1;
  }
  size_t device = request->resource->device;
  oc_resource_t *resource = oc_core_get_resource_by_uri("oic/d", device);
  int i;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(resource->types);
       i++) {
    size_t size = oc_string_array_get_item_size(resource->types, i);
    const char *t = (const char *)oc_string_array_get_item(resource->types, i);
    if (strncmp(t, "oic.d", 5) == 0) {
      /* take the first oic.d.xxx in the oic/d of the list of resource/device
       * types */
      rt_device = t;
      rt_devlen = size;
    }
  }

  if (rt_request != 0 && rt_device != 0 &&
      strncmp(rt_request, rt_device, rt_len) == 0) {
    /* request for specific device type */
    matches = 1;
  }

  if (matches > 0) {
    // create the following line:
    // <coap://[fe80::b1d6]:1111/oic/res>;ct=10000;rt="oic.wk.res
    // oic.d.sensor";if="oic.if.11 oic.if.baseline"

    size_t length = clf_add_line_to_buffer("<");
    response_length += length;

    oc_endpoint_t *eps =
      oc_connectivity_get_endpoints(request->resource->device);
    oc_string_t ep, uri;
    memset(&uri, 0, sizeof(oc_string_t));
    while (eps != NULL) {
      if (eps->flags & SECURED) {
        if (oc_endpoint_to_string(eps, &ep) == 0) {
          length = clf_add_str_to_buffer(oc_string(ep), oc_string_len(ep));
          response_length += length;
          oc_free_string(&ep);
          break;
        }
      }
      eps = eps->next;
    }

    length = clf_add_line_to_buffer("/oic/res>;");
    response_length += length;
    length = clf_add_line_to_buffer("rt=\"oic.wk.res ");
    response_length += length;
    length = clf_add_str_to_buffer(rt_device, rt_devlen);
    response_length += length;
    length = clf_add_line_to_buffer("\";");
    response_length += length;
    length =
      clf_add_line_to_buffer("if=\"oic.if.ll oic.if.baseline\";ct=10000");
    response_length += length;
  }

  request->response->response_buffer->content_format = APPLICATION_LINK_FORMAT;
  if (matches && response_length > 0) {
    request->response->response_buffer->response_length = response_length;
    request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  } else if (request->origin && (request->origin->flags & MULTICAST) == 0) {
    request->response->response_buffer->code =
      oc_status_code(OC_STATUS_BAD_REQUEST);
  } else {
    request->response->response_buffer->code = OC_IGNORE;
  }
}
#endif /* OC_WKCORE */

void
oc_create_discovery_resource(int resource_idx, size_t device)
{

#ifdef OC_WKCORE
  if (resource_idx == WELLKNOWNCORE) {

    oc_core_populate_resource(resource_idx, device, "/.well-known/core", 0, 0,
                              OC_DISCOVERABLE, oc_wkcore_discovery_handler, 0,
                              0, 0, 1, "wk");

    return;
  }
#endif /* OC_WKCORE */

  oc_core_populate_resource(resource_idx, device, "oic/res",
#ifdef OC_RES_BATCH_SUPPORT
                            OC_IF_B |
#endif /* OC_RES_BATCH_SUPPORT */
                              OC_IF_LL | OC_IF_BASELINE,
                            OC_IF_LL,
#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
                            OC_OBSERVABLE |
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */
                              OC_DISCOVERABLE,
                            oc_core_discovery_handler, 0, 0, 0, 1,
                            "oic.wk.res");
}

#ifdef OC_CLIENT
oc_discovery_flags_t
oc_ri_process_discovery_payload(const uint8_t *payload, int len,
                                oc_client_handler_t client_handler,
                                const oc_endpoint_t *endpoint, void *user_data)
{
  oc_discovery_handler_t handler = client_handler.discovery;
  oc_discovery_all_handler_t all_handler = client_handler.discovery_all;
  bool all = false;
  if (all_handler) {
    all = true;
  }
  oc_discovery_flags_t ret = OC_CONTINUE_DISCOVERY;
  oc_string_t *uri = NULL;
  oc_string_t *anchor = NULL;
  oc_string_array_t *types = NULL;
  oc_interface_mask_t iface_mask = 0;

  OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
  oc_rep_set_pool(&rep_objects);

  oc_rep_t *links = 0, *rep, *p;
  int s = oc_parse_rep(payload, len, &p);
  if (s != 0) {
    OC_WRN("error parsing discovery response");
  }
  links = rep = p;
  /*  While the oic.wk.res schema over the baseline interface provides for an
   *  array of objects, only one object is present and used in practice.
   *
   *  If rep->value.object != NULL, it means the response was from the baseline
   *  interface, and in that case make rep point to the properties of its first
   *  object. It is traversed in the following loop to obtain a handle to its
   *  array of links.
   */
  if (rep != NULL && rep->value.object) {
    rep = rep->value.object;
  }

  while (rep != NULL) {
    switch (rep->type) {
    /*  Ignore other oic.wk.res properties over here as they're known
     *  and fixed. Only process the "links" property.
     */
    case OC_REP_OBJECT_ARRAY: {
      if (oc_string_len(rep->name) == 5 &&
          memcmp(oc_string(rep->name), "links", 5) == 0) {
        links = rep->value.object_array;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }

  while (links != NULL) {
    /* Reset bm in every round as this can be omitted if 0. */
    oc_uuid_t di;
    oc_resource_properties_t bm = 0;
    oc_endpoint_t *eps_list = NULL;
    oc_rep_t *link = links->value.object;

    while (link != NULL) {
      switch (link->type) {
      case OC_REP_STRING: {
        if (oc_string_len(link->name) == 6 &&
            memcmp(oc_string(link->name), "anchor", 6) == 0) {
          anchor = &link->value.string;
          oc_str_to_uuid(oc_string(*anchor) + 6, &di);
        } else if (oc_string_len(link->name) == 4 &&
                   memcmp(oc_string(link->name), "href", 4) == 0) {
          uri = &link->value.string;
        }
      } break;
      case OC_REP_STRING_ARRAY: {
        size_t i;
        if (oc_string_len(link->name) == 2 &&
            strncmp(oc_string(link->name), "rt", 2) == 0) {
          types = &link->value.array;
        } else {
          iface_mask = 0;
          for (i = 0; i < oc_string_array_get_allocated_size(link->value.array);
               i++) {
            iface_mask |= oc_ri_get_interface_mask(
              oc_string_array_get_item(link->value.array, i),
              oc_string_array_get_item_size(link->value.array, i));
          }
        }
      } break;
      case OC_REP_OBJECT_ARRAY: {
        oc_rep_t *eps = link->value.object_array;
        oc_endpoint_t *eps_cur = NULL;
        oc_endpoint_t temp_ep;
        while (eps != NULL) {
          oc_rep_t *ep = eps->value.object;
          while (ep != NULL) {
            switch (ep->type) {
            case OC_REP_STRING: {
              if (oc_string_len(ep->name) == 2 &&
                  memcmp(oc_string(ep->name), "ep", 2) == 0) {
                if (oc_string_to_endpoint(&ep->value.string, &temp_ep, NULL) ==
                    0) {
                  if (!((temp_ep.flags & IPV6) &&
                        (temp_ep.addr.ipv6.port == 5683)) &&
#ifdef OC_IPV4
                      !((temp_ep.flags & IPV4) &&
                        (temp_ep.addr.ipv4.port == 5683)) &&
#endif /* OC_IPV4 */
                      !(temp_ep.flags & TCP) &&
                      (((endpoint->flags & IPV4) && (temp_ep.flags & IPV6)) ||
                       ((endpoint->flags & IPV6) && (temp_ep.flags & IPV4)))) {
                    goto next_ep;
                  }
                  if (eps_cur) {
                    eps_cur->next = oc_new_endpoint();
                    eps_cur = eps_cur->next;
                  } else {
                    eps_cur = eps_list = oc_new_endpoint();
                  }

                  if (eps_cur) {
                    memcpy(eps_cur, &temp_ep, sizeof(oc_endpoint_t));
                    eps_cur->next = NULL;
                    eps_cur->device = endpoint->device;
                    oc_endpoint_set_di(eps_cur, &di);
                    eps_cur->interface_index = endpoint->interface_index;
                    oc_endpoint_set_local_address(eps_cur,
                                                  endpoint->interface_index);
                    if (oc_ipv6_endpoint_is_link_local(eps_cur) == 0 &&
                        oc_ipv6_endpoint_is_link_local(endpoint) == 0) {
                      eps_cur->addr.ipv6.scope = endpoint->addr.ipv6.scope;
                    }
                    eps_cur->version = endpoint->version;
                  }
                }
              }
            } break;
            default:
              break;
            }
            ep = ep->next;
          }
        next_ep:
          eps = eps->next;
        }
      } break;
      case OC_REP_OBJECT: {
        oc_rep_t *policy = link->value.object;
        if (policy != NULL && oc_string_len(link->name) == 1 &&
            *(oc_string(link->name)) == 'p' && policy->type == OC_REP_INT &&
            oc_string_len(policy->name) == 2 &&
            memcmp(oc_string(policy->name), "bm", 2) == 0) {
          bm = policy->value.integer;
        }
      } break;
      default:
        break;
      }
      link = link->next;
    }

    if (eps_list &&
        (all ? all_handler(oc_string(*anchor), oc_string(*uri), *types,
                           iface_mask, eps_list, bm,
                           (links->next ? true : false), user_data)
             : handler(oc_string(*anchor), oc_string(*uri), *types, iface_mask,
                       eps_list, bm, user_data)) == OC_STOP_DISCOVERY) {
      oc_free_server_endpoints(eps_list);
      ret = OC_STOP_DISCOVERY;
      goto done;
    }
    oc_free_server_endpoints(eps_list);
    links = links->next;
  }

done:
  oc_free_rep(p);
#ifdef OC_DNS_CACHE
  oc_dns_clear_cache();
#endif /* OC_DNS_CACHE */
  return ret;
}
#endif /* OC_CLIENT */
