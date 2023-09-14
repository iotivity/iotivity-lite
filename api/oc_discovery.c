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
#include "api/oc_discovery_internal.h"
#include "api/oc_endpoint_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_server_api_internal.h"
#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_enums.h"
#include "port/oc_log_internal.h"
#include "util/oc_features.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif /* OC_CLIENT */

#ifdef OC_SECURITY
#include "security/oc_pstat_internal.h"
#include "security/oc_sdi_internal.h"
#include "security/oc_tls_internal.h"
#ifdef OC_RES_BATCH_SUPPORT
#include "security/oc_acl_internal.h"
#endif /* OC_RES_BATCH_SUPPORT*/
#endif /* OC_SECURITY */

#if defined(OC_COLLECTIONS) && defined(OC_SERVER)
#include "api/oc_collection_internal.h"
#endif /* OC_COLLECTIONS  && OC_SERVER */

#ifdef OC_HAS_FEATURE_ETAG
#include "api/oc_etag_internal.h"
#endif /* OC_HAS_FEATURE_ETAG */

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
      (request_origin && request_origin->interface_index != 0 &&
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

static void
discovery_encode_endpoint(CborEncoder *eps, const oc_endpoint_t *ep,
                          int latency)
{
  oc_rep_begin_object(eps, ep);
  oc_string64_t ep_str;
  if (oc_endpoint_to_string64(ep, &ep_str)) {
    g_err |= oc_rep_encode_text_string(&ep_map, "ep", OC_CHAR_ARRAY_LEN("ep"));
    g_err |= oc_rep_encode_text_string(&ep_map, oc_string(ep_str),
                                       oc_string_len(ep_str));
  }
  if (latency > 0) {
    g_err |=
      oc_rep_encode_text_string(&ep_map, "lat", OC_CHAR_ARRAY_LEN("lat"));
    g_err |= oc_rep_encode_uint(&ep_map, (uint64_t)latency);
  }
  oc_rep_end_object(eps, ep);
}

static void
discovery_encode_endpoints(const oc_resource_t *resource,
                           const oc_request_t *request, size_t device_index,
                           CborEncoder *link)
{
  g_err |= oc_rep_encode_text_string(link, "eps", OC_CHAR_ARRAY_LEN("eps"));
  oc_rep_begin_array(link, eps);

  const oc_endpoint_t *eps = oc_connectivity_get_endpoints(device_index);
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
    discovery_encode_endpoint(oc_rep_array(eps), eps, oc_core_get_latency());
  }
#ifdef OC_OSCORE
  if ((resource->properties & OC_SECURE_MCAST) != 0) {
    oc_rep_object_array_start_item(eps);
#ifdef OC_IPV4
#define OC_IPV4_MCAST_ENDPOINT "coap://224.0.1.187:5683"
    oc_rep_set_text_string_v1(eps, ep, OC_IPV4_MCAST_ENDPOINT,
                              OC_CHAR_ARRAY_LEN(OC_IPV4_MCAST_ENDPOINT));
#undef OC_IPV4_MCAST_ENDPOINT
#endif /* OC_IPV4 */
#define OC_IPV6_MCAST_ENDPOINT "coap://[ff02::158]:5683"
    oc_rep_set_text_string_v1(eps, ep, OC_IPV6_MCAST_ENDPOINT,
                              OC_CHAR_ARRAY_LEN(OC_IPV6_MCAST_ENDPOINT));
#undef OC_IPV6_MCAST_ENDPOINT
    oc_rep_object_array_end_item(eps);
  }
#endif /* OC_OSCORE */
  oc_rep_end_array(link, eps);
}

static bool
process_resource(const oc_resource_t *resource, const oc_request_t *request,
                 const char *anchor, size_t anchor_len, CborEncoder *links)
{
  if (resource == NULL || !oc_filter_resource_by_rt(resource, request) ||
      (resource->properties & OC_DISCOVERABLE) == 0) {
    return false;
  }

  oc_rep_start_object(links, link);

  // rel
  if (oc_core_get_resource_by_index(OCF_RES, resource->device) == resource) {
    oc_rep_set_array(link, rel);
    oc_rep_add_text_string_v1(rel, "self", OC_CHAR_ARRAY_LEN("self"));
    oc_rep_close_array(link, rel);
  }

  // anchor
  oc_rep_set_text_string_v1(link, anchor, anchor, anchor_len);

  // uri
  oc_rep_set_text_string_v1(link, href, oc_string(resource->uri),
                            oc_string_len(resource->uri));

  // rt
  oc_rep_set_array(link, rt);
  for (size_t i = 0; i < oc_string_array_get_allocated_size(resource->types);
       ++i) {
    size_t size = oc_string_array_get_item_size(resource->types, i);
    const char *t = (const char *)oc_string_array_get_item(resource->types, i);
    if (size > 0) {
      oc_rep_add_text_string_v1(rt, t, size);
    }
  }
  oc_rep_close_array(link, rt);

  // if
  oc_core_encode_interfaces_mask(oc_rep_object(link), resource->interfaces);

  // p
  oc_rep_set_object(link, p);
  oc_rep_set_uint(p, bm,
                  (uint8_t)(resource->properties & OCF_RES_POLICY_PROPERTIES));
  oc_rep_close_object(link, p);

  size_t device_index = request->resource->device;
  // eps
  discovery_encode_endpoints(resource, request, device_index,
                             oc_rep_object(link));

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
process_device_core_resources(const oc_request_t *request, const char *anchor,
                              size_t anchor_len, CborEncoder *links)
{
  int matches = 0;
  if (process_resource(oc_core_get_resource_by_index(OCF_P, 0), request, anchor,
                       anchor_len, links)) {
    matches++;
  }
#ifdef OC_HAS_FEATURE_PLGD_TIME
  if (process_resource(oc_core_get_resource_by_index(PLGD_TIME, 0), request,
                       anchor, anchor_len, links)) {
    matches++;
  }
#endif /* OC_HAS_FEATURE_PLGD_TIME */
  size_t device_index = request->resource->device;
  if (process_resource(oc_core_get_resource_by_index(OCF_RES, device_index),
                       request, anchor, anchor_len, links)) {
    matches++;
  }
  if (process_resource(oc_core_get_resource_by_index(OCF_D, device_index),
                       request, anchor, anchor_len, links)) {
    matches++;
  }

#ifdef OC_INTROSPECTION
  if (process_resource(
        oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, device_index),
        request, anchor, anchor_len, links)) {
    matches++;
  }
#endif /* OC_INTROSPECTION */

  if (oc_get_con_res_announced() &&
      process_resource(oc_core_get_resource_by_index(OCF_CON, device_index),
                       request, anchor, anchor_len, links)) {
    matches++;
  }
#ifdef OC_MNT
  if (process_resource(oc_core_get_resource_by_index(OCF_MNT, device_index),
                       request, anchor, anchor_len, links)) {
    matches++;
  }
#endif /* OC_MNT */
#ifdef OC_SOFTWARE_UPDATE
  if (process_resource(
        oc_core_get_resource_by_index(OCF_SW_UPDATE, device_index), request,
        anchor, anchor_len, links)) {
    matches++;
  }
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_SECURITY
  if (process_resource(
        oc_core_get_resource_by_index(OCF_SEC_DOXM, device_index), request,
        anchor, anchor_len, links)) {
    matches++;
  }

  if (process_resource(
        oc_core_get_resource_by_index(OCF_SEC_PSTAT, device_index), request,
        anchor, anchor_len, links)) {
    matches++;
  }

  if (process_resource(oc_core_get_resource_by_index(OCF_SEC_ACL, device_index),
                       request, anchor, anchor_len, links)) {
    matches++;
  }

  if (process_resource(oc_core_get_resource_by_index(OCF_SEC_AEL, device_index),
                       request, anchor, anchor_len, links)) {
    matches++;
  }

  if (process_resource(
        oc_core_get_resource_by_index(OCF_SEC_CRED, device_index), request,
        anchor, anchor_len, links)) {
    matches++;
  }

  if (process_resource(oc_core_get_resource_by_index(OCF_SEC_SP, device_index),
                       request, anchor, anchor_len, links)) {
    matches++;
  }

#ifdef OC_PKI
  if (process_resource(oc_core_get_resource_by_index(OCF_SEC_CSR, device_index),
                       request, anchor, anchor_len, links)) {
    matches++;
  }

  if (process_resource(
        oc_core_get_resource_by_index(OCF_SEC_ROLES, device_index), request,
        anchor, anchor_len, links)) {
    matches++;
  }
#endif /* OC_PKI */

  if (process_resource(oc_core_get_resource_by_index(OCF_SEC_SDI, device_index),
                       request, anchor, anchor_len, links)) {
    matches++;
  }

#endif /* OC_SECURITY */

#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
  if (process_resource(
        oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, device_index), request,
        anchor, anchor_len, links)) {
    matches++;
  }
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */
  return matches;
}

static int
process_device_resources(CborEncoder *links, const oc_request_t *request)
{
  size_t device_index = request->resource->device;
  char anchor[OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF) + OC_UUID_LEN] = { 0 };
  // ocf://
  memcpy(anchor, OC_SCHEME_OCF, OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF));
  // uuid
  oc_uuid_to_str(oc_core_get_device_id(device_index),
                 anchor + OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF), OC_UUID_LEN);
  size_t anchor_len = oc_strnlen(anchor, OC_ARRAY_SIZE(anchor));

  int matches =
    process_device_core_resources(request, anchor, anchor_len, links);
#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {
    if (resource->device != device_index ||
        !(resource->properties & OC_DISCOVERABLE))
      continue;

    if (process_resource(resource, request, anchor, anchor_len, links)) {
      matches++;
    }
  }

#if defined(OC_COLLECTIONS)
  const oc_resource_t *collection = (oc_resource_t *)oc_collection_get_all();
  for (; collection; collection = collection->next) {
    if (collection->device != device_index ||
        !(collection->properties & OC_DISCOVERABLE))
      continue;

    if (process_resource(collection, request, anchor, anchor_len, links)) {
      matches++;
    }
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */
  return matches;
}

static void
send_response(oc_request_t *request, oc_content_format_t content_format,
              int matches, size_t response_length)
{
  oc_status_t code = OC_STATUS_OK;
  if (matches && response_length) {
    //  do nothing - response already set up
  } else if (request->origin && (request->origin->flags & MULTICAST) == 0) {
    code = OC_STATUS_BAD_REQUEST;
    response_length = 0;
  } else {
    code = OC_IGNORE;
    response_length = 0;
  }
  oc_send_response_internal(request, code, content_format, response_length,
                            code != OC_IGNORE);
}

#ifdef OC_SPEC_VER_OIC
static bool
process_oic_1_1_resource(oc_resource_t *resource, oc_request_t *request,
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
  oc_rep_set_text_string_v1(res, href, oc_string(resource->uri),
                            oc_string_len(resource->uri));

  // rt
  oc_rep_set_array(res, rt);
  for (size_t i = 0; i < oc_string_array_get_allocated_size(resource->types);
       ++i) {
    size_t size = oc_string_array_get_item_size(resource->types, i);
    const char *t = (const char *)oc_string_array_get_item(resource->types, i);
    if (size > 0) {
      oc_rep_add_text_string(rt, t);
    }
  }
  oc_rep_close_array(res, rt);

  // if
  oc_core_encode_interfaces_mask(oc_rep_object(res), resource->interfaces);

  // p
  oc_rep_set_object(res, p);
  oc_rep_set_uint(p, bm,
                  (uint8_t)(resource->properties & OCF_RES_POLICY_PROPERTIES));

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
  oc_uuid_to_str(oc_core_get_device_id(device_num), uuid, OC_ARRAY_SIZE(uuid));

  oc_rep_start_object(device, links);
  oc_rep_set_text_string_v1(links, di, uuid,
                            oc_strnlen(uuid, OC_ARRAY_SIZE(uuid)));

  if (baseline) {
    oc_resource_t *ocf_res = oc_core_get_resource_by_index(OCF_RES, device_num);
    oc_rep_set_string_array(links, rt, ocf_res->types);
    oc_core_encode_interfaces_mask(oc_rep_object(links), ocf_res->interfaces);
  }

  oc_rep_set_array(links, links);

  if (process_oic_1_1_resource(oc_core_get_resource_by_index(OCF_P, device_num),
                               request, oc_rep_array(links)))
    matches++;

  if (process_oic_1_1_resource(oc_core_get_resource_by_index(OCF_D, device_num),
                               request, oc_rep_array(links)))
    matches++;

  /* oic.wk.con */
  if (oc_get_con_res_announced() &&
      process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_CON, device_num), request,
        oc_rep_array(links)))
    matches++;

#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {

    if (resource->device != device_num ||
        !(resource->properties & OC_DISCOVERABLE))
      continue;

    if (process_oic_1_1_resource(resource, request, oc_rep_array(links)))
      matches++;
  }

#if defined(OC_COLLECTIONS)
  oc_resource_t *collection = (oc_resource_t *)oc_collection_get_all();
  for (; collection; collection = collection->next) {
    if (collection->device != device_num ||
        !(collection->properties & OC_DISCOVERABLE))
      continue;

    if (process_oic_1_1_resource(collection, request, oc_rep_array(links)))
      matches++;
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */

#ifdef OC_SECURITY
  if (process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_DOXM, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_PSTAT, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_CRED, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_ACL, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_AEL, device_num), request,
        oc_rep_array(links)))
    matches++;

  if (process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_SP, device_num), request,
        oc_rep_array(links)))
    matches++;
#ifdef OC_PKI
  if (process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_CSR, device_num), request,
        oc_rep_array(links)))
    matches++;
  if (process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_SEC_ROLES, device_num), request,
        oc_rep_array(links)))
    matches++;
#endif /* OC_PKI */
#endif

#ifdef OC_INTROSPECTION
  if (process_oic_1_1_resource(
        oc_core_get_resource_by_index(OCF_INTROSPECTION_WK, device_num),
        request, oc_rep_array(links))) {
    matches++;
  }
#endif /* OC_INTROSPECTION */

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

  switch (iface_mask) {
  case OC_IF_LL: {
    oc_rep_start_links_array();
    for (size_t device = 0; device < oc_core_get_num_devices(); device++) {
      matches += process_oic_1_1_device_object(oc_rep_array(links), request,
                                               device, false);
    }
    oc_rep_end_links_array();
  } break;
  case OC_IF_BASELINE: {
    oc_rep_start_links_array();
    for (size_t device = 0; device < oc_core_get_num_devices(); device++) {
      matches += process_oic_1_1_device_object(oc_rep_array(links), request,
                                               device, true);
    }
    oc_rep_end_links_array();
  } break;
  default:
    break;
  }

  int response_length = oc_rep_get_encoded_payload_size();
  send_response(request, APPLICATION_CBOR, matches,
                response_length < 0 ? 0 : (size_t)response_length);
}
#endif /* OC_SPEC_VER_OIC */

#ifdef OC_RES_BATCH_SUPPORT

bool
oc_discovery_resource_is_in_batch_response(const oc_resource_t *resource,
                                           const oc_endpoint_t *endpoint,
                                           bool skipDiscoveryResource)
{
  // ignore non-discoverable resources
  if ((resource->properties & OC_DISCOVERABLE) == 0) {
    return false;
  }

  // ignore discovery resources: /oic/res (if skipDiscoveryResource is true) and
  // /.well-known/core (always)
  if (skipDiscoveryResource &&
      resource == oc_core_get_resource_by_index(OCF_RES, resource->device)) {
    return false;
  }
#ifdef OC_WKCORE
  if (resource ==
      oc_core_get_resource_by_index(WELLKNOWNCORE, resource->device)) {
    return false;
  }
#endif /* OC_WKCORE */

#ifdef OC_SECURITY
  // ignore SVRs
  if (oc_core_is_SVR(resource, resource->device) ||
      // and inaccessible resources
      !oc_sec_check_acl(OC_GET, resource, endpoint)) {
    return false;
  }
#else  /* !OC_SECURITY */
  (void)endpoint;
#endif /* OC_SECURITY */
  return true;
}

static void
process_batch_response(CborEncoder *links_array, oc_resource_t *resource,
                       const oc_endpoint_t *endpoint)
{
  if (resource == NULL ||
      !oc_discovery_resource_is_in_batch_response(resource, endpoint, true)) {
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
  rest_request.method = OC_GET;

  oc_rep_start_object((links_array), links_obj);

  char href[OC_MAX_OCF_URI_SIZE] = { 0 };
  memcpy(href, OC_SCHEME_OCF, OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF));
  char *buffer = href + OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF);
  oc_uuid_to_str(oc_core_get_device_id(resource->device), buffer, OC_UUID_LEN);
  buffer += OC_UUID_LEN - 1;
  memcpy(buffer, oc_string(resource->uri), oc_string_len(resource->uri));
  buffer[oc_string_len(resource->uri)] = '\0';

  oc_rep_set_text_string_v1(links_obj, href, href,
                            oc_strnlen(href, OC_ARRAY_SIZE(href)));
#ifdef OC_HAS_FEATURE_ETAG
  oc_rep_set_byte_string(links_obj, etag, (uint8_t *)&resource->etag,
                         sizeof(resource->etag));
#endif /* OC_HAS_FEATURE_ETAG */
  oc_rep_set_key_v1(oc_rep_object(links_obj), "rep", OC_CHAR_ARRAY_LEN("rep"));
  memcpy(oc_rep_get_encoder(), oc_rep_object(links_obj), sizeof(CborEncoder));

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
  memcpy(oc_rep_object(links_obj), oc_rep_get_encoder(), sizeof(CborEncoder));
  oc_rep_end_object((links_array), links_obj);
}

void
oc_discovery_create_batch_for_resource(CborEncoder *links,
                                       oc_resource_t *resource,
                                       const oc_endpoint_t *endpoint)
{
  process_batch_response(links, resource, endpoint);
}

typedef struct
{
  CborEncoder *links_array;
  const oc_endpoint_t *endpoint;
} iterate_batch_response_data_t;

static bool
discovery_iterate_batch_response(oc_resource_t *resource, void *data)
{
  iterate_batch_response_data_t *brd = (iterate_batch_response_data_t *)data;
  process_batch_response(brd->links_array, resource, brd->endpoint);
  return true;
}

static void
process_batch_request(CborEncoder *links_array, const oc_endpoint_t *endpoint,
                      size_t device)
{
  iterate_batch_response_data_t brd = { .links_array = links_array,
                                        .endpoint = endpoint };
  oc_resources_iterate(device, true, true, true, true,
                       discovery_iterate_batch_response, &brd);
}

#ifdef OC_HAS_FEATURE_ETAG

typedef struct
{
  const oc_endpoint_t *endpoint;
  uint64_t etag;
} iterate_get_etag_data_t;

static bool
discovery_iterate_get_batch_etag(oc_resource_t *resource, void *data)
{
  iterate_get_etag_data_t *ged = (iterate_get_etag_data_t *)data;
  if (!oc_discovery_resource_is_in_batch_response(resource, ged->endpoint,
                                                  false)) {
    return true;
  }

  if (resource->etag > ged->etag) {
    ged->etag = resource->etag;
  }
  return true;
}

uint64_t
oc_discovery_get_batch_etag(const oc_endpoint_t *endpoint, size_t device)
{
  iterate_get_etag_data_t ged = {
    .endpoint = endpoint,
    .etag = OC_ETAG_UNINITIALIZED,
  };
  oc_resources_iterate(device, true, true, true, true,
                       discovery_iterate_get_batch_etag, &ged);
  return ged.etag;
}

#endif /* OC_HAS_FEATURE_ETAG */

#endif /* OC_RES_BATCH_SUPPORT */

#ifdef OC_SECURITY
static bool
discovery_check_sduuid(oc_request_t *request, const char *query,
                       size_t query_len)
{
  const oc_sec_sdi_t *s = oc_sec_sdi_get(request->resource->device);
  if (s->priv) {
    oc_ignore_request(request);
    OC_DBG("private sdi");
    return false;
  }
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(&s->uuid, uuid, OC_UUID_LEN);
  if (query_len != (OC_UUID_LEN - 1)) {
    oc_ignore_request(request);
    OC_DBG("uuid mismatch: query_length=%zu", query_len);
    return false;
  }
  if (strncasecmp(query, uuid, OC_UUID_LEN - 1) != 0) {
    oc_ignore_request(request);
    OC_DBG("uuid mismatch: %s", uuid);
    return false;
  }
  return true;
}
#endif /* OC_SECURITY */

static void
discovery_resource_get(oc_request_t *request, oc_interface_mask_t iface_mask,
                       void *data)
{
  (void)data;

#ifdef OC_SPEC_VER_OIC
  if (request->origin && request->origin->version == OIC_VER_1_1_0) {
    oc_core_1_1_discovery_handler(request, iface_mask, data);
    return;
  }
#endif /* OC_SPEC_VER_OIC */

  // for dev without SVRs, ignore queries for backward compatibility
#ifdef OC_SECURITY
  const char *q;
  int ql = oc_get_query_value(request, OCF_RES_QUERY_SDUUID, &q);
  if (ql > 0 && !discovery_check_sduuid(request, q, (size_t)ql)) {
    return;
  }
#endif /* OC_SECURITY */

  int matches = 0;
  size_t device = request->resource->device;

  switch (iface_mask) {
  case OC_IF_LL: {
    oc_rep_start_links_array();
    matches += process_device_resources(oc_rep_array(links), request);
    oc_rep_end_links_array();
  } break;
#ifdef OC_RES_BATCH_SUPPORT
  case OC_IF_B: {
    if (request->origin == NULL
#ifdef OC_SECURITY
        || (request->origin->flags & SECURED) == 0
#endif /* OC_SECURITY */
    ) {
      OC_ERR("oc_discovery: insecure batch interface requests are unsupported");
      break;
    }
    CborEncoder encoder;
    oc_rep_start_links_array();
    memcpy(&encoder, oc_rep_get_encoder(), sizeof(CborEncoder));
    process_batch_request(&links_array, request->origin, device);
    memcpy(oc_rep_get_encoder(), &encoder, sizeof(CborEncoder));
    oc_rep_end_links_array();
    matches++;
  } break;
#endif /* OC_RES_BATCH_SUPPORT */
  case OC_IF_BASELINE: {
    oc_rep_start_links_array();
    oc_rep_start_object(oc_rep_array(links), props);
    memcpy(&root_map, &props_map, sizeof(CborEncoder));
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_RES, device));
#ifdef OC_SECURITY
    const oc_sec_sdi_t *s = oc_sec_sdi_get(device);
    if (!s->priv) {
      char uuid[OC_UUID_LEN];
      oc_uuid_to_str(&s->uuid, uuid, OC_UUID_LEN);
      oc_rep_set_text_string_v1(root, sduuid, uuid,
                                oc_strnlen(uuid, OC_ARRAY_SIZE(uuid)));
      oc_rep_set_text_string_v1(root, sdname, oc_string(s->name),
                                oc_string_len(s->name));
    }
#endif
    oc_rep_set_array(root, links);
    matches += process_device_resources(oc_rep_array(links), request);
    oc_rep_close_array(root, links);
    memcpy(&props_map, &root_map, sizeof(CborEncoder));
    oc_rep_end_object(oc_rep_array(links), props);
    oc_rep_end_links_array();
  } break;
  default:
    break;
  }

  int response_length = oc_rep_get_encoded_payload_size();
  send_response(request, APPLICATION_VND_OCF_CBOR, matches,
                response_length < 0 ? 0 : (size_t)response_length);
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
    oc_send_response_internal(request, OC_STATUS_BAD_REQUEST, TEXT_PLAIN, 0,
                              true);
    return;
  }

  oc_init_query_iterator();
  const char *key = NULL;
  size_t key_len = 0;
  const char *value = NULL;
  size_t value_len = 0;
  const char *rt_request = NULL;
  size_t rt_len = 0;
  while (oc_iterate_query(request, &key, &key_len, &value, &value_len) > 0) {
    if (strncmp(key, "rt", key_len) == 0) {
      rt_request = value;
      rt_len = value_len;
    }
  }

  if (rt_request != NULL && strncmp(rt_request, "oic.wk.res", rt_len) == 0) {
    /* request for all devices */
    matches = 1;
  }

  const char *rt_device = NULL;
  size_t rt_devlen = 0;
  size_t device = request->resource->device;
  oc_resource_t *resource =
    oc_core_get_resource_by_uri_v1("oic/d", OC_CHAR_ARRAY_LEN("oic/d"), device);
  for (size_t i = 0; i < oc_string_array_get_allocated_size(resource->types);
       ++i) {
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
    oc_string_t uri;
    memset(&uri, 0, sizeof(oc_string_t));
    while (eps != NULL) {
      if ((eps->flags & SECURED) == 0) {
        eps = eps->next;
        continue;
      }
      oc_string64_t ep;
      if (oc_endpoint_to_string64(eps, &ep)) {
        length = clf_add_str_to_buffer(oc_string(ep), oc_string_len(ep));
        response_length += length;
        break;
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

  send_response(request, APPLICATION_LINK_FORMAT, matches, response_length);
}

void
oc_create_wkcore_resource(size_t device)
{
  oc_core_populate_resource(WELLKNOWNCORE, device, "/.well-known/core", 0, 0,
                            OC_DISCOVERABLE, oc_wkcore_discovery_handler, 0, 0,
                            0, 1, "wk");
}

#endif /* OC_WKCORE */

void
oc_create_discovery_resource(size_t device)
{
  oc_core_populate_resource(OCF_RES, device, OCF_RES_URI,
                            (oc_interface_mask_t)OCF_RES_IF_MASK,
                            OCF_RES_DEFAULT_IF, OCF_RES_PROPERTIES_MASK,
                            discovery_resource_get, /*put*/ NULL, /*post*/ NULL,
                            /*delete*/ NULL, 1, OCF_RES_RT);
}

#ifdef OC_CLIENT
oc_discovery_flags_t
oc_discovery_process_payload(const uint8_t *payload, size_t len,
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

  oc_rep_t *p = NULL;
  int s = oc_parse_rep(payload, len, &p);
  if (s != 0) {
    OC_WRN("error parsing discovery response");
  }
  oc_rep_t *rep = p;
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

  oc_rep_t *links = p;
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
        if (oc_string_len(link->name) == 2 &&
            strncmp(oc_string(link->name), "rt", 2) == 0) {
          types = &link->value.array;
        } else {
          iface_mask = 0;
          for (size_t i = 0;
               i < oc_string_array_get_allocated_size(link->value.array); ++i) {
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

    if (eps_list && anchor != NULL && uri != NULL && types != NULL &&
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
