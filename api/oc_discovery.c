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
#include "api/oc_helpers_internal.h"
#include "api/oc_resource_internal.h"
#include "api/oc_rep_internal.h"
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

static bool
ep_origin_flags_and_interface_match(const oc_endpoint_t *origin,
                                    const oc_endpoint_t *ep)
{
  if (origin->interface_index != 0 &&
      origin->interface_index != ep->interface_index) {
    return false;
  }
  if (((origin->flags & IPV4) != 0 && (ep->flags & IPV6) != 0) ||
      ((origin->flags & IPV6) != 0 && (ep->flags & IPV4) != 0)) {
    return false;
  }
  return true;
}

bool
oc_filter_out_ep_for_resource(const oc_endpoint_t *ep,
                              const oc_resource_t *resource,
                              const oc_endpoint_t *request_origin,
                              size_t device_index, bool owned_for_SVRs)
{
  if (request_origin != NULL &&
      !ep_origin_flags_and_interface_match(request_origin, ep)) {
    return true;
  }

#ifndef OC_SECURITY
  (void)owned_for_SVRs;
#endif
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  if (((oc_sec_get_pstat(device_index))->s == OC_DOS_RFOTM) &&
      (resource->properties & OC_ACCESS_IN_RFOTM) != 0) {
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
  return (((resource->properties & OC_SECURE) != 0
#ifdef OC_SECURITY
           || owned_for_SVRs
#endif /* OC_SECURITY */
           ) &&
          (ep->flags & SECURED) == 0);
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
discovery_encode_endpoints(CborEncoder *link, const oc_resource_t *resource,
                           const oc_request_t *request, size_t device_index)
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
encode_resource(CborEncoder *links, const oc_resource_t *resource,
                const oc_request_t *request, oc_string_view_t anchor,
                bool include_endpoints)
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
  oc_rep_set_text_string_v1(link, anchor, anchor.data, anchor.length);

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
  oc_core_encode_interfaces_mask(oc_rep_object(link), resource->interfaces,
                                 false);

  // p
  oc_rep_set_object(link, p);
  oc_rep_set_uint(p, bm,
                  (uint8_t)(resource->properties & OCF_RES_POLICY_PROPERTIES));
  oc_rep_close_object(link, p);

  if (include_endpoints) {
    // eps
    discovery_encode_endpoints(oc_rep_object(link), resource, request,
                               request->resource->device);
  }

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
encode_device_core_resources(CborEncoder *links, const oc_request_t *request,
                             oc_string_view_t anchor, bool include_endpoints)
{
  int matches = 0;
  oc_core_resource_t platformRes[] = {
    OCF_P,
#ifdef OC_HAS_FEATURE_PLGD_TIME
    PLGD_TIME,
#endif /* OC_HAS_FEATURE_PLGD_TIME */
  };
  for (size_t i = 0; i < OC_ARRAY_SIZE(platformRes); i++) {
    if (encode_resource(links, oc_core_get_resource_by_index(platformRes[i], 0),
                        request, anchor, include_endpoints)) {
      matches++;
    }
  }

  size_t device_index = request->resource->device;
  if (oc_get_con_res_announced() &&
      encode_resource(links,
                      oc_core_get_resource_by_index(OCF_CON, device_index),
                      request, anchor, include_endpoints)) {
    matches++;
  }

  oc_core_resource_t res[] = {
    OCF_RES,
    OCF_D,
#ifdef OC_INTROSPECTION
    OCF_INTROSPECTION_WK,
#endif /* OC_INTROSPECTION */
#ifdef OC_MNT
    OCF_MNT,
#endif /* OC_MNT */
#ifdef OC_SOFTWARE_UPDATE
    OCF_SW_UPDATE,
#endif /* OC_SOFTWARE_UPDATE */
#ifdef OC_SECURITY
    OCF_SEC_DOXM,
    OCF_SEC_PSTAT,
    OCF_SEC_ACL,
    OCF_SEC_AEL,
    OCF_SEC_CRED,
    OCF_SEC_SP,
#ifdef OC_PKI
    OCF_SEC_CSR,
    OCF_SEC_ROLES,
#endif /* OC_PKI */
    OCF_SEC_SDI,
#endif /* OC_SECURITY */
#if defined(OC_CLIENT) && defined(OC_SERVER) && defined(OC_CLOUD)
    OCF_COAPCLOUDCONF,
#endif /* OC_CLIENT && OC_SERVER && OC_CLOUD */
  };
  for (size_t i = 0; i < OC_ARRAY_SIZE(res); i++) {
    if (encode_resource(links,
                        oc_core_get_resource_by_index(res[i], device_index),
                        request, anchor, include_endpoints)) {
      matches++;
    }
  }
  return matches;
}

static int
encode_device_resources(CborEncoder *links, const oc_request_t *request,
                        bool include_endpoints)
{
  size_t device_index = request->resource->device;
  char anchor[OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF) + OC_UUID_LEN] = { 0 };
  // ocf://
  memcpy(anchor, OC_SCHEME_OCF, OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF));
  // uuid
  oc_uuid_to_str(oc_core_get_device_id(device_index),
                 anchor + OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF), OC_UUID_LEN);
  size_t anchor_len = oc_strnlen(anchor, OC_ARRAY_SIZE(anchor));

  int matches = encode_device_core_resources(
    links, request, oc_string_view(anchor, anchor_len), include_endpoints);
#ifdef OC_SERVER
  oc_resource_t *resource = oc_ri_get_app_resources();
  for (; resource; resource = resource->next) {
    if (resource->device != device_index ||
        (resource->properties & OC_DISCOVERABLE) == 0)
      continue;

    if (encode_resource(links, resource, request,
                        oc_string_view(anchor, anchor_len),
                        include_endpoints)) {
      matches++;
    }
  }

#ifdef OC_COLLECTIONS
  const oc_resource_t *collection = (oc_resource_t *)oc_collection_get_all();
  for (; collection; collection = collection->next) {
    if (collection->device != device_index ||
        !(collection->properties & OC_DISCOVERABLE))
      continue;

    if (encode_resource(links, collection, request,
                        oc_string_view(anchor, anchor_len),
                        include_endpoints)) {
      matches++;
    }
  }
#endif /* OC_COLLECTIONS */
#endif /* OC_SERVER */
  return matches;
}

static void
send_response(oc_request_t *request, oc_content_format_t content_format,
              bool is_empty, oc_status_t code, size_t response_length)
{
  if (!is_empty && response_length > 0) {
    //  do nothing - response already set up
    oc_send_response_internal(request, code, content_format, response_length,
                              code != OC_IGNORE);
    return;
  }

  if (code == OC_STATUS_NOT_MODIFIED && is_empty) {
    response_length = 0;
  } else if (oc_endpoint_is_unicast(request->origin)) {
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
  oc_core_encode_interfaces_mask(oc_rep_object(res), resource->interfaces,
                                 false);

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
    oc_core_encode_interfaces_mask(oc_rep_object(links), ocf_res->interfaces,
                                   false);
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
  send_response(request, APPLICATION_CBOR, matches == 0, OC_STATUS_OK,
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
discovery_process_batch_response_write_href(char *buffer, size_t buffer_size,
                                            size_t device, oc_string_view_t uri)
{
  assert(buffer_size > OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF) + OC_UUID_LEN);
  memcpy(buffer, OC_SCHEME_OCF, OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF));
  buffer = buffer + OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF);
  buffer_size = buffer_size - OC_CHAR_ARRAY_LEN(OC_SCHEME_OCF);
  oc_uuid_to_str(oc_core_get_device_id(device), buffer, OC_UUID_LEN);
  buffer += OC_UUID_LEN - 1;
  buffer_size -= OC_UUID_LEN - 1;
  size_t to_write = uri.length;
  if (to_write + 1 > buffer_size) {
    OC_WRN("resource uri(%s) truncated", uri.data);
    to_write = buffer_size - 1;
  }
  assert(to_write > 0);
  memcpy(buffer, uri.data, to_write);
  buffer[to_write] = '\0';
}

typedef bool (*discovery_process_batch_response_filter_t)(const oc_resource_t *,
                                                          void *);

static bool
discovery_process_batch_response(
  CborEncoder *encoder, oc_resource_t *resource, const oc_endpoint_t *endpoint,
  discovery_process_batch_response_filter_t filter, void *filter_data)
{
  if (resource == NULL ||
      !oc_discovery_resource_is_in_batch_response(resource, endpoint, true) ||
      (filter != NULL && !filter(resource, filter_data))) {
    return false;
  }
  oc_request_t rest_request;
  memset(&rest_request, 0, sizeof(oc_request_t));
  oc_response_t response;
  memset(&response, 0, sizeof(oc_response_t));
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(oc_response_buffer_t));
  response.response_buffer = &response_buffer;
  rest_request.response = &response;
  rest_request.origin = endpoint;
  rest_request.query = 0;
  rest_request.query_len = 0;
  rest_request.method = OC_GET;

  oc_rep_start_object(encoder, links_obj);

  char href[OC_MAX_OCF_URI_SIZE] = { 0 };
  discovery_process_batch_response_write_href(href, OC_MAX_OCF_URI_SIZE,
                                              resource->device,
                                              oc_string_view2(&resource->uri));

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
  oc_rep_end_object(encoder, links_obj);
  return true;
}

void
oc_discovery_create_batch_for_resource(CborEncoder *links,
                                       oc_resource_t *resource,
                                       const oc_endpoint_t *endpoint)
{
  discovery_process_batch_response(links, resource, endpoint, NULL, NULL);
}

typedef struct
{
  CborEncoder *links;
  const oc_endpoint_t *endpoint;
  discovery_process_batch_response_filter_t filter;
  void *filter_data;
  int matches;
} discovery_batch_response_data_t;

static bool
discovery_iterate_batch_response(oc_resource_t *resource, void *data)
{
  discovery_batch_response_data_t *brd =
    (discovery_batch_response_data_t *)data;
  if (discovery_process_batch_response(brd->links, resource, brd->endpoint,
                                       brd->filter, brd->filter_data)) {
    ++brd->matches;
  }
  return true;
}

#ifdef OC_HAS_FEATURE_ETAG

typedef struct
{
  const oc_endpoint_t *endpoint;
  uint64_t etag;
} discovery_get_max_etag_data_t;

static bool
discovery_batch_iterate_get_max_etag(oc_resource_t *resource, void *data)
{
  discovery_get_max_etag_data_t *gmed = (discovery_get_max_etag_data_t *)data;
  if (!oc_discovery_resource_is_in_batch_response(resource, gmed->endpoint,
                                                  false)) {
    return true;
  }

  if (resource->etag > gmed->etag) {
    gmed->etag = resource->etag;
  }
  return true;
}

uint64_t
oc_discovery_get_batch_etag(const oc_endpoint_t *endpoint, size_t device)
{
  discovery_get_max_etag_data_t gmed = {
    .endpoint = endpoint,
    .etag = OC_ETAG_UNINITIALIZED,
  };
  oc_resources_iterate(device, true, true, true, true,
                       discovery_batch_iterate_get_max_etag, &gmed);
  return gmed.etag;
}

#ifdef OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES

typedef struct
{
  const oc_endpoint_t *endpoint;
  uint64_t etag;
  bool found;
} discovery_get_equal_etag_data_t;

static bool
discovery_batch_iterate_get_equal_etag(oc_resource_t *resource, void *data)
{
  discovery_get_equal_etag_data_t *geed =
    (discovery_get_equal_etag_data_t *)data;
  if (!oc_discovery_resource_is_in_batch_response(resource, geed->endpoint,
                                                  false)) {
    return true;
  }

  if (resource->etag == geed->etag) {
    OC_DBG("resource(%s) with etag %" PRIu64 " found", oc_string(resource->uri),
           resource->etag);
    geed->found = true;
    return false;
  }
  return true;
}

static bool
discovery_batch_has_resource_with_etag(uint64_t etag,
                                       const oc_endpoint_t *endpoint,
                                       size_t device)
{
  // check if a resource with given etag exists, if so we can use it
  discovery_get_equal_etag_data_t geed = {
    .endpoint = endpoint,
    .etag = etag,
    .found = false,
  };
  oc_resources_iterate(device, true, true, true, true,
                       discovery_batch_iterate_get_equal_etag, &geed);
  return geed.found;
}

typedef struct
{
  const oc_endpoint_t *endpoint;
  size_t device;
  uint64_t etag;
} discovery_find_candidate_etag_data_t;

static bool
discovery_iterate_incremental_updates(uint64_t etag, void *user_data)
{
  OC_DBG("oc_discovery: checking candidate etag(%" PRIu64 ")", etag);
  discovery_find_candidate_etag_data_t *ced =
    (discovery_find_candidate_etag_data_t *)user_data;
  if (etag < ced->etag) {
    return true;
  }
  if (!discovery_batch_has_resource_with_etag(etag, ced->endpoint,
                                              ced->device)) {
    OC_DBG("oc_discovery: no resource found for candidate etag(%" PRIu64 ")",
           etag);
    return true;
  }
  OC_DBG("oc_discovery: new candidate etag(%" PRIu64 ")", etag);
  ced->etag = etag;
  return true;
}

static uint64_t
discovery_find_incremental_updates_etag(const oc_request_t *request)
{
  // check incChanges key in query, if present we check if a resource with given
  // etag exists and then return only resources with etag > request->etag
  if (!oc_etag_has_incremental_updates_query(request->query,
                                             request->query_len)) {
    return OC_ETAG_UNINITIALIZED;
  }

  OC_DBG("oc_discovery: find highest valid etag for incremental updates");
  discovery_find_candidate_etag_data_t ced = {
    .endpoint = request->origin,
    .device = request->resource->device,
    .etag = OC_ETAG_UNINITIALIZED,
  };
  if (request->etag_len == sizeof(uint64_t)) {
    uint64_t etag0 = OC_ETAG_UNINITIALIZED;
    memcpy(&etag0, &request->etag[0], sizeof(uint64_t));
    if (discovery_batch_has_resource_with_etag(etag0, request->origin,
                                               request->resource->device)) {
      OC_DBG("oc_discovery: candidate etag0(%" PRIu64 ")", etag0);
      ced.etag = etag0;
    }
  }
  oc_etag_iterate_incremental_updates_query(
    request->query, request->query_len, discovery_iterate_incremental_updates,
    &ced);
  return ced.etag;
}

static bool
process_batch_request_filter_by_etag(const oc_resource_t *resource, void *data)
{
  const uint64_t *etag = (uint64_t *)data;
  return resource->etag > *etag;
}

#endif /* OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES */

#endif /* OC_HAS_FEATURE_ETAG */

static oc_status_t
discovery_process_batch_request(CborEncoder *links, const oc_request_t *request)
{
  const oc_endpoint_t *endpoint = request->origin;
  size_t device = request->resource->device;
  discovery_batch_response_data_t brd = {
    .links = links,
    .endpoint = endpoint,
    .filter = NULL,
    .filter_data = NULL,
    .matches = 0,
  };
#ifdef OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES
  uint64_t etag = discovery_find_incremental_updates_etag(request);
  if (etag != OC_ETAG_UNINITIALIZED) {
    brd.filter = process_batch_request_filter_by_etag;
    brd.filter_data = &etag;
  }
#endif /* OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES */

  oc_resources_iterate(device, true, true, true, true,
                       discovery_iterate_batch_response, &brd);

#ifdef OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES
  if (etag != OC_ETAG_UNINITIALIZED && brd.matches == 0) {
    OC_DBG("oc_discovery: no resources with etag > %" PRIu64 " found", etag);
    // no resources with etag > request->etag found, so we can return VALID
    return OC_STATUS_NOT_MODIFIED;
  }
#endif /* OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES */
  return OC_STATUS_OK;
}

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

#ifdef OC_SECURITY
static void
discovery_encode_sdi(CborEncoder *object, size_t device)
{
  const oc_sec_sdi_t *s = oc_sec_sdi_get(device);
  if (s->priv) {
    return;
  }
  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(&s->uuid, uuid, OC_UUID_LEN);
  oc_rep_object_set_text_string(object, OCF_RES_PROP_SDUUID,
                                OC_CHAR_ARRAY_LEN(OCF_RES_PROP_SDUUID), uuid,
                                oc_strnlen(uuid, OC_ARRAY_SIZE(uuid)));
  oc_rep_object_set_text_string(object, OCF_RES_PROP_SDNAME,
                                OC_CHAR_ARRAY_LEN(OCF_RES_PROP_SDNAME),
                                oc_string(s->name), oc_string_len(s->name));
}

#endif

static int
discovery_encode(const oc_request_t *request, oc_interface_mask_t iface)
{
  switch (iface) {
  case OC_IF_LL: {
    oc_rep_start_links_array();
    int matches = encode_device_resources(oc_rep_array(links), request, true);
    oc_rep_end_links_array();
    return matches > 0 ? OC_STATUS_OK : OC_IGNORE;
  }
#ifdef OC_RES_BATCH_SUPPORT
  case OC_IF_B: {
    if (request->origin == NULL
#ifdef OC_SECURITY
        || (request->origin->flags & SECURED) == 0
#endif /* OC_SECURITY */
    ) {
      OC_ERR("oc_discovery: insecure batch interface requests are unsupported");
      return -1;
    }
    oc_rep_start_links_array();
    int code = discovery_process_batch_request(oc_rep_array(links), request);
    oc_rep_end_links_array();
    return code;
  }
#endif /* OC_RES_BATCH_SUPPORT */
  case OC_IF_BASELINE:
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
  case PLGD_IF_ETAG:
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
  {
    int matches;
    size_t device = request->resource->device;
    oc_rep_begin_array(oc_rep_get_encoder(), root);
    oc_rep_begin_object(oc_rep_array(root), props);
    oc_process_baseline_interface_with_filter(
      oc_rep_object(props), oc_core_get_resource_by_index(OCF_RES, device),
      NULL, NULL);
#ifdef OC_SECURITY
    discovery_encode_sdi(oc_rep_object(props), device);
#endif
    oc_rep_open_array(props, links);
    matches = encode_device_resources(oc_rep_array(links), request,
                                      iface == OC_IF_BASELINE);
    oc_rep_close_array(props, links);
    oc_rep_end_object(oc_rep_array(root), props);
    oc_rep_end_array(oc_rep_get_encoder(), root);
    return matches > 0 ? OC_STATUS_OK : OC_STATUS_NOT_MODIFIED;
  }
  default:
    break;
  }

  return -1;
}

static void
discovery_resource_get(oc_request_t *request, oc_interface_mask_t iface,
                       void *data)
{
  (void)data;

#ifdef OC_SPEC_VER_OIC
  if (request->origin && request->origin->version == OIC_VER_1_1_0) {
    oc_core_1_1_discovery_handler(request, iface, data);
    return;
  }
#endif /* OC_SPEC_VER_OIC */

  // for dev without SVRs, ignore queries for backward compatibility
#ifdef OC_SECURITY
  const char *q;
  int ql = oc_get_query_value_v1(request, OCF_RES_QUERY_SDUUID,
                                 OC_CHAR_ARRAY_LEN(OCF_RES_QUERY_SDUUID), &q);
  if (ql > 0 && !discovery_check_sduuid(request, q, (size_t)ql)) {
    return;
  }
#endif /* OC_SECURITY */

  int code = discovery_encode(request, iface);
  if (code < 0) {
    code = OC_IGNORE;
  }
  int response_length = oc_rep_get_encoded_payload_size();
  bool has_data = (code == OC_STATUS_OK);
  send_response(request, APPLICATION_VND_OCF_CBOR, !has_data, code,
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
  oc_resource_t *resource = oc_core_get_resource_by_uri_v1(
    OCF_D_URI, OC_CHAR_ARRAY_LEN(OCF_D_URI), device);
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
        length += clf_add_str_to_buffer(oc_string(ep), oc_string_len(ep));
        break;
      }
      eps = eps->next;
    }

    length += clf_add_line_to_buffer("/oic/res>;");
    length += clf_add_line_to_buffer("rt=\"oic.wk.res ");
    length += clf_add_str_to_buffer(rt_device, rt_devlen);
    length += clf_add_line_to_buffer("\";");
    length +=
      clf_add_line_to_buffer("if=\"oic.if.ll oic.if.baseline\";ct=10000");
    response_length += length;
  }

  send_response(request, APPLICATION_LINK_FORMAT, matches == 0, OC_STATUS_OK,
                response_length);
}

void
oc_create_wkcore_resource(size_t device)
{
  oc_core_populate_resource(WELLKNOWNCORE, device, OC_WELLKNOWNCORE_URI,
                            /*iface_mask*/ 0, /*default_interface*/ 0,
                            OC_DISCOVERABLE, oc_wkcore_discovery_handler,
                            /*put*/ NULL, /*post*/ NULL, /*delete*/ NULL, 1,
                            OC_WELLKNOWNCORE_RT);
}

#endif /* OC_WKCORE */

void
oc_create_discovery_resource(size_t device)
{
  int interfaces = OC_IF_BASELINE | OC_IF_LL;
#ifdef OC_RES_BATCH_SUPPORT
  interfaces |= OC_IF_B;
#endif /* OC_RES_BATCH_SUPPORT */
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
  interfaces |= PLGD_IF_ETAG;
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
  oc_interface_mask_t default_interface = OC_IF_LL;
  assert((interfaces & default_interface) == default_interface);

  int properties = OC_DISCOVERABLE;
#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE
  properties |= OC_OBSERVABLE;
#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */
  oc_core_populate_resource(OCF_RES, device, OCF_RES_URI,
                            (oc_interface_mask_t)interfaces, default_interface,
                            properties, discovery_resource_get,
                            /*put*/ NULL, /*post*/ NULL,
                            /*delete*/ NULL, 1, OCF_RES_RT);
}

bool
oc_is_discovery_resource_uri(oc_string_view_t uri)
{
  return oc_resource_match_uri(OC_STRING_VIEW(OCF_RES_URI), uri);
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
  struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);

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
  oc_rep_set_pool(prev_rep_objects);
#ifdef OC_DNS_CACHE
  oc_dns_clear_cache();
#endif /* OC_DNS_CACHE */
  return ret;
}
#endif /* OC_CLIENT */
