/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "oc_config.h"

#ifdef OC_CLOUD

#include "api/oc_client_api_internal.h"
#include "api/oc_core_res_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_link_internal.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/options_internal.h"
#include "oc_api.h"
#include "oc_cloud_log_internal.h"
#include "oc_core_res.h"
#include "oc_rep.h"
#include "rd_client_internal.h"
#include "util/oc_buffer_internal.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

static void
rd_encode_resource(CborEncoder *parent, oc_resource_t *resource,
                   oc_string_view_t rel, int64_t ins)
{
  assert(parent != NULL);
  assert(resource != NULL);

  oc_rep_start_object(parent, links);
  oc_rep_set_text_string_v1(links, href, oc_string(resource->uri),
                            oc_string_len(resource->uri));
  oc_rep_set_string_array(links, rt, resource->types);
  oc_core_encode_interfaces_mask(oc_rep_object(links), resource->interfaces,
                                 false);
  if (rel.length > 0) {
    oc_rep_set_text_string_v1(links, rel, rel.data, rel.length);
  }
  oc_rep_set_int(links, ins, ins);
  oc_rep_set_object(links, p);
  oc_rep_set_uint(p, bm,
                  (uint8_t)(resource->properties & ~(OC_PERIODIC | OC_SECURE)));
  oc_rep_close_object(links, p);
  oc_rep_end_object(parent, links);
}

bool
rd_publish_encode(const oc_link_t *links, oc_string_view_t id,
                  oc_string_view_t name, uint32_t ttl)
{
  assert(id.data != NULL);
  assert(name.data != NULL);

  oc_rep_begin_root_object();
  oc_rep_set_text_string_v1(root, di, id.data, id.length);
  oc_rep_set_text_string_v1(root, n, name.data, name.length);
  oc_rep_set_int(root, ttl, ttl);

  oc_rep_set_array(root, links);
  for (const oc_link_t *link = links; link != NULL; link = link->next) {
    const char *rel = oc_string_array_get_item(link->rel, 0);
    size_t rel_len = oc_strnlen(rel, STRING_ARRAY_ITEM_MAX_LEN);
    if (rel_len == STRING_ARRAY_ITEM_MAX_LEN) {
      OC_CLOUD_WRN("Unterminated link rel string");
      continue;
    }
    rd_encode_resource(oc_rep_array(links), link->resource,
                       oc_string_view(rel, rel_len), link->ins);
  }
  oc_rep_close_array(root, links);
  oc_rep_end_root_object();

  if (oc_rep_get_cbor_errno() != CborNoError) {
    OC_CLOUD_ERR("Failed encoding payload: error(%d)",
                 (int)oc_rep_get_cbor_errno());
    return false;
  }
  return true;
}

static bool
rd_publish_with_device_id(const oc_link_t *links, const oc_endpoint_t *endpoint,
                          oc_string_view_t id, oc_string_view_t name,
                          uint32_t ttl, oc_response_handler_t handler,
                          oc_qos_t qos, void *user_data)
{
  if (!oc_init_post(OC_RSRVD_RD_URI, endpoint, "rt=oic.wk.rdpub", handler, qos,
                    user_data)) {
    OC_CLOUD_ERR("Could not init POST request for rd publish");
    return false;
  }

  if (!rd_publish_encode(links, id, name, ttl)) {
    OC_CLOUD_ERR("Could not encode publish payload");
    return false;
  }
  return oc_do_post();
}

bool
rd_publish(const oc_link_t *links, const oc_endpoint_t *endpoint, size_t device,
           uint32_t ttl, oc_response_handler_t handler, oc_qos_t qos,
           void *user_data)
{
  const oc_device_info_t *device_info = oc_core_get_device_info(device);
  if (device_info == NULL) {
    OC_CLOUD_ERR("device(%zu) info not found", device);
    return false;
  }
  char uuid_buf[OC_UUID_LEN] = { 0 };
  int uuid_len =
    oc_uuid_to_str_v1(&device_info->di, uuid_buf, OC_ARRAY_SIZE(uuid_buf));
  assert(uuid_len > 0);
  oc_string_view_t uuid = oc_string_view(uuid_buf, (size_t)uuid_len);
  oc_string_view_t name = oc_string_view2(&device_info->name);

  if (links != NULL) {
    return rd_publish_with_device_id(links, endpoint, uuid, name, ttl, handler,
                                     qos, user_data);
  }

  oc_link_t *link_p = oc_new_link(oc_core_get_resource_by_index(OCF_P, device));
  oc_link_t *link_d = oc_new_link(oc_core_get_resource_by_index(OCF_D, device));
  oc_list_add((oc_list_t)link_p, link_d);

  bool status = rd_publish_with_device_id(link_p, endpoint, uuid, name, ttl,
                                          handler, qos, user_data);
  oc_delete_link(link_p);
  oc_delete_link(link_d);
  return status;
}

static bool
rd_prepare_write_buffer(oc_write_buffer_t *wb, char *buffer, size_t buffer_size,
                        oc_string_view_t id)
{
  // enough room to write the "di={id}" part
  if (buffer_size <=
      /*di=*/3 + id.length) {
    OC_ERR("buffer too small");
    return false;
  }
  wb->buffer = buffer;
  wb->buffer_size = buffer_size;
  wb->total = 0;
  memcpy(wb->buffer, "di=", OC_CHAR_ARRAY_LEN("di="));
  wb->buffer += OC_CHAR_ARRAY_LEN("di=");
  wb->buffer_size -= OC_CHAR_ARRAY_LEN("di=");
  wb->total += OC_CHAR_ARRAY_LEN("di=");
  memcpy(wb->buffer, id.data, id.length);
  wb->buffer += id.length;
  wb->buffer_size -= id.length;
  wb->total += id.length;
  return true;
}

static coap_packet_t
rd_delete_packet(const oc_endpoint_t *endpoint)
{
  coap_packet_t packet;
  memset(&packet, 0, sizeof(coap_packet_t));
  // same packet as set up by prepare_coap_request for the unpublish request
  oc_request_init_packet(&packet, (endpoint->flags & TCP) != 0, COAP_TYPE_NON,
                         OC_DELETE, 0);
  oc_request_set_packet_options(
    &packet, APPLICATION_VND_OCF_CBOR, OC_STRING_VIEW(OC_RSRVD_RD_URI),
    OC_COAP_OPTION_OBSERVE_NOT_SET, OC_STRING_VIEW_NULL);
  return packet;
}

static bool
rd_delete_check_packet_size(coap_packet_t *packet, const char *query,
                            size_t query_len)
{
  coap_options_set_uri_query(packet, query, query_len);
  coap_calculate_header_size_result_t hdr =
    coap_calculate_header_size(packet, /*inner*/ true, /*outer*/ true,
                               /*oscore*/ false, COAP_TOKEN_LEN);
  return coap_check_header_size(hdr.size, 0);
}

typedef struct
{
  oc_response_handler_t handler;
  oc_qos_t qos;
  void *user_data;
} rd_delete_packet_t;

static bool
rd_delete_send_packet(const oc_endpoint_t *endpoint, oc_string_view_t query,
                      void *data)
{
  rd_delete_packet_t *pkt = (rd_delete_packet_t *)data;
  OC_DBG("Unpublishing links (query=%s)", query.data);
  if (!oc_do_delete(OC_RSRVD_RD_URI, endpoint, query.data, pkt->handler,
                    pkt->qos, pkt->user_data)) {
    OC_ERR("failed to unpublish links (query=%s)", query.data);
    return false;
  }
  return true;
}

// split the linked lists into two parts, the first part contains the
// links that were sent, the second part contains the links that were
// not sent
static rd_delete_result_t
rd_partition_links(rd_links_partition_t *partition, oc_link_t *links,
                   oc_link_t *deleted_tail)
{
  if (deleted_tail == NULL) {
    // no links were sent because the query buffer or the packet was too small
    // to fit any link
    return RD_DELETE_ERROR;
  }
  partition->deleted = links;
  partition->not_deleted = deleted_tail->next;
  deleted_tail->next = NULL;
  return partition->not_deleted == NULL ? RD_DELETE_ALL : RD_DELETE_PARTIAL;
}

rd_delete_result_t
rd_delete_fill_and_send_single_packet(
  oc_link_t *links, const oc_endpoint_t *endpoint, oc_string_view_t id,
  char *buffer, size_t buffer_size, rd_delete_on_packet_ready_t on_packet_ready,
  void *on_packet_ready_data, rd_links_partition_t *links_partition)
{
  assert(links != NULL);
  assert(endpoint != NULL);
  assert(buffer != NULL);
  assert(on_packet_ready != NULL);
  assert(links_partition != NULL);

  oc_write_buffer_t wb;
  if (!rd_prepare_write_buffer(&wb, buffer, buffer_size, id)) {
    return RD_DELETE_ERROR;
  }
  coap_packet_t packet = rd_delete_packet(endpoint);
  oc_link_t *prev_link = NULL;
  for (oc_link_t *link = links; link != NULL;
       prev_link = link, link = link->next) {
    // written buffer up to this point
    size_t written = wb.total;
    // the buffer is full, it contains the truncated query so must take the
    // previously written data only
    bool buffer_full = oc_buffer_write(&wb, "&ins=%" PRId64 "", link->ins) < 0;
    // we can't fit the query into the packet, send the packet with the
    // previously written data only
    bool packet_full =
      !buffer_full && !rd_delete_check_packet_size(&packet, buffer, wb.total);

    if (buffer_full || packet_full) {
      buffer[written] = '\0';
      oc_string_view_t query = oc_string_view(buffer, written);
      if (!on_packet_ready(endpoint, query, on_packet_ready_data)) {
        return RD_DELETE_ERROR;
      }
      return rd_partition_links(links_partition, links, prev_link);
    }
  }

  buffer[wb.total] = '\0';
  oc_string_view_t query = oc_string_view(buffer, wb.total);
  if (!on_packet_ready(endpoint, query, on_packet_ready_data)) {
    return RD_DELETE_ERROR;
  }
  return rd_partition_links(links_partition, links, prev_link);
}

rd_delete_result_t
rd_delete(oc_link_t *links, const oc_endpoint_t *endpoint, size_t device,
          oc_response_handler_t handler, oc_qos_t qos, void *user_data,
          rd_links_partition_t *links_partition)
{
  const oc_device_info_t *device_info = oc_core_get_device_info(device);
  if (device_info == NULL) {
    OC_CLOUD_ERR("device(%zu) info not found", device);
    return RD_DELETE_ERROR;
  }
  char uuid_buf[OC_UUID_LEN] = { 0 };
  int uuid_len =
    oc_uuid_to_str_v1(&device_info->di, uuid_buf, OC_ARRAY_SIZE(uuid_buf));
  assert(uuid_len > 0);
  oc_string_view_t uuid = oc_string_view(uuid_buf, (size_t)uuid_len);
  char buffer[COAP_MAX_HEADER_SIZE] = { 0 };
  rd_delete_packet_t pkt = {
    .handler = handler,
    .qos = qos,
    .user_data = user_data,
  };
  return rd_delete_fill_and_send_single_packet(
    links, endpoint, uuid, buffer, OC_ARRAY_SIZE(buffer), rd_delete_send_packet,
    &pkt, links_partition);
}

#endif /* OC_CLOUD */
