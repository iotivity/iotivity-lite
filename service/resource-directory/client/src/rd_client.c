/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "rd_client.h"
#include "oc_api.h"
#include "oc_collection.h"
#include "oc_core_res.h"
#include "oc_log.h"

#define RD_PUBLISH_TTL 86400

bool
rd_publish(oc_endpoint_t *endpoint, oc_link_t *links, int device_index,
           oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  char uuid[MAX_UUID_LENGTH] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, MAX_UUID_LENGTH);

  bool status = false;
  if (!links) {
    oc_link_t *link_p =
      oc_new_link(oc_core_get_resource_by_index(OCF_P, device_index));
    oc_link_t *link_d =
      oc_new_link(oc_core_get_resource_by_index(OCF_D, device_index));
    oc_list_add((oc_list_t)link_p, link_d);

    status = rd_publish_with_device_id(endpoint, uuid, link_p, handler, qos,
                                       user_data);
    oc_delete_link(link_p);
    oc_delete_link(link_d);
  } else {
    status =
      rd_publish_with_device_id(endpoint, uuid, links, handler, qos, user_data);
  }

  return status;
}

bool
rd_publish_with_device_id(oc_endpoint_t *endpoint, const char *id,
                          oc_link_t *links, oc_response_handler_t handler,
                          oc_qos_t qos, void *user_data)
{
  if (!endpoint || !id || !links || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  if (oc_init_post(OC_RSRVD_RD_URI, endpoint, "rt=oic.wk.rdpub", handler, qos,
                   user_data)) {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, di, id);
    oc_rep_set_int(root, lt, RD_PUBLISH_TTL);

    oc_rep_set_array(root, links);
    oc_link_t *link = links;
    while (link != NULL) {
      oc_rep_object_array_start_item(links);
      oc_rep_set_text_string(links, href, oc_string(link->resource->uri));
      oc_rep_set_string_array(links, rt, link->resource->types);
      oc_core_encode_interfaces_mask(oc_rep_object(links),
                                     link->resource->interfaces);
      oc_rep_set_int(links, ins, 0);
      oc_rep_set_string_array(links, rel, link->rel);
      oc_rep_object_array_end_item(links);
      link = link->next;
    }
    oc_rep_close_array(root, links);
    oc_rep_end_root_object();
  } else {
    OC_ERR("Could not init POST request for rd publish");
    return false;
  }

  return oc_do_post();
}

bool
rd_delete(oc_endpoint_t *endpoint, int device_index,
          oc_response_handler_t handler, oc_qos_t qos, void *user_data)
{
  char uuid[MAX_UUID_LENGTH] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, MAX_UUID_LENGTH);

  return rd_delete_with_device_id(endpoint, uuid, handler, qos, user_data);
}

bool
rd_delete_with_device_id(oc_endpoint_t *endpoint, const char *id,
                         oc_response_handler_t handler, oc_qos_t qos,
                         void *user_data)
{
  if (!endpoint || !id || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  oc_string_t query;
  oc_concat_strings(&query, "di=", id);

  bool status = oc_do_delete(OC_RSRVD_RD_URI, endpoint, oc_string(query),
                             handler, qos, user_data);
  if (!status) {
    OC_ERR("Could not DELETE request for rd delete");
  }
  oc_free_string(&query);

  return status;
}
