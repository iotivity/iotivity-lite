/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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
#include "port/oc_log.h"
#include <stdlib.h>

#define RD_PUBLISH_TTL 86400

static void _add_resource_payload(CborEncoder *parent, oc_resource_t *resource,
                                  char *rel, char *ins) {
  if (!parent || !resource) {
    OC_ERR("Error of input parameters");
    return;
  }
  oc_rep_start_object(parent, links);
  oc_rep_set_text_string(links, href, oc_string(resource->uri));
  oc_rep_set_string_array(links, rt, resource->types);
  oc_core_encode_interfaces_mask(oc_rep_object(links), resource->interfaces);
  if (rel)
    oc_rep_set_text_string(links, rel, rel);
  int ins_int = 0;
  if (ins)
    ins_int = atoi(ins);
  oc_rep_set_int(links, ins, ins_int);
  oc_rep_set_object(links, p);
  oc_rep_set_uint(p, bm,
                  (uint8_t)(resource->properties & ~(OC_PERIODIC | OC_SECURE)));
  oc_rep_close_object(links, p);
  oc_rep_end_object(parent, links);
}

static bool rd_publish_with_device_id(oc_endpoint_t *endpoint, oc_link_t *links,
                                      const char *id, const char *name,
                                      oc_response_handler_t handler,
                                      oc_qos_t qos, void *user_data) {
  if (!endpoint || !id || !links || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  if (oc_init_post(OC_RSRVD_RD_URI, endpoint, "rt=oic.wk.rdpub", handler, qos,
                   user_data)) {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, di, id);
    oc_rep_set_text_string(root, n, name);
    oc_rep_set_int(root, lt, RD_PUBLISH_TTL);

    oc_rep_set_array(root, links);
    oc_link_t *link = links;
    while (link != NULL) {
      _add_resource_payload(oc_rep_array(links), link->resource,
                            oc_string_array_get_item(link->rel, 0),
                            oc_string(link->ins));
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

bool rd_publish(oc_endpoint_t *endpoint, oc_link_t *links, size_t device_index,
                oc_response_handler_t handler, oc_qos_t qos, void *user_data) {
  char uuid[OC_UUID_LEN] = {0};
  oc_device_info_t *device_info = oc_core_get_device_info(device_index);
  if (!device_info)
    return false;
  oc_uuid_to_str(&device_info->di, uuid, OC_UUID_LEN);

  bool status = false;
  if (!links) {
    oc_link_t *link_p =
        oc_new_link(oc_core_get_resource_by_index(OCF_P, device_index));
    oc_link_t *link_d =
        oc_new_link(oc_core_get_resource_by_index(OCF_D, device_index));
    oc_list_add((oc_list_t)link_p, link_d);

    status = rd_publish_with_device_id(endpoint, link_p, uuid,
                                       oc_string(device_info->name), handler,
                                       qos, user_data);
    oc_delete_link(link_p);
    oc_delete_link(link_d);
  } else {
    status = rd_publish_with_device_id(endpoint, links, uuid,
                                       oc_string(device_info->name), handler,
                                       qos, user_data);
  }

  return status;
}

static bool rd_delete_with_device_id(oc_endpoint_t *endpoint, oc_link_t *links,
                                     const char *id,
                                     oc_response_handler_t handler,
                                     oc_qos_t qos, void *user_data) {
  if (!endpoint || !id || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  oc_string_t uri_query;
  memset(&uri_query, 0, sizeof(oc_string_t));
  oc_concat_strings(&uri_query, "di=", id);
  while (links) {
    oc_concat_strings(&uri_query, "&ins=", oc_string(links->ins));
  }

  bool ret = oc_do_delete(OC_RSRVD_RD_URI, endpoint, oc_string(uri_query),
                          handler, qos, user_data);
  oc_free_string(&uri_query);
  return ret;
}

bool rd_delete(oc_endpoint_t *endpoint, oc_link_t *links, size_t device_index,
               oc_response_handler_t handler, oc_qos_t qos, void *user_data) {
  char uuid[OC_UUID_LEN] = {0};
  oc_device_info_t *device_info = oc_core_get_device_info(device_index);
  if (!device_info)
    return false;
  oc_uuid_to_str(&device_info->di, uuid, OC_UUID_LEN);

  return rd_delete_with_device_id(endpoint, links, uuid, handler, qos,
                                  user_data);
}
