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
#include "oc_core_res.h"
#include "oc_log.h"

bool
rd_publish(oc_endpoint_t *endpoint, oc_resource_t *resource,
           oc_response_handler_t handler, void *user_data)
{
  if (!endpoint) {
    OC_ERR("Error of input parameters");
    return false;
  }

  char target_uri[23] = { 0 };
  snprintf(target_uri, 23, "%s?rt=%s", OC_RSRVD_RD_URI,
           OC_RSRVD_RESOURCE_TYPE_RDPUBLISH);

  if (oc_init_post(target_uri, endpoint, NULL, handler, LOW_QOS, user_data)) {
    char uuid[37];
    oc_uuid_to_str(oc_core_get_device_id(0), uuid, 37);

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, di, uuid);
    oc_rep_set_int(root, OC_RSRVD_DEVICE_TTL, OIC_RD_PUBLISH_TTL);

    oc_rep_set_array(root, links);
    oc_rep_object_array_start_item(links);
    oc_rep_set_text_string(links, href, oc_string(resource->uri));
    oc_rep_set_string_array(links, rt, resource->types);
    oc_core_encode_interfaces_mask(oc_rep_object(links), resource->interfaces);
    oc_rep_object_array_end_item(links);
    oc_rep_close_array(root, links);

    oc_rep_end_root_object();
  } else {
    OC_ERR("Could not init POST request for rd publish");
    return false;
  }

  return oc_do_post();
}

bool
rd_delete(oc_endpoint_t *endpoint, oc_response_handler_t handler,
          void *user_data)
{
  if (!endpoint) {
    OC_ERR("Error of input parameters");
    return false;
  }

  char uuid[37];
  oc_uuid_to_str(oc_core_get_device_id(0), uuid, 37);

  char target_uri[49] = { 0 };
  snprintf(target_uri, 49, "%s?di=%s", OC_RSRVD_RD_URI, uuid);
  if (!oc_do_delete(target_uri, endpoint, handler, LOW_QOS, user_data)) {
    OC_ERR("Could not DELETE request for rd delete");
    return false;
  }

  return true;
}
