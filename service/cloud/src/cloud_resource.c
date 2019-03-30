/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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

#include "cloud_internal.h"
#include "oc_api.h"
#include "oc_config.h"

#define OC_RSRVD_RES_TYPE_COAPCLOUDCONF "oic.r.coapcloudconf"
#define OC_RSRVD_URI_COAPCLOUDCONF "/CoapCloudConfResURI"
#define OC_RSRVD_ACCESSTOKEN "at"
#define OC_RSRVD_AUTHPROVIDER "apn"
#define OC_RSRVD_CISERVER "cis"
#define OC_RSRVD_SERVERID "sid"
#define OC_RSRVD_LAST_ERROR_CODE "clec"

static void cloud_response(cloud_context_t *ctx) {
  oc_rep_start_root_object();
  oc_process_baseline_interface(ctx->cloud_conf);
  oc_rep_set_text_string(root, apn,
                         (oc_string(ctx->store.auth_provider) != NULL
                              ? oc_string(ctx->store.auth_provider)
                              : ""));
  oc_rep_set_text_string(
      root, cis,
      (oc_string(ctx->store.ci_server) ? oc_string(ctx->store.ci_server) : ""));
  oc_rep_set_text_string(
      root, sid, (oc_string(ctx->store.sid) ? oc_string(ctx->store.sid) : ""));
  oc_rep_set_text_string(root, at, "");
  oc_rep_set_int(root, clec, (int)ctx->last_error);

  oc_rep_end_root_object();
}

static void get_cloud(oc_request_t *request, oc_interface_mask_t interface,
                      void *user_data) {
  cloud_context_t *ctx = (cloud_context_t *)user_data;
  OC_DBG("GET request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  cloud_response(ctx);
  oc_send_response(request, OC_STATUS_OK);
}

static bool cloud_update_from_request(cloud_context_t *ctx,
                                      oc_request_t *request) {
  bool changed = false;
  cloud_conf_update_t data;
  memset(&data, 0, sizeof(data));

  if (oc_rep_get_string(request->request_payload, OC_RSRVD_ACCESSTOKEN,
                        &data.access_token, &data.access_token_len)) {
    changed = true;
  }

  if (oc_rep_get_string(request->request_payload, OC_RSRVD_AUTHPROVIDER,
                        &data.auth_provider, &data.auth_provider_len)) {
    changed = true;
  }

  if (oc_rep_get_string(request->request_payload, OC_RSRVD_CISERVER,
                        &data.ci_server, &data.ci_server_len)) {
    changed = true;
  }

  // OCF 2.0 spec version added sid property.
  if (oc_rep_get_string(request->request_payload, OC_RSRVD_SERVERID, &data.sid,
                        &data.sid_len)) {
    changed = true;
  }

  if (changed) {
    cloud_update_by_resource(ctx, &data);
  }
  return changed;
}

static void post_cloud(oc_request_t *request, oc_interface_mask_t interface,
                       void *user_data) {
  cloud_context_t *ctx = (cloud_context_t *)user_data;
  OC_DBG("POST request received");

  if (interface != OC_IF_BASELINE) {
    OC_ERR("Resource does not support this interface: %d", interface);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  bool changed = cloud_update_from_request(ctx, request);
  cloud_response(ctx);
  oc_send_response(request,
                   changed ? OC_STATUS_CHANGED : OC_STATUS_NOT_MODIFIED);

  // Notify observers about data change
  if (changed) {
    oc_notify_observers(ctx->cloud_conf);
  }
}

bool cloud_resource_init(cloud_context_t *ctx) {
  oc_resource_t *res = oc_new_resource("cloud", OC_RSRVD_URI_COAPCLOUDCONF, 1,
                                       ctx->device_index);
  if (!res) {
    OC_WRN("insufficient memory to create resource for cloud resource");
    return false;
  }

  oc_resource_bind_resource_type(res, OC_RSRVD_RES_TYPE_COAPCLOUDCONF);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
  oc_resource_set_request_handler(res, OC_GET, get_cloud, ctx);
  oc_resource_set_request_handler(res, OC_POST, post_cloud, ctx);
  if (!oc_add_resource(res)) {
    oc_delete_resource(res);
    return false;
  }
  ctx->cloud_conf = res;

  return true;
}
