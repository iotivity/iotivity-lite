/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_resource_internal.h"
#include "api/oc_core_res_internal.h"
#include "oc_api.h"
#include "oc_cloud_internal.h"
#include "oc_cloud_log_internal.h"
#include "oc_cloud_store_internal.h"
#include "oc_core_res.h"

oc_string_view_t
oc_cps_to_string(oc_cps_t cps)
{
  switch (cps) {
  case OC_CPS_UNINITIALIZED:
    return OC_STRING_VIEW(OC_CPS_UNINITIALIZED_STR);
  case OC_CPS_READYTOREGISTER:
    return OC_STRING_VIEW(OC_CPS_READYTOREGISTER_STR);
  case OC_CPS_REGISTERING:
    return OC_STRING_VIEW(OC_CPS_REGISTERING_STR);
  case OC_CPS_REGISTERED:
    return OC_STRING_VIEW(OC_CPS_REGISTERED_STR);
  case OC_CPS_FAILED:
    return OC_STRING_VIEW(OC_CPS_FAILED_STR);
  case OC_CPS_DEREGISTERING:
    return OC_STRING_VIEW(OC_CPS_DEREGISTERING_STR);
  default:
    break;
  }
  return OC_STRING_VIEW_NULL;
}

static bool
cloud_encode(const oc_cloud_context_t *ctx)
{
  OC_CLOUD_DBG("Creating Cloud Response");
  oc_rep_start_root_object();

  const oc_resource_t *cloud_conf =
    oc_core_get_resource_by_index(OCF_COAPCLOUDCONF, ctx->device);
  oc_process_baseline_interface(cloud_conf);

  oc_string_view_t auth_provider = oc_string_view2(&ctx->store.auth_provider);
  oc_rep_set_text_string_v1(root, apn, auth_provider.data,
                            auth_provider.length);

  oc_string_view_t cis = oc_string_view2(&ctx->store.ci_server);
  oc_rep_set_text_string_v1(root, cis, cis.data, cis.length);

  oc_string_view_t sid = oc_string_view2(&ctx->store.sid);
  oc_rep_set_text_string_v1(root, sid, sid.data, sid.length);

  oc_rep_set_int(root, clec, (int)ctx->last_error);

  OC_CLOUD_DBG(
    "Creating Cloud Response: auth provider=%s, cis=%s, sid=%s, clec=%d",
    auth_provider.data != NULL ? auth_provider.data : "",
    cis.data != NULL ? cis.data : "", sid.data != NULL ? sid.data : "",
    (int)ctx->last_error);

  oc_string_view_t cps = oc_cps_to_string(ctx->store.cps);
  if (cps.length > 0) {
    OC_CLOUD_DBG("Creating Cloud Response: cps=%s", cps.data);
    oc_rep_set_text_string_v1(root, cps, cps.data, cps.length);
  }

  oc_rep_end_root_object();
  return oc_rep_get_cbor_errno() == CborNoError;
}

static void
cloud_resource_get(oc_request_t *request, oc_interface_mask_t interface,
                   void *user_data)
{
  (void)user_data;
  (void)interface;
  OC_CLOUD_DBG("GET request received");

  const oc_cloud_context_t *ctx =
    oc_cloud_get_context(request->resource->device);
  if (ctx == NULL || !cloud_encode(ctx)) {
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
    return;
  }

  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

static bool
cloud_update_from_request(oc_cloud_context_t *ctx, const oc_request_t *request)
{
  cloud_conf_update_t data;
  memset(&data, 0, sizeof(data));

  char *access_token = NULL;
  bool has_at = oc_rep_get_string(request->request_payload,
                                  OCF_COAPCLOUDCONF_PROP_ACCESSTOKEN,
                                  &access_token, &data.access_token_len);
  if (has_at) {
    data.access_token = access_token;
  }

  char *auth_provider = NULL;
  if (oc_rep_get_string(request->request_payload,
                        OCF_COAPCLOUDCONF_PROP_AUTHPROVIDER, &auth_provider,
                        &data.auth_provider_len)) {
    data.auth_provider = auth_provider;
  }

  char *ci_server = NULL;
  bool has_cis =
    oc_rep_get_string(request->request_payload, OCF_COAPCLOUDCONF_PROP_CISERVER,
                      &ci_server, &data.ci_server_len);
  if (has_cis) {
    data.ci_server = ci_server;
  }

  // OCF 2.0 spec version added sid property.
  char *sid = NULL;
  bool has_sid =
    oc_rep_get_string(request->request_payload, OCF_COAPCLOUDCONF_PROP_SERVERID,
                      &sid, &data.sid_len);
  if (has_sid) {
    data.sid = sid;
  }

  if (has_cis && (data.ci_server_len == 0 || (has_at && has_sid))) {
    cloud_update_by_resource(ctx, &data);
    return true;
  }
  return false;
}

static void
cloud_resource_post(oc_request_t *request, oc_interface_mask_t interface,
                    void *user_data)
{
  (void)user_data;
  (void)interface;
  oc_cloud_context_t *ctx = oc_cloud_get_context(request->resource->device);
  if (!ctx) {
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
    return;
  }
  OC_CLOUD_DBG("POST request received");
  bool request_invalid_in_state = true;
  switch (ctx->store.cps) {
  case OC_CPS_UNINITIALIZED:
  case OC_CPS_READYTOREGISTER:
  case OC_CPS_FAILED:
  case OC_CPS_DEREGISTERING:
    request_invalid_in_state = false;
    break;
  case OC_CPS_REGISTERING:
  case OC_CPS_REGISTERED: {
    // Update allowed but only for a "cis" of empty string
    //
    char *cis;
    size_t cis_len = 0;
    if (oc_rep_get_string(request->request_payload,
                          OCF_COAPCLOUDCONF_PROP_CISERVER, &cis, &cis_len) &&
        cis_len == 0) {
      request_invalid_in_state = false;
    }
  }
  }
  if (request_invalid_in_state) {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }

  char *cps;
  size_t cps_len = 0;
  if (oc_rep_get_string(request->request_payload,
                        OCF_COAPCLOUDCONF_PROP_PROVISIONINGSTATUS, &cps,
                        &cps_len)) {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
    return;
  }

  bool changed = cloud_update_from_request(ctx, request);
  cloud_encode(ctx);
  oc_send_response_with_callback(
    request, changed ? OC_STATUS_CHANGED : OC_STATUS_BAD_REQUEST, true);
  if (changed) {
    cloud_store_dump_async(&ctx->store);
  }
}

void
oc_create_cloudconf_resource(size_t device)
{
  OC_CLOUD_DBG("oc_cloud_resource: Initializing CoAPCloudConf resource");

  oc_core_populate_resource(
    OCF_COAPCLOUDCONF, device, OCF_COAPCLOUDCONF_URI, OCF_COAPCLOUDCONF_IF_MASK,
    OCF_COAPCLOUDCONF_DEFAULT_IF, OC_SECURE | OC_DISCOVERABLE | OC_OBSERVABLE,
    cloud_resource_get, /*put*/ NULL, cloud_resource_post, /*delete*/ NULL, 1,
    OCF_COAPCLOUDCONF_RT);
}

#endif /* OC_CLOUD */
