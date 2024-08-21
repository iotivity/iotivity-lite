/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#include "plgd_dps_apis_internal.h"
#include "plgd_dps_cloud_internal.h"
#include "plgd_dps_context_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_manager_internal.h"
#include "plgd_dps_provision_internal.h"
#include "plgd_dps_provision_cloud_internal.h"
#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_internal.h"

#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_manager_internal.h"
#include "oc_api.h"
#include "oc_cloud.h"
#include "oc_cloud_access.h"
#include "oc_core_res.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "security/oc_pstat_internal.h"

#include <assert.h>

#define PLGD_DPS_CLOUD_URI "/api/v1/provisioning/cloud-configuration"

bool
dps_register_cloud_fill_data(const oc_rep_t *payload, cloud_conf_t *cloud)
{
  const oc_rep_t *act =
    oc_rep_get_by_type_and_key(payload, OC_REP_STRING, DPS_CLOUD_ACCESSTOKEN,
                               OC_CHAR_ARRAY_LEN(DPS_CLOUD_ACCESSTOKEN));
  if (act == NULL) {
    DPS_ERR("key(%s) missing in %s response", DPS_CLOUD_ACCESSTOKEN,
            PLGD_DPS_CLOUD_URI);
    return false;
  }
  const oc_rep_t *apn =
    oc_rep_get_by_type_and_key(payload, OC_REP_STRING, DPS_CLOUD_AUTHPROVIDER,
                               OC_CHAR_ARRAY_LEN(DPS_CLOUD_AUTHPROVIDER));
  if (apn == NULL) {
    DPS_ERR("key(%s) missing in %s response", DPS_CLOUD_AUTHPROVIDER,
            PLGD_DPS_CLOUD_URI);
    return false;
  }
  const oc_rep_t *cis =
    oc_rep_get_by_type_and_key(payload, OC_REP_STRING, DPS_CLOUD_CISERVER,
                               OC_CHAR_ARRAY_LEN(DPS_CLOUD_CISERVER));
  if (cis == NULL) {
    DPS_ERR("key(%s) missing in %s response", DPS_CLOUD_CISERVER,
            PLGD_DPS_CLOUD_URI);
    return false;
  }
  const oc_rep_t *sid =
    oc_rep_get_by_type_and_key(payload, OC_REP_STRING, DPS_CLOUD_SERVERID,
                               OC_CHAR_ARRAY_LEN(DPS_CLOUD_SERVERID));
  if (sid == NULL) {
    DPS_ERR("key(%s) missing in %s response", DPS_CLOUD_SERVERID,
            PLGD_DPS_CLOUD_URI);
    return false;
  }
  cloud->access_token = &act->value.string;
  cloud->auth_provider = &apn->value.string;
  cloud->ci_server = &cis->value.string;
  cloud->sid = &sid->value.string;

  const oc_rep_t *servers = oc_rep_get_by_type_and_key(
    payload, OC_REP_OBJECT_ARRAY, DPS_CLOUD_ENDPOINTS,
    OC_CHAR_ARRAY_LEN(DPS_CLOUD_ENDPOINTS));
  if (servers != NULL) {
    cloud->ci_servers = servers->value.object_array;
#if DPS_DBG_IS_ENABLED
    // GCOVR_EXCL_START
    for (const oc_rep_t *server = cloud->ci_servers; server != NULL;
         server = server->next) {
      const oc_rep_t *rep = oc_rep_get_by_type_and_key(
        server->value.object, OC_REP_STRING, DPS_CLOUD_ENDPOINT_URI,
        OC_CHAR_ARRAY_LEN(DPS_CLOUD_ENDPOINT_URI));
      oc_string_view_t uriv = { 0 };
      if (rep != NULL) {
        uriv = oc_string_view2(&rep->value.string);
      }
      rep = oc_rep_get_by_type_and_key(
        server->value.object, OC_REP_STRING, DPS_CLOUD_ENDPOINT_ID,
        OC_CHAR_ARRAY_LEN(DPS_CLOUD_ENDPOINT_ID));
      oc_string_view_t idv = { 0 };
      if (rep != NULL) {
        idv = oc_string_view2(&rep->value.string);
      }
      DPS_DBG("cloud server: uri(%s) id(%s)",
              uriv.data != NULL ? uriv.data : "NULL",
              idv.data != NULL ? idv.data : "NULL");
    }
    // GCOVR_EXCL_STOP
#endif /* DPS_DBG_IS_ENABLED */
  }

  return true;
}

static void
cloud_deregister_handler(oc_client_response_t *resp)
{
#if DPS_ERR_IS_ENABLED
  // GCOVR_EXCL_START
  DPS_DBG("cloud deregister handler");
  if (resp->code == OC_STATUS_DELETED) {
    DPS_DBG("cloud deregistered");
  } else {
    DPS_ERR("cloud deregister failed");
  }
  // GCOVR_EXCL_STOP
#endif /* DPS_ERR_IS_ENABLED */
  // close hijacked session
  oc_close_session(resp->endpoint);
}

static bool
cloud_deregister(const oc_cloud_context_t *cloud_ctx, uint16_t timeout)
{
  DPS_DBG("try deregister device %zu by DELETE request",
          oc_cloud_get_device(cloud_ctx));

  const oc_endpoint_t *cloud_ep = oc_cloud_get_server(cloud_ctx);
  assert(cloud_ep != NULL); // should always be allocated at this point
  if (oc_endpoint_is_empty(cloud_ep)) {
    return false;
  }
  oc_cloud_access_conf_t conf = {
    .endpoint = cloud_ep,
    .device = oc_cloud_get_device(cloud_ctx),
    .selected_identity_cred_id = oc_cloud_get_identity_cert_chain(cloud_ctx),
    .handler = cloud_deregister_handler,
    .user_data = NULL,
    .timeout = timeout,
  };
  return oc_cloud_access_deregister(
    conf, oc_string(*oc_cloud_get_user_id(cloud_ctx)), NULL);
}

plgd_dps_error_t
dps_handle_set_cloud_response(oc_client_response_t *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data->user_data;
  cloud_conf_t cloud;
  memset(&cloud, 0, sizeof(cloud));
  if (!dps_register_cloud_fill_data(data->payload, &cloud)) {
    DPS_ERR("cannot parse configure cloud response for device(%zu)",
            ctx->device);
    return PLGD_DPS_ERROR_RESPONSE;
  }

  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx == NULL) {
    DPS_ERR("cannot get cloud context for device(%zu)", ctx->device);
    return PLGD_DPS_ERROR_SET_CLOUD;
  }

  if ((oc_cloud_get_status(cloud_ctx) & OC_CLOUD_LOGGED_IN) != 0) {
    const oc_string_t *cloud_ctx_cis = oc_cloud_get_server_uri(cloud_ctx);
    const oc_uuid_t *cloud_ctx_sid = oc_cloud_get_server_id(cloud_ctx);
    if (cloud_ctx_cis == NULL || cloud_ctx_sid == NULL) {
      DPS_ERR("cannot get cloud server for device(%zu)", ctx->device);
      return PLGD_DPS_ERROR_SET_CLOUD;
    }
    oc_string_view_t sidv = oc_string_view2(cloud.sid);
    oc_uuid_t sid;
    oc_str_to_uuid_v1(sidv.data, sidv.length, &sid);
    const oc_string_t *cloud_apn =
      oc_cloud_get_authorization_provider_name(cloud_ctx);
    if (dps_is_equal_string(*cloud_ctx_cis, *cloud.ci_server) &&
        oc_uuid_is_equal(*cloud_ctx_sid, sid) && cloud_apn != NULL &&
        dps_is_equal_string(*cloud_apn, *cloud.auth_provider)) {
      DPS_DBG("cloud configuration is already set for device(%zu)",
              ctx->device);
      return PLGD_DPS_OK;
    }

    // deregister device from old cloud
    if (!oc_uuid_is_equal(*cloud_ctx_sid, sid)) {
      DPS_DBG("deregister device(%zu) from old cloud", ctx->device);
      if (cloud_deregister(cloud_ctx, 3)) {
        // connection is closed in cloud_deregister_handler, so we hijack the
        // connection and reset the cloud context
        DPS_DBG("deregister has been sent, hijack the connection");
        cloud_ctx->cloud_ep_state = OC_SESSION_DISCONNECTED;
        memset(cloud_ctx->cloud_ep, 0, sizeof(oc_endpoint_t));
        oc_cloud_context_clear(cloud_ctx, true);
      } else {
        DPS_ERR("failed to deregister device(%zu) from old cloud", ctx->device);
      }
    } else {
      DPS_DBG("deregister device(%zu) from old cloud is not executed because: "
              "cloud id(%s) has not been changed",
              ctx->device, sidv.data != NULL ? sidv.data : "(NULL)");
    }
  }

  // stop the cloud, otherwise oc_cloud_provision_conf_resource would restart
  // the cloud automatically, with the new configuration, but we want to wait
  // for the DPS reprovisioning to be done and then start it manually
  oc_cloud_manager_stop_v1(cloud_ctx, false);
  dps_cloud_observer_deinit(ctx);

  const char *ci_server = oc_string(*cloud.ci_server);
  const char *access_token = oc_string(*cloud.access_token);
  const char *sid = oc_string(*cloud.sid);
  const char *auth_provider = oc_string(*cloud.auth_provider);
  DPS_DBG("cloud configuration:");
  DPS_DBG("\tserver: %s", ci_server != NULL ? ci_server : "");
  DPS_DBG("\taccess_token: %s", access_token != NULL ? access_token : "");
  DPS_DBG("\tsid: %s", sid != NULL ? sid : "");
  DPS_DBG("\tauth_provider: %s", auth_provider != NULL ? auth_provider : "");

  if (oc_cloud_provision_conf_resource(cloud_ctx, ci_server, access_token, sid,
                                       auth_provider) != 0) {
    DPS_ERR("failed to configure cloud for device(%zu)", ctx->device);
    return PLGD_DPS_ERROR_SET_CLOUD;
  }
  dps_cloud_add_servers(cloud_ctx, cloud.ci_servers);
  return PLGD_DPS_OK;
}

bool
dps_has_cloud_configuration(size_t device)
{
  const oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(device);
  if (cloud_ctx == NULL) {
    return false;
  }
  bool has_server = oc_cloud_get_server_uri(cloud_ctx) != NULL;
  bool has_access_token =
    !oc_string_is_empty(oc_cloud_get_access_token(cloud_ctx));
  return has_server && has_access_token;
}

void
dps_set_cloud_handler(oc_client_response_t *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data->user_data;
#if DPS_DBG_IS_ENABLED
  dps_print_status("set cloud handler: ", ctx->status);
#endif /* DPS_DBG_IS_ENABLED */
  // we check only for PLGD_DPS_FAILURE flag, because retry will be rescheduled
  // if necessary
  if ((ctx->status & (PLGD_DPS_HAS_CLOUD | PLGD_DPS_FAILURE)) ==
      PLGD_DPS_HAS_CLOUD) {
    DPS_DBG("skipping duplicit call of set cloud handler");
    return;
  }

  // execute status callback right after this handler ends
  dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
  oc_remove_delayed_callback(ctx, dps_manager_provision_retry_async);
  ctx->status &= ~PLGD_DPS_PROVISIONED_ERROR_FLAGS;

  plgd_dps_error_t err = PLGD_DPS_ERROR_SET_CLOUD;
  const uint32_t expected_status = PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME |
                                   PLGD_DPS_HAS_OWNER | PLGD_DPS_GET_CLOUD;
  if (ctx->status != expected_status) {
#if DPS_ERR_IS_ENABLED
    // GCOVR_EXCL_START
    char str[256]; // NOLINT
    int ret = dps_status_to_logstr(ctx->status, str, sizeof(str));
    DPS_ERR("invalid status(%u:%s) in set cloud handler", (unsigned)ctx->status,
            ret >= 0 ? str : "(NULL)");
    // GCOVR_EXCL_STOP
#endif /* DPS_ERR_IS_ENABLED */
    goto error;
  }

  int ret = dps_provisioning_check_response(ctx, data->code, data->payload);
  if (ret != 0) {
    DPS_ERR("invalid %s response", PLGD_DPS_CLOUD_URI);
    // ctx->status and ctx->last_error are set in
    // dps_provisioning_check_response
    dps_provisioning_handle_failure(ctx, data->code, /*schedule_retry*/ true);
    return;
  }

  err = dps_handle_set_cloud_response(data);
  if (err != PLGD_DPS_OK) {
    goto error;
  }

  DPS_INFO("Cloud configuration set successfully");
  dps_set_ps_and_last_error(
    ctx, PLGD_DPS_HAS_CLOUD,
    PLGD_DPS_GET_CLOUD | PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  dps_retry_reset(ctx, dps_provision_get_next_action(ctx));
  ctx->transient_retry_count = 0;

  // go to next step -> get credentials
  dps_provisioning_schedule_next_step(ctx);
  return;

error:
  dps_set_ps_and_last_error(ctx, PLGD_DPS_FAILURE, 0, err);
}

bool
dps_provisioning_set_cloud_encode_selected_gateway(
  const plgd_dps_context_t *ctx)
{
  const oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx == NULL) {
    DPS_ERR("cannot get cloud context for device(%zu)", ctx->device);
    return false;
  }

  const oc_endpoint_address_t *selected_gateway =
    oc_cloud_selected_server_address(cloud_ctx);
  if (selected_gateway == NULL) {
    return true;
  }

  const oc_string_t *selected_uri = oc_endpoint_address_uri(selected_gateway);
  assert(selected_uri != NULL);

  const oc_uuid_t *selected_uuid = oc_endpoint_address_uuid(selected_gateway);
  assert(selected_uuid != NULL);
  char uuid[OC_UUID_LEN] = { 0 };
  int uuid_len = oc_uuid_to_str_v1(selected_uuid, uuid, OC_UUID_LEN);
  assert(uuid_len > 0);

  // {
  //   uri: ${uri},
  //   id: ${uuid}
  // }
  oc_rep_open_object(root, selectedGateway);
  oc_rep_set_text_string_v1(selectedGateway, uri, oc_string(*selected_uri),
                            oc_string_len_unsafe(*selected_uri));
  oc_rep_set_text_string_v1(selectedGateway, id, uuid, (size_t)uuid_len);
  oc_rep_close_object(root, selectedGateway);
  return oc_rep_get_cbor_errno() == CborNoError;
}

bool
dps_provisioning_set_cloud_encode_payload(const plgd_dps_context_t *ctx)
{
  const oc_uuid_t *device_id = oc_core_get_device_id(ctx->device);
  if (device_id == NULL) {
    DPS_ERR("failed to get device id");
    return false;
  }
  char uuid[OC_UUID_LEN] = { 0 };
  int uuid_len = oc_uuid_to_str_v1(device_id, uuid, OC_UUID_LEN);
  assert(uuid_len > 0);

  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, di, uuid, uuid_len);
  if (!dps_provisioning_set_cloud_encode_selected_gateway(ctx)) {
    return false;
  }
  oc_rep_end_root_object();

  return oc_rep_get_cbor_errno() == CborNoError;
}

bool
dps_provisioning_set_cloud(plgd_dps_context_t *ctx)
{
  DPS_INFO("Get cloud configuration");
  assert(ctx->endpoint != NULL);
#ifdef OC_SECURITY
  if (!oc_device_is_in_dos_state(ctx->device,
                                 OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP))) {
    DPS_ERR("device is not in RFNOP state");
    return false;
  }
#endif /* OC_SECURITY */

  if (!oc_init_post(PLGD_DPS_CLOUD_URI, ctx->endpoint, NULL,
                    dps_set_cloud_handler, LOW_QOS, ctx)) {
    DPS_ERR("could not init POST request to %s", PLGD_DPS_CLOUD_URI);
    return false;
  }

  if (!dps_provisioning_set_cloud_encode_payload(ctx)) {
    DPS_ERR("could not encode payload for POST request to %s",
            PLGD_DPS_CLOUD_URI);
    return false;
  }

  dps_setup_tls(ctx);
  if (!oc_do_post_with_timeout(dps_retry_get_timeout(&ctx->retry))) {
    dps_reset_tls();
    DPS_ERR("failed to dispatch POST request to %s", PLGD_DPS_CLOUD_URI);
    return false;
  }
  dps_set_ps_and_last_error(ctx, PLGD_DPS_GET_CLOUD, 0, PLGD_DPS_OK);
  return true;
}
