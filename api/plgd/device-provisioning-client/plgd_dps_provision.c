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
#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_manager_internal.h"
#include "plgd_dps_context_internal.h"
#include "plgd_dps_provision_internal.h"
#include "plgd_dps_provision_cloud_internal.h"
#include "plgd_dps_provision_owner_internal.h"
#include "plgd_dps_security_internal.h"
#include "plgd_dps_store_internal.h"
#include "plgd_dps_tag_internal.h"
#include "plgd_dps_time_internal.h"
#include "plgd_dps_internal.h"

#include "oc_acl.h"
#include "oc_core_res.h"
#include "oc_store.h"
#include "security/oc_pstat_internal.h"

#include <stdint.h>
#include <string.h>

#define PLGD_DPS_ACLS_URI "/api/v1/provisioning/acls"

int
dps_provisioning_check_response(plgd_dps_context_t *ctx, oc_status_t code,
                                const oc_rep_t *payload)
{
  plgd_dps_error_t err = dps_check_response(ctx, code, payload);
  if (err == PLGD_DPS_OK) {
    return 0;
  }

  uint32_t err_status = 0;
  if (err == PLGD_DPS_ERROR_CONNECT) {
    // While retrying, keep last error (lec) to PLGD_DPS_OK
    err = PLGD_DPS_OK;
    err_status = PLGD_DPS_TRANSIENT_FAILURE;
  } else {
    err_status = PLGD_DPS_FAILURE;
  }

  dps_set_ps_and_last_error(ctx, err_status, 0, err);
  return -1;
}

#if DPS_DBG_IS_ENABLED
static void
dps_on_apply_acl(oc_sec_on_apply_acl_data_t acl_data, void *user_data)
{
  // GCOVR_EXCL_START
  (void)user_data;
  if (acl_data.ace == NULL) {
    return;
  }
  DPS_DBG("apply acl:");
  bool duplicate = !acl_data.created && acl_data.replaced_ace == NULL;
  int replaced_aceid =
    acl_data.replaced_ace != NULL ? acl_data.replaced_ace->aceid : -1;
  DPS_DBG("\tcreated:%d created resource:%d duplicate:%d replaced aceid:%d",
          acl_data.created, acl_data.created_resource, duplicate,
          replaced_aceid);
  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(&acl_data.rowneruuid, uuid, sizeof(uuid));
  const char *tag =
    oc_string_len(acl_data.ace->tag) > 0 ? oc_string(acl_data.ace->tag) : "";
  DPS_DBG("\trowneruuid:%s aceid:%d subject_type:%d permission:%d tag:%s", uuid,
          acl_data.ace->aceid, acl_data.ace->subject_type,
          acl_data.ace->permission, tag);
  oc_ace_res_t *res = (oc_ace_res_t *)oc_list_head(acl_data.ace->resources);
  if (res != NULL) {
    DPS_DBG("\tresources:");
    for (; res != NULL; res = res->next) {
      const char *href =
        oc_string_len(res->href) > 0 ? oc_string(res->href) : "";
      DPS_DBG("\t\thref:%s wildcard:%d", href, res->wildcard);
    }
  }
  // GCOVR_EXCL_STOP
}
#endif /* DPS_DBG_IS_ENABLED */

static int
dps_handle_get_acls_response(oc_client_response_t *data)
{
  const plgd_dps_context_t *ctx = (plgd_dps_context_t *)data->user_data;
  const oc_resource_t *res =
    oc_core_get_resource_by_index(OCF_SEC_ACL, ctx->device);
  if (res == NULL) {
    DPS_ERR("cannot find ACL resource for device(%zu)", ctx->device);
    return -1;
  }

  dps_acls_set_stale_tag(ctx->device);

  oc_sec_pstat_t *pstat = oc_sec_get_pstat(ctx->device);
  pstat->s = OC_DOS_RFPRO;
#if DPS_DBG_IS_ENABLED
  oc_sec_on_apply_acl_cb_t on_apply_ace_cb = dps_on_apply_acl;
#else  /* !DPS_DBG_IS_ENABLED */
  oc_sec_on_apply_acl_cb_t on_apply_ace_cb = NULL;
#endif /* DPS_DBG_IS_ENABLED */
  int ret = oc_sec_apply_acl(data->payload, ctx->device, on_apply_ace_cb,
                             /*on_apply_ace_data*/ NULL);
  pstat->s = OC_DOS_RFNOP;
  if (ret != 0) {
    DPS_ERR("cannot apply acl resource update for device(%zu)", ctx->device);
    dps_acls_remove_stale_tag(ctx->device);
    return -1;
  }
  dps_remove_stale_acls(ctx->device);

#if DPS_DBG_IS_ENABLED
  dps_print_acls(ctx->device);
#endif /* DPS_DBG_IS_ENABLED */

  oc_sec_dump_acl(ctx->device);
  return 0;
}

static void
dps_get_acls_handler(oc_client_response_t *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data->user_data;
#if DPS_DBG_IS_ENABLED
  dps_print_status("get acls handler: ", ctx->status);
#endif /* DPS_DBG_IS_ENABLED */
  // we check only for PLGD_DPS_FAILURE flag, because retry will be rescheduled
  // if necessary
  if ((ctx->status & (PLGD_DPS_HAS_ACLS | PLGD_DPS_FAILURE)) ==
      PLGD_DPS_HAS_ACLS) {
    DPS_DBG("skipping duplicit call of get acls handler");
    return;
  }
  // execute status callback right after this handler ends
  dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
  oc_remove_delayed_callback(ctx, dps_manager_provision_retry_async);
  ctx->status &= ~PLGD_DPS_PROVISIONED_ERROR_FLAGS;

  const uint32_t expected_status = PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME |
                                   PLGD_DPS_HAS_OWNER | PLGD_DPS_HAS_CLOUD |
                                   PLGD_DPS_HAS_CREDENTIALS | PLGD_DPS_GET_ACLS;
  if (ctx->status != expected_status) {
#if DPS_ERR_IS_ENABLED
    // GCOVR_EXCL_START
    char str[256]; // NOLINT
    int ret = dps_status_to_logstr(ctx->status, str, sizeof(str));
    DPS_ERR("invalid status(%u:%s) in get acls handler", (unsigned)ctx->status,
            ret >= 0 ? str : "(NULL)");
    // GCOVR_EXCL_STOP
#endif /* DPS_ERR_IS_ENABLED */
    goto error;
  }

  int ret = dps_provisioning_check_response(ctx, data->code, data->payload);
  if (ret != 0) {
    DPS_ERR("invalid %s response(status=%d)", PLGD_DPS_ACLS_URI, data->code);
    // ctx->status and ctx->last_error are set in
    // dps_provisioning_check_response
    goto finish;
  }

  ret = dps_handle_get_acls_response(data);
  if (ret != 0) {
    goto error;
  }

  DPS_INFO("Acls set successfully");
  dps_set_ps_and_last_error(
    ctx, PLGD_DPS_HAS_ACLS,
    PLGD_DPS_GET_ACLS | PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  dps_retry_reset(ctx, dps_provision_get_next_action(ctx));
  ctx->transient_retry_count = 0;

  // go to next step -> start cloud
  dps_provisioning_schedule_next_step(ctx);
  return;

error:
  dps_set_ps_and_last_error(ctx, PLGD_DPS_FAILURE, PLGD_DPS_HAS_ACLS,
                            PLGD_DPS_ERROR_GET_ACLS);
finish:
  if ((ctx->status & PLGD_DPS_PROVISIONED_ERROR_FLAGS) != 0) {
    dps_provisioning_handle_failure(ctx, data->code, /*schedule_retry*/ true);
  }
}

static bool
dps_get_acls(plgd_dps_context_t *ctx)
{
  DPS_INFO("Get acls");
#ifdef OC_SECURITY
  if (!oc_device_is_in_dos_state(ctx->device,
                                 OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP))) {
    DPS_ERR("device is not in RFNOP state");
    return false;
  }
#endif /* OC_SECURITY */

  dps_setup_tls(ctx);
  if (!oc_do_get_with_timeout(PLGD_DPS_ACLS_URI, ctx->endpoint, NULL,
                              dps_retry_get_timeout(&ctx->retry),
                              dps_get_acls_handler, LOW_QOS, ctx)) {
    DPS_ERR("failed to dispatch GET request to %s", PLGD_DPS_ACLS_URI);
    dps_reset_tls();
    return false;
  }
  dps_set_ps_and_last_error(ctx, PLGD_DPS_GET_ACLS,
                            PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  return true;
}

static void
dps_get_credentials_handler(oc_client_response_t *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data->user_data;
#if DPS_DBG_IS_ENABLED
  dps_print_status("get credentials handler: ", ctx->status);
#endif /* DPS_DBG_IS_ENABLED */
  // we check only for PLGD_DPS_FAILURE flag, because retry will be rescheduled
  // if necessary
  if ((ctx->status & (PLGD_DPS_HAS_CREDENTIALS | PLGD_DPS_FAILURE)) ==
      PLGD_DPS_HAS_CREDENTIALS) {
    DPS_DBG("skipping duplicit call of get credentials handler");
    return;
  }
  // execute status callback right after this handler ends
  dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
  oc_remove_delayed_callback(ctx, dps_manager_provision_retry_async);
  ctx->status &= ~PLGD_DPS_PROVISIONED_ERROR_FLAGS;

  const uint32_t expected_status = PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME |
                                   PLGD_DPS_HAS_OWNER | PLGD_DPS_HAS_CLOUD |
                                   PLGD_DPS_GET_CREDENTIALS;
  if (ctx->status != expected_status) {
#if DPS_ERR_IS_ENABLED
    // GCOVR_EXCL_START
    char str[256]; // NOLINT
    int ret = dps_status_to_logstr(ctx->status, str, sizeof(str));
    DPS_ERR("invalid status(%u:%s) in get credentials handler",
            (unsigned)ctx->status, ret >= 0 ? str : "(NULL)");
    // GCOVR_EXCL_STOP
#endif /* DPS_ERR_IS_ENABLED */
    goto error;
  }

  if (dps_provisioning_check_response(ctx, data->code, data->payload) != 0) {
    DPS_ERR("invalid %s response(status=%d)", PLGD_DPS_CREDS_URI, data->code);
    // ctx->status and ctx->last_error are set in
    // dps_provisioning_check_response
    goto finish;
  }

  if (!dps_pki_replace_certificates(ctx->device, data->payload,
                                    data->endpoint)) {
    goto error;
  }

  if (!dps_check_credentials_and_schedule_renewal(ctx, 0)) {
    DPS_ERR("valid certificates not found");
    goto error;
  }

  if (!dps_try_set_identity_chain(ctx->device)) {
    DPS_ERR("failed to set identity certificate chain");
    goto error;
  }

  DPS_INFO("Credentials set successfully");
  dps_set_ps_and_last_error(
    ctx, PLGD_DPS_HAS_CREDENTIALS,
    PLGD_DPS_GET_CREDENTIALS | PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  dps_retry_reset(ctx, dps_provision_get_next_action(ctx));
  ctx->transient_retry_count = 0;

  // go to next step -> get acls
  dps_provisioning_schedule_next_step(ctx);
  return;

error:
  dps_set_ps_and_last_error(ctx, PLGD_DPS_FAILURE, PLGD_DPS_HAS_CREDENTIALS,
                            PLGD_DPS_ERROR_GET_CREDENTIALS);
finish:
  if ((ctx->status & PLGD_DPS_PROVISIONED_ERROR_FLAGS) != 0) {
    dps_provisioning_handle_failure(ctx, data->code, /*schedule_retry*/ true);
  }
}

/**
 * @brief Request provisioning credentials.
 *
 * Prepare and send POST request to PLGD_DPS_CREDS_URI and register
 * handler for response with credentials.
 *
 * @param ctx device registration context
 * @return true POST request successfully dispatched
 * @return false on failure
 */
static bool
dps_get_credentials(plgd_dps_context_t *ctx)
{
  DPS_INFO("Get credentials");
#ifdef OC_SECURITY
  if (!oc_device_is_in_dos_state(ctx->device,
                                 OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP))) {
    DPS_ERR("device is not in RFNOP state");
    return false;
  }
#endif /* OC_SECURITY */
  if (!dps_pki_send_csr(ctx, dps_get_credentials_handler)) {
    return false;
  }
  dps_set_ps_and_last_error(ctx, PLGD_DPS_GET_CREDENTIALS,
                            PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  return true;
}

void
dps_provisioning_schedule_next_step(plgd_dps_context_t *ctx)
{
  dps_reset_delayed_callback(ctx, dps_provision_next_step_async, 0);
}

static bool
dps_provision_next_step_time(plgd_dps_context_t *ctx)
{
  if (!dps_get_plgd_time(ctx)) {
    DPS_ERR("Getting of DPS time failed");
    return false;
  }
  return true;
}

static bool
dps_provision_next_step_owner(plgd_dps_context_t *ctx)
{
  if (!dps_get_owner(ctx)) {
    DPS_ERR("Getting of DPS ownership failed");
    return false;
  }
  return true;
}

static bool
dps_provision_next_step_cloud_configuration(plgd_dps_context_t *ctx)
{
  if (!dps_provisioning_set_cloud(ctx)) {
    DPS_ERR("Get of cloud configuration failed");
    return false;
  }
  return true;
}

static bool
dps_provision_next_step_credentials(plgd_dps_context_t *ctx)
{
  if (!dps_get_credentials(ctx)) {
    DPS_ERR("Getting of DPS credentials failed");
    return false;
  }
  return true;
}

static bool
dps_provision_next_step_acls(plgd_dps_context_t *ctx)
{
  if (!dps_get_acls(ctx)) {
    DPS_ERR("Getting of DPS ACLs failed");
    return false;
  }
  return true;
}

enum {
  DPS_START_CLOUD_OK = 0,
  DPS_START_CLOUD_MISSING_CERTIFICATES = -1,
  DPS_START_CLOUD_FAILED = -2,
};

static int
dps_provision_next_step_start_cloud(plgd_dps_context_t *ctx)
{
  if (!oc_has_delayed_callback(ctx, dps_pki_renew_certificates_async, false)) {
    // replacing of certificates was triggered and skipped in the meantime, we
    // recheck all credentials to verify that they are still valid and to
    // reschedule callback to replace expired certificates
    DPS_DBG("renewal of certificates not scheduled, force recheck");
    if (!dps_check_credentials_and_schedule_renewal(ctx, 0)) {
      DPS_ERR("Starting of cloud registration failed: %s",
              "no valid certificates found");
      return DPS_START_CLOUD_MISSING_CERTIFICATES;
    }
  }
  if (!dps_provisioning_start_cloud(ctx)) {
    DPS_ERR("Starting of cloud registration failed");
    return DPS_START_CLOUD_FAILED;
  }
  return DPS_START_CLOUD_OK;
}

plgd_dps_status_t
dps_provision_get_next_action(const plgd_dps_context_t *ctx)
{
  if ((ctx->status & PLGD_DPS_HAS_TIME) == 0) {
    return PLGD_DPS_GET_TIME;
  }
  if ((ctx->status & PLGD_DPS_HAS_OWNER) == 0) {
    return PLGD_DPS_GET_OWNER;
  }
  if ((ctx->status & PLGD_DPS_HAS_CLOUD) == 0) {
    return PLGD_DPS_GET_CLOUD;
  }
  if ((ctx->status & PLGD_DPS_HAS_CREDENTIALS) == 0) {
    return PLGD_DPS_GET_CREDENTIALS;
  }
  if ((ctx->status & PLGD_DPS_HAS_ACLS) == 0) {
    return PLGD_DPS_GET_ACLS;
  }
  return 0;
}

oc_event_callback_retval_t
dps_provision_next_step_async(void *user_data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)user_data;
  bool provisioned = false;
  bool failure = false;
  bool missing_certificates = false;

  if ((ctx->status & PLGD_DPS_HAS_TIME) == 0) {
    failure = !dps_provision_next_step_time(ctx);
    goto finish;
  }

  if ((ctx->status & PLGD_DPS_HAS_OWNER) == 0) {
    failure = !dps_provision_next_step_owner(ctx);
    goto finish;
  }

  if ((ctx->status & PLGD_DPS_HAS_CLOUD) == 0) {
    failure = !dps_provision_next_step_cloud_configuration(ctx);
    goto finish;
  }

  if ((ctx->status & PLGD_DPS_HAS_CREDENTIALS) == 0) {
    failure = !dps_provision_next_step_credentials(ctx);
    goto finish;
  }

  if ((ctx->status & PLGD_DPS_HAS_ACLS) == 0) {
    failure = !dps_provision_next_step_acls(ctx);
    goto finish;
  }

  if (dps_is_provisioned(ctx)) {
    provisioned = true;
    if (!dps_is_provisioned_with_cloud_started(ctx)) {
      int ret = dps_provision_next_step_start_cloud(ctx);
      failure = ret != DPS_START_CLOUD_OK;
      missing_certificates = ret == DPS_START_CLOUD_MISSING_CERTIFICATES;
      goto finish;
    }
  }

finish:
  if (failure) {
    ctx->status |= PLGD_DPS_FAILURE;
    dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
    if (!provisioned) {
      // if provisioning is not done then schedule retry in case of error or
      // timeout
      dps_reset_delayed_callback_ms(ctx, dps_manager_provision_retry_async,
                                    dps_retry_get_delay(&ctx->retry));
    } else if (missing_certificates) {
      // we have to redo from the credentials step if certificates expired in
      // the meantime
      dps_set_ps_and_last_error(ctx, 0,
                                PLGD_DPS_GET_CREDENTIALS |
                                  PLGD_DPS_HAS_CREDENTIALS | PLGD_DPS_GET_ACLS |
                                  PLGD_DPS_HAS_ACLS,
                                ctx->last_error);
      dps_reset_delayed_callback_ms(ctx, dps_manager_provision_retry_async,
                                    dps_retry_get_delay(&ctx->retry));
    }
    return OC_EVENT_DONE;
  }
  if (provisioned) {
    dps_set_has_been_provisioned_since_reset(ctx, true);
  }
  return OC_EVENT_DONE;
}

oc_event_callback_retval_t
dps_provisioning_start_async(void *user_data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)user_data;
#define DPS_PROVISIONING_WAIT_INTERVAL_MS (500)
  if (oc_reset_in_progress(plgd_dps_get_device(ctx))) {
    DPS_DBG("reset in progress");
    dps_reset_delayed_callback_ms(ctx, dps_provisioning_start_async,
                                  DPS_PROVISIONING_WAIT_INTERVAL_MS);
    return OC_EVENT_DONE;
  }
  if (oc_process_is_closing_all_tls_sessions()) {
    DPS_DBG(
      "tls not ready, waiting for close all tls sessions event to finish");
    dps_reset_delayed_callback_ms(ctx, dps_provisioning_start_async,
                                  DPS_PROVISIONING_WAIT_INTERVAL_MS);
    return OC_EVENT_DONE;
  }
  dps_provisioning_schedule_next_step(ctx);
  return OC_EVENT_DONE;
}

void
dps_provisioning_start(plgd_dps_context_t *ctx)
{
#if DPS_INFO_IS_ENABLED
  // GCOVR_EXCL_START
#define ENDPOINT_STR_LEN 256
  char ep_str[ENDPOINT_STR_LEN] = { 0 };
#undef ENDPOINT_STR_LEN
  bool valid = dps_endpoint_log_string(ctx->endpoint, ep_str, sizeof(ep_str));
  DPS_INFO("Provisioning starting with %s", valid ? ep_str : "NULL");
  // GCOVR_EXCL_STOP
#endif /* DPS_INFO_IS_ENABLED */
  dps_reset_delayed_callback(ctx, dps_provisioning_start_async, 0);
}

bool
dps_provisioning_start_cloud(plgd_dps_context_t *ctx)
{
  DPS_INFO("DPS provisioning steps finished successfully");
  // execute status callback right after this handler ends
  dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
  oc_remove_delayed_callback(ctx, dps_manager_provision_retry_async);

  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx == NULL) {
    DPS_ERR("Cloud context not found");
    return false;
  }

  if (oc_cloud_manager_is_started(cloud_ctx)) {
#if DPS_INFO_IS_ENABLED
    // GCOVR_EXCL_START
    const oc_string_t *ep_str = oc_cloud_get_server_uri(cloud_ctx);
    const char *ep_cstr = ep_str != NULL ? oc_string(*ep_str) : "NULL";
    DPS_INFO("Restarting cloud registration with endpoint(%s)",
             ep_cstr != NULL ? ep_cstr : "NULL");
    // GCOVR_EXCL_STOP
#endif /* DPS_INFO_IS_ENABLED */
    oc_cloud_manager_restart(cloud_ctx);
    goto finish;
  }

#if DPS_INFO_IS_ENABLED
  // GCOVR_EXCL_START
  const oc_string_t *ep_str = oc_cloud_get_server_uri(cloud_ctx);
  const char *ep_cstr = ep_str != NULL ? oc_string(*ep_str) : "NULL";
  DPS_INFO("Starting cloud registration with endpoint(%s)",
           ep_cstr != NULL ? ep_cstr : "NULL");
  // GCOVR_EXCL_STOP
#endif /* DPS_INFO_IS_ENABLED */
  if (oc_cloud_manager_start(cloud_ctx, ctx->callbacks.on_cloud_status_change,
                             ctx->callbacks.on_cloud_status_change_data) != 0) {
    dps_set_ps_and_last_error(ctx, PLGD_DPS_FAILURE, PLGD_DPS_CLOUD_STARTED,
                              PLGD_DPS_ERROR_START_CLOUD);
    plgd_dps_force_reprovision(ctx);
    dps_reset_delayed_callback_ms(ctx, dps_manager_provision_retry_async,
                                  dps_retry_get_delay(&ctx->retry));
    return false;
  }

finish:
  dps_retry_reset(ctx, dps_provision_get_next_action(ctx));
  ctx->transient_retry_count = 0;
  dps_set_ps_and_last_error(ctx, PLGD_DPS_CLOUD_STARTED,
                            PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  dps_store_dump_async(ctx);
  dps_endpoint_close(ctx->endpoint);
  dps_cloud_observer_on_provisioning_started(ctx, cloud_ctx);
  return true;
}

bool
dps_is_provisioned(const plgd_dps_context_t *ctx)
{
  return (ctx->status &
          (PLGD_DPS_PROVISIONED_MASK | PLGD_DPS_PROVISIONED_ERROR_FLAGS)) ==
         PLGD_DPS_PROVISIONED_MASK;
}

bool
dps_is_provisioned_with_cloud_started(const plgd_dps_context_t *ctx)
{
  if (!dps_is_provisioned(ctx)) {
    return false;
  }
  const oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx == NULL || !oc_cloud_manager_is_started(cloud_ctx)) {
    return false;
  }

  return (ctx->status & PLGD_DPS_CLOUD_STARTED) != 0;
}

/// Maximal number of allowed consecutive transient failures before full
/// reprovisioning is forced
const uint8_t DPS_MAX_TRANSIENT_RETRY_COUNT = 3;

void
dps_provisioning_handle_failure(plgd_dps_context_t *ctx, oc_status_t code,
                                bool schedule_retry)
{
  bool reprovision = (ctx->status & PLGD_DPS_FAILURE) != 0;
  if ((ctx->status & PLGD_DPS_TRANSIENT_FAILURE) != 0) {
    ++ctx->transient_retry_count;
    if (ctx->transient_retry_count >= DPS_MAX_TRANSIENT_RETRY_COUNT) {
      DPS_DBG(
        "transient retry count limit reached, forcing full reprovisioning");
      ctx->transient_retry_count = 0;
      reprovision = true;
    }
  }
  if (reprovision) {
    plgd_dps_force_reprovision(ctx);
  }

  if (schedule_retry) {
    uint64_t interval =
      dps_is_timeout_error_code(code) ? 0 : dps_retry_get_delay(&ctx->retry);
    dps_reset_delayed_callback_ms(ctx, dps_manager_provision_retry_async,
                                  interval);
  }
}
