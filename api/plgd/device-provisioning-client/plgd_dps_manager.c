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
#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_manager_internal.h"
#include "plgd_dps_provision_cloud_internal.h"
#include "plgd_dps_provision_internal.h"
#include "plgd_dps_security_internal.h"
#include "plgd_dps_store_internal.h"
#include "plgd_dps_time_internal.h"
#include "plgd_dps_internal.h"

#include "oc_cred.h"
#include "security/oc_cred_util_internal.h"
#include "util/oc_list.h"

#include <stdint.h>

#define ACCESS_TOKEN_KEY "accesstoken"
#define REFRESH_TOKEN_KEY "refreshtoken"
#define REDIRECTURI_KEY "redirecturi"
#define USER_ID_KEY "uid"
#define EXPIRESIN_KEY "expiresin"

void
dps_manager_start(plgd_dps_context_t *ctx)
{
  if (!ctx->manager_started) {
    DPS_DBG("dps_manager_start");
    ctx->manager_started = true;
    dps_reset_delayed_callback(ctx, dps_manager_provision_async, 0);
  }
  _oc_signal_event_loop();
}

static bool
dps_mfg_certificate_iterate(const oc_sec_cred_t *cred, void *data)
{
  if (cred->credtype == OC_CREDTYPE_CERT &&
      cred->credusage == OC_CREDUSAGE_MFG_CERT && !dps_is_dps_cred(cred)) {
    (*(const oc_sec_cred_t **)data) = cred;
    return false;
  }
  return true;
}

static bool
dps_has_mfg_certificate(size_t device)
{
  const oc_sec_creds_t *creds = oc_sec_get_creds(device);
  const oc_sec_cred_t *mfg_cred = NULL;
  oc_cred_iterate(creds->creds, dps_mfg_certificate_iterate, &mfg_cred);
  if (mfg_cred != NULL) {
    DPS_DBG("Manufacturer certificate(%d) found", mfg_cred->credid);
    return true;
  }
  return false;
}

static bool
dps_mfg_trusted_root_ca_iterate(const oc_sec_cred_t *cred, void *data)
{
  if (cred->credtype == OC_CREDTYPE_CERT &&
      cred->credusage == OC_CREDUSAGE_MFG_TRUSTCA && !dps_is_dps_cred(cred)) {
    (*(const oc_sec_cred_t **)data) = cred;
    return false;
  }
  return true;
}

static bool
dps_has_mfg_trusted_root_ca(size_t device)
{
  const oc_sec_cred_t *trusted_ca = NULL;
  const oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_cred_iterate(creds->creds, dps_mfg_trusted_root_ca_iterate, &trusted_ca);
  if (trusted_ca != NULL) {
    DPS_DBG("manufacturer trusted root ca(%d) found", trusted_ca->credid);
    return true;
  }
  return false;
}

provision_and_cloud_observer_flags_t
dps_get_provision_and_cloud_observer_flags(plgd_dps_context_t *ctx)
{
  uint32_t provisionFlags = 0;
  uint8_t cloudObserverStatus = 0;
  if (dps_has_plgd_time()) {
    provisionFlags |= PLGD_DPS_HAS_TIME;
  }
  if (((provisionFlags & PLGD_DPS_HAS_TIME) != 0) && dps_has_owner(ctx)) {
    provisionFlags |= PLGD_DPS_HAS_OWNER;
  }
  if (((provisionFlags & PLGD_DPS_HAS_OWNER) != 0) &&
      dps_has_cloud_configuration(ctx->device)) {
    provisionFlags |= PLGD_DPS_HAS_CLOUD;
  }
  if (((provisionFlags & PLGD_DPS_HAS_CLOUD) != 0) &&
      dps_check_credentials_and_schedule_renewal(ctx, 0) &&
      dps_try_set_identity_chain(ctx->device)) {
    provisionFlags |= PLGD_DPS_HAS_CREDENTIALS;
  }
  if (((provisionFlags & PLGD_DPS_HAS_CREDENTIALS) != 0) &&
      dps_has_acls(ctx->device)) {
    provisionFlags |= PLGD_DPS_HAS_ACLS;
  }
  if (((provisionFlags & PLGD_DPS_HAS_ACLS) != 0) &&
      dps_cloud_is_registered(ctx->device)) {
    if (dps_cloud_is_started(ctx->device)) {
      provisionFlags |= PLGD_DPS_CLOUD_STARTED;
    }
    cloudObserverStatus |= OC_CLOUD_REGISTERED;
    if (dps_cloud_is_logged_in(ctx->device)) {
      cloudObserverStatus |= OC_CLOUD_LOGGED_IN;
    }
  }
  return (provision_and_cloud_observer_flags_t){
    .provision_flags = provisionFlags,
    .cloud_observer_status = cloudObserverStatus,
  };
}

int
plgd_dps_manager_start(plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  if (plgd_dps_manager_is_started(ctx)) {
    DPS_DBG("DPS manager already started");
    return 0;
  }

  if (plgd_dps_endpoint_is_empty(ctx)) {
    DPS_DBG("DPS is uninitialized state: endpoint is empty");
    dps_set_ps_and_last_error(ctx, 0, PLGD_DPS_PROVISIONED_ALL_FLAGS,
                              PLGD_DPS_OK);
    ctx->force_reprovision = false;
    return 0;
  }

  DPS_DBG("DPS manager starting");
#if DPS_DBG_IS_ENABLED
  dps_print_peers();
  dps_print_certificates(ctx->device);
  dps_print_acls(ctx->device);
#endif /* DPS_DBG_IS_ENABLED */
  if (!dps_has_mfg_certificate(ctx->device)) {
    DPS_ERR("Manufacturer certificate not set");
    return -1;
  }
  if (!ctx->skip_verify && !dps_has_mfg_trusted_root_ca(ctx->device)) {
    DPS_WRN("Manufacturer trusted root CA not set");
  }

  ctx->status = 0;
  uint32_t new_status = PLGD_DPS_INITIALIZED;
  if (!ctx->force_reprovision) {
    provision_and_cloud_observer_flags_t pacf =
      dps_get_provision_and_cloud_observer_flags(ctx);
    new_status |= pacf.provision_flags;
    ctx->cloud_observer.last_status |= pacf.cloud_observer_status;
  }
  ctx->force_reprovision = false;
  dps_set_ps_and_last_error(ctx, new_status, 0, PLGD_DPS_OK);
  dps_retry_reset(ctx, dps_provision_get_next_action(ctx));
  ctx->transient_retry_count = 0;
  if (dps_is_provisioned(ctx)) {
    dps_set_has_been_provisioned_since_reset(ctx, false);
  }

  dps_store_dump_async(ctx);
  dps_manager_start(ctx);
#ifdef OC_SESSION_EVENTS
  plgd_dps_session_callbacks_deinit(ctx);
  plgd_dps_session_callbacks_init(ctx);
  plgd_dps_interface_callbacks_deinit();
  plgd_dps_interface_callbacks_init();
#endif /* OC_SESSION_EVENTS */
  return 0;
}

bool
plgd_dps_manager_is_started(const plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->manager_started;
}

oc_event_callback_retval_t
dps_manager_start_async(void *user_data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)user_data;
  oc_free_endpoint(ctx->endpoint);
  ctx->endpoint = oc_new_endpoint();
  memset(ctx->endpoint, 0, sizeof(oc_endpoint_t));
  dps_manager_start(ctx);
  return OC_EVENT_DONE;
}

int
plgd_dps_manager_restart(plgd_dps_context_t *ctx)
{
  plgd_dps_manager_stop(ctx);
  return plgd_dps_manager_start(ctx);
}

void
dps_manager_stop(plgd_dps_context_t *ctx)
{
  DPS_DBG("dps_manager_stop");
  oc_remove_delayed_callback(ctx, dps_provisioning_start_async);
  oc_remove_delayed_callback(ctx, dps_manager_provision_async);
  oc_remove_delayed_callback(ctx, dps_manager_provision_retry_async);
  oc_remove_delayed_callback(ctx, dps_manager_reprovision_and_restart_async);
  oc_remove_delayed_callback(ctx, dps_provision_next_step_async);
  oc_remove_delayed_callback(ctx, dps_status_callback_handler);
  oc_remove_delayed_callback(ctx, dps_pki_renew_certificates_async);
  oc_remove_delayed_callback(ctx, dps_pki_renew_certificates_retry_async);
  oc_remove_delayed_callback(
    ctx, dps_cloud_observer_reprovision_server_uuid_change_async);
  dps_cloud_observer_deinit(ctx);
  ctx->manager_started = false;
}

void
plgd_dps_manager_stop(plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  DPS_DBG("DPS manager stop");
#ifdef OC_SESSION_EVENTS
  plgd_dps_session_callbacks_deinit(ctx);
  if (dps_context_list_is_empty()) {
    plgd_dps_interface_callbacks_deinit();
  }
  oc_remove_delayed_callback(ctx, dps_manager_start_async);
#endif /* OC_SESSION_EVENTS */
  dps_manager_stop(ctx);
  dps_endpoint_disconnect(ctx);
}

void
dps_manager_reprovision_and_restart(plgd_dps_context_t *ctx)
{
  plgd_dps_force_reprovision(ctx);
  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(ctx->device);
  if (cloud_ctx != NULL) {
    DPS_DBG("Stop cloud manager");
    if (oc_cloud_manager_stop(cloud_ctx) != 0) {
      DPS_ERR("failed to stop cloud manager");
    }
  }
  if (plgd_dps_manager_restart(ctx) != 0) {
    DPS_ERR("failed to reprovisiong and restart DPS");
  }
}

oc_event_callback_retval_t
dps_manager_reprovision_and_restart_async(void *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data;
  dps_manager_reprovision_and_restart(ctx);
  return OC_EVENT_DONE;
}

oc_event_callback_retval_t
dps_manager_provision_retry_async(void *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data;
  dps_endpoint_disconnect(ctx);
  // TODO: wait for disconnect, only if really disconnected then continue
  dps_retry_increment(ctx, dps_provision_get_next_action(ctx));
  return dps_manager_provision_async(ctx);
}

oc_event_callback_retval_t
dps_manager_provision_async(void *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data;
  if (ctx->force_reprovision) {
    DPS_DBG("update status to force full reprovision");
    dps_set_ps_and_last_error(ctx, 0,
                              PLGD_DPS_GET_TIME | PLGD_DPS_GET_OWNER |
                                PLGD_DPS_GET_CLOUD | PLGD_DPS_GET_CREDENTIALS |
                                PLGD_DPS_GET_ACLS | PLGD_DPS_PROVISIONED_MASK,
                              ctx->last_error);
    ctx->force_reprovision = false;
  }

  if (dps_is_provisioned_with_cloud_started(ctx)) {
    dps_cloud_observe_status(ctx);
    return OC_EVENT_DONE;
  }

  if ((ctx->status & PLGD_DPS_INITIALIZED) == 0) {
    DPS_DBG("provisioning skipped: DPS is not initialized");
    return OC_EVENT_DONE;
  }

  DPS_DBG("try provision(%d)", ctx->retry.count);
  if (plgd_dps_endpoint_is_empty(ctx)) {
    DPS_DBG("endpoint dps is empty");
    ctx->status = 0;
    dps_manager_stop(ctx);
    return OC_EVENT_DONE;
  }
  const oc_string_t *ep_uri =
    oc_endpoint_addresses_selected_uri(&ctx->store.endpoints);
  assert(ep_uri != NULL); // checked in plgd_dps_endpoint_is_empty above
  if (dps_endpoint_init(ctx, ep_uri) != 0) {
    DPS_ERR("failed to initialize endpoint %s to dps",
            ep_uri != NULL ? oc_string(*ep_uri) : "NULL");
    goto retry;
  }
  bool valid_owned = dps_is_dos_owned(ctx->device) || dps_set_self_owned(ctx);
  if (!valid_owned) {
    DPS_ERR("failed to set device(%zu) as self owned", ctx->device);
    goto retry;
  }
  dps_provisioning_start(ctx);
  return OC_EVENT_DONE;

retry:
  // while retrying, keep last error (lec) to PLGD_DPS_OK
  dps_set_last_error(ctx, PLGD_DPS_OK);
  // retry on error
  dps_reset_delayed_callback_ms(ctx, dps_manager_provision_retry_async,
                                dps_retry_get_delay(&ctx->retry));
  return OC_EVENT_DONE;
}
