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
#include "plgd_dps_log_internal.h"
#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_manager_internal.h"
#include "plgd_dps_provision_internal.h"
#include "plgd_dps_time_internal.h"
#include "plgd_dps_verify_certificate_internal.h"
#include "plgd/plgd_time.h"

#include "oc_api.h"
#include "oc_clock_util.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "security/oc_pstat_internal.h"

#include <assert.h>

#define DPS_ONE_HOUR ((oc_clock_time_t)(60 * 60) * OC_CLOCK_SECOND)

struct
{
  oc_clock_time_t delta; // the minimal difference between the system clock and
                         // the time calculated by plgd-time required for the
                         // system time to be considered unreliable
                         // TODO: make this configurable
} g_dps_time_cfg = {
  .delta = DPS_ONE_HOUR,
};

bool
dps_has_plgd_time(void)
{
  return plgd_time_is_active();
}

static bool
dps_system_time_is_synchronized(oc_clock_time_t system_time,
                                oc_clock_time_t plgd_time)
{
  return system_time > plgd_time ||
         plgd_time - system_time <= g_dps_time_cfg.delta;
}

oc_clock_time_t
dps_time(void)
{
  oc_clock_time_t now = oc_clock_time();
  if (!plgd_time_is_active()) {
    return now;
  }
  oc_clock_time_t plgd_now = plgd_time();
  return dps_system_time_is_synchronized(now, plgd_now) ? now : plgd_now;
}

static int
dps_set_time(oc_clock_time_t time)
{
#if DPS_DBG_IS_ENABLED || DPS_INFO_IS_ENABLED
  oc_clock_time_t now = oc_clock_time();
#endif
#if DPS_DBG_IS_ENABLED
// GCOVR_EXCL_START
#define RFC3339_BUFFER_SIZE (64)
  char system_ts[RFC3339_BUFFER_SIZE] = { 0 };
  oc_clock_encode_time_rfc3339(now, system_ts, sizeof(system_ts));
  char server_ts[RFC3339_BUFFER_SIZE] = { 0 };
  oc_clock_encode_time_rfc3339(time, server_ts, sizeof(server_ts));
  DPS_DBG("set time: system_time=%s, server time=%s", system_ts, server_ts);
// GCOVR_EXCL_STOP
#endif /* DPS_DBG_IS_ENABLED */
#if DPS_INFO_IS_ENABLED
  // GCOVR_EXCL_START
  if (!dps_system_time_is_synchronized(now, time)) {
    DPS_INFO("System time desynchronization detected");
  }
  // GCOVR_EXCL_STOP
#endif /* DPS_INFO_IS_ENABLED */
  return plgd_time_set_time(time);
}

static void
dps_get_time_handler(oc_status_t code, oc_clock_time_t time, void *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data;
#if DPS_DBG_IS_ENABLED
  dps_print_status("get time handler: ", ctx->status);
#endif /* DPS_DBG_IS_ENABLED */

  // we check only for PLGD_DPS_FAILURE flag, because retry will be rescheduled
  // if necessary
  if ((ctx->status & (PLGD_DPS_HAS_TIME | PLGD_DPS_FAILURE)) ==
      PLGD_DPS_HAS_TIME) {
    DPS_DBG("skipping duplicit call of get time handler");
    return;
  }
  // execute status callback right after this handler ends
  dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
  oc_remove_delayed_callback(ctx, dps_manager_provision_retry_async);
  ctx->status &= ~PLGD_DPS_PROVISIONED_ERROR_FLAGS;

  const uint32_t expected_status = PLGD_DPS_INITIALIZED | PLGD_DPS_GET_TIME;
  if (ctx->status != expected_status) {
#if DPS_ERR_IS_ENABLED
    // GCOVR_EXCL_START
    char str[256]; // NOLINT
    int ret = dps_status_to_logstr(ctx->status, str, sizeof(str));
    DPS_ERR("invalid status(%u:%s) in get time handler", (unsigned)ctx->status,
            ret >= 0 ? str : "(NULL)");
    // GCOVR_EXCL_STOP
#endif /* DPS_ERR_IS_ENABLED */
    goto error;
  }

  plgd_dps_error_t err = dps_provisioning_check_response(ctx, code, NULL);
  if (err != PLGD_DPS_OK) {
    DPS_ERR("invalid %s response(code=%d)", PLGD_DPS_TIME_URI, code);
    // ctx->status and ctx->last_error are set in
    // dps_provisioning_check_response
    goto finish;
  }

  if (dps_set_time(time) != 0) {
    DPS_ERR("cannot set time");
    goto error;
  }

  dps_set_ps_and_last_error(
    ctx, PLGD_DPS_HAS_TIME,
    PLGD_DPS_GET_TIME | PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  dps_retry_reset(ctx, dps_provision_get_next_action(ctx));
  ctx->transient_retry_count = 0;

  // if we are waiting for an insecure TCP session to close the next step will
  // be scheduled from the session disconnect handler
  if ((ctx->endpoint_state == OC_SESSION_DISCONNECTED) ||
      !ctx->closing_insecure_peer) {
    // go to next step -> get owner
    dps_provisioning_schedule_next_step(ctx);
  }
  return;

error:
  dps_set_ps_and_last_error(ctx, PLGD_DPS_FAILURE, PLGD_DPS_HAS_TIME,
                            PLGD_DPS_ERROR_GET_TIME);
finish:
  if ((ctx->status & PLGD_DPS_PROVISIONED_ERROR_FLAGS) != 0) {
    // when waiting to close insecure peer the scheduling of retry is handled by
    // the session disconnected handler
    dps_provisioning_handle_failure(
      ctx, code,
      (ctx->endpoint_state == OC_SESSION_DISCONNECTED) ||
        !ctx->closing_insecure_peer);
  }
}

bool
dps_get_plgd_time(plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  DPS_INFO("Get time");
#ifdef OC_SECURITY
  if (!oc_device_is_in_dos_state(ctx->device,
                                 OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP))) {
    DPS_ERR("device is not in RFNOP state");
    return false;
  }
#endif /* OC_SECURITY */

  oc_tls_select_cloud_ciphersuite();

  plgd_time_fetch_config_t fetch_cfg;
  if (ctx->skip_verify) {
    dps_verify_certificate_data_t *vcd = dps_verify_certificate_data_new(
      oc_tls_peer_pki_default_verification_params());
    if (vcd == NULL) {
      return false;
    }
    oc_pki_user_data_t verify_data = {
      .data = vcd,
      .free = dps_verify_certificate_data_free,
    };
    fetch_cfg = plgd_time_fetch_config_with_custom_verification(
      ctx->endpoint, PLGD_DPS_TIME_URI, dps_get_time_handler, ctx,
      dps_retry_get_timeout(&ctx->retry),
      PLGD_DPS_DISABLE_SELECT_IDENTITY_CERT_CHAIN, dps_verify_certificate,
      verify_data);
  } else {
    fetch_cfg = plgd_time_fetch_config(
      ctx->endpoint, PLGD_DPS_TIME_URI, dps_get_time_handler, ctx,
      dps_retry_get_timeout(&ctx->retry),
      PLGD_DPS_DISABLE_SELECT_IDENTITY_CERT_CHAIN, true);
  }

  unsigned flags = 0;
  if (!plgd_time_fetch(fetch_cfg, &flags)) {
    DPS_ERR("failed to dispatch get time from endpoint");
    dps_reset_tls();
    return false;
  }
  DPS_DBG("Get time: flags=%u", flags);
  if ((flags & PLGD_TIME_FETCH_FLAG_TCP_SESSION_OPENED) != 0) {
    ctx->closing_insecure_peer = true;
  }

#if DPS_DBG_IS_ENABLED
  dps_endpoint_print_peers(ctx->endpoint);
#endif /* DPS_DBG_IS_ENABLED */

  dps_set_ps_and_last_error(ctx, PLGD_DPS_GET_TIME,
                            PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  return true;
}
