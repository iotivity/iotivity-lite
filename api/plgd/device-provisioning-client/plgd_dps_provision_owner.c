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
#include "plgd_dps_context_internal.h"
#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_manager_internal.h"
#include "plgd_dps_provision_internal.h"
#include "plgd_dps_provision_owner_internal.h"
#include "plgd_dps_security_internal.h"
#include "plgd_dps_internal.h"

#include "oc_acl.h"
#include "oc_api.h"
#include "oc_client_state.h"
#include "oc_cred.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_uuid.h"
#include "security/oc_doxm_internal.h"
#include "security/oc_pstat_internal.h"
#include "util/oc_macros_internal.h"

#include <string.h>

int
dps_handle_get_owner_response(oc_client_response_t *data)
{
  const char *owner_str = NULL;
  const oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    if (dps_is_property(rep, OC_REP_STRING, "devowneruuid",
                        OC_CHAR_ARRAY_LEN("devowneruuid"))) {
      owner_str = oc_string(rep->value.string);
      rep = rep->next;
      continue;
    }

    DPS_ERR("unexpected property(%s)", oc_string(rep->name));
    return -1;
  }

  if (owner_str == NULL) {
    DPS_ERR("owner not found");
    return -1;
  }

  oc_uuid_t owner;
  oc_str_to_uuid(owner_str, &owner);
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data->user_data;
  if (!dps_set_owner(ctx, &owner)) {
    DPS_ERR("cannot own device");
    return -1;
  }
  DPS_DBG("device owner set to %s", owner_str);
  return 0;
}

static void
dps_get_owner_handler(oc_client_response_t *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data->user_data;
#if DPS_DBG_IS_ENABLED
  dps_print_status("get owner handler: ", ctx->status);
#endif /* DPS_DBG_IS_ENABLED */
  // we check only for PLGD_DPS_FAILURE flag, because retry will be rescheduled
  // if necessary
  if ((ctx->status & (PLGD_DPS_HAS_OWNER | PLGD_DPS_FAILURE)) ==
      PLGD_DPS_HAS_OWNER) {
    DPS_DBG("skipping duplicit call of get owner handler");
    return;
  }
  // execute status callback right after this handler ends
  dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
  oc_remove_delayed_callback(ctx, dps_manager_provision_retry_async);
  ctx->status &= ~PLGD_DPS_PROVISIONED_ERROR_FLAGS;

  uint32_t expected_status =
    PLGD_DPS_INITIALIZED | PLGD_DPS_HAS_TIME | PLGD_DPS_GET_OWNER;
  if (ctx->status != expected_status) {
#if DPS_ERR_IS_ENABLED
    // GCOVR_EXCL_START
    char str[256]; // NOLINT
    int ret = dps_status_to_logstr(ctx->status, str, sizeof(str));
    DPS_ERR("invalid status(%u:%s) in get owner handler", (unsigned)ctx->status,
            ret >= 0 ? str : "(NULL)");
    // GCOVR_EXCL_STOP
#endif /* DPS_ERR_IS_ENABLED */
    goto error;
  }

  int ret = dps_provisioning_check_response(ctx, data->code, data->payload);
  if (ret != 0) {
    DPS_ERR("invalid %s response(code=%d)", PLGD_DPS_OWNERSHIP_URI, data->code);
    // ctx->status and ctx->last_error are set in
    // dps_provisioning_check_response
    goto finish;
  }

  ret = dps_handle_get_owner_response(data);
  if (ret != 0) {
    goto error;
  }

  DPS_INFO("Owner set successfully");
  dps_set_ps_and_last_error(
    ctx, PLGD_DPS_HAS_OWNER,
    PLGD_DPS_GET_OWNER | PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  dps_retry_reset(ctx, dps_provision_get_next_action(ctx));
  ctx->transient_retry_count = 0;

#if DPS_DBG_IS_ENABLED
  dps_print_owner(ctx->device);
#endif /* DPS_DBG_IS_ENABLED */

  // go to next step -> get cloud configuration
  dps_provisioning_schedule_next_step(ctx);
  return;

error:
  dps_set_ps_and_last_error(ctx, PLGD_DPS_FAILURE, PLGD_DPS_HAS_OWNER,
                            PLGD_DPS_ERROR_GET_OWNER);
finish:
  if ((ctx->status & PLGD_DPS_PROVISIONED_ERROR_FLAGS) != 0) {
    dps_provisioning_handle_failure(ctx, data->code, /*schedule_retry*/ true);
  }
}

/**
 * @brief Request ownership UUID.
 *
 * Prepare and send GET request to PLGD_DPS_OWNERSHIP_URI and register
 * handler for response with ownership data.
 *
 * @param ctx device registration context
 * @return true POST request successfully dispatched
 * @return false on failure
 */
bool
dps_get_owner(plgd_dps_context_t *ctx)
{
  DPS_INFO("Get owner");
#ifdef OC_SECURITY
  if (!oc_device_is_in_dos_state(ctx->device,
                                 OC_PSTAT_DOS_ID_FLAG(OC_DOS_RFNOP))) {
    DPS_ERR("device is not in RFNOP state");
    return false;
  }
#endif /* OC_SECURITY */

  dps_setup_tls(ctx);
  if (!oc_do_get_with_timeout(PLGD_DPS_OWNERSHIP_URI, ctx->endpoint, NULL,
                              dps_retry_get_timeout(&ctx->retry),
                              dps_get_owner_handler, LOW_QOS, ctx)) {
    DPS_ERR("failed to dispatch GET request to %s", PLGD_DPS_OWNERSHIP_URI);
    dps_reset_tls();
    return false;
  }
  dps_set_ps_and_last_error(ctx, PLGD_DPS_GET_OWNER,
                            PLGD_DPS_PROVISIONED_ERROR_FLAGS, PLGD_DPS_OK);
  return true;
}

#if DPS_DBG_IS_ENABLED

void
dps_print_owner(size_t device)
{
  // GCOVR_EXCL_START
  DPS_DBG("owner:");
  const oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  char deviceuuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(&doxm->deviceuuid, deviceuuid, sizeof(deviceuuid));
  char devowneruuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(&doxm->devowneruuid, devowneruuid, sizeof(devowneruuid));
  char rowneruuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(&doxm->rowneruuid, rowneruuid, sizeof(rowneruuid));
  DPS_DBG("\tdoxm: deviceuuid=%s devowneruuid=%s rowneruuid=%s", deviceuuid,
          devowneruuid, rowneruuid);

  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  oc_uuid_to_str(&pstat->rowneruuid, rowneruuid, sizeof(rowneruuid));
  DPS_DBG("\tpstat: rowneruuid=%s", rowneruuid);

  const oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_uuid_to_str(&creds->rowneruuid, rowneruuid, sizeof(rowneruuid));
  DPS_DBG("\tcreds: rowneruuid=%s", rowneruuid);

  const oc_sec_acl_t *acls = oc_sec_get_acl(device);
  oc_uuid_to_str(&acls->rowneruuid, rowneruuid, sizeof(rowneruuid));
  DPS_DBG("\tacls: rowneruuid=%s", rowneruuid);
  // GCOVR_EXCL_STOP
}

#endif /* DPS_DBG_IS_ENABLED */
