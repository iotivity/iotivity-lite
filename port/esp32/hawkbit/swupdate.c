/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#include "debug_print.h"
#include "hawkbit.h"
#include "hawkbit_action.h"
#include "hawkbit_internal.h"
#include "hawkbit_util.h"

#include "api/oc_swupdate_internal.h"
#include "oc_api.h"
#include "oc_swupdate.h"

void
log_status(const char *prefix, const hawkbit_context_t *ctx,
           const hawkbit_action_t *action)
{
#ifdef APP_DEBUG
  size_t device = hawkbit_get_device(ctx);
  oc_swupdate_t *swu_ctx = oc_swupdate_get_context(device);
  oc_swupdate_state_t swu_state = oc_swupdate_get_state(swu_ctx);
  oc_swupdate_action_t swu_action = oc_swupdate_get_action(swu_ctx);
  APP_DBG("%s swu_state: %s, swu_action: %s, action: %s, execute_all_steps: %d",
          prefix, oc_swupdate_state_to_str(swu_state),
          oc_swupdate_action_to_str(swu_action),
          action != NULL ? hawkbit_action_type_to_string(action->type) : "NULL",
          hawkbit_execute_all_steps(ctx) ? 1 : 0);
#else  /* !APP_DEBUG */
  (void)prefix;
  (void)ctx;
  (void)action;
#endif /* APP_DEBUG */
}

int
validate_purl(const char *purl)
{
  APP_DBG("%s", __func__);
  if (purl == NULL) {
    return -1;
  }
  if (purl[0] == '\0') {
    return 0;
  }
  return hawkbit_parse_package_url(purl, NULL) ? 0 : 1;
}

static void
hawkbit_swupdate_new_version_available(const hawkbit_context_t *ctx,
                                       const char *version)
{
  oc_swupdate_result_t result = hawkbit_execute_all_steps(ctx)
                                  ? OC_SWUPDATE_RESULT_SUCCESS
                                  : OC_SWUPDATE_RESULT_IDLE;
  APP_DBG("swupdate new version(%s) available: %d", version, (int)result);
  oc_swupdate_notify_new_version_available(hawkbit_get_device(ctx), version,
                                           result);
}

static void
hawkbit_handle_software_availability_check(hawkbit_context_t *ctx,
                                           const hawkbit_action_t *action)
{
  size_t device = hawkbit_get_device(ctx);
  oc_swupdate_t *swu_ctx = oc_swupdate_get_context(device);
  // check if the a notification about this version has not been sent already
  const char *nv = oc_swupdate_get_new_version(swu_ctx);
  APP_DBG("%s deploy /oc/swu.nv: %s, version: %s", __func__,
          nv != NULL ? nv : "",
          oc_string(action->data.deploy.deployment.chunk.version));
  bool notify =
    (nv == NULL ||
     strlen(nv) !=
       oc_string_len(action->data.deploy.deployment.chunk.version) ||
     strcmp(nv, oc_string(action->data.deploy.deployment.chunk.version)) != 0);
  if (notify) {
    hawkbit_set_download(ctx, action->data.deploy.deployment);
    hawkbit_swupdate_new_version_available(
      ctx, oc_string(action->data.deploy.deployment.chunk.version));
  }
}

static void
hawkbit_on_polling_action(hawkbit_context_t *ctx,
                          const hawkbit_action_t *action)
{
  log_status(__func__, ctx, action);
  size_t device = hawkbit_get_device(ctx);
  oc_swupdate_t *swu_ctx = oc_swupdate_get_context(device);
  oc_swupdate_action_t swu_action = oc_swupdate_get_action(swu_ctx);
  if (action->type == HAWKBIT_ACTION_DEPLOY) {
    if (swu_action == OC_SWUPDATE_ISAC || swu_action == OC_SWUPDATE_UPGRADE) {
      hawkbit_handle_software_availability_check(ctx, action);
      return;
    }
  }
}

static void
hawkbit_swupdate_done(hawkbit_context_t *ctx, oc_swupdate_result_t result)
{
  hawkbit_set_execute_all_steps(ctx, false);
  APP_DBG("swupdate done: %d", (int)result);
  oc_swupdate_notify_done(hawkbit_get_device(ctx), result);
}

void
hawkbit_start(hawkbit_context_t *ctx)
{
  APP_DBG("hawkbit start");
  hawkbit_start_polling(ctx, hawkbit_on_polling_action);
}

int
check_new_version(size_t device, const char *purl, const char *version)
{
  hawkbit_context_t *ctx = hawkbit_get_context(device);
  log_status(__func__, ctx, NULL);
  if (purl == NULL || purl[0] == '\0') {
    hawkbit_swupdate_done(ctx, OC_SWUPDATE_RESULT_IDLE);
    return 0;
  }

  hawkbit_poll_and_reschedule(ctx, /*forceReschedule*/ false);
  return 0;
}

static void
hawkbit_swupdate_downloaded(const hawkbit_context_t *ctx, const char *version)
{
  oc_swupdate_result_t result = hawkbit_execute_all_steps(ctx)
                                  ? OC_SWUPDATE_RESULT_SUCCESS
                                  : OC_SWUPDATE_RESULT_IDLE;
  APP_DBG("swupdate downloaded: %d", (int)result);
  oc_swupdate_notify_downloaded(hawkbit_get_device(ctx), version, result);
}

static void
hawkbit_on_download_done(hawkbit_context_t *ctx, bool success)
{
  if (!success) {
    hawkbit_clear_download(ctx);
    hawkbit_swupdate_done(ctx, OC_SWUPDATE_RESULT_IDLE);
    return;
  }
  hawkbit_clear_download(ctx);
  const hawkbit_async_update_t *update = hawkbit_get_update(ctx);
  if (update == NULL) {
    APP_ERR("hawkbit download error: stored updated not found");
    hawkbit_swupdate_done(ctx, OC_SWUPDATE_RESULT_IDLE);
    return;
  }
  hawkbit_swupdate_downloaded(ctx, oc_string(update->version));
}

int
download_update(size_t device, const char *url)
{
  (void)url;
  hawkbit_context_t *ctx = hawkbit_get_context(device);
  log_status(__func__, ctx, NULL);
  hawkbit_download(ctx, hawkbit_on_download_done);
  return 0;
}

static oc_event_callback_retval_t
hawkbit_restart_async_no_repeat(void *data)
{
  hawkbit_context_t *ctx = (hawkbit_context_t *)data;
  hawkbit_restart_device(ctx);
  return OC_EVENT_DONE;
}

int
perform_upgrade(size_t device, const char *url)
{
  APP_DBG("%s", __func__);
  hawkbit_context_t *ctx = hawkbit_get_context(device);
  const hawkbit_async_update_t *update = hawkbit_get_update(ctx);
  if (update == NULL) {
    hawkbit_set_execute_all_steps(ctx, true);
    return check_new_version(device, url, NULL);
  }
  oc_swupdate_notify_upgrading(device, oc_string(update->version),
                               oc_clock_time(), OC_SWUPDATE_RESULT_SUCCESS);

  if (!hawkbit_update(ctx)) {
    hawkbit_swupdate_done(ctx, OC_SWUPDATE_RESULT_UPGRADE_FAIL);
    return -1;
  }
  hawkbit_clear_update(ctx);
  hawkbit_swupdate_done(ctx, OC_SWUPDATE_RESULT_SUCCESS);
  oc_set_delayed_callback(ctx, hawkbit_restart_async_no_repeat, 0);
  return 0;
}
