/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 * Copyright (c) 2024 plgd.dev s.r.o.
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
#include "api/cloud/oc_cloud_log_internal.h"
#include "api/cloud/oc_cloud_schedule_internal.h"
#include "api/oc_server_api_internal.h"
#include "oc_cloud.h"
#include "util/oc_endpoint_address_internal.h"
#include "util/oc_macros_internal.h"
#include "port/oc_random.h"

#include <assert.h>

#define OC_CLOUD_DEFAULT_RETRY_TIMEOUTS                                        \
  {                                                                            \
    2 * MILLISECONDS_PER_SECOND, 4 * MILLISECONDS_PER_SECOND,                  \
      8 * MILLISECONDS_PER_SECOND, 16 * MILLISECONDS_PER_SECOND,               \
      32 * MILLISECONDS_PER_SECOND, 64 * MILLISECONDS_PER_SECOND               \
  }

static uint16_t g_retry_timeout_ms[OC_CLOUD_RETRY_TIMEOUTS_SIZE] =
  OC_CLOUD_DEFAULT_RETRY_TIMEOUTS;

bool
oc_cloud_set_retry_timeouts(const uint16_t *timeouts, uint8_t size)
{
  if (timeouts == NULL) {
    OC_CLOUD_DBG("retry timeouts reset to defaults");
    uint16_t def[] = OC_CLOUD_DEFAULT_RETRY_TIMEOUTS;
    memcpy(g_retry_timeout_ms, def, sizeof(g_retry_timeout_ms));
    return true;
  }

  if (size > OC_ARRAY_SIZE(g_retry_timeout_ms)) {
    OC_ERR("invalid retry timeouts array");
    return false;
  }
  for (int i = 0; i < size; ++i) {
    if (timeouts[i] == 0) {
      OC_ERR("invalid retry timeout value");
      return false;
    }
  }

  memset(g_retry_timeout_ms, 0, sizeof(g_retry_timeout_ms));
  memcpy(g_retry_timeout_ms, timeouts, size * sizeof(uint16_t));
#if OC_DBG_IS_ENABLED
  OC_CLOUD_DBG("retry timeouts set to:");
  for (int i = 0; i < size; ++i) {
    OC_CLOUD_DBG("\t%ums", (unsigned)timeouts[i]);
  }
#endif /* OC_DBG_IS_ENABLED */
  return true;
}

int
oc_cloud_get_retry_timeouts(uint16_t *timeouts, uint8_t size)
{
  uint8_t count = 0;
  for (; count < (uint8_t)OC_ARRAY_SIZE(g_retry_timeout_ms); ++count) {
    if (g_retry_timeout_ms[count] == 0) {
      break;
    }
  }
  if (size < count) {
    return -1;
  }
  memcpy(timeouts, g_retry_timeout_ms, count * sizeof(uint16_t));
  return count;
}

bool
cloud_retry_is_over(uint8_t retry_count)
{
  return retry_count >= OC_ARRAY_SIZE(g_retry_timeout_ms) ||
         g_retry_timeout_ms[retry_count] == 0;
}

static bool
OC_NONNULL()
  default_schedule_action(oc_cloud_context_t *ctx, uint8_t retry_count,
                          uint64_t *delay, uint16_t *timeout)
{
  if (cloud_retry_is_over(retry_count)) {
    // we have made all attempts, try to select next server
    OC_CLOUD_DBG("retry loop over, selecting next server");
    oc_endpoint_addresses_select_next(&ctx->store.ci_servers);
    return false;
  }
  assert(g_retry_timeout_ms[retry_count] >= MILLISECONDS_PER_SECOND);
  *timeout = (g_retry_timeout_ms[retry_count] / MILLISECONDS_PER_SECOND);
  // for delay use timeout/2 value + random [0, timeout/2]
  *delay = (uint64_t)(g_retry_timeout_ms[retry_count]) / 2;
  // Include a random delay to prevent multiple devices from attempting to
  // connect or make requests simultaneously.
  *delay += oc_random_value() % *delay;
  return true;
}

static bool
on_action_response_set_retry(oc_cloud_context_t *ctx, oc_cloud_action_t action,
                             uint8_t retry_count, uint64_t *delay)
{
  bool ok = false;
  if (ctx->schedule_action.on_schedule_action != NULL) {
    ok = ctx->schedule_action.on_schedule_action(
      action, retry_count, delay, &ctx->schedule_action.timeout,
      ctx->schedule_action.user_data);
  } else {
    ok = default_schedule_action(ctx, retry_count, delay,
                                 &ctx->schedule_action.timeout);
  }
  if (!ok) {
    OC_CLOUD_DBG("for retry(%d), action(%s) is stopped", retry_count,
                 oc_cloud_action_to_str(action));
    return false;
  }
  OC_CLOUD_DBG(
    "for retry(%d), action(%s) is delayed for %llu milliseconds with "
    "and set with %u seconds timeout",
    retry_count, oc_cloud_action_to_str(action), (long long unsigned)*delay,
    ctx->schedule_action.timeout);
  return true;
}

bool
cloud_schedule_action(oc_cloud_context_t *ctx, oc_cloud_action_t action,
                      oc_trigger_t callback, bool is_retry)
{
  uint64_t interval = 0;
  uint8_t count = 0;

  if (action == OC_CLOUD_ACTION_REFRESH_TOKEN) {
    if (is_retry) {
      count = ++ctx->retry.refresh_token_count;
    } else {
      ctx->retry.refresh_token_count = 0;
    }
  } else {
    if (is_retry) {
      count = ++ctx->retry.count;
    } else {
      ctx->retry.count = 0;
    }
  }
  if (!on_action_response_set_retry(ctx, action, count, &interval)) {
    return false;
  }
  oc_reset_delayed_callback_ms(ctx, callback, interval);
  return true;
}

void
oc_cloud_set_schedule_action(oc_cloud_context_t *ctx,
                             oc_cloud_schedule_action_cb_t on_schedule_action,
                             void *user_data)
{
  ctx->schedule_action.on_schedule_action = on_schedule_action;
  ctx->schedule_action.user_data = user_data;
}

#endif /* OC_CLOUD */
