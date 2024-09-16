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

#include "plgd_dps_context_internal.h"
#include "plgd_dps_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_retry_internal.h"

#include "port/oc_random.h"
#include "util/oc_endpoint_address_internal.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

// NOLINTNEXTLINE(modernize-*)
#define MIN_DELAYED_VALUE_MS (256)

#if DPS_DBG_IS_ENABLED
static void
dps_retry_print_configuration(const uint8_t cfg[PLGD_DPS_MAX_RETRY_VALUES_SIZE])
{
  // GCOVR_EXCL_START
  DPS_DBG("retry configuration:");
  for (size_t i = 0; i < PLGD_DPS_MAX_RETRY_VALUES_SIZE && cfg[i] != 0; ++i) {
    DPS_DBG("\t%d: %ds", (int)i, (int)cfg[i]);
  }
  // GCOVR_EXCL_STOP
}
#endif /* DPS_DBG_IS_ENABLED */

void
dps_retry_init(plgd_dps_retry_t *ret)
{
  memset(ret, 0, sizeof(plgd_dps_retry_t));
  uint8_t default_message_timeout[] = {
    10, 20, 40, 80, 120
  }; // NOLINT(readability-magic-numbers)
  memcpy(&ret->default_cfg, &default_message_timeout,
         sizeof(default_message_timeout));
#if DPS_DBG_IS_ENABLED
  dps_retry_print_configuration(ret->default_cfg);
#endif /* DPS_DBG_IS_ENABLED */
}

bool
plgd_dps_set_retry_configuration(plgd_dps_context_t *ctx, const uint8_t cfg[],
                                 size_t cfg_size)
{
  assert(ctx != NULL);
  if (cfg_size == 0 || cfg_size > PLGD_DPS_MAX_RETRY_VALUES_SIZE) {
    return false;
  }

  for (size_t i = 0; i < cfg_size; ++i) {
    if (cfg[i] == 0) {
      return false;
    }
  }

  memset(&ctx->retry.default_cfg, 0,
         sizeof(cfg[0]) * PLGD_DPS_MAX_RETRY_VALUES_SIZE);
  memcpy(&ctx->retry.default_cfg, cfg, sizeof(cfg[0]) * cfg_size);
#if DPS_DBG_IS_ENABLED
  dps_retry_print_configuration(ctx->retry.default_cfg);
#endif /* DPS_DBG_IS_ENABLED */
  return true;
}

int
plgs_dps_get_retry_configuration(const plgd_dps_context_t *ctx, uint8_t *buffer,
                                 size_t buffer_size)
{
  assert(ctx != NULL);
  assert(buffer != NULL);

  int cfg_size = 0;
  for (size_t i = 0; i < PLGD_DPS_MAX_RETRY_VALUES_SIZE; ++i) {
    if (ctx->retry.default_cfg[i] == 0) {
      break;
    }
    ++cfg_size;
  }

  if (buffer_size < (size_t)cfg_size) {
    return -1;
  }

  memcpy(buffer, &ctx->retry.default_cfg[0],
         sizeof(ctx->retry.default_cfg[0]) * cfg_size);
  return cfg_size;
}

uint8_t
dps_retry_size(const plgd_dps_retry_t *ret)
{
  uint8_t index;
  for (index = 0; index < (uint8_t)PLGD_DPS_MAX_RETRY_VALUES_SIZE; ++index) {
    if (ret->default_cfg[index] == 0) {
      break;
    }
  }
  return index;
}

// for delay use timeout/2 value + random [0, timeout/2]
static uint64_t
get_delay_from_timeout(uint16_t timeout)
{
  if (timeout == 0) {
    return oc_random_value() % MIN_DELAYED_VALUE_MS;
  }
  uint64_t delay = (uint64_t)timeout * MILLISECONDS_PER_SECOND / 2;
  // Include a random delay to prevent multiple devices from attempting to
  // connect or make requests simultaneously.
  delay += oc_random_value() % delay;
  return delay;
}

static bool
default_schedule_action(plgd_dps_context_t *ctx, uint8_t retry_count,
                        uint64_t *delay, uint16_t *timeout)
{
  if (retry_count >= dps_retry_size(&ctx->retry)) {
    // we have made all attempts, try to select next server
    DPS_DBG("retry loop over, selecting next DPS endpoint");
    oc_endpoint_addresses_select_next(&ctx->store.endpoints);
    return false;
  }
  *timeout = ctx->retry.default_cfg[retry_count];
  *delay = get_delay_from_timeout(*timeout);
  return true;
}

#if DPS_DBG_IS_ENABLED
static const char *
plgd_dps_status_to_str(plgd_dps_status_t action)
{
  // GCOVR_EXCL_START
  if (action == 0) {
    return "reinitialize";
  }
  return dps_status_flag_to_str(action);
  // GCOVR_EXCL_STOP
}
#endif /* DPS_DBG_IS_ENABLED */

static bool
on_action_response_set_retry(plgd_dps_context_t *ctx, plgd_dps_status_t action,
                             uint8_t retry_count, uint64_t *delay,
                             uint16_t *timeout)
{
  bool success = false;
  if (ctx->retry.schedule_action.on_schedule_action != NULL) {
    success = ctx->retry.schedule_action.on_schedule_action(
      ctx, action, retry_count, delay, timeout,
      ctx->retry.schedule_action.user_data);
  } else {
    success = default_schedule_action(ctx, retry_count, delay, timeout);
  }
  if (!success) {
    DPS_DBG("for retry(%d), action(%s) is not scheduled", retry_count,
            plgd_dps_status_to_str(action));
    return false;
  }
  DPS_DBG("for retry(%d), action(%s) is delayed for %llu milliseconds with and "
          "set with %u seconds timeout",
          retry_count, plgd_dps_status_to_str(action),
          (long long unsigned)*delay, ctx->retry.schedule_action.timeout);
  return true;
}

static bool
dps_schedule_action(plgd_dps_context_t *ctx, uint8_t count,
                    plgd_dps_status_t action)
{
  uint64_t delay = 0;
  uint16_t timeout = 0;

  if (!on_action_response_set_retry(ctx, action, count, &delay, &timeout)) {
    if (count == 0) {
      // To prevent an infinite loop, we check if count is 0, indicating that
      // dps_retry_reset has already been called. In such cases, we return false
      // since calling it again is not allowed. The responsibility of handling
      // this situation and resetting to default values lies with
      // dps_retry_reset.
      return false;
    }
    dps_retry_reset(ctx, action);
    return true;
  }
  ctx->retry.schedule_action.delay = delay;
  ctx->retry.schedule_action.timeout = timeout;
  return true;
}

void
dps_retry_increment(plgd_dps_context_t *ctx, plgd_dps_status_t action)
{
  DPS_DBG("retry counter increment");
  ++ctx->retry.count;
  dps_schedule_action(ctx, ctx->retry.count, action);
}

void
dps_retry_reset(plgd_dps_context_t *ctx, plgd_dps_status_t action)
{
  DPS_DBG("retry counter reset");
  ctx->retry.count = 0;
  if (!dps_schedule_action(ctx, ctx->retry.count, action)) {
    // reset must be always set timeout and delay
    ctx->retry.schedule_action.timeout = DEFAULT_RESET_TIMEOUT;
    ctx->retry.schedule_action.delay =
      get_delay_from_timeout(ctx->retry.schedule_action.timeout);
  }
}

uint16_t
dps_retry_get_timeout(const plgd_dps_retry_t *ret)
{
  assert(ret->count < PLGD_DPS_MAX_RETRY_VALUES_SIZE);
  uint16_t val = ret->schedule_action.timeout;
  if (val == 0) {
    val = DEFAULT_RESET_TIMEOUT;
  }
  return val;
}

uint64_t
dps_retry_get_delay(const plgd_dps_retry_t *ret)
{
  assert(ret->count < PLGD_DPS_MAX_RETRY_VALUES_SIZE);
  uint64_t val = ret->schedule_action.delay;
  if (val == 0) {
    val = get_delay_from_timeout(DEFAULT_RESET_TIMEOUT);
  }
  return val;
}

static void
dps_set_schedule_action(plgd_dps_retry_t *ret,
                        plgd_dps_schedule_action_cb_t on_schedule_action,
                        void *user_data)
{
  assert(ret != NULL);
  ret->schedule_action.on_schedule_action = on_schedule_action;
  ret->schedule_action.user_data = user_data;
}

void
plgd_dps_set_schedule_action(plgd_dps_context_t *ctx,
                             plgd_dps_schedule_action_cb_t on_schedule_action,
                             void *user_data)
{
  assert(ctx != NULL);
  dps_set_schedule_action(&ctx->retry, on_schedule_action, user_data);
}
