/****************************************************************************
 *
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

#ifndef OC_CLOUD_SCHEDULE_INTERNAL_H
#define OC_CLOUD_SCHEDULE_INTERNAL_H

#include "oc_cloud.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MILLISECONDS_PER_SECOND (1000)
#define MILLISECONDS_PER_MINUTE (60 * MILLISECONDS_PER_SECOND)
#define MILLISECONDS_PER_HOUR (60 * MILLISECONDS_PER_MINUTE)

/** Check if retrying is over (checks whether the timeout value indexed by \p
 * retry_count is zero) */
bool cloud_retry_is_over(uint8_t retry_count);

/** Set timeout intervals for the default retry action */
#define OC_CLOUD_RETRY_TIMEOUTS_SIZE (6)

/** Set timeout intervals for the default retry action */
bool oc_cloud_set_retry_timeouts(const uint16_t *timeouts, uint8_t size);

/** Get timeout intervals for the default retry action */
int oc_cloud_get_retry_timeouts(uint16_t *timeouts, uint8_t size) OC_NONNULL();

/** Schedule a cloud action */
bool cloud_schedule_action(oc_cloud_context_t *ctx, oc_cloud_action_t action,
                           oc_trigger_t callback, bool is_retry) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_SCHEDULE_INTERNAL_H */
