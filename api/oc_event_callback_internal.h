/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *               2023 plgd.dev s.r.o.

 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#ifndef OC_EVENT_CALLBACK_INTERNAL_H
#define OC_EVENT_CALLBACK_INTERNAL_H

#include "oc_config.h"
#include "oc_ri.h"
#include "oc_ri_internal.h"
#include "util/oc_compiler.h"
#include "util/oc_process.h"
#include "util/oc_etimer_internal.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Event callback
 */
typedef struct oc_event_callback_s
{
  struct oc_event_callback_s *next; ///< next callback
  struct oc_etimer timer;           ///< timer
  oc_trigger_t callback;            ///< callback to be invoked
  void *data;                       ///< data for the callback
} oc_event_callback_t;

#ifndef OC_DYNAMIC_ALLOCATION

#define OC_MAX_EVENT_CALLBACKS                                                 \
  (OC_NUM_CORE_PLATFORM_RESOURCES +                                            \
   OC_NUM_CORE_LOGICAL_DEVICE_RESOURCES * OC_MAX_NUM_DEVICES +                 \
   OC_MAX_APP_RESOURCES + OC_MAX_NUM_CONCURRENT_REQUESTS * 2)

#endif /* !OC_DYNAMIC_ALLOCATION */

/** @brief Initialize lists of event callbacks */
void oc_event_callbacks_init(void);

/** @brief Deinitialize lists of event callbacks */
void oc_event_callbacks_shutdown(void);

/** @brief Start the timed event callbacks handler oc_process */
void oc_event_callbacks_process_start(void);

/** @brief Exit the timed event callbacks handler oc_process */
void oc_event_callbacks_process_exit(void);

/** @brief The callback and data pair is currently being processed by
 * poll_event_callback_timers */
bool oc_timed_event_callback_is_currently_processed(const void *cb_data,
                                                    oc_trigger_t event_callback)
  OC_NONNULL(2);

#ifdef OC_SERVER
/**
 * @brief Add observation callback for given resource
 *
 * @param resource Resource to add observation callback for
 *
 * @note Callback won't be added if there is already one for given resource
 */
bool oc_periodic_observe_callback_add(oc_resource_t *resource) OC_NONNULL();

/**
 * @brief Remove the observation callback for given resource
 *
 * @return true if callback was removed, false otherwise
 */
bool oc_periodic_observe_callback_remove(const oc_resource_t *resource)
  OC_NONNULL();

/** @brief Get the observation callback for given resource */
oc_event_callback_t *oc_periodic_observe_callback_get(
  const oc_resource_t *resource) OC_NONNULL();

/** @brief Get the number of observation callbacks */
size_t oc_periodic_observe_callback_count(void);

#endif /* OC_SERVER */

/** @brief Process for timed events. */
OC_PROCESS_NAME(oc_timed_callback_events);

#ifdef __cplusplus
}
#endif

#endif /* OC_EVENT_CALLBACK_INTERNAL_H */
