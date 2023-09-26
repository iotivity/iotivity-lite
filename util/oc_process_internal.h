
/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
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
 ******************************************************************/

#ifndef OC_PROCESS_INTERNAL_H
#define OC_PROCESS_INTERNAL_H

#include "oc_process.h"
#include "util/oc_compiler.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initialize the process module.
 *
 * This function initializes the process module and should be called by the
 * system boot-up code.
 */
void oc_process_init(void);

/**
 * \brief Deinitialize the process module.
 */
void oc_process_shutdown(void);

/**
 * @brief This function is responsible for determining whether an event should
 * be removed from the event queue of a given process.
 *
 * @param ev The event to be dropped.
 * @param data The auxiliary data to be sent with the event
 * @param user_data Data to be passed to the drop_event function.
 * @return true Drop the event.
 */

/**
 * @brief Callback invoked for each event iterated by
 * oc_process_iterate_events.
 *
 * @param p process of the event
 * @param ev the event
 * @param data data of the event
 * @return true to continue iteration
 * @return false to stop iteration
 */
typedef bool (*oc_process_iterate_event_fn_t)(const struct oc_process *p,
                                              oc_process_event_t ev,
                                              oc_process_data_t data,
                                              void *user_data);
/**
 * @brief Iterate over all events and invoke given callback.
 *
 * @param fn callback invoked for each resource (cannot be NULL)
 * @param fn_data custom user data passed to \p fn
 *
 * @note if \p fn returns false then iteration is stopped immediately and the
 * remaining events are not iterated
 */
void oc_process_iterate_events(oc_process_iterate_event_fn_t fn, void *fn_data)
  OC_NONNULL(1);

#ifdef OC_TEST

/** @brief Get the maximal number of events */
oc_process_num_events_t oc_process_num_events(void);

/**
 * @brief Temporarily suspend a process.
 *
 * Events posted to a suspended process are instead queued and they are reposted
 * once the process is resumed. The queue is of limited size and overflowing
 * events are dropped.
 *
 * @param p process to suspend (cannot be NULL)
 */
void oc_process_suspend(struct oc_process *p) OC_NONNULL();

/**
 * @brief Resume suspended process
 *
 * @param p process to resume (cannot be NULL)
 */
void oc_process_resume(struct oc_process *p) OC_NONNULL();

/**
 * @brief Append event to a queue
 */
int oc_process_queue_event(struct oc_process *p, oc_process_event_t ev,
                           oc_process_data_t data) OC_NONNULL(1);

/**
 * @brief Unqueue all events and repost them.
 */
void oc_process_unqueue_events(void);

#endif /* OC_TEST */

#ifdef __cplusplus
}
#endif

#endif /* OC_PROCESS_INTERNAL_H */
