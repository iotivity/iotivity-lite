
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

#ifdef OC_TEST

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
