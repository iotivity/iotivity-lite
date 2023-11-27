/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
/**
 * @file oc_poll_loop.h
 *
 * Default implementation of the main loop using poll.
 *
 * Uses eventfd on Linux and Android, anonymous pipe on other POSIX systems,
 * unnamed event object with WaitForSingleObject on Windows.
 *
 * @warning If your application creates additional threads and needs further
 * synchronization, you must implement your own main loop.
 */
#ifndef PORT_OC_POLL_LOOP_H
#define PORT_OC_POLL_LOOP_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_SIMPLE_MAIN_LOOP

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Initialize handles */
bool oc_poll_loop_init(void);

/** @brief Shutdown handles */
void oc_poll_loop_shutdown(void);

/** @brief Run the main loop until termination. */
void oc_poll_loop_run(void);

/** @brief Signal the main loop to wake up and process events. */
void oc_poll_loop_signal(void);

/** @brief Terminate the main loop. */
void oc_poll_loop_terminate(void);

/** @brief Check if the main loop has been terminated. */
bool oc_poll_loop_is_terminated(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_HAS_FEATURE_SIMPLE_MAIN_LOOP */

#endif /* PORT_OC_POLL_LOOP_H */
