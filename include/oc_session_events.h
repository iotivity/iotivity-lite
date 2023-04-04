/****************************************************************************
 *
 * Copyright (c) 2018 Intel Corporation
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
 * @file oc_session_events.h
 *
 * @author Kishen Maloor
 * @author Daniel Adam
 */

#ifndef OC_SESSION_EVENTS_H
#define OC_SESSION_EVENTS_H

#include "oc_export.h"
#include "oc_endpoint.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief session states
 */
typedef enum {
  OC_SESSION_CONNECTED,    ///< session connected
  OC_SESSION_DISCONNECTED, ///< session disconnected
} oc_session_state_t;

#define OC_ERR_SESSION_EVENT_HANDLER_NOT_FOUND -2

/**
 * @brief Callback function to pass the session event infomation to App.
 *
 * @param endpoint endpoint info which the session event is happened.
 * @param state enum values in oc_session_state_t.
 *
 * @deprecated replaced by session_event_handler_v1_t in v2.2.5.4
 */
typedef void (*session_event_handler_t)(const oc_endpoint_t *endpoint,
                                        oc_session_state_t state);

/**
 * @brief Callback function to pass the session event infomation to App.
 *
 * @param endpoint endpoint info which the session event is happened
 * @param state enum values in oc_session_state_t
 * @param user_data user data provided by the user to
 * oc_add_session_event_callback_v1
 *
 * @see oc_add_session_event_callback_v1
 */
typedef void (*session_event_handler_v1_t)(const oc_endpoint_t *endpoint,
                                           oc_session_state_t state,
                                           void *user_data);

/**
 * @brief set delay for events
 *
 * @param secs delay in seconds
 */
OC_API
void oc_session_events_set_event_delay(int secs);

#ifdef __cplusplus
}
#endif

#endif /* OC_SESSION_EVENTS_H */
