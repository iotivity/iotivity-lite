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
#include "util/oc_compiler.h"

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

#define OC_ERR_SESSION_EVENT_HANDLER_NOT_FOUND (-2)

/**
 * @brief Callback function to pass the session event infomation to App.
 *
 * @param endpoint endpoint info which the session event is happened.
 * @param state enum values in oc_session_state_t.
 *
 * @note will be removed with deprecated functions oc_add_session_event_callback
 * and oc_remove_session_event_callback in the future
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

/**
 * @brief Add the callback to receive session event notifications.
 *
 * @param cb  The callback to be added. Must not be NULL.
 * @return 0 on success
 * @return -1 on error
 *
 * @deprecated replaced by oc_add_session_event_callback_v1 in v2.2.5.4
 */
OC_API
int oc_add_session_event_callback(session_event_handler_t cb)
  OC_DEPRECATED("replaced by oc_add_session_event_callback_v1 in v2.2.5.4");

/**
 * @brief Add the callback to receive session event notifications.
 *
 * @param cb The callback to be added (cannot be NULL).
 * @param user_data user data passed to the callback when invoked
 * @return 0 on success
 * @return -1 on error
 */
OC_API
int oc_add_session_event_callback_v1(session_event_handler_v1_t cb,
                                     void *user_data);

/**
 * @brief Remove the callback to receive session event notifications.
 * @param cb The callback to be removed. Must not be NULL.
 * @return 0 on success
 * @return -1 on error
 *
 * @deprecated replaced by oc_remove_session_event_callback_v1 in v2.2.5.4
 */
OC_API
int oc_remove_session_event_callback(session_event_handler_t cb)
  OC_DEPRECATED("replaced by oc_remove_session_event_callback_v1 in v2.2.5.4");

/**
 * @brief Remove the callback with to receive session event notifications.
 *
 * @param cb The callback to be removed.
 * @param user_data user data provided to the callback by
 oc_add_session_event_callback_v1
 * @param ignore_user_data ignore user_data and match only the function pointer
 * @return 0 on success
 * @return OC_ERR_SESSION_EVENT_HANDLER_NOT_FOUND when no match was found
 * @return -1 other errors
 *
 * @see oc_add_session_event_callback_v1
 */
OC_API
int oc_remove_session_event_callback_v1(session_event_handler_v1_t cb,
                                        void *user_data, bool ignore_user_data);

#ifdef __cplusplus
}
#endif

#endif /* OC_SESSION_EVENTS_H */
