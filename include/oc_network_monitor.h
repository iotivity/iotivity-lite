/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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
  @file
*/
#ifndef OC_NETWORK_HELPERS_H
#define OC_NETWORK_HELPERS_H

#include "oc_export.h"
#include "oc_network_events.h"
#include "oc_session_events.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Add the callback to receive change notifications for Network interface
 * event.
 * @param cb  The callback to be added. Must not be NULL.
 * @return 0 on success
 * @return -1 on error
 */
int oc_add_network_interface_event_callback(interface_event_handler_t cb);

/**
 * @brief Remove the callback to receive change notifications for Network
 * interface event.
 * @param cb  The callback to be removed. Must not be NULL.
 * @return 0 on success
 * @return -1 on error
 */
int oc_remove_network_interface_event_callback(interface_event_handler_t cb);

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
int oc_add_session_event_callback(session_event_handler_t cb) OC_DEPRECATED(
  "replaced by oc_add_session_event_callback_v1, deprecated in v2.2.5.4");

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
int oc_remove_session_event_callback(session_event_handler_t cb) OC_DEPRECATED(
  "replaced by oc_remove_session_event_callback_v1, deprecated in v2.2.5.4");

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

#endif /* OC_NETWORK_HELPERS_H */
