/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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

#ifndef OC_SESSION_EVENTS_INTERNAL_H
#define OC_SESSION_EVENTS_INTERNAL_H

#include "oc_endpoint.h"
#include "oc_session_events.h"
#include "util/oc_process.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OC_SESSION_EVENT_API_V0 (0)
#define OC_SESSION_EVENT_API_V1 (1)

/**
 * @brief Structure to hold versioned session events handlers
 */
typedef struct
{
  union {
    session_event_handler_t v0;
    session_event_handler_v1_t v1;
  } handler;
  uint8_t version; ///< OC_SESSION_EVENT_API_V0 -> use v0 handler
                   ///< OC_SESSION_EVENT_API_V1 -> use v1 handler
} session_event_versioned_handler_t;

/** Create v0 session event handler */
session_event_versioned_handler_t oc_session_event_versioned_handler(
  session_event_handler_t cb);

/** Create v1 session event handler */
session_event_versioned_handler_t oc_session_event_versioned_handler_v1(
  session_event_handler_v1_t cb);

/**
 * Structure to manage session event handler list.
 */
typedef struct oc_session_event_cb
{
  struct oc_session_event_cb *next;
  session_event_versioned_handler_t vh;
  void *user_data;
} oc_session_event_cb_t;

OC_PROCESS_NAME(oc_session_events);

/**
 * @brief session start event
 *
 * @param endpoint start event on endpoint
 */
void oc_session_start_event(const oc_endpoint_t *endpoint);

/**
 * @brief session end event
 *
 * @param endpoint stop event on endpoint
 */
void oc_session_end_event(const oc_endpoint_t *endpoint);

/**
 * @brief Invoke all session handlers associated with given endpoint
 *
 * @param endpoint endpoint of the session event (cannot be NULLL)
 * @param state new session state
 */
void oc_handle_session(const oc_endpoint_t *endpoint, oc_session_state_t state);

/**
 * @brief Check if session events are currently in the process of being
 * disconnected.
 *
 * @return true all sessions are currently being iterated, disconnected and
 * deallocated
 * @return false otherwise
 */
bool oc_session_events_disconnect_is_ongoing(void);

/**
 * @brief Find first session event callback matching the input parameters.
 *
 * @param cb handler to match
 * @param user_data match user data (only valid for v1 handlers)
 * @param ignore_user_data ignore user data for match (only valid for v1
 * handlers)
 * @return oc_session_event_cb_t* first matched session event callback
 * @return NULL if no match is found
 */
oc_session_event_cb_t *oc_session_event_callback_find(
  session_event_versioned_handler_t cb, const void *user_data,
  bool ignore_user_data);

/**
 * @brief Remove all previously registered session event notifications
 * callbacks.
 */
void oc_session_events_remove_all_callbacks(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_SESSION_EVENTS_INTERNAL_H */
