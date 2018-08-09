/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_SESSION_EVENTS_H
#define OC_SESSION_EVENTS_H

#include "oc_endpoint.h"
#include "port/oc_network_events_mutex.h"
#include "util/oc_process.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
  OC_SESSION_CONNECTED,
  OC_SESSION_DISCONNECTED
} oc_session_state_t;

/**
  @brief Callback function to pass the session event infomation to App.
  @param endpoint  endpoint info which the session event is happened.
  @param state  enum values in oc_session_state_t.
*/
typedef void (*session_event_handler_t)(const oc_endpoint_t *endpoint,
                                        oc_session_state_t state);

/**
 * Structure to manage session event handler list.
 */
typedef struct oc_session_event_cb
{
  struct oc_session_event_cb *next;
  session_event_handler_t handler;
} oc_session_event_cb_t;

OC_PROCESS_NAME(oc_session_events);

void oc_session_start_event(oc_endpoint_t *endpoint);
void oc_session_end_event(oc_endpoint_t *endpoint);
void oc_handle_session(oc_endpoint_t *endpoint, oc_session_state_t state);

#ifdef __cplusplus
}
#endif

#endif /* OC_SESSION_EVENTS_H */
