/*
// Copyright (c) 2016 Intel Corporation
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

#ifndef OC_NETWORK_EVENTS_H
#define OC_NETWORK_EVENTS_H

#include "port/oc_network_events_mutex.h"
#include "util/oc_process.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  NETWORK_INTERFACE_DOWN,
  NETWORK_INTERFACE_UP
} oc_interface_event_t;

/**
  @brief Callback function to pass the network interface up/down infomation
    to App.
  @param event  enum values in oc_interface_event_t.
*/
typedef void (*interface_event_handler_t)(oc_interface_event_t event);

/**
 * Structure to manage network interface handler list.
 */
typedef struct oc_network_interface_cb
{
  struct oc_network_interface_cb *next;
  interface_event_handler_t handler;
} oc_network_interface_cb_t;

OC_PROCESS_NAME(oc_network_events);

typedef struct oc_message_s oc_message_t;

void oc_network_event(oc_message_t *message);

void oc_network_interface_event(oc_interface_event_t event);

#ifdef __cplusplus
}
#endif

#endif /* OC_NETWORK_EVENTS_H */
