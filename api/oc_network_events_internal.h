/****************************************************************************
 *
 * Copyright 2016-2018 Intel Corporation, All Rights Reserved.
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

#ifndef OC_NETWORK_EVENTS_INTERNAL_H
#define OC_NETWORK_EVENTS_INTERNAL_H

#include "port/oc_connectivity.h"
#include "oc_config.h"
#include "oc_network_events.h"
#include "oc_tcp_internal.h"
#include "util/oc_features.h"
#include "util/oc_process.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief process network events
 */
OC_PROCESS_NAME(oc_network_events);

/**
 * @brief network receive event
 *
 * @param message the network message (cannot be NULL)
 */
void oc_network_receive_event(oc_message_t *message) OC_NONNULL();

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
/**
 * @brief network TCP connect event
 *
 * @param event the TCP on connect event (cannot be NULL)
 */
void oc_network_tcp_connect_event(oc_tcp_on_connect_event_t *event)
  OC_NONNULL();
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

/**
 * @brief Drop received events for endpoint
 *
 * @param endpoint the endpoint (cannot be NULL)
 * @return number of events dropped
 */
int oc_network_drop_receive_events(const oc_endpoint_t *endpoint) OC_NONNULL();

#ifdef OC_NETWORK_MONITOR
/**
 * Structure to manage network interface handler list.
 */
typedef struct oc_network_interface_cb
{
  struct oc_network_interface_cb *next;
  interface_event_handler_t handler;
} oc_network_interface_cb_t;

/**
 * @brief interface change network event
 *
 * @param event the event
 */
void oc_network_interface_event(oc_interface_event_t event);
#endif /* OC_NETWORK_MONITOR */

#ifdef __cplusplus
}
#endif

#endif /* OC_NETWORK_EVENTS_INTERNAL_H */
