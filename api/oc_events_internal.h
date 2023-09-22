/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation, All Rights Reserved.
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

#ifndef OC_EVENTS_H
#define OC_EVENTS_H

#include "api/oc_helpers_internal.h"
#include "oc_config.h"
#include "port/oc_log_internal.h"
#include "util/oc_features.h"
#include "util/oc_process.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  INBOUND_NETWORK_EVENT,
  UDP_TO_TLS_EVENT,
  RI_TO_TLS_EVENT,
  INBOUND_RI_EVENT,
  OUTBOUND_NETWORK_EVENT,
  TLS_READ_DECRYPTED_DATA,
#ifdef OC_CLIENT
  TLS_WRITE_APPLICATION_DATA,
#endif /* OC_CLIENT */
#ifdef OC_NETWORK_MONITOR
  INTERFACE_DOWN,
  INTERFACE_UP,
#endif                    /* OC_NETWORK_MONITOR */
  TLS_CLOSE_ALL_SESSIONS, /* close all TLS sessions for reset reason*/
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  TCP_CONNECT_SESSION,
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
#ifdef OC_OSCORE
  INBOUND_OSCORE_EVENT,
  OUTBOUND_OSCORE_EVENT,
  OUTBOUND_GROUP_OSCORE_EVENT,
#endif /* OC_OSCORE */
#ifdef OC_SOFTWARE_UPDATE
  SW_UPDATE_NSA,
  SW_UPDATE_DOWNLOADED,
  SW_UPDATE_UPGRADING,
  SW_UPDATE_DONE,
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_HAS_FEATURE_PUSH
  PUSH_RSC_STATE_CHANGED,
#endif /* OC_HAS_FEATURE_PUSH */
  __NUM_OC_EVENT_TYPES__
} oc_events_t;

/** @brief Assign an oc_process_event_t for each oc_events_t */
void oc_event_assign_oc_process_events(void);

/**
 * @brief convert oc_events_t value to oc_process_event_t value
 *
 * @param event value to convert
 * @return corresponding oc_process_event_t value
 */
oc_process_event_t oc_event_to_oc_process_event(oc_events_t event);

#if OC_DBG_IS_ENABLED

/** @brief Get human-readable name for event */
oc_string_view_t oc_process_event_name(oc_process_event_t event);

#endif /* OC_DBG_IS_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* OC_EVENTS_H */
