/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *               2023 plgd.dev s.r.o.
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
 ***************************************************************************/

#include "oc_events_internal.h"
#include "util/oc_features.h"

#include <assert.h>

/** Translation array of oc_events_t to oc_process_event_t */
static oc_process_event_t oc_events[__NUM_OC_EVENT_TYPES__] = { 0 };

void
oc_event_assign_oc_process_events(void)
{
  for (int i = 0; i < __NUM_OC_EVENT_TYPES__; ++i) {
    oc_events[i] = oc_process_alloc_event();
  }
}

oc_process_event_t
oc_event_to_oc_process_event(oc_events_t event)
{
  assert(event < __NUM_OC_EVENT_TYPES__);
  return oc_events[event];
}

#if OC_DBG_IS_ENABLED

oc_string_view_t
oc_process_event_name(oc_process_event_t event)
{
  if (event == oc_event_to_oc_process_event(INBOUND_NETWORK_EVENT)) {
    return OC_STRING_VIEW("inbound-message");
  }
  if (event == oc_event_to_oc_process_event(OUTBOUND_NETWORK_EVENT)) {
    return OC_STRING_VIEW("outbound-message");
  }
  if (event == oc_event_to_oc_process_event(UDP_TO_TLS_EVENT)) {
    return OC_STRING_VIEW("inbound-tls-message");
  }
  if (event == oc_event_to_oc_process_event(RI_TO_TLS_EVENT)) {
    return OC_STRING_VIEW("outbound-tls-message");
  }
  if (event == oc_event_to_oc_process_event(INBOUND_RI_EVENT)) {
    return OC_STRING_VIEW("inbound-coap-message");
  }
  if (event == oc_event_to_oc_process_event(TLS_READ_DECRYPTED_DATA)) {
    return OC_STRING_VIEW("inbound-application-data");
  }
#ifdef OC_CLIENT
  if (event == oc_event_to_oc_process_event(TLS_WRITE_APPLICATION_DATA)) {
    return OC_STRING_VIEW("outbound-application-data");
  }
#endif /* OC_CLIENT */
#ifdef OC_OSCORE
  if (event == oc_event_to_oc_process_event(INBOUND_OSCORE_EVENT)) {
    return OC_STRING_VIEW("inbound-oscore-message");
  }
  if (event == oc_event_to_oc_process_event(OUTBOUND_OSCORE_EVENT)) {
    return OC_STRING_VIEW("outbound-oscore-message");
  }
  if (event == oc_event_to_oc_process_event(OUTBOUND_GROUP_OSCORE_EVENT)) {
    return OC_STRING_VIEW("outbound-oscore-multicast-message");
  }
#endif /* OC_OSCORE */
  if (event == oc_event_to_oc_process_event(TLS_CLOSE_ALL_SESSIONS)) {
    return OC_STRING_VIEW("close-all-tls-sessions");
  }
#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
  if (event == oc_event_to_oc_process_event(TCP_CONNECT_SESSION)) {
    return OC_STRING_VIEW("connect-tcp-session");
  }
#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#ifdef OC_NETWORK_MONITOR
  if (event == oc_event_to_oc_process_event(INTERFACE_DOWN)) {
    return OC_STRING_VIEW("network-down");
  }
  if (event == oc_event_to_oc_process_event(INTERFACE_UP)) {
    return OC_STRING_VIEW("network-up");
  }
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_SOFTWARE_UPDATE
  if (event == oc_event_to_oc_process_event(SW_UPDATE_NSA)) {
    return OC_STRING_VIEW("software-update-available");
  }
  if (event == oc_event_to_oc_process_event(SW_UPDATE_DOWNLOADED)) {
    return OC_STRING_VIEW("software-update-downloaded");
  }
  if (event == oc_event_to_oc_process_event(SW_UPDATE_UPGRADING)) {
    return OC_STRING_VIEW("software-update-upgrading");
  }
  if (event == oc_event_to_oc_process_event(SW_UPDATE_DONE)) {
    return OC_STRING_VIEW("software-update-done");
  }
#endif /* OC_SOFTWARE_UPDATE */
#ifdef OC_HAS_FEATURE_PUSH
  if (event == oc_event_to_oc_process_event(PUSH_RSC_STATE_CHANGED)) {
    return OC_STRING_VIEW("push-resource-state-changed");
  }
#endif /* OC_HAS_FEATURE_PUSH */
  return OC_STRING_VIEW("");
}

#endif /* OC_DBG_IS_ENABLED */
