/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_network_monitors.h"
#include "oc_events.h"
#include "oc_signal_event_loop.h"
#include "util/oc_memb.h"
#include <string.h>

OC_MEMB(oc_network_status_s, oc_network_status_t,
        OC_MAX_NUM_CONCURRENT_REQUESTS);

OC_PROCESS(oc_network_monitors, "");
OC_PROCESS_THREAD(oc_network_monitors, ev, data)
{
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&(oc_network_monitors))) {
    OC_PROCESS_YIELD();
    if (ev == oc_events[NETWORK_MONITOR_EVENT]) {
      oc_network_status_t *item = (oc_network_status_t *)data;
      if (item->type == OC_ADAPTER_CHANGED) {
        item->status.adapter.callback(item->status.adapter.up);
#ifdef OC_TCP
      } else if (item->type == OC_CONNECTION_CHANGED) {
        item->status.connection.callback(&item->status.connection.endpoint,
                                         item->status.connection.connected);
#endif /* OC_TCP */
      }
      oc_memb_free(&oc_network_status_s, item);
    }
  }
  OC_PROCESS_END();
}

void
oc_networt_monitor_dispatch_event(oc_network_status_t *item)
{
  oc_network_status_t *new_item =
    (oc_network_status_t *)oc_memb_alloc(&oc_network_status_s);

  new_item->type = item->type;
  if (item->type == OC_ADAPTER_CHANGED) {
    new_item->status.adapter.callback = item->status.adapter.callback;
    new_item->status.adapter.up = item->status.adapter.up;
#ifdef OC_TCP
  } else if (item->type == OC_CONNECTION_CHANGED) {
    new_item->status.connection.callback = item->status.connection.callback;
    memcpy(&new_item->status.connection.endpoint,
           &item->status.connection.endpoint, sizeof(oc_endpoint_t));
    new_item->status.connection.connected = item->status.connection.connected;
#endif /* OC_TCP */
  } else {
    OC_ERR("Not support network monitor type.");
    oc_memb_free(&oc_network_status_s, new_item);
    return;
  }

  if (oc_process_post(&oc_network_monitors, oc_events[NETWORK_MONITOR_EVENT],
                      new_item) == OC_PROCESS_ERR_FULL) {
    oc_memb_free(&oc_network_status_s, new_item);
    return;
  }

  _oc_signal_event_loop();
}