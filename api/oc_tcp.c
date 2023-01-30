/****************************************************************************
 *
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

#include "port/oc_network_event_handler_internal.h"
#include "util/oc_memb.h"
#include "oc_tcp_internal.h"

OC_MEMB(g_oc_tcp_on_connect_event_s, oc_tcp_on_connect_event_t,
        OC_MAX_TCP_PEERS); //< guarded by oc_network_event_handler_mutex

static oc_tcp_on_connect_event_t *
oc_tcp_on_connect_event_allocate()
{
  oc_network_event_handler_mutex_lock();
  oc_tcp_on_connect_event_t *event =
    (oc_tcp_on_connect_event_t *)oc_memb_alloc(&g_oc_tcp_on_connect_event_s);
  oc_network_event_handler_mutex_unlock();
  return event;
}

oc_tcp_on_connect_event_t *
oc_tcp_on_connect_event_create(const oc_endpoint_t *endpoint, int state,
                               on_tcp_connect_t fn, void *fn_data)
{
  oc_tcp_on_connect_event_t *event = oc_tcp_on_connect_event_allocate();
  if (event == NULL) {
    OC_ERR("could not allocate new TCP on connect object");
    return NULL;
  }
  memcpy(&event->endpoint, endpoint, sizeof(oc_endpoint_t));
  event->state = state;
  event->fn = fn;
  event->fn_data = fn_data;
  return event;
}

void
oc_tcp_on_connect_event_free(oc_tcp_on_connect_event_t *event)
{
  if (event == NULL) {
    return;
  }
  oc_network_event_handler_mutex_lock();
  oc_memb_free(&g_oc_tcp_on_connect_event_s, event);
  oc_network_event_handler_mutex_unlock();
}

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */
