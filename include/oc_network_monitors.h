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

#ifndef OC_NETWORK_MONITORS_H
#define OC_NETWORK_MONITORS_H

#include "port/oc_connectivity.h"
#include "util/oc_process.h"
#include <stdbool.h>

typedef enum {
  OC_ADAPTER_CHANGED,
  OC_CONNECTION_CHANGED
} network_status_type_t;

typedef struct oc_network_status_t
{
  network_status_type_t type;

  union
  {
    /* This param is used for adapter status changed callback. */
    struct
    {
      ip_adapter_changed_cb_t callback;
      bool up;
    } adapter;

#ifdef OC_TCP
    /* This param is used for connection status changed callback. */
    struct
    {
      tcp_connection_changed_cb_t callback;
      oc_endpoint_t endpoint;
      bool connected;
    } connection;
#endif /* OC_TCP */
  } status;
} oc_network_status_t;

OC_PROCESS_NAME(oc_network_monitors);

/**
  @brief Dispatch event regarding network status change to
    oc_network_monitors proto-thread.
  @param item  status changed informations.
*/
void oc_networt_monitor_dispatch_event(oc_network_status_t *item);
#endif /* OC_NETWORK_MONITORS_H */
