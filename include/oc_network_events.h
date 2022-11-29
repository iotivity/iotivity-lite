/****************************************************************************
 *
 * Copyright 2016-2018 Intel Corporation, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

/**
 * @file
 */

#ifndef OC_NETWORK_EVENTS_H
#define OC_NETWORK_EVENTS_H

#include "util/oc_process.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Network events
 */
typedef enum {
  NETWORK_INTERFACE_DOWN, ///< network interface down
  NETWORK_INTERFACE_UP    ///< network interface up
} oc_interface_event_t;

/**
  @brief Callback function to pass the network interface up/down infomation
    to App.
  @param event  enum values in oc_interface_event_t.
*/
typedef void (*interface_event_handler_t)(oc_interface_event_t event);

#ifdef __cplusplus
}
#endif

#endif /* OC_NETWORK_EVENTS_H */
