/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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
/**
  @file
*/
#ifndef OC_NETWORK_HELPERS_H
#define OC_NETWORK_HELPERS_H

#include "oc_export.h"
#include "oc_network_events.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Add the callback to receive change notifications for Network interface
 * event.
 * @param cb  The callback to be added. Must not be NULL.
 * @return 0 on success
 * @return -1 on error
 */
OC_API
int oc_add_network_interface_event_callback(interface_event_handler_t cb);

/**
 * @brief Remove the callback to receive change notifications for Network
 * interface event.
 * @param cb  The callback to be removed. Must not be NULL.
 * @return 0 on success
 * @return -1 on error
 */
OC_API
int oc_remove_network_interface_event_callback(interface_event_handler_t cb);

#ifdef __cplusplus
}
#endif

#endif /* OC_NETWORK_HELPERS_H */
