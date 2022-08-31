/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation, All Rights Reserved.
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

#ifndef OC_NETWORK_EVENT_HANDLER_INTERNAL_H
#define OC_NETWORK_EVENT_HANDLER_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief initialize the network event handler mutex
 */
void oc_network_event_handler_mutex_init(void);

/**
 * @brief lock the network event hander
 */
void oc_network_event_handler_mutex_lock(void);

/**
 * @brief unlock the network event handler
 */
void oc_network_event_handler_mutex_unlock(void);

/**
 * @brief destroy the network event handler mutex
 */
void oc_network_event_handler_mutex_destroy(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_NETWORK_EVENT_HANDLER_INTERNAL_H */
