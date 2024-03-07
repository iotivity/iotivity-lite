/******************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
 ******************************************************************/
/**
  @file
*/
#ifndef OC_BUFFER_H
#define OC_BUFFER_H

#include "port/oc_connectivity.h"
#include "util/oc_memb.h"
#include "util/oc_process.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief function to allocate an incoming message
 *
 * @return oc_message_t* the allocated message
 */
oc_message_t *oc_allocate_message(void);

/**
 * @brief set callback for memory availability of incoming message buffers
 *
 * @param cb the callback
 */
void oc_set_buffers_avail_cb(oc_memb_buffers_avail_callback_t cb);

/**
 * @brief allocate message from specific memory pool
 *
 * @param pool the memory pool to use for allocation
 * @return oc_message_t* the message
 */
oc_message_t *oc_allocate_message_from_pool(oc_memb_t *pool);

/**
 * @brief add reference (for tracking in use)
 *
 * @param message the message
 */
void oc_message_add_ref(oc_message_t *message);

/**
 * @brief remove reference (for tracking in use)
 *
 * @param message the message
 */
void oc_message_unref(oc_message_t *message);

/**
 * @brief receive (CoAP) message
 *
 * @param message the received messsage
 */
void oc_recv_message(oc_message_t *message);

/**
 * @brief send (CoAP) message
 *
 * @param message the CoAP message
 */
void oc_send_message(oc_message_t *message);

#ifdef __cplusplus
}
#endif

#endif /* OC_BUFFER_H */
