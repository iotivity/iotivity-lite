/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#ifndef OC_MESSAGE_INTERNAL_H
#define OC_MESSAGE_INTERNAL_H

#include "port/oc_connectivity.h"
#include "util/oc_features.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate incoming message of given size.
 *
 * @note \p size is ignored of the data buffer is statically allocated
 *
 * @param size size of the message
 * @return oc_message_t* message with allocated buffer
 * @return NULL on error
 */
oc_message_t *oc_message_allocate_with_size(size_t size);

/**
 * @brief Allocate message.
 *
 * @return oc_message_t* the CoAP message
 * @return NULL on error
 */
oc_message_t *oc_message_allocate_outgoing(void);

/**
 * @brief Allocate outgoing message of given size.
 *
 * @note \p size is ignored of the data buffer is statically allocated
 *
 * @param size size of the message
 * @return oc_message_t* message with allocated buffer
 * @return NULL on error
 */
oc_message_t *oc_message_allocate_outgoing_with_size(size_t size);

/**
 * @brief Get maximum size of the message buffer
 *
 * The size of the buffer depends on compilation options (it may be static or
 * dynamic and have differing sizes).
 *
 * @return size_t size of the message buffer
 */
size_t oc_message_max_buffer_size(void);

/** @brief Get the current reference count */
uint8_t oc_message_refcount(const oc_message_t *message) OC_NONNULL();

/** @brief Decrease reference count and return true if message was
 * deallocated.*/
bool oc_message_unref2(oc_message_t *message);

/** @brief Deallocate the message */
void oc_message_deallocate(oc_message_t *message) OC_NONNULL();

/**
 * @brief Get size of the message buffer
 *
 * The size of the buffer depends on compilation options (it may be static or
 * dynamic and have differing sizes).
 *
 * @param message the message to get the buffer size
 * @return size_t size of the message buffer
 */
size_t oc_message_buffer_size(const oc_message_t *message) OC_NONNULL();

#ifdef OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER
/**
 * @brief Shrink the message buffer to the minimum size.
 *
 * @param message the message to shrink
 * @param size the new size of the shrunk buffer
 */
void oc_message_shrink_buffer(oc_message_t *message, size_t size) OC_NONNULL();
#endif /* OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */

#ifdef __cplusplus
}
#endif

#endif /* OC_MESSAGE_INTERNAL_H */
