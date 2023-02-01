/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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

#ifndef OC_REP_ENCODE_INTERNAL_H
#define OC_REP_ENCODE_INTERNAL_H

#include "cbor.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize global cbor encoder with buffer.
 *
 * @note the encoder doesn't store the pointer to the buffer directly, instead
 * it stores an offset from the global buffer to allow reallocation.
 *
 * @param buffer buffer used by the global encoder (cannot be NULL)
 * @param size size of the buffer
 */
void oc_rep_encoder_init(uint8_t *buffer, size_t size);

/**
 * @brief Initialize global cbor encoder with buffer and enable buffer
 * reallocation.
 *
 * If the buffer is too small then the buffer will be enlarged using the realloc
 * syscall. The size of the buffer cannot exceed the maximal allowed size.
 *
 * @note the encoder doesn't store the pointer to the buffer directly, instead
 * it stores an offset from the global buffer to allow reallocation.
 *
 * @param buffer pointer buffer used by the global encoder (cannot be NULL)
 * @param size size of the buffer
 * @param max_size maximal allowed size of the buffer
 */
void oc_rep_encoder_realloc_init(uint8_t **buffer, size_t size, int max_size);

/**
 * @brief Recalcute the pointer to the buffer and the pointer to the end of the
 * buffer to be offsets from the global buffer.
 */
CborEncoder *oc_rep_encoder_convert_ptr_to_offset(CborEncoder *encoder);

/**
 * @brief Recalcute from relative offsets to pointer to buffer usable by cbor
 * library.
 */
CborEncoder *oc_rep_encoder_convert_offset_to_ptr(CborEncoder *encoder);

#ifdef __cplusplus
}
#endif

#endif /* OC_REP_ENCODE_INTERNAL_H */
