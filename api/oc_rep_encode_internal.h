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

#include "oc_rep.h"
#include "oc_ri.h"
#include "util/oc_compiler.h"

#include <cbor.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Encoding interface */
typedef CborError (*oc_rep_encode_null_t)(CborEncoder *encoder) OC_NONNULL();

typedef CborError (*oc_rep_encode_boolean_t)(CborEncoder *encoder, bool value)
  OC_NONNULL();

typedef CborError (*oc_rep_encode_int_t)(CborEncoder *encoder, int64_t value)
  OC_NONNULL();

typedef CborError (*oc_rep_encode_uint_t)(CborEncoder *encoder, uint64_t value)
  OC_NONNULL();

typedef CborError (*oc_rep_encode_floating_point_t)(CborEncoder *encoder,
                                                    CborType fpType,
                                                    const void *value)
  OC_NONNULL();

typedef CborError (*oc_rep_encode_double_t)(CborEncoder *encoder, double value)
  OC_NONNULL();

typedef CborError (*oc_rep_encode_text_string_t)(CborEncoder *encoder,
                                                 const char *string,
                                                 size_t length) OC_NONNULL();

typedef CborError (*oc_rep_encode_byte_string_t)(CborEncoder *encoder,
                                                 const uint8_t *string,
                                                 size_t length) OC_NONNULL();

typedef CborError (*oc_rep_encoder_create_array_t)(CborEncoder *encoder,
                                                   CborEncoder *arrayEncoder,
                                                   size_t length) OC_NONNULL();

typedef CborError (*oc_rep_encoder_create_map_t)(CborEncoder *encoder,
                                                 CborEncoder *mapEncoder,
                                                 size_t length) OC_NONNULL();
typedef CborError (*oc_rep_encoder_close_container_t)(
  CborEncoder *encoder, const CborEncoder *containerEncoder) OC_NONNULL();

typedef struct oc_rep_encoder_t
{
  oc_rep_encoder_type_t type;

  oc_rep_encode_null_t encode_null;
  oc_rep_encode_boolean_t encode_boolean;
  oc_rep_encode_int_t encode_int;
  oc_rep_encode_uint_t encode_uint;
  oc_rep_encode_floating_point_t encode_floating_point;
  oc_rep_encode_double_t encode_double;
  oc_rep_encode_text_string_t encode_text_string;
  oc_rep_encode_byte_string_t encode_byte_string;
  oc_rep_encoder_create_array_t create_array;
  oc_rep_encoder_create_map_t create_map;
  oc_rep_encoder_close_container_t close_container;
} oc_rep_encoder_t;

/** Return an initialized CBOR encoder. */
oc_rep_encoder_t oc_rep_cbor_encoder(void);

/**
 * @brief Initialize global encoder buffer.
 *
 * @note the pointer to the buffer directly isn't stored directly, instead
 * an offset is stored to allow reallocation.
 *
 * @param buffer buffer used by the global encoder (cannot be NULL)
 * @param size size of the buffer
 */
void oc_rep_buffer_init(uint8_t *buffer, size_t size);

/**
 * @brief Initialize global encoder buffer and enable buffer reallocation.
 *
 * If the buffer is too small then the buffer will be enlarged using the realloc
 * syscall. The size of the buffer cannot exceed the maximal allowed size.
 *
 * @note the pointer to the buffer directly isn't stored directly, instead
 * an offset is stored to allow reallocation.
 *
 * @param buffer pointer buffer used by the global encoder (cannot be NULL)
 * @param size size of the buffer
 * @param max_size maximal allowed size of the buffer
 */
void oc_rep_buffer_realloc_init(uint8_t **buffer, size_t size, size_t max_size);

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

/**
 * @brief Set the encoder type to encode the response payload according to the
 * accept option.
 *
 * @param accept the accept option
 * @return true if the encoder type is set successfully
 */
bool oc_rep_encoder_set_type_by_accept(oc_content_format_t accept);

/** Get content format of the global encoder */
oc_content_format_t oc_rep_encoder_get_content_format(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_REP_ENCODE_INTERNAL_H */
