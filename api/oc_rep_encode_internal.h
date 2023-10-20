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

typedef struct
{
  uint8_t *ptr;
  size_t size;

#ifdef OC_DYNAMIC_ALLOCATION
  size_t max_size;
  uint8_t **pptr;
  bool enable_realloc;
#endif /* OC_DYNAMIC_ALLOCATION */
} oc_rep_encoder_buffer_t;

/** Rep encoder interface */
typedef size_t (*oc_get_buffer_size_t)(const CborEncoder *encoder,
                                       const uint8_t *buffer) OC_NONNULL();

typedef size_t (*oc_get_extra_bytes_needed_t)(const CborEncoder *encoder)
  OC_NONNULL();

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
                                                 size_t length) OC_NONNULL(1);

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

typedef struct oc_rep_encoder_implementation_t
{
  oc_get_buffer_size_t get_buffer_size;
  oc_get_extra_bytes_needed_t get_extra_bytes_needed;

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
} oc_rep_encoder_implementation_t;

typedef struct oc_rep_encoder_t
{
  oc_rep_encoder_type_t type;
  oc_rep_encoder_implementation_t impl;
  oc_rep_encoder_buffer_t buffer;
  CborEncoder ctx;
} oc_rep_encoder_t;

/** Return pointer to the global encoder */
oc_rep_encoder_t *oc_rep_global_encoder(void) OC_RETURNS_NONNULL;

typedef struct oc_rep_encoder_reset_t
{
  oc_rep_encoder_t encoder;
  CborEncoder root_map_ctx;
  CborEncoder links_array_ctx;
} oc_rep_encoder_reset_t;

/** Set global encoder and return the previous */
oc_rep_encoder_reset_t oc_rep_global_encoder_reset(
  const oc_rep_encoder_reset_t *reset);

/** Get encoder. */
oc_rep_encoder_t oc_rep_encoder(oc_rep_encoder_type_t type,
                                oc_rep_encoder_buffer_t buffer);

/**
 * @brief Initialize global encoder buffer.
 *
 * @note the pointer to the buffer directly isn't stored directly, instead
 * an offset is stored to allow reallocation.
 *
 * @param encoder encoder (cannot be NULL)
 * @param buffer buffer used by the global encoder
 * @param size size of the buffer
 */
void oc_rep_encoder_buffer_init(oc_rep_encoder_t *encoder, uint8_t *buffer,
                                size_t size) OC_NONNULL(1);

#ifdef OC_DYNAMIC_ALLOCATION

/**
 * @brief Initialize encoder buffer and enable buffer reallocation.
 *
 * If the buffer is too small then the buffer will be enlarged using the realloc
 * syscall. The size of the buffer cannot exceed the maximal allowed size.
 *
 * @note the pointer to the buffer directly isn't stored directly, instead
 * an offset is stored to allow reallocation.
 *
 * @param encoder encoder (cannot be NULL)
 * @param buffer pointer buffer used by the global encoder
 * @param size size of the buffer
 * @param max_size maximal allowed size of the buffer
 */
void oc_rep_encoder_buffer_realloc_init(oc_rep_encoder_t *encoder,
                                        uint8_t **buffer, size_t size,
                                        size_t max_size) OC_NONNULL(1);

#endif /* OC_DYNAMIC_ALLOCATION */

/** @brief Get the size of the encoded data in the payload buffer. */
int oc_rep_encoder_payload_size(oc_rep_encoder_t *encoder) OC_NONNULL();

/** @brief Get the number of unwritten bytes in the payload buffer. */
long oc_rep_encoder_remaining_size(oc_rep_encoder_t *encoder) OC_NONNULL();

#ifdef OC_DYNAMIC_ALLOCATION
/** @brief Shrink encoder buffer to the payload size */
bool oc_rep_encoder_shrink_buffer(oc_rep_encoder_t *encoder) OC_NONNULL();
#endif /* OC_DYNAMIC_ALLOCATION */

/**
 * @brief Recalcute the pointer to the buffer and the pointer to the end of the
 * buffer to be offsets from the global buffer.
 */
void oc_rep_encoder_convert_ptr_to_offset(const oc_rep_encoder_t *encoder,
                                          CborEncoder *subEncoder) OC_NONNULL();

/**
 * @brief Recalcute from relative offsets to pointer to buffer usable by cbor
 * library.
 */
void oc_rep_encoder_convert_offset_to_ptr(const oc_rep_encoder_t *encoder,
                                          CborEncoder *subEncoder) OC_NONNULL();

/**
 * @brief Set the encoder type to encode the response payload according to the
 * accept option.
 *
 * @param accept the accept option
 * @return true if the encoder type is set successfully
 */
bool oc_rep_encoder_set_type_by_accept(oc_content_format_t accept);

/** @brief Get content format of the global encoder */
bool oc_rep_encoder_get_content_format(oc_content_format_t *format)
  OC_NONNULL();

/** @brief Write raw data to encoder */
int oc_rep_encoder_write_raw(oc_rep_encoder_t *encoder, const uint8_t *data,
                             size_t len) OC_NONNULL(1);

/** @brief Write null representation to encoder */
CborError oc_rep_encoder_write_null(oc_rep_encoder_t *encoder,
                                    CborEncoder *subEncoder) OC_NONNULL();

/** @brief Write boolean representation to encoder */
CborError oc_rep_encoder_write_boolean(oc_rep_encoder_t *encoder,
                                       CborEncoder *subEncoder, bool value)
  OC_NONNULL();

/** @brief Write integer representation to encoder */
CborError oc_rep_encoder_write_int(oc_rep_encoder_t *encoder,
                                   CborEncoder *subEncoder, int64_t value)
  OC_NONNULL();

/** @brief Write unsigned integer representation to encoder */
CborError oc_rep_encoder_write_uint(oc_rep_encoder_t *encoder,
                                    CborEncoder *subEncoder, uint64_t value)
  OC_NONNULL();

/** @brief Write double representation to encoder */
CborError oc_rep_encoder_write_floating_point(oc_rep_encoder_t *encoder,
                                              CborEncoder *subEncoder,
                                              CborType fpType,
                                              const void *value) OC_NONNULL();

/** @brief Write double representation to encoder */
CborError oc_rep_encoder_write_double(oc_rep_encoder_t *encoder,
                                      CborEncoder *subEncoder, double value)
  OC_NONNULL();

/** @brief Write byte string representation to encoder */
CborError oc_rep_encoder_write_text_string(oc_rep_encoder_t *encoder,
                                           CborEncoder *subEncoder,
                                           const char *string, size_t length)
  OC_NONNULL(1, 2);

/** @brief Write byte string representation to encoder */
CborError oc_rep_encoder_write_byte_string(oc_rep_encoder_t *encoder,
                                           CborEncoder *subEncoder,
                                           const uint8_t *string, size_t length)
  OC_NONNULL(1, 2);

/** @brief Write representation of opening an array to encoder */
CborError oc_rep_encoder_write_array_open(oc_rep_encoder_t *encoder,
                                          CborEncoder *subEncoder,
                                          CborEncoder *arrayEncoder,
                                          size_t length) OC_NONNULL();

/** @brief Write representation of opening a map to encoder */
CborError oc_rep_encoder_write_map_open(oc_rep_encoder_t *encoder,
                                        CborEncoder *subEncoder,
                                        CborEncoder *mapEncoder, size_t length)
  OC_NONNULL();

/** @brief Write representation of closing a container to encoder */
CborError oc_rep_encoder_write_container_close(oc_rep_encoder_t *encoder,
                                               CborEncoder *subEncoder,
                                               CborEncoder *containerEncoder)
  OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_REP_ENCODE_INTERNAL_H */
