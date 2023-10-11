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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_CRC_ENCODER

#include "oc_rep_encode_crc_internal.h"
#include "util/oc_crc_internal.h"
#include "util/oc_macros_internal.h"

typedef enum crc_flag_t {
  CrcFlagBytesNeeded = 1 << 0,
  CrcFlagHasPayload = 1 << 1,

  CrcFlagIsMap = 1 << 2,
} crc_flag_t;

static size_t
rep_crc_get_buffer_size(const CborEncoder *encoder, const uint8_t *buffer)
{
  (void)buffer;
  if ((encoder->flags & CrcFlagHasPayload) != 0) {
    return sizeof(uint64_t);
  }
  return 0;
}

static size_t
rep_crc_get_extra_bytes_needed(const CborEncoder *encoder)
{
  if ((encoder->flags & CrcFlagBytesNeeded) != 0) {
    return encoder->data.bytes_needed;
  }
  return 0;
}

static CborError
rep_crc_append_to_buffer(CborEncoder *encoder, CborType data_type,
                         const void *data, size_t len)
{
  size_t size = 0;
  if (encoder->data.ptr != NULL) {
    size = encoder->end - encoder->data.ptr;
  }

  uint64_t crc = 0;
  if (size < sizeof(crc)) {
    encoder->flags |= CrcFlagBytesNeeded;
    encoder->data.bytes_needed = (ptrdiff_t)(sizeof(crc) - size);
    return CborErrorOutOfMemory;
  }

  encoder->flags &= ~CrcFlagBytesNeeded;
  if ((encoder->flags & CrcFlagHasPayload) != 0) {
    memcpy(&crc, encoder->data.ptr, sizeof(crc));
  }

  uint8_t type[] = { (uint8_t)data_type };
  crc = oc_crc64(crc, type, OC_ARRAY_SIZE(type));
  if (len > 0) {
    crc = oc_crc64(crc, data, len);
  }
  memcpy(encoder->data.ptr, &crc, sizeof(crc));
  encoder->flags |= CrcFlagHasPayload;
  return CborNoError;
}

static CborError
rep_crc_encode_null(CborEncoder *encoder)
{
  return rep_crc_append_to_buffer(encoder, CborNullType, NULL, 0);
}

static CborError
rep_crc_encode_bool(CborEncoder *encoder, bool value)
{
  uint8_t crc_bool = { value ? OC_CRC_REP_TRUE : OC_CRC_REP_FALSE };
  return rep_crc_append_to_buffer(encoder, CborBooleanType, &crc_bool, 1);
}

static CborError
rep_crc_encode_int(CborEncoder *encoder, int64_t value)
{
  return rep_crc_append_to_buffer(encoder, CborIntegerType, &value,
                                  sizeof(value));
}

static CborError
rep_crc_encode_floating_point(CborEncoder *encoder, CborType fpType,
                              const void *value)
{
  uint8_t size = 0;
  if (fpType == CborDoubleType) {
    size = sizeof(double);
  } else if (fpType == CborFloatType) {
    size = sizeof(float);
  } else if (fpType == CborHalfFloatType) {
    size = sizeof(uint16_t);
  }
  if (size == 0) {
    return CborErrorIllegalType;
  }
  return rep_crc_append_to_buffer(encoder, fpType, value, size);
}

static CborError
rep_crc_encode_double(CborEncoder *encoder, double value)
{
  return rep_crc_append_to_buffer(encoder, CborDoubleType, &value,
                                  sizeof(value));
}

static CborError
rep_crc_encode_uint(CborEncoder *encoder, uint64_t value)
{
  return rep_crc_append_to_buffer(encoder, CborIntegerType, &value,
                                  sizeof(value));
}

static CborError
rep_crc_encode_byte_string(CborEncoder *encoder, const uint8_t *string,
                           size_t length)
{
  return rep_crc_append_to_buffer(encoder, CborByteStringType, string, length);
}

static CborError
rep_crc_encode_text_string(CborEncoder *encoder, const char *string,
                           size_t length)
{
  return rep_crc_append_to_buffer(encoder, CborTextStringType, string, length);
}

static CborError
rep_crc_encoder_create_container(CborEncoder *encoder, CborEncoder *container,
                                 size_t length, bool isMap)
{
  (void)length;
  uint8_t open_byte = OC_CRC_OPEN_CONTAINER;
  int err = rep_crc_append_to_buffer(
    encoder, isMap ? CborMapType : CborArrayType, &open_byte, 1);
  if (err == CborNoError) {
    memcpy(container, encoder, sizeof(CborEncoder));
    container->flags =
      isMap ? encoder->flags | CrcFlagIsMap : encoder->flags & ~CrcFlagIsMap;
  } else if (err == CborErrorOutOfMemory) {
    memcpy(container, encoder, sizeof(CborEncoder));
  }
  return err;
}

static CborError
rep_crc_encoder_create_array(CborEncoder *encoder, CborEncoder *container,
                             size_t length)
{
  return rep_crc_encoder_create_container(encoder, container, length, false);
}

static CborError
rep_crc_encoder_create_map(CborEncoder *encoder, CborEncoder *container,
                           size_t length)
{
  return rep_crc_encoder_create_container(encoder, container, length, true);
}

static CborError
rep_crc_encoder_close_container(CborEncoder *encoder,
                                const CborEncoder *container)
{
  // synchronise buffer state with that of the container
  encoder->end = container->end;
  encoder->data = container->data;
  CborType type =
    (container->flags & CrcFlagIsMap) != 0 ? CborMapType : CborArrayType;
  uint8_t close_byte = OC_CRC_CLOSE_CONTAINER;
  return rep_crc_append_to_buffer(encoder, type, &close_byte, 1);
}

oc_rep_encoder_implementation_t
oc_rep_crc_encoder(void)
{
  return (oc_rep_encoder_implementation_t){
    .get_buffer_size = &rep_crc_get_buffer_size,
    .get_extra_bytes_needed = &rep_crc_get_extra_bytes_needed,

    .encode_null = &rep_crc_encode_null,
    .encode_boolean = &rep_crc_encode_bool,
    .encode_int = &rep_crc_encode_int,
    .encode_uint = &rep_crc_encode_uint,
    .encode_floating_point = &rep_crc_encode_floating_point,
    .encode_double = &rep_crc_encode_double,
    .encode_byte_string = &rep_crc_encode_byte_string,
    .encode_text_string = &rep_crc_encode_text_string,
    .create_array = &rep_crc_encoder_create_array,
    .create_map = &rep_crc_encoder_create_map,
    .close_container = &rep_crc_encoder_close_container,
  };
}

#endif /* OC_HAS_FEATURE_CRC_ENCODER */
