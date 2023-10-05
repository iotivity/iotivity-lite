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

#ifdef OC_JSON_ENCODER

#include "oc_rep_encode_json_internal.h"
#include "util/oc_macros_internal.h"

#include <inttypes.h>
#include <stddef.h>
#include <string.h>

typedef enum json_types_t {
  KeyType = 1 << 0,
  ValueType = 1 << 1,
  ArrayType = 1 << 2,
  MapType = 1 << 3,
} json_types_t;

static bool
rep_json_would_overflow(CborEncoder *encoder, size_t len)
{
  ptrdiff_t remaining = (ptrdiff_t)encoder->end;
  remaining -=
    remaining ? (ptrdiff_t)encoder->data.ptr : encoder->data.bytes_needed;
  remaining -= (ptrdiff_t)len;
  return remaining < 0;
}

static void
rep_json_advance_ptr(CborEncoder *encoder, size_t n)
{
  if (encoder->end != NULL) {
    encoder->data.ptr += n;
  } else {
    encoder->data.bytes_needed += (ptrdiff_t)n;
  }
}

static CborError
rep_json_append_to_buffer(CborEncoder *encoder, const void *data, size_t len)
{
  if (rep_json_would_overflow(encoder, len)) {
    if (encoder->end != NULL) {
      len -= encoder->end - encoder->data.ptr;
      encoder->end = NULL;
      encoder->data.bytes_needed = 0;
    }

    rep_json_advance_ptr(encoder, len);
    return CborErrorOutOfMemory;
  }

  memcpy(encoder->data.ptr, data, len);
  encoder->data.ptr += len;
  return CborNoError;
}

static CborError
rep_json_append_separator(CborEncoder *encoder)
{
  if ((encoder->flags & MapType) != 0) {
    if ((encoder->flags & KeyType) != 0) {
      return rep_json_append_to_buffer(encoder, ":", 1);
    }
    if ((encoder->flags & ValueType) != 0) {
      return rep_json_append_to_buffer(encoder, ",", 1);
    }
    return CborNoError;
  }
  if (encoder->flags == ArrayType) {
    return CborNoError;
  }
  if ((encoder->flags & ArrayType) != 0) {
    return rep_json_append_to_buffer(encoder, ",", 1);
  }
  return CborNoError;
}

static CborError
rep_json_encode_null(CborEncoder *encoder)
{
  if (((encoder->flags & KeyType) == 0) && (encoder->flags & MapType) != 0) {
    return CborErrorImproperValue;
  }
  CborError err = rep_json_append_separator(encoder);
#define JSON_NULL "null"
  err |=
    rep_json_append_to_buffer(encoder, JSON_NULL, OC_CHAR_ARRAY_LEN(JSON_NULL));
#undef JSON_NULL
  if (err == CborNoError) {
    encoder->flags &= ~KeyType;
    encoder->flags |= ValueType;
  }
  return err;
}

static CborError
rep_json_encode_boolean(CborEncoder *encoder, bool value)
{
  if (((encoder->flags & KeyType) == 0) && (encoder->flags & MapType) != 0) {
    return CborErrorImproperValue;
  }
  CborError err = rep_json_append_separator(encoder);
#define JSON_TRUE "true"
#define JSON_FALSE "false"
  if (value) {
    err |= rep_json_append_to_buffer(encoder, JSON_TRUE,
                                     OC_CHAR_ARRAY_LEN(JSON_TRUE));
  } else {
    err |= rep_json_append_to_buffer(encoder, JSON_FALSE,
                                     OC_CHAR_ARRAY_LEN(JSON_FALSE));
  }
#undef JSON_TRUE
#undef JSON_FALSE
  if (err == CborNoError) {
    encoder->flags &= ~KeyType;
    encoder->flags |= ValueType;
  }
  return err;
}

static CborError
rep_json_encode_int(CborEncoder *encoder, int64_t value)
{
  if (((encoder->flags & KeyType) == 0) && (encoder->flags & MapType) != 0) {
    return CborErrorImproperValue;
  }
  if ((value > OC_REP_JSON_INT_MAX) || (value < OC_REP_JSON_INT_MIN)) {
    return CborErrorDataTooLarge;
  }
  char buf[32] = { 0 };
  int len = snprintf(buf, sizeof(buf), "%" PRId64, value);
  if (len < 0 || (size_t)len >= sizeof(buf)) {
    return CborErrorUnexpectedEOF;
  }
  CborError err = rep_json_append_separator(encoder);
  err |= rep_json_append_to_buffer(encoder, buf, len);
  if (err == CborNoError) {
    encoder->flags &= ~KeyType;
    encoder->flags |= ValueType;
  }
  return err;
}

static CborError
rep_json_encode_uint(CborEncoder *encoder, uint64_t value)
{
  if (((encoder->flags & KeyType) == 0) && (encoder->flags & MapType) != 0) {
    return CborErrorImproperValue;
  }
  if (value > OC_REP_JSON_UINT_MAX) {
    return CborErrorDataTooLarge;
  }
  char buf[32] = { 0 };
  int len = snprintf(buf, sizeof(buf), "%" PRIu64, value);
  if (len < 0 || (size_t)len >= sizeof(buf)) {
    return CborErrorUnexpectedEOF;
  }
  CborError err = rep_json_append_separator(encoder);
  err |= rep_json_append_to_buffer(encoder, buf, len);
  if (err == CborNoError) {
    encoder->flags &= ~KeyType;
    encoder->flags |= ValueType;
  }
  return err;
}

static CborError
rep_json_encode_byte_string(CborEncoder *encoder, const uint8_t *string,
                            size_t length)
{
  // TODO: implement, encode as base64
  (void)encoder;
  (void)string;
  (void)length;
  return CborErrorUnsupportedType;
}

static CborError
rep_json_encode_text_string(CborEncoder *encoder, const char *string,
                            size_t length)
{
  CborError err = rep_json_append_separator(encoder);
  err |= rep_json_append_to_buffer(encoder, "\"", 1);
  err |= rep_json_append_to_buffer(encoder, string, length);
  err |= rep_json_append_to_buffer(encoder, "\"", 1);
  if (err != CborNoError) {
    return err;
  }
  if (encoder->flags & MapType) {
    if (encoder->flags & KeyType) {
      // "key" -> value was encoded
      encoder->flags &= ~KeyType;
      encoder->flags |= ValueType;
    } else if (encoder->flags & ValueType) {
      // "value" -> key was encoded
      encoder->flags &= ~ValueType;
      encoder->flags |= KeyType;
    } else {
      // empty map -> key was encoded
      encoder->flags |= KeyType;
    }
  }
  if (encoder->flags & ArrayType) {
    encoder->flags |= ValueType;
  }
  return err;
}

static CborError
rep_json_encode_floating_point(CborEncoder *encoder, CborType fpType,
                               const void *value)
{
  // TODO: implement
  (void)encoder;
  (void)fpType;
  (void)value;
  return CborErrorUnsupportedType;
}

static CborError
rep_json_encode_double(CborEncoder *encoder, double value)
{
  if (((encoder->flags & KeyType) == 0) && (encoder->flags & MapType) != 0) {
    return CborErrorImproperValue;
  }
  char buf[320] = { 0 };
  int len = snprintf(buf, sizeof(buf), "%f", value);
  if (len < 0 || (size_t)len >= sizeof(buf)) {
    return CborErrorUnexpectedEOF;
  }
  CborError err = rep_json_append_separator(encoder);
  err |= rep_json_append_to_buffer(encoder, buf, len);
  if (err == CborNoError) {
    encoder->flags &= ~KeyType;
    encoder->flags |= ValueType;
  }
  return err;
}

static void
rep_json_prepare_container(CborEncoder *encoder, CborEncoder *container,
                           json_types_t json_type)
{
  container->data.ptr = encoder->data.ptr;
  container->end = encoder->end;
  container->flags = json_type;
}

static CborError
rep_json_encoder_create_array(CborEncoder *encoder, CborEncoder *container,
                              size_t length)
{
  (void)length;
  if (((encoder->flags & KeyType) == 0) && (encoder->flags & MapType) != 0) {
    return CborErrorImproperValue;
  }
  CborError err = rep_json_append_separator(encoder);
  err |= rep_json_append_to_buffer(encoder, "[", 1);
  if (err == CborNoError) {
    encoder->flags &= ~KeyType;
    encoder->flags |= ValueType;
    rep_json_prepare_container(encoder, container, ArrayType);
  } else if (err == CborErrorOutOfMemory) {
    memcpy(container, encoder, sizeof(CborEncoder));
  }
  return err;
}

static CborError
rep_json_encoder_create_map(CborEncoder *encoder, CborEncoder *container,
                            size_t length)
{
  (void)length;
  if (((encoder->flags & KeyType) == 0) && (encoder->flags & MapType) != 0) {
    return CborErrorImproperValue;
  }
  CborError err = rep_json_append_separator(encoder);
  err |= rep_json_append_to_buffer(encoder, "{", 1);
  if (err == CborNoError) {
    encoder->flags &= ~KeyType;
    encoder->flags |= ValueType;
    rep_json_prepare_container(encoder, container, MapType);
  } else if (err == CborErrorOutOfMemory) {
    memcpy(container, encoder, sizeof(CborEncoder));
  }
  return err;
}

static CborError
rep_json_encoder_close_container(CborEncoder *encoder,
                                 const CborEncoder *container)
{
  // synchronise buffer state with that of the container
  encoder->end = container->end;
  encoder->data = container->data;
  const char *break_byte = (container->flags & MapType) != 0 ? "}" : "]";
  return rep_json_append_to_buffer(encoder, break_byte, 1);
}

oc_rep_encoder_t
oc_rep_json_encoder(void)
{
  return (oc_rep_encoder_t){
    .type = OC_REP_JSON_ENCODER,

    .encode_null = &rep_json_encode_null,
    .encode_boolean = &rep_json_encode_boolean,
    .encode_int = &rep_json_encode_int,
    .encode_uint = &rep_json_encode_uint,
    .encode_byte_string = &rep_json_encode_byte_string,
    .encode_text_string = &rep_json_encode_text_string,
    .encode_floating_point = &rep_json_encode_floating_point,
    .encode_double = &rep_json_encode_double,
    .create_array = &rep_json_encoder_create_array,
    .create_map = &rep_json_encoder_create_map,
    .close_container = &rep_json_encoder_close_container,
  };
}

#endif /* OC_JSON_ENCODER */
