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

#include "oc_rep.h"
#include "oc_rep_encode_internal.h"
#include "port/oc_log_internal.h"

#ifdef OC_JSON_ENCODER
#include "oc_rep_encode_json_internal.h"
#endif /* OC_JSON_ENCODER */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct
{
  uint8_t *buffer;

#ifdef OC_DYNAMIC_ALLOCATION
  size_t buffer_size;
  size_t buffer_max_size;
  uint8_t **buffer_ptr;
  bool enable_realloc;
#endif /* OC_DYNAMIC_ALLOCATION */
} oc_rep_buffer_t;

CborEncoder g_encoder;

static oc_rep_buffer_t g_rep_buffer = {
  .buffer = NULL,
#ifdef OC_DYNAMIC_ALLOCATION
  .buffer_size = 0,
  .buffer_max_size = 0,
  .buffer_ptr = NULL,
  .enable_realloc = false,
#endif /* OC_DYNAMIC_ALLOCATION */
};

#define OC_REP_CBOR_ENCODER_INIT                                               \
  {                                                                            \
    .type = OC_REP_CBOR_ENCODER,                                               \
                                                                               \
    .encode_null = &cbor_encode_null, .encode_boolean = &cbor_encode_boolean,  \
    .encode_int = &cbor_encode_int, .encode_uint = &cbor_encode_uint,          \
    .encode_floating_point = &cbor_encode_floating_point,                      \
    .encode_double = &cbor_encode_double,                                      \
    .encode_text_string = &cbor_encode_text_string,                            \
    .encode_byte_string = &cbor_encode_byte_string,                            \
    .create_array = &cbor_encoder_create_array,                                \
    .create_map = &cbor_encoder_create_map,                                    \
    .close_container = &cbor_encoder_close_container,                          \
  }

static oc_rep_encoder_t g_rep_encoder = OC_REP_CBOR_ENCODER_INIT;

oc_rep_encoder_t
oc_rep_cbor_encoder(void)
{
  return (oc_rep_encoder_t)OC_REP_CBOR_ENCODER_INIT;
}

#undef OC_REP_CBOR_ENCODER_INIT

CborEncoder *
oc_rep_encoder_convert_offset_to_ptr(CborEncoder *encoder)
{
  if (!encoder || (encoder->data.ptr && !encoder->end)) {
    return encoder;
  }
  encoder->data.ptr = g_rep_buffer.buffer + (intptr_t)encoder->data.ptr;
#ifdef OC_DYNAMIC_ALLOCATION
  encoder->end =
    g_rep_buffer.buffer ? g_rep_buffer.buffer + g_rep_buffer.buffer_size : NULL;
#else  /* OC_DYNAMIC_ALLOCATION */
  encoder->end = g_rep_buffer.buffer + (intptr_t)encoder->end;
#endif /* !OC_DYNAMIC_ALLOCATION */
  return encoder;
}

CborEncoder *
oc_rep_encoder_convert_ptr_to_offset(CborEncoder *encoder)
{
  if (!encoder || (encoder->data.ptr && !encoder->end)) {
    return encoder;
  }
  encoder->data.ptr = (uint8_t *)(encoder->data.ptr - g_rep_buffer.buffer);
  encoder->end = (uint8_t *)(encoder->end - g_rep_buffer.buffer);
  return encoder;
}

#ifdef OC_DYNAMIC_ALLOCATION
static size_t
oc_rep_encoder_get_extra_bytes_needed(CborEncoder *encoder)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  size_t size = cbor_encoder_get_extra_bytes_needed(encoder);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  return size;
}

static CborError
realloc_buffer(size_t needed)
{
  if (!g_rep_buffer.enable_realloc ||
      g_rep_buffer.buffer_size + needed > g_rep_buffer.buffer_max_size) {
    return CborErrorOutOfMemory;
  }
  // preallocate buffer to avoid reallocation
  if (2 * (g_rep_buffer.buffer_size + needed) <
      (g_rep_buffer.buffer_max_size / 4)) {
    needed += g_rep_buffer.buffer_size + needed;
  } else {
    needed = g_rep_buffer.buffer_max_size - g_rep_buffer.buffer_size;
  }
  uint8_t *tmp = (uint8_t *)realloc(*g_rep_buffer.buffer_ptr,
                                    g_rep_buffer.buffer_size + needed);
  if (tmp == NULL) {
    return CborErrorOutOfMemory;
  }
  *g_rep_buffer.buffer_ptr = tmp;
  g_rep_buffer.buffer = tmp;
  g_rep_buffer.buffer_size = g_rep_buffer.buffer_size + needed;
  return CborNoError;
}

#endif /* OC_DYNAMIC_ALLOCATION */

void
oc_rep_encoder_set_type(oc_rep_encoder_type_t encoder_type)
{
  if (encoder_type == OC_REP_CBOR_ENCODER) {
    g_rep_encoder = oc_rep_cbor_encoder();
    return;
  }

#ifdef OC_JSON_ENCODER
  if (encoder_type == OC_REP_JSON_ENCODER) {
    g_rep_encoder = oc_rep_json_encoder();
    return;
  }
#endif /* OC_JSON_ENCODER */
}

oc_rep_encoder_type_t
oc_rep_encoder_get_type(void)
{
  return g_rep_encoder.type;
}

bool
oc_rep_encoder_set_type_by_accept(oc_content_format_t accept)
{
  if (accept == APPLICATION_CBOR || accept == APPLICATION_VND_OCF_CBOR ||
      accept == APPLICATION_NOT_DEFINED) {
    oc_rep_encoder_set_type(OC_REP_CBOR_ENCODER);
    return true;
  }
#ifdef OC_JSON_ENCODER
  if (accept == APPLICATION_JSON || accept == APPLICATION_TD_JSON) {
    oc_rep_encoder_set_type(OC_REP_JSON_ENCODER);
    return true;
  }
#endif /* OC_JSON_ENCODER */
  return false;
}

oc_content_format_t
oc_rep_encoder_get_content_format(void)
{
#ifdef OC_JSON_ENCODER
  if (g_rep_encoder.type == OC_REP_JSON_ENCODER) {
    return APPLICATION_JSON;
  }
#endif /* OC_JSON_ENCODER */
  return APPLICATION_VND_OCF_CBOR;
}

void
oc_rep_buffer_init(uint8_t *buffer, size_t size)
{
  g_rep_buffer.buffer = buffer;
#ifdef OC_DYNAMIC_ALLOCATION
  g_rep_buffer.enable_realloc = false;
  g_rep_buffer.buffer_size = size;
  g_rep_buffer.buffer_ptr = NULL;
  g_rep_buffer.buffer_max_size = size;
#endif /* OC_DYNAMIC_ALLOCATION */
  cbor_encoder_init(&g_encoder, g_rep_buffer.buffer, size, 0);
  oc_rep_encoder_convert_ptr_to_offset(&g_encoder);
}

#ifdef OC_DYNAMIC_ALLOCATION
void
oc_rep_buffer_realloc_init(uint8_t **buffer, size_t size, size_t max_size)
{
  assert(buffer != NULL);
  g_rep_buffer.buffer_size = size;
  g_rep_buffer.buffer_max_size = max_size;
  g_rep_buffer.buffer_ptr = buffer;
  g_rep_buffer.buffer = *buffer;
  g_rep_buffer.enable_realloc = true;
  cbor_encoder_init(&g_encoder, g_rep_buffer.buffer, size, 0);
  oc_rep_encoder_convert_ptr_to_offset(&g_encoder);
}
#endif /* OC_DYNAMIC_ALLOCATION */

CborEncoder *
oc_rep_get_encoder(void)
{
  return &g_encoder;
}

const uint8_t *
oc_rep_get_encoder_buf(void)
{
  return g_rep_buffer.buffer;
}

#ifdef OC_DYNAMIC_ALLOCATION
int
oc_rep_get_encoder_buffer_size(void)
{
  return (int)g_rep_buffer.buffer_size;
}
#endif /* OC_DYNAMIC_ALLOCATION */

uint8_t *
oc_rep_shrink_encoder_buf(uint8_t *buf)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return buf;
#else  /* !OC_DYNAMIC_ALLOCATION */
  if (!g_rep_buffer.enable_realloc || !buf || !g_rep_buffer.buffer_ptr ||
      buf != g_rep_buffer.buffer)
    return buf;
  int size = oc_rep_get_encoded_payload_size();
  if (size <= 0) {
    // if the size is 0, then it means that the encoder was not used at all
    return buf;
  }
  uint8_t *tmp = (uint8_t *)realloc(buf, size);
  if (tmp == NULL && size > 0) {
    return buf;
  }
  OC_DBG("cbor encoder buffer was shrinked from %d to %d",
         (int)g_rep_buffer.buffer_size, size);
  g_rep_buffer.buffer_size = (size_t)size;
  *g_rep_buffer.buffer_ptr = tmp;
  g_rep_buffer.buffer = tmp;
  return tmp;
#endif /* OC_DYNAMIC_ALLOCATION */
}

int
oc_rep_get_encoded_payload_size(void)
{
  oc_rep_encoder_convert_offset_to_ptr(&g_encoder);
  size_t size = cbor_encoder_get_buffer_size(&g_encoder, g_rep_buffer.buffer);
  size_t needed = cbor_encoder_get_extra_bytes_needed(&g_encoder);
  oc_rep_encoder_convert_ptr_to_offset(&g_encoder);
  if (g_err == CborErrorOutOfMemory) {
    OC_WRN("Insufficient memory: Increase OC_MAX_APP_DATA_SIZE to "
           "accomodate a larger payload(+%d)",
           (int)needed);
    (void)needed;
  }
  if (g_err != CborNoError) {
    return -1;
  }
  return (int)size;
}

void
oc_rep_encode_raw(const uint8_t *data, size_t len)
{
  if (g_encoder.end == NULL) {
    OC_WRN("encoder has not set end pointer.");
    g_err = CborErrorInternalError;
    return;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  size_t remaining = g_rep_buffer.buffer_size - (size_t)g_encoder.data.ptr;
  if (remaining < len) {
    size_t needed = len - remaining;
    if (!g_rep_buffer.enable_realloc) {
      OC_WRN("Insufficient memory: Increase OC_MAX_APP_DATA_SIZE to "
             "accomodate a larger payload(+%d)",
             (int)needed);
      g_err = CborErrorOutOfMemory;
      return;
    }
    CborEncoder prevEncoder;
    memcpy(&prevEncoder, &g_encoder, sizeof(prevEncoder));
    CborError err = realloc_buffer(needed);
    if (err != CborNoError) {
      g_err = err;
      return;
    }
    memcpy(&g_encoder, &prevEncoder, sizeof(prevEncoder));
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  intptr_t needed = (intptr_t)g_encoder.end - (intptr_t)g_encoder.data.ptr;
  if (needed < (intptr_t)len) {
    OC_WRN("Insufficient memory: Increase OC_MAX_APP_DATA_SIZE to "
           "accomodate a larger payload(+%d)",
           (int)needed);
    g_err = CborErrorOutOfMemory;
    return;
  }
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_rep_encoder_convert_offset_to_ptr(&g_encoder);
  memcpy(g_encoder.data.ptr, data, len);
  g_encoder.data.ptr = g_encoder.data.ptr + len;
  g_err = CborNoError;
  oc_rep_encoder_convert_ptr_to_offset(&g_encoder);
}

static CborError
oc_rep_encode_null_internal(CborEncoder *encoder)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  CborError err = g_rep_encoder.encode_null(encoder);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_null(CborEncoder *encoder)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_null_internal(encoder);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_null_internal(encoder);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_null_internal(encoder);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_boolean_internal(CborEncoder *encoder, bool value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  CborError err = g_rep_encoder.encode_boolean(encoder, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_boolean(CborEncoder *encoder, bool value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_boolean_internal(encoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_boolean_internal(encoder, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_boolean_internal(encoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_int_internal(CborEncoder *encoder, int64_t value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  CborError err = g_rep_encoder.encode_int(encoder, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_int(CborEncoder *encoder, int64_t value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_int_internal(encoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_int_internal(encoder, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_int_internal(encoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_uint_internal(CborEncoder *encoder, uint64_t value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  CborError err = g_rep_encoder.encode_uint(encoder, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_uint(CborEncoder *encoder, uint64_t value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_uint_internal(encoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_uint_internal(encoder, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_uint_internal(encoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_floating_point_internal(CborEncoder *encoder, CborType fpType,
                                      const void *value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  CborError err = g_rep_encoder.encode_floating_point(encoder, fpType, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_floating_point(CborEncoder *encoder, CborType fpType,
                             const void *value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_floating_point_internal(encoder, fpType, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_floating_point_internal(encoder, fpType, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_floating_point_internal(encoder, fpType, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_double_internal(CborEncoder *encoder, double value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  CborError err = g_rep_encoder.encode_double(encoder, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_double(CborEncoder *encoder, double value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_double_internal(encoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_double_internal(encoder, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_double_internal(encoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_text_string_internal(CborEncoder *encoder, const char *string,
                                   size_t length)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  CborError err = g_rep_encoder.encode_text_string(encoder, string, length);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_text_string(CborEncoder *encoder, const char *string,
                          size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_text_string_internal(encoder, string, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_text_string_internal(encoder, string, length);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_text_string_internal(encoder, string, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_byte_string_internal(CborEncoder *encoder, const uint8_t *string,
                                   size_t length)

{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  CborError err = g_rep_encoder.encode_byte_string(encoder, string, length);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_byte_string(CborEncoder *encoder, const uint8_t *string,
                          size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_byte_string_internal(encoder, string, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_byte_string_internal(encoder, string, length);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_byte_string_internal(encoder, string, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encoder_create_array_internal(CborEncoder *encoder,
                                     CborEncoder *arrayEncoder, size_t length)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  oc_rep_encoder_convert_offset_to_ptr(arrayEncoder);
  CborError err = g_rep_encoder.create_array(encoder, arrayEncoder, length);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  oc_rep_encoder_convert_ptr_to_offset(arrayEncoder);
  return err;
}

CborError
oc_rep_encoder_create_array(CborEncoder *encoder, CborEncoder *arrayEncoder,
                            size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encoder_create_array_internal(encoder, arrayEncoder, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborEncoder prevArrayEncoder;
  memcpy(&prevArrayEncoder, arrayEncoder, sizeof(prevArrayEncoder));
  CborError err =
    oc_rep_encoder_create_array_internal(encoder, arrayEncoder, length);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(arrayEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    memcpy(arrayEncoder, &prevArrayEncoder, sizeof(prevArrayEncoder));
    return oc_rep_encoder_create_array_internal(encoder, arrayEncoder, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encoder_create_map_internal(CborEncoder *encoder,
                                   CborEncoder *mapEncoder, size_t length)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  oc_rep_encoder_convert_offset_to_ptr(mapEncoder);
  CborError err = g_rep_encoder.create_map(encoder, mapEncoder, length);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  oc_rep_encoder_convert_ptr_to_offset(mapEncoder);
  return err;
}

CborError
oc_rep_encoder_create_map(CborEncoder *encoder, CborEncoder *mapEncoder,
                          size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encoder_create_map_internal(encoder, mapEncoder, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevMapEncoder;
  memcpy(&prevMapEncoder, mapEncoder, sizeof(prevMapEncoder));
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err =
    oc_rep_encoder_create_map_internal(encoder, mapEncoder, length);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(mapEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(mapEncoder, &prevMapEncoder, sizeof(prevMapEncoder));
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encoder_create_map_internal(encoder, mapEncoder, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encoder_close_container_internal(CborEncoder *encoder,
                                        CborEncoder *containerEncoder)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder);
  oc_rep_encoder_convert_offset_to_ptr(containerEncoder);
  CborError err = g_rep_encoder.close_container(encoder, containerEncoder);
  oc_rep_encoder_convert_ptr_to_offset(encoder);
  oc_rep_encoder_convert_ptr_to_offset(containerEncoder);
  return err;
}

CborError
oc_rep_encoder_close_container(CborEncoder *encoder,
                               CborEncoder *containerEncoder)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encoder_close_container_internal(encoder, containerEncoder);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevContainerEncoder;
  memcpy(&prevContainerEncoder, containerEncoder, sizeof(prevContainerEncoder));
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err =
    oc_rep_encoder_close_container_internal(encoder, containerEncoder);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    memcpy(containerEncoder, &prevContainerEncoder,
           sizeof(prevContainerEncoder));
    return oc_rep_encoder_close_container_internal(encoder, containerEncoder);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}
