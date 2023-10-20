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

#include "api/oc_rep_encode_cbor_internal.h"
#include "api/oc_rep_encode_internal.h"
#include "oc_rep.h"
#include "port/oc_log_internal.h"
#include "util/oc_features.h"

#ifdef OC_JSON_ENCODER
#include "api/oc_rep_encode_json_internal.h"
#endif /* OC_JSON_ENCODER */

#ifdef OC_HAS_FEATURE_CRC_ENCODER
#include "api/oc_rep_encode_crc_internal.h"
#endif /* OC_HAS_FEATURE_CRC_ENCODER */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static oc_rep_encoder_t g_rep_encoder = { .type = OC_REP_CBOR_ENCODER,
                                          .impl = OC_REP_CBOR_ENCODER_INIT,
                                          .buffer = {
                                            .ptr = NULL,
                                            .size = 0,
#ifdef OC_DYNAMIC_ALLOCATION
                                            .max_size = 0,
                                            .pptr = NULL,
                                            .enable_realloc = false,
#endif /* OC_DYNAMIC_ALLOCATION */
                                          }, };

oc_rep_encoder_t *
oc_rep_global_encoder(void)
{
  return &g_rep_encoder;
}

void
oc_rep_encoder_convert_ptr_to_offset(const oc_rep_encoder_t *encoder,
                                     CborEncoder *subEncoder)
{
  if (encoder->buffer.ptr == NULL || subEncoder->data.ptr == NULL ||
      subEncoder->end == NULL) {
    return;
  }
  subEncoder->data.ptr =
    (uint8_t *)(subEncoder->data.ptr - encoder->buffer.ptr);
  subEncoder->end = (uint8_t *)(subEncoder->end - encoder->buffer.ptr);
}

void
oc_rep_encoder_convert_offset_to_ptr(const oc_rep_encoder_t *encoder,
                                     CborEncoder *subEncoder)
{
  if (encoder->buffer.ptr == NULL ||
      // don't convert in bytes needed state
      (subEncoder->data.ptr != NULL && subEncoder->end == NULL)) {
    return;
  }
  subEncoder->data.ptr = encoder->buffer.ptr + (intptr_t)subEncoder->data.ptr;
  subEncoder->end = encoder->buffer.ptr + (intptr_t)encoder->buffer.size;
}

static void
rep_cbor_context_init(oc_rep_encoder_t *encoder, size_t size)
{
  cbor_encoder_init(&encoder->ctx, encoder->buffer.ptr, size, 0);
  oc_rep_encoder_convert_ptr_to_offset(encoder, &encoder->ctx);
}

void
oc_rep_encoder_buffer_init(oc_rep_encoder_t *encoder, uint8_t *buffer,
                           size_t size)
{
  encoder->buffer.ptr = buffer;
  encoder->buffer.size = size;
#ifdef OC_DYNAMIC_ALLOCATION
  encoder->buffer.enable_realloc = false;
  encoder->buffer.pptr = NULL;
  encoder->buffer.max_size = size;
#endif /* OC_DYNAMIC_ALLOCATION */
  rep_cbor_context_init(encoder, size);
}

#ifdef OC_DYNAMIC_ALLOCATION

void
oc_rep_encoder_buffer_realloc_init(oc_rep_encoder_t *encoder, uint8_t **buffer,
                                   size_t size, size_t max_size)
{
  encoder->buffer.size = size;
  encoder->buffer.max_size = max_size;
  encoder->buffer.pptr = buffer;
  encoder->buffer.ptr = *buffer;
  encoder->buffer.enable_realloc = true;
  rep_cbor_context_init(encoder, size);
}

#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_DYNAMIC_ALLOCATION
static size_t
rep_encoder_get_extra_bytes_needed(const oc_rep_encoder_t *encoder,
                                   CborEncoder *subEncoder)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  size_t size = encoder->impl.get_extra_bytes_needed(subEncoder);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  return size;
}

static CborError
rep_buffer_realloc(oc_rep_encoder_t *encoder, size_t needed)
{
  if (!encoder->buffer.enable_realloc) {
    return CborErrorOutOfMemory;
  }
  if (encoder->buffer.size + needed > encoder->buffer.max_size) {
    OC_WRN("Insufficient memory: Increase OC_MAX_APP_DATA_SIZE to accomodate a "
           "larger payload(+%zu)",
           needed);
    return CborErrorOutOfMemory;
  }

  // preallocate buffer to avoid reallocation
  if (2 * (encoder->buffer.size + needed) < (encoder->buffer.max_size / 4)) {
    needed += encoder->buffer.size + needed;
  } else {
    needed = encoder->buffer.max_size - encoder->buffer.size;
  }
  size_t new_size = encoder->buffer.size + needed;
  uint8_t *tmp = (uint8_t *)realloc(*encoder->buffer.pptr, new_size);
  if (tmp == NULL) {
    OC_ERR("Memory reallocation failed");
    return CborErrorOutOfMemory;
  }
  *encoder->buffer.pptr = tmp;
  encoder->buffer.ptr = tmp;
  encoder->buffer.size = new_size;
  return CborNoError;
}

#endif /* OC_DYNAMIC_ALLOCATION */

oc_rep_encoder_t
oc_rep_encoder(oc_rep_encoder_type_t type, oc_rep_encoder_buffer_t buffer)
{
  oc_rep_encoder_t encoder = {
    .type = OC_REP_CBOR_ENCODER,
    .impl = oc_rep_cbor_encoder(),
  };

#ifdef OC_JSON_ENCODER
  if (type == OC_REP_JSON_ENCODER) {
    encoder.type = OC_REP_JSON_ENCODER;
    encoder.impl = oc_rep_json_encoder();
  }
#endif /* OC_JSON_ENCODER */

#ifdef OC_HAS_FEATURE_CRC_ENCODER
  if (type == OC_REP_CRC_ENCODER) {
    encoder.type = OC_REP_CRC_ENCODER;
    encoder.impl = oc_rep_crc_encoder();
  }
#endif /* OC_HAS_FEATURE_CRC_ENCODER */

  (void)type;
  encoder.buffer = buffer;
  rep_cbor_context_init(&encoder, encoder.buffer.size);
  return encoder;
}

void
oc_rep_encoder_set_type(oc_rep_encoder_type_t type)
{
  g_rep_encoder = oc_rep_encoder(type, g_rep_encoder.buffer);
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

bool
oc_rep_encoder_get_content_format(oc_content_format_t *format)
{
#ifdef OC_JSON_ENCODER
  if (g_rep_encoder.type == OC_REP_JSON_ENCODER) {
    *format = APPLICATION_JSON;
    return true;
  }
#endif /* OC_JSON_ENCODER */
#ifdef OC_HAS_FEATURE_CRC_ENCODER
  if (g_rep_encoder.type == OC_REP_CRC_ENCODER) {
    // encoding of message payloads with crc is not supported
    return false;
  }
#endif /* OC_HAS_FEATURE_CRC_ENCODER */

  *format = APPLICATION_VND_OCF_CBOR;
  return true;
}

oc_rep_encoder_reset_t
oc_rep_global_encoder_reset(const oc_rep_encoder_reset_t *reset)
{
  oc_rep_encoder_reset_t prev = {
    .encoder = g_rep_encoder,
  };
  prev.root_map_ctx = root_map;
  prev.links_array_ctx = links_array;

  if (reset != NULL) {
    g_rep_encoder = reset->encoder;
    root_map = reset->root_map_ctx;
    links_array = reset->links_array_ctx;
    g_err = CborNoError;
  }

  return prev;
}

CborEncoder *
oc_rep_get_encoder(void)
{
  return &g_rep_encoder.ctx;
}

const uint8_t *
oc_rep_get_encoder_buf(void)
{
  return g_rep_encoder.buffer.ptr;
}

#ifdef OC_DYNAMIC_ALLOCATION
int
oc_rep_get_encoder_buffer_size(void)
{
  return (int)g_rep_encoder.buffer.size;
}
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_DYNAMIC_ALLOCATION

bool
oc_rep_encoder_shrink_buffer(oc_rep_encoder_t *encoder)
{
  if (!encoder->buffer.enable_realloc || encoder->buffer.pptr == NULL) {
    return false;
  }
  int size = oc_rep_encoder_payload_size(encoder);
  if (size <= 0 || size == (int)encoder->buffer.size) {
    // if the size is 0, then it means that the encoder was not used at all
    // if the size is already the same as the buffer size, then there is no
    // need to shrink
    return false;
  }
  uint8_t *tmp = (uint8_t *)realloc(encoder->buffer.ptr, size);
  if (tmp == NULL) {
    OC_ERR("Memory reallocation failed");
    return false;
  }
  OC_DBG("encoder buffer was shrinked from %d to %d", (int)encoder->buffer.size,
         size);
  encoder->buffer.size = (size_t)size;
  *encoder->buffer.pptr = tmp;
  encoder->buffer.ptr = tmp;
  return true;
}

#endif /* OC_DYNAMIC_ALLOCATION */

uint8_t *
oc_rep_shrink_encoder_buf(uint8_t *buf)
{
#ifdef OC_DYNAMIC_ALLOCATION
  if (buf == NULL || buf != g_rep_encoder.buffer.ptr) {
    return buf;
  }
  if (!oc_rep_encoder_shrink_buffer(&g_rep_encoder)) {
    return buf;
  }
  return g_rep_encoder.buffer.ptr;
#else  /* !OC_DYNAMIC_ALLOCATION */
  return buf;
#endif /* OC_DYNAMIC_ALLOCATION */
}

int
oc_rep_encoder_payload_size(oc_rep_encoder_t *encoder)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, &encoder->ctx);
  size_t size =
    encoder->impl.get_buffer_size(&encoder->ctx, encoder->buffer.ptr);
  size_t needed = encoder->impl.get_extra_bytes_needed(&encoder->ctx);
  oc_rep_encoder_convert_ptr_to_offset(encoder, &encoder->ctx);
  if (g_err == CborErrorOutOfMemory) {
    OC_WRN("Insufficient memory: Increase OC_MAX_APP_DATA_SIZE to "
           "accomodate a larger payload(+%zu)",
           needed);
    (void)needed;
  }
  if (g_err != CborNoError) {
    return -1;
  }
  return (int)size;
}

int
oc_rep_get_encoded_payload_size(void)
{
  return oc_rep_encoder_payload_size(&g_rep_encoder);
}

long
oc_rep_encoder_remaining_size(oc_rep_encoder_t *encoder)
{
  if (encoder->ctx.end == NULL) {
    OC_WRN("encoder has not set end pointer.");
    return -1;
  }
  assert(encoder->buffer.size >= (size_t)encoder->ctx.data.ptr);
  return (long)(encoder->buffer.size - (size_t)encoder->ctx.data.ptr);
}

CborError
oc_rep_encoder_write_raw(oc_rep_encoder_t *encoder, const uint8_t *data,
                         size_t len)
{
  long remaining = oc_rep_encoder_remaining_size(encoder);
  if (remaining < 0) {
    return CborErrorInternalError;
  }
  if ((size_t)remaining < len) {
#ifdef OC_DYNAMIC_ALLOCATION
    if (!encoder->buffer.enable_realloc) {
      OC_WRN(
        "Insufficient memory: Reallocation of the encoder buffer disabled");
      return CborErrorOutOfMemory;
    }
    CborEncoder prevEncoder;
    memcpy(&prevEncoder, &encoder->ctx, sizeof(prevEncoder));
    size_t needed = len - remaining;
    CborError err = rep_buffer_realloc(encoder, needed);
    if (err != CborNoError) {
      return err;
    }
    memcpy(&encoder->ctx, &prevEncoder, sizeof(prevEncoder));
#else  /* OC_DYNAMIC_ALLOCATION */
    OC_WRN("Insufficient memory: Increase OC_MAX_APP_DATA_SIZE to "
           "accomodate a larger payload(+%zu)",
           len - remaining);
    return CborErrorOutOfMemory;
#endif /* !OC_DYNAMIC_ALLOCATION */
  }
  oc_rep_encoder_convert_offset_to_ptr(encoder, &encoder->ctx);
  memcpy(encoder->ctx.data.ptr, data, len);
  // TODO: this is not correct for crc encoder, add write raw interface function
  encoder->ctx.data.ptr = encoder->ctx.data.ptr + len;
  oc_rep_encoder_convert_ptr_to_offset(encoder, &encoder->ctx);
  return CborNoError;
}

void
oc_rep_encode_raw(const uint8_t *data, size_t len)
{
  g_err = oc_rep_encoder_write_raw(&g_rep_encoder, data, len);
}

static CborError
rep_encode_null_internal(const oc_rep_encoder_t *encoder,
                         CborEncoder *subEncoder)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  CborError err = encoder->impl.encode_null(subEncoder);
  oc_rep_encoder_convert_ptr_to_offset(oc_rep_global_encoder(), subEncoder);
  return err;
}

CborError
oc_rep_encoder_write_null(oc_rep_encoder_t *encoder, CborEncoder *subEncoder)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encode_null_internal(encoder, subEncoder);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err = rep_encode_null_internal(encoder, subEncoder);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, subEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    return rep_encode_null_internal(encoder, subEncoder);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encode_null(CborEncoder *encoder)
{
  return oc_rep_encoder_write_null(&g_rep_encoder, encoder);
}

static CborError
rep_encode_boolean_internal(const oc_rep_encoder_t *encoder,
                            CborEncoder *subEncoder, bool value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  CborError err = encoder->impl.encode_boolean(subEncoder, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  return err;
}

CborError
oc_rep_encoder_write_boolean(oc_rep_encoder_t *encoder, CborEncoder *subEncoder,
                             bool value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encode_boolean_internal(encoder, subEncoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err = rep_encode_boolean_internal(encoder, subEncoder, value);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, subEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    return rep_encode_boolean_internal(encoder, subEncoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encode_boolean(CborEncoder *encoder, bool value)
{
  return oc_rep_encoder_write_boolean(&g_rep_encoder, encoder, value);
}

static CborError
rep_encode_int_internal(const oc_rep_encoder_t *encoder,
                        CborEncoder *subEncoder, int64_t value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  CborError err = encoder->impl.encode_int(subEncoder, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  return err;
}

CborError
oc_rep_encoder_write_int(oc_rep_encoder_t *encoder, CborEncoder *subEncoder,
                         int64_t value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encode_int_internal(encoder, subEncoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err = rep_encode_int_internal(encoder, subEncoder, value);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, subEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    return rep_encode_int_internal(encoder, subEncoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encode_int(CborEncoder *subEncoder, int64_t value)
{
  return oc_rep_encoder_write_int(&g_rep_encoder, subEncoder, value);
}

static CborError
rep_encode_uint_internal(const oc_rep_encoder_t *encoder,
                         CborEncoder *subEncoder, uint64_t value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  CborError err = encoder->impl.encode_uint(subEncoder, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  return err;
}

CborError
oc_rep_encoder_write_uint(oc_rep_encoder_t *encoder, CborEncoder *subEncoder,
                          uint64_t value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encode_uint_internal(encoder, subEncoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err = rep_encode_uint_internal(encoder, subEncoder, value);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, subEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    return rep_encode_uint_internal(encoder, subEncoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encode_uint(CborEncoder *subEncoder, uint64_t value)
{
  return oc_rep_encoder_write_uint(&g_rep_encoder, subEncoder, value);
}

static CborError
rep_encode_floating_point_internal(const oc_rep_encoder_t *encoder,
                                   CborEncoder *subEncoder, CborType fpType,
                                   const void *value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  CborError err =
    encoder->impl.encode_floating_point(subEncoder, fpType, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  return err;
}

CborError
oc_rep_encoder_write_floating_point(oc_rep_encoder_t *encoder,
                                    CborEncoder *subEncoder, CborType fpType,
                                    const void *value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encode_floating_point_internal(encoder, subEncoder, fpType, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err =
    rep_encode_floating_point_internal(encoder, subEncoder, fpType, value);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, subEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    return rep_encode_floating_point_internal(encoder, subEncoder, fpType,
                                              value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encode_floating_point(CborEncoder *subEncoder, CborType fpType,
                             const void *value)
{
  return oc_rep_encoder_write_floating_point(&g_rep_encoder, subEncoder, fpType,
                                             value);
}

static CborError
rep_encode_double_internal(const oc_rep_encoder_t *encoder,
                           CborEncoder *subEncoder, double value)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  CborError err = encoder->impl.encode_double(subEncoder, value);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  return err;
}

CborError
oc_rep_encoder_write_double(oc_rep_encoder_t *encoder, CborEncoder *subEncoder,
                            double value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encode_double_internal(encoder, subEncoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err = rep_encode_double_internal(encoder, subEncoder, value);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, subEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    return rep_encode_double_internal(encoder, subEncoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encode_double(CborEncoder *subEncoder, double value)
{
  return oc_rep_encoder_write_double(&g_rep_encoder, subEncoder, value);
}

static CborError
rep_encode_text_string_internal(const oc_rep_encoder_t *encoder,
                                CborEncoder *subEncoder, const char *string,
                                size_t length)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  CborError err = encoder->impl.encode_text_string(subEncoder, string, length);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  return err;
}

CborError
oc_rep_encoder_write_text_string(oc_rep_encoder_t *encoder,
                                 CborEncoder *subEncoder, const char *string,
                                 size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encode_text_string_internal(encoder, subEncoder, string, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err =
    rep_encode_text_string_internal(encoder, subEncoder, string, length);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, subEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    return rep_encode_text_string_internal(encoder, subEncoder, string, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encode_text_string(CborEncoder *subEncoder, const char *string,
                          size_t length)
{
  return oc_rep_encoder_write_text_string(&g_rep_encoder, subEncoder, string,
                                          length);
}

static CborError
rep_encode_byte_string_internal(const oc_rep_encoder_t *encoder,
                                CborEncoder *subEncoder, const uint8_t *string,
                                size_t length)

{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  CborError err = encoder->impl.encode_byte_string(subEncoder, string, length);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  return err;
}

CborError
oc_rep_encoder_write_byte_string(oc_rep_encoder_t *encoder,
                                 CborEncoder *subEncoder, const uint8_t *string,
                                 size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encode_byte_string_internal(encoder, subEncoder, string, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err =
    rep_encode_byte_string_internal(encoder, subEncoder, string, length);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, subEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    return rep_encode_byte_string_internal(encoder, subEncoder, string, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encode_byte_string(CborEncoder *encoder, const uint8_t *string,
                          size_t length)
{
  return oc_rep_encoder_write_byte_string(&g_rep_encoder, encoder, string,
                                          length);
}

static CborError
rep_encoder_create_array_internal(const oc_rep_encoder_t *encoder,
                                  CborEncoder *subEncoder,
                                  CborEncoder *arrayEncoder, size_t length)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  oc_rep_encoder_convert_offset_to_ptr(encoder, arrayEncoder);
  CborError err = encoder->impl.create_array(subEncoder, arrayEncoder, length);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  oc_rep_encoder_convert_ptr_to_offset(encoder, arrayEncoder);
  return err;
}

CborError
oc_rep_encoder_write_array_open(oc_rep_encoder_t *encoder,
                                CborEncoder *subEncoder,
                                CborEncoder *arrayEncoder, size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encoder_create_array_internal(encoder, subEncoder, arrayEncoder,
                                           length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborEncoder prevArrayEncoder;
  memcpy(&prevArrayEncoder, arrayEncoder, sizeof(prevArrayEncoder));
  CborError err = rep_encoder_create_array_internal(encoder, subEncoder,
                                                    arrayEncoder, length);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, arrayEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    memcpy(arrayEncoder, &prevArrayEncoder, sizeof(prevArrayEncoder));
    return rep_encoder_create_array_internal(encoder, subEncoder, arrayEncoder,
                                             length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encoder_create_array(CborEncoder *subEncoder, CborEncoder *arrayEncoder,
                            size_t length)
{
  return oc_rep_encoder_write_array_open(&g_rep_encoder, subEncoder,
                                         arrayEncoder, length);
}

static CborError
rep_encoder_create_map_internal(const oc_rep_encoder_t *encoder,
                                CborEncoder *subEncoder,
                                CborEncoder *mapEncoder, size_t length)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  oc_rep_encoder_convert_offset_to_ptr(encoder, mapEncoder);
  CborError err = encoder->impl.create_map(subEncoder, mapEncoder, length);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  oc_rep_encoder_convert_ptr_to_offset(encoder, mapEncoder);
  return err;
}

CborError
oc_rep_encoder_write_map_open(oc_rep_encoder_t *encoder,
                              CborEncoder *subEncoder, CborEncoder *mapEncoder,
                              size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encoder_create_map_internal(encoder, subEncoder, mapEncoder,
                                         length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevMapEncoder;
  memcpy(&prevMapEncoder, mapEncoder, sizeof(prevMapEncoder));
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err =
    rep_encoder_create_map_internal(encoder, subEncoder, mapEncoder, length);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, mapEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(mapEncoder, &prevMapEncoder, sizeof(prevMapEncoder));
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    return rep_encoder_create_map_internal(encoder, subEncoder, mapEncoder,
                                           length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encoder_create_map(CborEncoder *subEncoder, CborEncoder *mapEncoder,
                          size_t length)
{
  return oc_rep_encoder_write_map_open(&g_rep_encoder, subEncoder, mapEncoder,
                                       length);
}

static CborError
rep_encoder_close_container_internal(const oc_rep_encoder_t *encoder,
                                     CborEncoder *subEncoder,
                                     CborEncoder *containerEncoder)
{
  oc_rep_encoder_convert_offset_to_ptr(encoder, subEncoder);
  oc_rep_encoder_convert_offset_to_ptr(encoder, containerEncoder);
  CborError err = encoder->impl.close_container(subEncoder, containerEncoder);
  oc_rep_encoder_convert_ptr_to_offset(encoder, subEncoder);
  oc_rep_encoder_convert_ptr_to_offset(encoder, containerEncoder);
  return err;
}

CborError
oc_rep_encoder_write_container_close(oc_rep_encoder_t *encoder,
                                     CborEncoder *subEncoder,
                                     CborEncoder *containerEncoder)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return rep_encoder_close_container_internal(encoder, subEncoder,
                                              containerEncoder);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevContainerEncoder;
  memcpy(&prevContainerEncoder, containerEncoder, sizeof(prevContainerEncoder));
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, subEncoder, sizeof(prevEncoder));
  CborError err =
    rep_encoder_close_container_internal(encoder, subEncoder, containerEncoder);
  if (err == CborErrorOutOfMemory) {
    err = rep_buffer_realloc(
      encoder, rep_encoder_get_extra_bytes_needed(encoder, subEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(subEncoder, &prevEncoder, sizeof(prevEncoder));
    memcpy(containerEncoder, &prevContainerEncoder,
           sizeof(prevContainerEncoder));
    return rep_encoder_close_container_internal(encoder, subEncoder,
                                                containerEncoder);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encoder_close_container(CborEncoder *subEncoder,
                               CborEncoder *containerEncoder)
{
  return oc_rep_encoder_write_container_close(&g_rep_encoder, subEncoder,
                                              containerEncoder);
}

/* oc_rep_object interface */

CborError
oc_rep_object_set_null(CborEncoder *object, const char *key, size_t key_len)
{
  CborError err = oc_rep_encode_text_string(object, key, key_len);
  err |= oc_rep_encode_null(object);
  return err;
}

CborError
oc_rep_object_set_boolean(CborEncoder *object, const char *key, size_t key_len,
                          bool value)
{
  CborError err = oc_rep_encode_text_string(object, key, key_len);
  err |= oc_rep_encode_boolean(object, value);
  return err;
}

CborError
oc_rep_object_set_int(CborEncoder *object, const char *key, size_t key_len,
                      int64_t value)
{
  CborError err = oc_rep_encode_text_string(object, key, key_len);
  err |= oc_rep_encode_int(object, value);
  return err;
}

CborError
oc_rep_object_set_uint(CborEncoder *object, const char *key, size_t key_len,
                       uint64_t value)
{
  CborError err = oc_rep_encode_text_string(object, key, key_len);
  err |= oc_rep_encode_uint(object, value);
  return err;
}

CborError
oc_rep_object_set_double(CborEncoder *object, const char *key, size_t key_len,
                         double value)
{
  CborError err = oc_rep_encode_text_string(object, key, key_len);
  err |= oc_rep_encode_double(object, value);
  return err;
}

CborError
oc_rep_object_set_text_string(CborEncoder *object, const char *key,
                              size_t key_len, const char *value,
                              size_t value_len)
{
  CborError err = oc_rep_encode_text_string(object, key, key_len);
  err |=
    oc_rep_encode_text_string(object, value == NULL ? "" : value, value_len);
  return err;
}

CborError
oc_rep_object_set_byte_string(CborEncoder *object, const char *key,
                              size_t key_len, const uint8_t *value,
                              size_t length)
{
  CborError err = oc_rep_encode_text_string(object, key, key_len);
  err |= oc_rep_encode_byte_string(object, value, length);
  return err;
}

CborError
oc_rep_object_set_string_array(CborEncoder *object, const char *key,
                               size_t key_len, const oc_string_array_t *array)
{
  CborError err = oc_rep_encode_text_string(object, key, key_len);
  CborEncoder arrayEncoder;
  memset(&arrayEncoder, 0, sizeof(arrayEncoder));
  err |=
    oc_rep_encoder_create_array(object, &arrayEncoder, CborIndefiniteLength);
  for (size_t i = 0; i < oc_string_array_get_allocated_size(*array); ++i) {
    size_t item_len = oc_string_array_get_item_size(*array, i);
    if (item_len > 0) {
      err |= oc_rep_encode_text_string(
        &arrayEncoder, oc_string_array_get_item(*array, i), item_len);
    }
  }
  err |= oc_rep_encoder_close_container(object, &arrayEncoder);
  return err;
}
