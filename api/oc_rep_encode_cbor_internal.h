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

#ifndef OC_REP_ENCODE_CBOR_INTERNAL_H
#define OC_REP_ENCODE_CBOR_INTERNAL_H

#include "api/oc_rep_encode_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OC_REP_CBOR_ENCODER_INIT                                               \
  {                                                                            \
    .get_buffer_size = &cbor_encoder_get_buffer_size,                          \
    .get_extra_bytes_needed = &cbor_encoder_get_extra_bytes_needed,            \
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

/** Return CBOR encoder implementation. */
oc_rep_encoder_implementation_t oc_rep_cbor_encoder(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_REP_ENCODE_JSON_INTERNAL_H */
