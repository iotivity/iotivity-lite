/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_REP_H
#define OC_REP_H

#include "deps/tinycbor/src/cbor.h"
#include "oc_helpers.h"
#include "util/oc_memb.h"
#include <config.h>
#include <stdbool.h>
#include <stdint.h>

extern CborEncoder g_encoder, root_map, links_array;
extern CborError g_err;

void oc_rep_new(uint8_t *payload, int size);
int oc_rep_finalize(void);

#define oc_rep_object(name) &name##_map
#define oc_rep_array(name) &name##_array

#define oc_rep_set_double(object, key, value)                                  \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_double(&object##_map, value);                         \
  } while (0)

#define oc_rep_set_int(object, key, value)                                     \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_int(&object##_map, value);                            \
  } while (0)

#define oc_rep_set_uint(object, key, value)                                    \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_uint(&object##_map, value);                           \
  } while (0)

#define oc_rep_set_boolean(object, key, value)                                 \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_boolean(&object##_map, value);                        \
  } while (0)

#define oc_rep_set_text_string(object, key, value)                             \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_text_string(&object##_map, value, strlen(value));     \
  } while (0)

#define oc_rep_set_byte_string(object, key, value, length)                     \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_byte_string(&object##_map, value, length);            \
  } while (0)

#define oc_rep_start_array(parent, key)                                        \
  do {                                                                         \
    CborEncoder key##_array;                                                   \
  g_err |=                                                                     \
    cbor_encoder_create_array(&parent, &key##_array, CborIndefiniteLength)

#define oc_rep_end_array(parent, key)                                          \
  g_err |= cbor_encoder_close_container(&parent, &key##_array);                \
  }                                                                            \
  while (0)

#define oc_rep_start_links_array()                                             \
  g_err |=                                                                     \
    cbor_encoder_create_array(&g_encoder, &links_array, CborIndefiniteLength)

#define oc_rep_end_links_array()                                               \
  g_err |= cbor_encoder_close_container(&g_encoder, &links_array)

#define oc_rep_start_root_object()                                             \
  g_err |= cbor_encoder_create_map(&g_encoder, &root_map, CborIndefiniteLength)

#define oc_rep_end_root_object()                                               \
  g_err |= cbor_encoder_close_container(&g_encoder, &root_map)

#define oc_rep_add_byte_string(parent, value)                                  \
  g_err |= cbor_encode_byte_string(&parent##_array, value, strlen(value))

#define oc_rep_add_text_string(parent, value)                                  \
  g_err |= cbor_encode_text_string(&parent##_array, value, strlen(value))

#define oc_rep_add_double(parent, value)                                       \
  g_err |= cbor_encode_double(&parent##_array, value)

#define oc_rep_add_int(parent, value)                                          \
  g_err |= cbor_encode_int(&parent##_array, value)

#define oc_rep_add_boolean(parent, value)                                      \
  g_err |= cbor_encode_boolean(&parent##_array, value)

#define oc_rep_set_key(parent, key)                                            \
  g_err |= cbor_encode_text_string(&parent, key, strlen(key))

#define oc_rep_set_array(object, key)                                          \
  g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));         \
  oc_rep_start_array(object##_map, key)

#define oc_rep_close_array(object, key) oc_rep_end_array(object##_map, key)

#define oc_rep_start_object(parent, key)                                       \
  do {                                                                         \
    CborEncoder key##_map;                                                     \
  g_err |= cbor_encoder_create_map(&parent, &key##_map, CborIndefiniteLength)

#define oc_rep_end_object(parent, key)                                         \
  g_err |= cbor_encoder_close_container(&parent, &key##_map);                  \
  }                                                                            \
  while (0)

#define oc_rep_object_array_start_item(key)                                    \
  oc_rep_start_object(key##_array, key)

#define oc_rep_object_array_end_item(key) oc_rep_end_object(key##_array, key)

#define oc_rep_set_object(object, key)                                         \
  g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));         \
  oc_rep_start_object(object##_map, key)

#define oc_rep_close_object(object, key) oc_rep_end_object(object##_map, key)

#define oc_rep_set_int_array(object, key, values, length)                      \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    CborEncoder key##_value_array;                                             \
    g_err |=                                                                   \
      cbor_encoder_create_array(&object##_map, &key##_value_array, length);    \
    int i;                                                                     \
    for (i = 0; i < length; i++) {                                             \
      g_err |= cbor_encode_int(&key##_value_array, values[i]);                 \
    }                                                                          \
    g_err |= cbor_encoder_close_container(&object##_map, &key##_value_array);  \
  } while (0)

#define oc_rep_set_bool_array(object, key, values, length)                     \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    CborEncoder key##_value_array;                                             \
    g_err |=                                                                   \
      cbor_encoder_create_array(&object##_map, &key##_value_array, length);    \
    int i;                                                                     \
    for (i = 0; i < length; i++) {                                             \
      g_err |= cbor_encode_boolean(&key##_value_array, values[i]);             \
    }                                                                          \
    g_err |= cbor_encoder_close_container(&object##_map, &key##_value_array);  \
  } while (0)

#define oc_rep_set_double_array(object, key, values, length)                   \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    CborEncoder key##_value_array;                                             \
    g_err |=                                                                   \
      cbor_encoder_create_array(&object##_map, &key##_value_array, length);    \
    int i;                                                                     \
    for (i = 0; i < length; i++) {                                             \
      g_err |= cbor_encode_floating_point(&key##_value_array, CborDoubleType,  \
                                          &values[i]);                         \
    }                                                                          \
    g_err |= cbor_encoder_close_container(&object##_map, &key##_value_array);  \
  } while (0)

#define oc_rep_set_string_array(object, key, values)                           \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    CborEncoder key##_value_array;                                             \
    g_err |= cbor_encoder_create_array(&object##_map, &key##_value_array,      \
                                       CborIndefiniteLength);                  \
    int i;                                                                     \
    for (i = 0; i < (int)oc_string_array_get_allocated_size(values); i++) {    \
      if (oc_string_array_get_item_size(values, i) > 0) {                      \
        g_err |= cbor_encode_text_string(                                      \
          &key##_value_array, oc_string_array_get_item(values, i),             \
          oc_string_array_get_item_size(values, i));                           \
      }                                                                        \
    }                                                                          \
    g_err |= cbor_encoder_close_container(&object##_map, &key##_value_array);  \
  } while (0)

CborError oc_rep_get_cbor_errno(void);

typedef enum {
  OC_REP_NIL = 0,
  OC_REP_INT = 0x01,
  OC_REP_DOUBLE = 0x02,
  OC_REP_BOOL = 0x03,
  OC_REP_BYTE_STRING = 0x04,
  OC_REP_STRING = 0x05,
  OC_REP_OBJECT = 0x06,
  OC_REP_ARRAY = 0x08,
  OC_REP_INT_ARRAY = 0x09,
  OC_REP_DOUBLE_ARRAY = 0x0A,
  OC_REP_BOOL_ARRAY = 0x0B,
  OC_REP_BYTE_STRING_ARRAY = 0x0C,
  OC_REP_STRING_ARRAY = 0x0D,
  OC_REP_OBJECT_ARRAY = 0x0E
} oc_rep_value_type_t;

typedef struct oc_rep_s
{
  oc_rep_value_type_t type;
  struct oc_rep_s *next;
  oc_string_t name;
  union oc_rep_value
  {
    int integer;
    bool boolean;
    double double_p;
    oc_string_t string;
    oc_array_t array;
    struct oc_rep_s *object;
    struct oc_rep_s *object_array;
  } value;
} oc_rep_t;

void oc_rep_set_pool(struct oc_memb *rep_objects_pool);

int oc_parse_rep(const uint8_t *payload, int payload_size,
                 oc_rep_t **value_list);

void oc_free_rep(oc_rep_t *rep);

#endif /* OC_REP_H */
