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

/**
  @brief OC Representation object setters & getters stored as (key,value) pairs.
  @file
*/

#include "deps/tinycbor/src/cbor.h"
#include "oc_helpers.h"
#include "util/oc_memb.h"
#include <config.h>
#include <stdbool.h>
#include <stdint.h>

extern CborEncoder g_encoder, root_map, links_array;
extern int g_err;

/**
  @brief A function to initialize payload CBOR buffer.
  @param[in] payload CBOR buffer to be used by CBOR encoder.
  @param[in] size Size of the payload CBOR buffer.
*/
void oc_rep_new(uint8_t *payload, int size);

/**
  @brief A function to reset CBOR buffer and reset CBOR error code.
*/
void oc_rep_reset(void);

/**
  @brief A function to finalize the encoded CBOR buffer.
  @return int Size of encoded CBOR buffer.
*/
int oc_rep_finalize(void);

#define oc_rep_object(name) &name##_map
#define oc_rep_array(name) &name##_array

/**
  @brief A macro to set integer with given key,value for CBOR object.
*/
#define oc_rep_set_double(object, key, value)                                  \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_double(&object##_map, value);                         \
  } while (0)

/**
  @brief A macro to set integer with given key,value for CBOR object.
*/
#define oc_rep_set_int(object, key, value)                                     \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_int(&object##_map, value);                            \
  } while (0)

/**
  @brief A macro to set unsigned integer with given key,value for CBOR object.
*/
#define oc_rep_set_uint(object, key, value)                                    \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_uint(&object##_map, value);                           \
  } while (0)

/**
  @brief A macro to set boolean with given key,value for CBOR object.
*/
#define oc_rep_set_boolean(object, key, value)                                 \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_boolean(&object##_map, value);                        \
  } while (0)

/**
  @brief A macro to set string with given key,value for CBOR object.
*/
#define oc_rep_set_text_string(object, key, value)                             \
  do {                                                                         \
    if (value != NULL) {                                                       \
      g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));     \
      g_err |= cbor_encode_text_string(&object##_map, value, strlen(value));   \
    }                                                                          \
  } while (0)

/**
  @brief A macro to set byte string with given key,value,length for CBOR object.
*/
#define oc_rep_set_byte_string(object, key, value, length)                     \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_byte_string(&object##_map, value, length);            \
  } while (0)

/**
  @brief A macro to start array with given key for parent object.
*/
#define oc_rep_start_array(parent, key)                                        \
  do {                                                                         \
    CborEncoder key##_array;                                                   \
  g_err |=                                                                     \
    cbor_encoder_create_array(&parent, &key##_array, CborIndefiniteLength)

/**
  @brief A macro to close array with given key for parent object.
*/
#define oc_rep_end_array(parent, key)                                          \
  g_err |= cbor_encoder_close_container(&parent, &key##_array);                \
  }                                                                            \
  while (0)

/**
  @brief A macro to start links array.
*/
#define oc_rep_start_links_array()                                             \
  g_err |=                                                                     \
    cbor_encoder_create_array(&g_encoder, &links_array, CborIndefiniteLength)

/**
  @brief A macro to end links array.
*/
#define oc_rep_end_links_array()                                               \
  g_err |= cbor_encoder_close_container(&g_encoder, &links_array)

/**
  @brief A macro to start root object.
*/
#define oc_rep_start_root_object()                                             \
  g_err |= cbor_encoder_create_map(&g_encoder, &root_map, CborIndefiniteLength)

/**
  @brief A macro to close root object.
*/
#define oc_rep_end_root_object()                                               \
  g_err |= cbor_encoder_close_container(&g_encoder, &root_map)

/**
  @brief A macro to add byte string value for parent object.
*/
#define oc_rep_add_byte_string(parent, value)                                  \
  if (value != NULL)                                                           \
  g_err |= cbor_encode_byte_string(&parent##_array, value, strlen(value))

/**
  @brief A macro to add string value for parent object.
*/
#define oc_rep_add_text_string(parent, value)                                  \
  if (value != NULL)                                                           \
  g_err |= cbor_encode_text_string(&parent##_array, value, strlen(value))

/**
  @brief A macro to add double value for parent object.
*/
#define oc_rep_add_double(parent, value)                                       \
  g_err |= cbor_encode_double(&parent##_array, value)

/**
  @brief A macro to add integer value for parent object.
*/
#define oc_rep_add_int(parent, value)                                          \
  g_err |= cbor_encode_int(&parent##_array, value)

/**
  @brief A macro to add boolean value for parent object.
*/
#define oc_rep_add_boolean(parent, value)                                      \
  g_err |= cbor_encode_boolean(&parent##_array, value)

/**
  @brief A macro to set key for parent object.
*/
#define oc_rep_set_key(parent, key)                                            \
  if (key != NULL)                                                             \
  g_err |= cbor_encode_text_string(&parent, key, strlen(key))

/**
  @brief A macro to set array encoding for a given key in CBOR object.
*/
#define oc_rep_set_array(object, key)                                          \
  g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));         \
  oc_rep_start_array(object##_map, key)

/**
  @brief A macro to close array encoding for a given key in CBOR object.
*/
#define oc_rep_close_array(object, key) oc_rep_end_array(object##_map, key)

/**
  @brief A macro to start encoding for a given key in CBOR object.
*/
#define oc_rep_start_object(parent, key)                                       \
  do {                                                                         \
    CborEncoder key##_map;                                                     \
  g_err |= cbor_encoder_create_map(&parent, &key##_map, CborIndefiniteLength)

/**
  @brief A macro to end encoding for a given key in CBOR object.
*/
#define oc_rep_end_object(parent, key)                                         \
  g_err |= cbor_encoder_close_container(&parent, &key##_map);                  \
  }                                                                            \
  while (0)

/**
  @brief A macro to start array encoding for a given key.
*/
#define oc_rep_object_array_start_item(key)                                    \
  oc_rep_start_object(key##_array, key)

/**
  @brief A macro to end array encoding for a given key.
*/
#define oc_rep_object_array_end_item(key) oc_rep_end_object(key##_array, key)

/**
  @brief A macro to start map encoding for a given key for a CBOR object.
*/
#define oc_rep_set_object(object, key)                                         \
  g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));         \
  oc_rep_start_object(object##_map, key)

/**
  @brief A macro to cloase map encoding for a given key for a CBOR object.
*/
#define oc_rep_close_object(object, key) oc_rep_end_object(object##_map, key)

/**
  @brief A macro to set the integer array.
  @param[in] object The CBOR encoder object where (key,values) will be added.
  @param[in] key The string key to be added.
  @param[in] values The integer array to be added.
  @param[in] length The length of values to be added.
*/
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

/**
  @brief A macro to set the boolean array.
  @param[in] object The CBOR encoder object where (key,values) will be added.
  @param[in] key The string key to be added.
  @param[in] values The boolean array to be added.
  @param[in] length The length of values to be added.
*/
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

/**
  @brief A macro to set the double array.
  @param[in] object The CBOR encoder object where (key,values) will be added.
  @param[in] key The string key to be added.
  @param[in] values The double array to be added.
  @param[in] length The length of values to be added.
*/
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

/**
  @brief A macro to set the string array.
  @param[in] object The CBOR encoder object where (key,values) will be added.
  @param[in] key The string key to be added.
  @param[in] values The string array to be added.
*/
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

/**
  @brief An enumeration which defines the value types in OC Representation.
*/
typedef enum {
  OC_REP_NIL = 0,                     /*!< Default value type */
  OC_REP_INT = 0x01,                  /*!< Integer value type */
  OC_REP_DOUBLE = 0x02,               /*!< Double value type */
  OC_REP_BOOL = 0x03,                 /*!< Boolean value type */
  OC_REP_BYTE_STRING = 0x04,          /*!< Byte String value type */
  OC_REP_STRING = 0x05,               /*!< String value type */
  OC_REP_OBJECT = 0x06,               /*!< OC Representation Object value type */
  OC_REP_ARRAY = 0x08,                /*!< Array value type */
  OC_REP_INT_ARRAY = 0x09,            /*!< Integer Array value type */
  OC_REP_DOUBLE_ARRAY = 0x0A,         /*!< Double Array value type */
  OC_REP_BOOL_ARRAY = 0x0B,           /*!< Boolean Array value type */
  OC_REP_BYTE_STRING_ARRAY = 0x0C,    /*!< Byte String Array value type */
  OC_REP_STRING_ARRAY = 0x0D,         /*!< String Array value type */
  OC_REP_OBJECT_ARRAY = 0x0E          /*!< OC Representation Object Array value type */
} oc_rep_value_type_t;

/**
  @brief The OC Representation data structure node.
*/
typedef struct oc_rep_s
{
  oc_rep_value_type_t type;           /*!< OC Representation value type @see oc_rep_value_type_t */
  struct oc_rep_s *next;              /*!< Link List pointer next */
  oc_string_t name;                   /*!< key */
  union oc_rep_value
  {
    int integer;
    bool boolean;
    double double_p;
    oc_string_t string;
    oc_array_t array;
    struct oc_rep_s *object;
    struct oc_rep_s *object_array;
  } value;                            /*!< value (union) */
} oc_rep_t;

void oc_rep_set_pool(struct oc_memb *rep_objects_pool);

/**
  @brief A function parse a CBOR payload and store in OC Representation.
  @param[in] payload The CBOR payload data.
  @param[in] payload_size The CBOR payload data size.
  @param[out] value_list The output value list returned.
  @return int Result of parsing operation.
  @retval CborNoError if CBOR parsing is successful.
  @retval CborErrorOutOfMemory if we run out of memory during parsing.
  @retval CborError* if CBOR parsing is unsuccessful.
*/
int oc_parse_rep(const uint8_t *payload, int payload_size,
                 oc_rep_t **value_list);

/**
  @brief A function to free the OC Representation.
  @param[in] rep The OC Representation needs to be freed.
*/
void oc_free_rep(oc_rep_t *rep);

/**
  @brief A function to get the int value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_int(oc_rep_t *rep, const char *key, int *value);

/**
  @brief A function to get the bool value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_bool(oc_rep_t *rep, const char *key, bool *value);

/**
  @brief A function to get the double value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_double(oc_rep_t *rep, const char *key, double *value);

/**
  @brief A function to get the byte string value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @param[out] size The size of the value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_byte_string(oc_rep_t *rep, const char *key, char **value, int *size);

/**
  @brief A function to get the string value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @param[out] size The size of the value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_string(oc_rep_t *rep, const char *key, char **value, int *size);

/**
  @brief A function to get the int array value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @param[out] size The size of the value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_int_array(oc_rep_t *rep, const char *key, int **value, int *size);

/**
  @brief A function to get the bool array value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @param[out] size The size of the value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_bool_array(oc_rep_t *rep, const char *key, bool **value, int *size);

/**
  @brief A function to get the double array value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @param[out] size The size of the value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_double_array(oc_rep_t *rep, const char *key, double **value, int *size);

/**
  @brief A function to get the byte string array value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @param[out] size The size of the value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_byte_string_array(oc_rep_t *rep, const char *key, oc_string_array_t *value, int *size);

/**
  @brief A function to get the string array value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @param[out] size The size of the value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_string_array(oc_rep_t *rep, const char *key, oc_string_array_t *value, int *size);

/**
  @brief A function to get the object value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_object(oc_rep_t *rep, const char *key, oc_rep_t **value);

/**
  @brief A function to get the object array value from OC Representation.
  @param[in] rep The OC Representation where data is stored.
  @param[in] key The string which is used to store the value.
  @param[out] value The output value returned.
  @return bool Result of get operation.
  @retval true if get is successful.
  @retval false if any input parameter is NULL,
                or the rep doesn't have the key.
*/
bool oc_rep_get_object_array(oc_rep_t *rep, const char *key, oc_rep_t **value);

#endif /* OC_REP_H */
